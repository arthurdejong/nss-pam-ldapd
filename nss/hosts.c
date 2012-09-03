/*
   hosts.c - NSS lookup functions for hosts database

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007, 2008, 2010, 2012 Arthur de Jong
   Copyright (C) 2010 Symas Corporation

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301 USA
*/

#include "config.h"

#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "prototypes.h"
#include "common.h"
#include "compat/attrs.h"

/* Redefine some ERROR_OUT macros as we also want to set h_errnop. */

#undef ERROR_OUT_OPENERROR
#define ERROR_OUT_OPENERROR \
  *errnop=ENOENT; \
  *h_errnop=HOST_NOT_FOUND; \
  return (errno==EAGAIN)?NSS_STATUS_TRYAGAIN:NSS_STATUS_UNAVAIL;

#undef ERROR_OUT_READERROR
#define ERROR_OUT_READERROR(fp) \
  (void)tio_close(fp); \
  fp=NULL; \
  *errnop=ENOENT; \
  *h_errnop=NO_RECOVERY; \
  return NSS_STATUS_UNAVAIL;

#undef ERROR_OUT_BUFERROR
#define ERROR_OUT_BUFERROR(fp) \
  (void)tio_close(fp); \
  fp=NULL; \
  *errnop=ERANGE; \
  *h_errnop=TRY_AGAIN; \
  return NSS_STATUS_TRYAGAIN;

#undef ERROR_OUT_WRITEERROR
#define ERROR_OUT_WRITEERROR(fp) \
  ERROR_OUT_READERROR(fp)

/* read a single host entry from the stream, filtering on the
   specified address family, result is stored in result
   it will an empty entry if no addresses in the address family
   were available */
static nss_status_t read_hostent(
        TFILE *fp,int af,struct hostent *result,
        char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  int32_t numaddr;
  int i;
  int readaf;
  size_t bufptr=0;
  /* read the host entry */
  READ_BUF_STRING(fp,result->h_name);
  READ_BUF_STRINGLIST(fp,result->h_aliases);
  result->h_addrtype=af;
  result->h_length=0;
  /* read number of addresses to follow */
  READ_INT32(fp,numaddr);
  /* allocate memory for array */
  /* Note: this may allocate too much memory (e.g. also for
           address records of other address families) but
           this is a simple way to do it */
  BUF_ALLOC(fp,result->h_addr_list,char *,numaddr+1);
  /* go through the address list and filter on af */
  i=0;
  while (--numaddr>=0)
  {
    /* read address family and size */
    READ_INT32(fp,readaf);
    READ_INT32(fp,tmp2int32);
    if (readaf==af)
    {
      /* read the address */
      result->h_length=tmp2int32;
      READ_BUF(fp,result->h_addr_list[i++],tmp2int32);
    }
    else
    {
      SKIP(fp,tmpint32);
    }
  }
  /* null-terminate address list */
  result->h_addr_list[i]=NULL;
  return NSS_STATUS_SUCCESS;
}

/* this is a wrapper around read_hostent() that does error handling
   if the read address list does not contain any addresses for the
   specified address familiy */
static nss_status_t read_hostent_erronempty(
        TFILE *fp,int af,struct hostent *result,
        char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  nss_status_t retv;
  retv=read_hostent(fp,af,result,buffer,buflen,errnop,h_errnop);
  /* check result */
  if (retv!=NSS_STATUS_SUCCESS)
    return retv;
  /* check empty address list
     (note that we cannot do this in the read_hostent() function as closing
     the socket there will cause problems with the {set,get,end}ent() functions
     below)
  */
  if (result->h_addr_list[0]==NULL)
  {
    *errnop=ENOENT;
    *h_errnop=NO_ADDRESS;
    (void)tio_close(fp);
    return NSS_STATUS_NOTFOUND;
  }
  return NSS_STATUS_SUCCESS;
}

/* this is a wrapper around read_hostent() that skips to the
   next address if the address list does not contain any addresses for the
   specified address familiy */
static nss_status_t read_hostent_nextonempty(
        TFILE *fp,int af,struct hostent *result,
        char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  int32_t tmpint32;
  nss_status_t retv;
  /* check until we read an non-empty entry */
  do
  {
    /* read a host entry */
    retv=read_hostent(fp,af,result,buffer,buflen,errnop,h_errnop);
    /* check result */
    if (retv!=NSS_STATUS_SUCCESS)
      return retv;
    /* skip to the next entry if we read an empty address */
    if (result->h_addr_list[0]==NULL)
    {
      retv=NSS_STATUS_NOTFOUND;
      READ_RESPONSE_CODE(fp);
    }
    /* do another loop run if we read an empty address */
  }
  while (retv!=NSS_STATUS_SUCCESS);
  return NSS_STATUS_SUCCESS;
}

/* write an address value */
#define WRITE_ADDRESS(fp,af,len,addr) \
  WRITE_INT32(fp,af); \
  WRITE_INT32(fp,len); \
  WRITE(fp,addr,len);

#ifdef NSS_FLAVOUR_GLIBC

/* this function looks up a single host entry and returns all the addresses
   associated with the host in a single address familiy
   name            - IN  - hostname to lookup
   af              - IN  - address familty to present results for
   result          - OUT - entry found
   buffer,buflen   - OUT - buffer to store allocated stuff on
   errnop,h_errnop - OUT - for reporting errors */
nss_status_t _nss_ldap_gethostbyname2_r(
        const char *name,int af,struct hostent *result,
        char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  NSS_BYNAME(NSLCD_ACTION_HOST_BYNAME,
             name,
             read_hostent_erronempty(fp,af,result,buffer,buflen,errnop,h_errnop));
}

/* this function just calls the gethostbyname2() variant with the address
   familiy set */
nss_status_t _nss_ldap_gethostbyname_r(
        const char *name,struct hostent *result,
        char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  return _nss_ldap_gethostbyname2_r(name,AF_INET,result,buffer,buflen,errnop,h_errnop);
}

/* this function looks up a single host entry and returns all the addresses
   associated with the host in a single address familiy
   addr            - IN  - the address to look up
   len             - IN  - the size of the addr struct
   af              - IN  - address familty the address is specified as
   result          - OUT - entry found
   buffer,buflen   - OUT - buffer to store allocated stuff on
   errnop,h_errnop - OUT - for reporting errors */
nss_status_t _nss_ldap_gethostbyaddr_r(
        const void *addr,socklen_t len,int af,struct hostent *result,
        char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  NSS_BYGEN(NSLCD_ACTION_HOST_BYADDR,
            WRITE_ADDRESS(fp,af,len,addr),
            read_hostent_erronempty(fp,af,result,buffer,buflen,errnop,h_errnop))
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *hostentfp;

nss_status_t _nss_ldap_sethostent(int UNUSED(stayopen))
{
  NSS_SETENT(hostentfp);
}

/* this function only returns addresses of the AF_INET address family */
nss_status_t _nss_ldap_gethostent_r(
        struct hostent *result,
        char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  NSS_GETENT(hostentfp,NSLCD_ACTION_HOST_ALL,
             read_hostent_nextonempty(hostentfp,AF_INET,result,buffer,buflen,errnop,h_errnop));
}

/* close the stream opened with sethostent() above */
nss_status_t _nss_ldap_endhostent(void)
{
  NSS_ENDENT(hostentfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

struct nss_ldap_hosts_backend
{
  nss_backend_op_t *ops;
  int n_ops;
  TFILE *fp;
};

#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN

static nss_status_t read_hoststring(TFILE *fp,nss_XbyY_args_t *args,int erronempty)
{
  struct hostent result;
  nss_status_t retv;
  char *buffer;
  size_t buflen;
  int i;
  /* read the hostent */
  if (erronempty)
    retv=read_hostent_erronempty(fp,NSS_ARGS(args)->key.hostaddr.type,&result,NSS_ARGS(args)->buf.buffer,args->buf.buflen,&NSS_ARGS(args)->erange,&(NSS_ARGS(args)->h_errno));
  else
    retv=read_hostent_nextonempty(fp,NSS_ARGS(args)->key.hostaddr.type,&result,NSS_ARGS(args)->buf.buffer,args->buf.buflen,&NSS_ARGS(args)->erange,&(NSS_ARGS(args)->h_errno));
  if (retv!=NSS_STATUS_SUCCESS)
    return retv;
  /* allocate a temporary buffer */
  buflen=args->buf.buflen;
  buffer=(char *)malloc(buflen);
  /* build the formatted string */
  /* FIXME: implement proper buffer size checking */
  if (result.h_addr_list)
  {
    struct in_addr in;
    (void)memcpy(&in.s_addr,result.h_addr_list[0],sizeof(in.s_addr));
    sprintf(buffer,"%s %s",inet_ntoa(in),result.h_name);
    if (result.h_aliases)
    {
      int j;
      for (j=0;result.h_aliases[j];j++)
      {
        strcat(buffer,"  ");
        strcat(buffer,result.h_aliases[j]);
      }
    }
    for (i=1;result.h_addr_list[i];i++)
    {
      (void)memcpy(&in.s_addr,result.h_addr_list[i],sizeof(in.s_addr));
      strcat(buffer,"\n");
      strcat(buffer,inet_ntoa(in));
      strcat(buffer," ");
      strcat(buffer,result.h_name);
      /* TODO: aliases only supplied to the first address */
      /* need review */
    }
  }
  /* copy the result back to the result buffer and free the temporary one */
  strcpy(NSS_ARGS(args)->buf.buffer,buffer);
  free(buffer);
  NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.buffer;
  NSS_ARGS(args)->returnlen=strlen(NSS_ARGS(args)->buf.buffer);
  return NSS_STATUS_SUCCESS;
}

#define READ_RESULT_ERRONEMPTY(fp) \
  NSS_ARGS(args)->buf.result? \
    read_hostent_erronempty(fp,NSS_ARGS(args)->key.hostaddr.type,(struct hostent *)NSS_ARGS(args)->buf.result,NSS_ARGS(args)->buf.buffer,NSS_ARGS(args)->buf.buflen,&NSS_ARGS(args)->erange,&(NSS_ARGS(args)->h_errno)): \
    read_hoststring(fp,args,1); \
  if ((NSS_ARGS(args)->buf.result)&&(retv==NSS_STATUS_SUCCESS)) \
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;

#define READ_RESULT_NEXTONEMPTY(fp) \
  NSS_ARGS(args)->buf.result? \
    read_hostent_nextonempty(fp,NSS_ARGS(args)->key.hostaddr.type,(struct hostent *)NSS_ARGS(args)->buf.result,NSS_ARGS(args)->buf.buffer,NSS_ARGS(args)->buf.buflen,&NSS_ARGS(args)->erange,&(NSS_ARGS(args)->h_errno)): \
    read_hoststring(fp,args,0); \
  if ((NSS_ARGS(args)->buf.result)&&(retv==NSS_STATUS_SUCCESS)) \
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;

#else /* not HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

#define READ_RESULT_ERRONEMPTY(fp) \
  read_hostent_erronempty(fp,NSS_ARGS(args)->key.hostaddr.type,(struct hostent *)NSS_ARGS(args)->buf.result,NSS_ARGS(args)->buf.buffer,NSS_ARGS(args)->buf.buflen,&NSS_ARGS(args)->erange,&(NSS_ARGS(args)->h_errno)); \
  if (retv==NSS_STATUS_SUCCESS) \
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;

#define READ_RESULT_NEXTONEMPTY(fp) \
  read_hostent_nextonempty(fp,NSS_ARGS(args)->key.hostaddr.type,(struct hostent *)NSS_ARGS(args)->buf.result,NSS_ARGS(args)->buf.buffer,NSS_ARGS(args)->buf.buflen,&NSS_ARGS(args)->erange,&(NSS_ARGS(args)->h_errno)); \
  if (retv==NSS_STATUS_SUCCESS) \
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;

#endif /* not HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

/* hack to set the correct errno and h_errno */
#define h_errnop &(NSS_ARGS(args)->h_errno)

static nss_status_t hosts_gethostbyname(nss_backend_t UNUSED(*be),void *args)
{
  NSS_BYNAME(NSLCD_ACTION_HOST_BYNAME,
             NSS_ARGS(args)->key.name,
             READ_RESULT_ERRONEMPTY(fp));
}

static nss_status_t hosts_gethostbyaddr(nss_backend_t UNUSED(*be),void *args)
{
  NSS_BYGEN(NSLCD_ACTION_HOST_BYADDR,
            WRITE_ADDRESS(fp,NSS_ARGS(args)->key.hostaddr.type,NSS_ARGS(args)->key.hostaddr.len,NSS_ARGS(args)->key.hostaddr.addr),
            READ_RESULT_ERRONEMPTY(fp));
}

static nss_status_t hosts_sethostent(nss_backend_t *be,void UNUSED(*args))
{
  NSS_SETENT(LDAP_BE(be)->fp);
}

static nss_status_t hosts_gethostent(nss_backend_t *be,void *args)
{
  NSS_GETENT(LDAP_BE(be)->fp,NSLCD_ACTION_HOST_ALL,
             READ_RESULT_NEXTONEMPTY(LDAP_BE(be)->fp));
}

static nss_status_t hosts_endhostent(nss_backend_t *be,void UNUSED(*args))
{
  NSS_ENDENT(LDAP_BE(be)->fp);
}

static nss_backend_op_t hosts_ops[]={
  nss_ldap_destructor,
  hosts_endhostent,
  hosts_sethostent,
  hosts_gethostent,
  hosts_gethostbyname,
  hosts_gethostbyaddr
};

nss_backend_t *_nss_ldap_hosts_constr(const char UNUSED(*db_name),
                  const char UNUSED(*src_name),const char UNUSED(*cfg_args))
{
  return nss_ldap_constructor(hosts_ops,sizeof(hosts_ops));
}

#endif /* NSS_FLAVOUR_SOLARIS */
