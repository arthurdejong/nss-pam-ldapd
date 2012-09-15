/*
   service.c - NSS lookup functions for services database

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

#include "prototypes.h"
#include "common.h"
#include "compat/attrs.h"

/* read a single services result entry from the stream */
static nss_status_t read_servent(
        TFILE *fp,struct servent *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  size_t bufptr=0;
  memset(result,0,sizeof(struct servent));
  READ_BUF_STRING(fp,result->s_name);
  READ_BUF_STRINGLIST(fp,result->s_aliases);
  /* store port number in network byte order */
  READ_TYPE(fp,tmpint32,int32_t);
  result->s_port=htons((uint16_t)tmpint32);
  READ_BUF_STRING(fp,result->s_proto);
  /* we're done */
  return NSS_STATUS_SUCCESS;
}

#ifdef NSS_FLAVOUR_GLIBC

/* get a service entry by name and protocol */
nss_status_t _nss_ldap_getservbyname_r(
        const char *name,const char *protocol,struct servent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYGEN(NSLCD_ACTION_SERVICE_BYNAME,
            WRITE_STRING(fp,name);WRITE_STRING(fp,protocol),
            read_servent(fp,result,buffer,buflen,errnop));
}

/* get a service entry by port and protocol */
nss_status_t _nss_ldap_getservbyport_r(
        int port,const char *protocol,struct servent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYGEN(NSLCD_ACTION_SERVICE_BYNUMBER,
            WRITE_INT32(fp,ntohs(port));WRITE_STRING(fp,protocol),
            read_servent(fp,result,buffer,buflen,errnop));
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *serventfp;

/* open request to get all services */
nss_status_t _nss_ldap_setservent(int UNUSED(stayopen))
{
  NSS_SETENT(serventfp);
}

/* read a single returned service definition */
nss_status_t _nss_ldap_getservent_r(
        struct servent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(serventfp,NSLCD_ACTION_SERVICE_ALL,
             read_servent(serventfp,result,buffer,buflen,errnop));
}

/* close the stream opened by setservent() above */
nss_status_t _nss_ldap_endservent(void)
{
  NSS_ENDENT(serventfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN

static nss_status_t read_servstring(TFILE *fp,nss_XbyY_args_t *args)
{
  struct servent result;
  nss_status_t retv;
  char *buffer;
  size_t buflen;
  int i;
  /* read the servent */
  retv=read_servent(fp,&result,NSS_ARGS(args)->buf.buffer,args->buf.buflen,&NSS_ARGS(args)->erange);
  if (retv!=NSS_STATUS_SUCCESS)
    return retv;
  /* allocate a temporary buffer */
  buflen=args->buf.buflen;
  buffer=(char *)malloc(buflen);
  /* build the formatted string */
  /* FIXME: implement proper buffer size checking */
  sprintf(buffer,"%s %d/%s",result.s_name,result.s_port,result.s_proto);
  if (result.s_aliases)
    for (i=0;result.s_aliases[i];i++)
    {
      strcat(buffer," ");
      strcat(buffer,result.s_aliases[i]);
    }
  /* copy the result back to the result buffer and free the temporary one */
  strcpy(NSS_ARGS(args)->buf.buffer,buffer);
  free(buffer);
  NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.buffer;
  NSS_ARGS(args)->returnlen=strlen(NSS_ARGS(args)->buf.buffer);
  return NSS_STATUS_SUCCESS;
}

#define READ_RESULT(fp) \
  NSS_ARGS(args)->buf.result? \
    read_servent(fp,(struct servent *)NSS_ARGS(args)->buf.result,NSS_ARGS(args)->buf.buffer,NSS_ARGS(args)->buf.buflen,&NSS_ARGS(args)->erange): \
    read_servstring(fp,args); \
  if ((NSS_ARGS(args)->buf.result)&&(retv==NSS_STATUS_SUCCESS)) \
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;

#else /* not HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

#define READ_RESULT(fp) \
  read_servent(fp,(struct servent *)NSS_ARGS(args)->buf.result,NSS_ARGS(args)->buf.buffer,NSS_ARGS(args)->buf.buflen,&NSS_ARGS(args)->erange); \
  if (retv==NSS_STATUS_SUCCESS) \
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;

#endif /* not HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

static nss_status_t services_getservbyname(nss_backend_t UNUSED(*be),void *args)
{
  NSS_BYGEN(NSLCD_ACTION_SERVICE_BYNAME,
            WRITE_STRING(fp,NSS_ARGS(args)->key.serv.serv.name);
            WRITE_STRING(fp,NSS_ARGS(args)->key.serv.proto),
            READ_RESULT(fp));
}

static nss_status_t services_getservbyport(nss_backend_t UNUSED(*be),void *args)
{
  NSS_BYGEN(NSLCD_ACTION_SERVICE_BYNUMBER,
            WRITE_INT32(fp,ntohs(NSS_ARGS(args)->key.serv.serv.port));
            WRITE_STRING(fp,NSS_ARGS(args)->key.serv.proto),
            READ_RESULT(fp));
}

static nss_status_t services_setservent(nss_backend_t *be,void UNUSED(*args))
{
  NSS_SETENT(LDAP_BE(be)->fp);
}

static nss_status_t services_getservent(nss_backend_t *be,void *args)
{
  NSS_GETENT(LDAP_BE(be)->fp,NSLCD_ACTION_SERVICE_ALL,
             READ_RESULT(LDAP_BE(be)->fp));
}

static nss_status_t services_endservent(nss_backend_t *be,void UNUSED(*args))
{
  NSS_ENDENT(LDAP_BE(be)->fp);
}

static nss_backend_op_t services_ops[]={
  nss_ldap_destructor,
  services_endservent,
  services_setservent,
  services_getservent,
  services_getservbyname,
  services_getservbyport
};

nss_backend_t *_nss_ldap_services_constr(const char UNUSED(*db_name),
                  const char UNUSED(*src_name),const char UNUSED(*cfg_args))
{
  return nss_ldap_constructor(services_ops,sizeof(services_ops));
}

#endif /* NSS_FLAVOUR_SOLARIS */
