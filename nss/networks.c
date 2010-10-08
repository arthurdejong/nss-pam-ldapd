/*
   networks.c - NSS lookup functions for networks database

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007, 2008, 2010 Arthur de Jong
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

/* read a single network entry from the stream, ignoring entries
   that are not AF_INET (IPv4), result is stored in result */
static nss_status_t read_netent(
        TFILE *fp,struct netent *result,
        char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  int32_t numaddr,i;
  int readaf;
  size_t bufptr=0;
  nss_status_t retv=NSS_STATUS_NOTFOUND;
  /* read the network entry */
  READ_BUF_STRING(fp,result->n_name);
  READ_BUF_STRINGLIST(fp,result->n_aliases);
  result->n_addrtype=AF_INET;
  /* read number of addresses to follow */
  READ_TYPE(fp,numaddr,int32_t);
  /* go through the address list and filter on af */
  i=0;
  while (--numaddr>=0)
  {
    /* read address family and size */
    READ_INT32(fp,readaf);
    READ_INT32(fp,tmp2int32);
    if ((readaf==AF_INET)&&(tmp2int32==4))
    {
      /* read address and translate to host byte order */
      READ_TYPE(fp,tmpint32,int32_t);
      result->n_net=ntohl((uint32_t)tmpint32);
      /* signal that we've read a proper entry */
      retv=NSS_STATUS_SUCCESS;
      /* don't return here to not upset the stream */
    }
    else
    {
      /* skip unsupported address families */
      SKIP(fp,tmpint32);
    }
  }
  return retv;
}

/* write an address value */
/* version 2.10 of glibc changed the address from network to host order
   (changelog entry 2009-07-01) */
#define WRITE_ADDRESS(fp,addr) \
  WRITE_INT32(fp,AF_INET); \
  WRITE_INT32(fp,4); \
  WRITE_INT32(fp,htonl(addr));

#ifdef NSS_FLAVOUR_GLIBC

/* get a network entry by name */
nss_status_t _nss_ldap_getnetbyname_r(
        const char *name,struct netent *result,
        char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  NSS_BYNAME(NSLCD_ACTION_NETWORK_BYNAME,buffer,buflen,
             name,
             read_netent(fp,result,buffer,buflen,errnop,h_errnop));
  return retv;
}

/* Note: the af parameter is ignored and is assumed to be AF_INET */
/* TODO: implement handling of af parameter */
nss_status_t _nss_ldap_getnetbyaddr_r(
        uint32_t addr,int UNUSED(af),struct netent *result,
        char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  NSS_BYGEN(NSLCD_ACTION_NETWORK_BYADDR,buffer,buflen,
            WRITE_ADDRESS(fp,addr),
            read_netent(fp,result,buffer,buflen,errnop,h_errnop))
  return retv;
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *netentfp;

/* start a request to read all networks */
nss_status_t _nss_ldap_setnetent(int UNUSED(stayopen))
{
  NSS_SETENT(netentfp);
}

/* get a single network entry from the stream */
nss_status_t _nss_ldap_getnetent_r(
        struct netent *result,
        char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  NSS_GETENT(netentfp,NSLCD_ACTION_NETWORK_ALL,buffer,buflen,
             read_netent(netentfp,result,buffer,buflen,errnop,h_errnop));
  return retv;
}

/* close the stream opened by setnetent() above */
nss_status_t _nss_ldap_endnetent(void)
{
  NSS_ENDENT(netentfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

static nss_status_t _nss_nslcd_getnetbyname_r(
        const char *name,struct netent *result,char *buffer,
        size_t buflen,int *errnop,int *h_errnop)
{
  NSS_BYNAME(NSLCD_ACTION_NETWORK_BYNAME,buffer,buflen,
             name,
             read_netent(fp,result,buffer,buflen,errnop,h_errnop));
  return retv;
}

static nss_status_t _xnss_ldap_getnetbyname_r(nss_backend_t UNUSED(*be),void *args)
{
  struct netent priv_network;
  struct netent *network=NSS_ARGS(args)->buf.result?(struct netent *)NSS_ARGS(args)->buf.result:&priv_network;
  int af=NSS_ARGS(args)->key.netaddr.type;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  int h_errno;
  char *data_ptr;
  nss_status_t status;
  if (NSS_ARGS(args)->buf.buflen<0)
  {
    NSS_ARGS(args)->erange=1;
    return NSS_STATUS_TRYAGAIN;
  }
  status=_nss_nslcd_getnetbyname_r(NSS_ARGS(args)->key.name,network,buffer,
                buflen,&errno,&h_errno);
  if (status!=NSS_STATUS_SUCCESS)
  {
    NSS_ARGS(args)->h_errno=h_errno;
    return status;
  }
  if (!NSS_ARGS(args)->buf.result)
  {
    /* result==NULL, return file format */
    data_ptr=(char *)malloc(buflen);
    sprintf(data_ptr,"%s %s",network->n_name,inet_ntoa(network->n_net)); /* ipNetworkNumber */
    if (network->n_aliases)
    {
      int i;
      for (i=0; network->n_aliases[i]; i++)
      {
        strcat(data_ptr," ");
        strcat(data_ptr,network->n_aliases[i]);
      }
    }
    strcpy(buffer,data_ptr);
    free(data_ptr);
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.buffer;
    NSS_ARGS(args)->returnlen=strlen(NSS_ARGS(args)->buf.buffer);
  }
  else
  {
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;
  }
  NSS_ARGS(args)->h_errno=h_errno;
  return status;
}

/* Note: the af parameter is ignored and is assumed to be AF_INET */
/* TODO: implement handling of af parameter */
static nss_status_t _nss_nslcd_getnetbyaddr_r(
        uint32_t addr,int UNUSED(af),struct netent *result,
        char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  NSS_BYGEN(NSLCD_ACTION_NETWORK_BYADDR,buffer,buflen,
            WRITE_ADDRESS(fp,addr),
            read_netent(fp,result,buffer,buflen,errnop,h_errnop))
  return retv;
}

/* Note: the af parameter is ignored and is assumed to be AF_INET */
/* TODO: implement handling of af parameter */
static nss_status_t _xnss_ldap_getnetbyaddr_r(nss_backend_t UNUSED(*be),void *args)
{
  struct netent priv_network;
  struct netent *network=NSS_ARGS(args)->buf.result?(struct netent *)NSS_ARGS(args)->buf.result:&priv_network;
  int addr=NSS_ARGS(args)->key.netaddr.net; /* is an addr an int? */
  int af=NSS_ARGS(args)->key.netaddr.type;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  int h_errno;
  char *data_ptr;
  struct in_addr in_addr;
  nss_status_t status;
  if (NSS_ARGS(args)->buf.buflen<0)
  {
    NSS_ARGS(args)->erange=1;
    return NSS_STATUS_TRYAGAIN;
  }
  status=_nss_nslcd_getnetbyaddr_r(addr,af,network,buffer,buflen,&errno,&h_errno);
  if (status!=NSS_STATUS_SUCCESS)
  {
    NSS_ARGS(args)->h_errno=h_errno;
    return status;
  }
  if (!NSS_ARGS(args)->buf.result)
  {
    /* result==NULL, return file format */
    (void)memcpy(&in_addr.s_addr,addr,sizeof(in_addr.s_addr));
    data_ptr=(char *)malloc(buflen);
    sprintf(data_ptr,"%s %s",network->n_name,
        inet_ntoa(in_addr)); /* ipNetworkNumber */
    if (network->n_aliases)
    {
      int i;
      for (i=0; network->n_aliases[i]; i++)
      {
        strcat(data_ptr," ");
        strcat(data_ptr,network->n_aliases[i]);
      }
    }
    strcpy(buffer,data_ptr);
    free(data_ptr);
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.buffer;
    NSS_ARGS(args)->returnlen=strlen(NSS_ARGS(args)->buf.buffer);
  }
  else
  {
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;
  }
  NSS_ARGS(args)->h_errno=h_errno;
  return status;
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *netentfp;

static nss_status_t _xnss_ldap_setnetent(nss_backend_t UNUSED(*be),void UNUSED(*args))
{
  NSS_SETENT(netentfp);
}

static nss_status_t _nss_nslcd_getnetent_r(
        struct netent *result,char *buffer,size_t buflen,
        int *errnop,int *h_errnop)
{
  NSS_GETENT(netentfp,NSLCD_ACTION_NETWORK_ALL,buffer,buflen,
             read_netent(netentfp,result,buffer,buflen,errnop,h_errnop));
  return retv;
}

static nss_status_t _xnss_ldap_getnetent_r(nss_backend_t UNUSED(*be),void *args)
{
  struct netent priv_network;
  struct netent *network=NSS_ARGS(args)->buf.result?(struct netent *)NSS_ARGS(args)->buf.result:&priv_network;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  int h_errno;
  char *data_ptr;
  nss_status_t status;
  if (NSS_ARGS(args)->buf.buflen<0)
  {
    NSS_ARGS(args)->erange=1;
    return NSS_STATUS_TRYAGAIN;
  }
  status=_nss_nslcd_getnetent_r(network,buffer,buflen,&errno,&h_errno);
  if (status!=NSS_STATUS_SUCCESS)
    return status;
  if (!NSS_ARGS(args)->buf.result)
  {
    /* result==NULL, return file format */
    data_ptr=(char *)malloc(buflen);
    sprintf(data_ptr,"%s %s",network->n_name,
                inet_ntoa(network->n_net)); /* ipNetworkNumber */
    if (network->n_aliases)
    {
      int i;
      for (i=0; network->n_aliases[i]; i++)
      {
        strcat(data_ptr," ");
        strcat(data_ptr,network->n_aliases[i]);
      }
    }
    strcpy(buffer,data_ptr);
    free(data_ptr);
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.buffer;
    NSS_ARGS(args)->returnlen=strlen(NSS_ARGS(args)->buf.buffer);
  }
  else
  {
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;
  }
  NSS_ARGS(args)->h_errno=h_errno;
  return status;
}

static nss_status_t _xnss_ldap_endnetent(nss_backend_t UNUSED(*be),void UNUSED(*args))
{
  NSS_ENDENT(netentfp);
}

static nss_status_t _xnss_ldap_networks_destr(nss_backend_t *be,void UNUSED(*args))
{
  free(be);
  return NSS_STATUS_SUCCESS;
}

static nss_backend_op_t net_ops[]={
  _xnss_ldap_networks_destr,
  _xnss_ldap_endnetent,
  _xnss_ldap_setnetent,
  _xnss_ldap_getnetent_r,
  _xnss_ldap_getnetbyname_r,
  _xnss_ldap_getnetbyaddr_r
};

nss_backend_t *_nss_ldap_networks_constr(const char UNUSED(*db_name),
                           const char UNUSED(*src_name),const char UNUSED(*cfg_args))
{
  nss_backend_t *be;
  if (!(be=(nss_backend_t *)malloc(sizeof(*be))))
    return NULL;
  be->ops=net_ops;
  be->n_ops=sizeof(net_ops)/sizeof(nss_backend_op_t);
  return (nss_backend_t *)be;
}

#endif /* NSS_FLAVOUR_SOLARIS */
