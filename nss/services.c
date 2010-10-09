/*
   service.c - NSS lookup functions for services database

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

#include "prototypes.h"
#include "common.h"
#include "compat/attrs.h"

/* thread-local file pointer to an ongoing request */
static __thread TFILE *serventfp;

/* read a single services result entry from the stream */
static nss_status_t read_servent(
        TFILE *fp,struct servent *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  size_t bufptr=0;
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
  NSS_BYGEN(NSLCD_ACTION_SERVICE_BYNAME,buffer,buflen,
            WRITE_STRING(fp,name);WRITE_STRING(fp,protocol),
            read_servent(fp,result,buffer,buflen,errnop));
  return retv;
}

/* get a service entry by port and protocol */
nss_status_t _nss_ldap_getservbyport_r(
        int port,const char *protocol,struct servent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYGEN(NSLCD_ACTION_SERVICE_BYNUMBER,buffer,buflen,
            WRITE_INT32(fp,ntohs(port));WRITE_STRING(fp,protocol),
            read_servent(fp,result,buffer,buflen,errnop));
  return retv;
}

/* thread-local file pointer to an ongoing request */
/* static __thread TFILE *protoentfp; */

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
  NSS_GETENT(serventfp,NSLCD_ACTION_SERVICE_ALL,buffer,buflen,
             read_servent(serventfp,result,buffer,buflen,errnop));
  return retv;
}

/* close the stream opened by setservent() above */
nss_status_t _nss_ldap_endservent(void)
{
  NSS_ENDENT(serventfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

static nss_status_t _nss_nslcd_getservbyname_r(
        const char *name,const char *protocol,struct servent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYGEN(NSLCD_ACTION_SERVICE_BYNAME,buffer,buflen,
            WRITE_STRING(fp,name);WRITE_STRING(fp,protocol),
            read_servent(fp,result,buffer,buflen,errnop));
  return retv;
}

static nss_status_t _nss_nslcd_getservbyport_r(
        int port,const char *protocol,struct servent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYGEN(NSLCD_ACTION_SERVICE_BYNUMBER,buffer,buflen,
            WRITE_INT32(fp,ntohs(port));WRITE_STRING(fp,protocol),
            read_servent(fp,result,buffer,buflen,errnop));
  return retv;
}

static nss_status_t _xnss_ldap_setservent(nss_backend_t UNUSED(*be),void UNUSED(*args))
{
  NSS_SETENT(serventfp);
}

static nss_status_t _nss_nslcd_getservent_r(
        struct servent *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(serventfp,NSLCD_ACTION_SERVICE_ALL,buffer,buflen,
             read_servent(serventfp,result,buffer,buflen,errnop));
  return retv;
}

static nss_status_t _xnss_ldap_endservent(nss_backend_t UNUSED(*be),void UNUSED(*args))
{
  NSS_ENDENT(serventfp);
}

static nss_status_t _xnss_ldap_getservbyname_r(nss_backend_t UNUSED(*be),void *args)
{
  struct servent priv_service;
  struct servent *service=NSS_ARGS(args)->buf.result?(struct servent *)NSS_ARGS(args)->buf.result:&priv_service;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  char *data_ptr;
  nss_status_t status;
  status=_nss_nslcd_getservbyname_r(NSS_ARGS(args)->key.serv.serv.name,NSS_ARGS(args)->key.serv.proto,service,
                                buffer,buflen,&errno);
  if (status!=NSS_STATUS_SUCCESS)
    return status;
  if (!NSS_ARGS(args)->buf.result)
  {
    /* result==NULL, return file format */
    data_ptr=(char *)malloc(buflen);
    sprintf(data_ptr,"%s %d/%s",service->s_name,service->s_port,
            service->s_proto);
    if (service->s_aliases)
    {
      int i;
      for (i=0; service->s_aliases[i]; i++)
      {
        strcat(data_ptr," ");
        strcat(data_ptr,service->s_aliases[i]);
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
  return status;
}

static nss_status_t _xnss_ldap_getservbyport_r(nss_backend_t UNUSED(*be),void *args)
{
  int port=NSS_ARGS(args)->key.serv.serv.port;
  struct servent priv_service;
  struct servent *service=NSS_ARGS(args)->buf.result?(struct servent *)NSS_ARGS(args)->buf.result:&priv_service;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  char *data_ptr;
  nss_status_t status;
  status=_nss_nslcd_getservbyport_r(port,NSS_ARGS(args)->key.serv.proto,service,buffer,buflen,&errno);
  if (status!=NSS_STATUS_SUCCESS)
    return status;
  if (!NSS_ARGS(args)->buf.result)
  {
    /* result==NULL, return file format */
    data_ptr=(char *)malloc(buflen);
    sprintf(data_ptr,"%s %d/%s",service->s_name,port,
            service->s_proto);
    if (service->s_aliases)
    {
      int i;
      for (i=0; service->s_aliases[i]; i++)
      {
        strcat(data_ptr," ");
        strcat(data_ptr,service->s_aliases[i]);
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
  return status;
}

static nss_status_t _xnss_ldap_getservent_r(nss_backend_t UNUSED(*be),void *args)
{
  struct servent priv_service;
  struct servent *service=NSS_ARGS(args)->buf.result?(struct servent *)NSS_ARGS(args)->buf.result:&priv_service;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  char *data_ptr;
  nss_status_t status;
  status=_nss_nslcd_getservent_r(service,buffer,buflen,&errno);
  if (status!=NSS_STATUS_SUCCESS)
    return status;
  if (!NSS_ARGS(args)->buf.result)
  {
    /* result==NULL, return file format */
    data_ptr=(char *)malloc(buflen);
    sprintf(data_ptr,"%s %d/%s",service->s_name,service->s_port,
            service->s_proto);
    if (service->s_aliases)
    {
      int i;
      for (i=0; service->s_aliases[i]; i++)
      {
        strcat(data_ptr," ");
        strcat(data_ptr,service->s_aliases[i]);
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
  return status;
}

static nss_status_t _xnss_ldap_services_destr(nss_backend_t *be,void UNUSED(*args))
{
  free(be);
  return NSS_STATUS_SUCCESS;
}

static nss_backend_op_t services_ops[]={
  _xnss_ldap_services_destr,
  _xnss_ldap_endservent,
  _xnss_ldap_setservent,
  _xnss_ldap_getservent_r,
  _xnss_ldap_getservbyname_r,
  _xnss_ldap_getservbyport_r
};

nss_backend_t *_nss_ldap_services_constr(const char UNUSED(*db_name),
                           const char UNUSED(*src_name),const char UNUSED(*cfg_args))
{
  nss_backend_t *be;
  if (!(be=(nss_backend_t *)malloc(sizeof(*be))))
    return NULL;
  be->ops=services_ops;
  be->n_ops=sizeof(services_ops)/sizeof(nss_backend_op_t);
  return (nss_backend_t *)be;
}

#endif /* NSS_FLAVOUR_SOLARIS */
