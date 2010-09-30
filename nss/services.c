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

static nss_status_t read_servent(
        TFILE *fp,struct servent *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  size_t bufptr=0;
  READ_BUF_STRING(fp,result->s_name);
  READ_BUF_STRINGLIST(fp,result->s_aliases);
  READ_TYPE(fp,tmpint32,int32_t);
  result->s_port=htons((uint16_t)tmpint32);
  READ_BUF_STRING(fp,result->s_proto);
  /* we're done */
  return NSS_STATUS_SUCCESS;
}

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_nslcd_getservbyname_r(
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_getservbyname_r(
#endif /* HAVE_NSSWITCH_H */
        const char *name,const char *protocol,struct servent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYGEN(NSLCD_ACTION_SERVICE_BYNAME,
            WRITE_STRING(fp,name);WRITE_STRING(fp,protocol),
            read_servent(fp,result,buffer,buflen,errnop));

}

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_nslcd_getservbyport_r(
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_getservbyport_r(
#endif /* HAVE_NSSWITCH_H */
        int port,const char *protocol,struct servent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYGEN(NSLCD_ACTION_SERVICE_BYNUMBER,
            WRITE_INT32(fp,ntohs(port));WRITE_STRING(fp,protocol),
            read_servent(fp,result,buffer,buflen,errnop));
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *protoentfp;

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_ldap_setservent(nss_backend_t *serv_context,void *args)
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_setservent(int UNUSED(stayopen))
#endif /* HAVE_NSSWITCH_H */
{
  NSS_SETENT(protoentfp);
}

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_nslcd_getservent_r(
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_getservent_r(
#endif /* HAVE_NSSWITCH_H */
        struct servent *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(protoentfp,NSLCD_ACTION_SERVICE_ALL,
             read_servent(protoentfp,result,buffer,buflen,errnop));
}

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_ldap_endservent(nss_backend_t *serv_context,void *args)
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_endservent(void)
#endif /* HAVE_NSSWITCH_H */
{
  NSS_ENDENT(protoentfp);
}

#ifdef HAVE_NSSWITCH_H

static nss_status_t _nss_ldap_getservbyname_r(nss_backend_t *be,void *args)
{
  char *name=(char *)NSS_ARGS(args)->key.serv.serv.name;
  char *protocol=NSS_ARGS(args)->key.serv.proto?(char *)NSS_ARGS(args)->key.serv.proto:"";
  struct servent priv_service;
  struct servent *service=NSS_ARGS(args)->buf.result?(struct servent *)NSS_ARGS(args)->buf.result:&priv_service;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  char *data_ptr;
  nss_status_t status;
  status=_nss_nslcd_getservbyname_r(name,protocol,service,
                                buffer,buflen,&errno);
  if (status!=NSS_STATUS_SUCCESS)
    return status;
  if (!NSS_ARGS(args)->buf.result)
  {
    /* result==NULL, return file format */
    data_ptr=(char *)malloc(buflen);
    sprintf(data_ptr,"%s %d/%s",name,service->s_port,
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

static nss_status_t _nss_ldap_getservbyport_r(nss_backend_t *be,void *args)
{
  int port=NSS_ARGS(args)->key.serv.serv.port;
  char *protocol=(char *)NSS_ARGS(args)->key.serv.proto;
  struct servent priv_service;
  struct servent *service=NSS_ARGS(args)->buf.result?(struct servent *)NSS_ARGS(args)->buf.result:&priv_service;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  char *data_ptr;
  nss_status_t status;
  status=_nss_nslcd_getservbyport_r(port,protocol,service,buffer,buflen,&errno);
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

static nss_status_t _nss_ldap_getservent_r(nss_backend_t *serv_context,void *args)
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

static nss_status_t _nss_ldap_services_destr(nss_backend_t *serv_context,void *args)
{
  return _nss_ldap_default_destr(serv_context,args);
}

static nss_backend_op_t services_ops[]={
  _nss_ldap_services_destr,
  _nss_ldap_endservent,
  _nss_ldap_setservent,
  _nss_ldap_getservent_r,
  _nss_ldap_getservbyname_r,
  _nss_ldap_getservbyport_r
};

nss_backend_t *_nss_ldap_services_constr(const char *db_name,
                           const char *src_name,const char *cfg_args)
{
  nss_ldap_backend_t *be;
  if (!(be=(nss_ldap_backend_t *)malloc(sizeof(*be))))
    return NULL;
  be->ops=services_ops;
  be->n_ops=sizeof(services_ops)/sizeof(nss_backend_op_t);
  if (_nss_ldap_default_constr(be)!=NSS_STATUS_SUCCESS)
    return NULL;
  return (nss_backend_t *)be;
}

#endif /* HAVE_NSSWITCH_H */
