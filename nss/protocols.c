/*
   protocols.c - NSS lookup functions for protocol database

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

static nss_status_t read_protoent(
        TFILE *fp,struct protoent *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  size_t bufptr=0;
  READ_BUF_STRING(fp,result->p_name);
  READ_BUF_STRINGLIST(fp,result->p_aliases);
  READ_INT32(fp,result->p_proto);
  return NSS_STATUS_SUCCESS;
}

#ifdef NSS_FLAVOUR_GLIBC

nss_status_t _nss_ldap_getprotobyname_r(
        const char *name,struct protoent *result,char *buffer,
        size_t buflen,int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_PROTOCOL_BYNAME,buffer,buflen,
             name,
             read_protoent(fp,result,buffer,buflen,errnop));
  return retv;
}

nss_status_t _nss_ldap_getprotobynumber_r(
        int number,struct protoent *result,char *buffer,
        size_t buflen,int *errnop)
{
  NSS_BYINT32(NSLCD_ACTION_PROTOCOL_BYNUMBER,buffer,buflen,
              number,
              read_protoent(fp,result,buffer,buflen,errnop));
  return retv;
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *protoentfp;

nss_status_t _nss_ldap_setprotoent(int UNUSED(stayopen))
{
  NSS_SETENT(protoentfp);
}

nss_status_t _nss_ldap_getprotoent_r(
        struct protoent *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(protoentfp,NSLCD_ACTION_PROTOCOL_ALL,buffer,buflen,
             read_protoent(protoentfp,result,buffer,buflen,errnop));
  return retv;
}

nss_status_t _nss_ldap_endprotoent(void)
{
  NSS_ENDENT(protoentfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

static nss_status_t _nss_nslcd_getprotobyname_r(
        const char *name,struct protoent *result,char *buffer,
        size_t buflen,int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_PROTOCOL_BYNAME,buffer,buflen,
             name,
             read_protoent(fp,result,buffer,buflen,errnop));
  return retv;
}

static nss_status_t _xnss_ldap_getprotobyname_r(nss_backend_t UNUSED(*be),void *args)
{
  struct protoent priv_proto;
  struct protoent *proto=NSS_ARGS(args)->buf.result?(struct protoent *)NSS_ARGS(args)->buf.result:&priv_proto;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  char *data_ptr;
  nss_status_t status;
  if (NSS_ARGS(args)->buf.buflen<0)
  {
    NSS_ARGS(args)->erange=1;
    return NSS_STATUS_TRYAGAIN;
  }
  status=_nss_nslcd_getprotobyname_r(NSS_ARGS(args)->key.name,proto,buffer,buflen,&errno);
  if (status!=NSS_STATUS_SUCCESS)
    return status;
  if (!NSS_ARGS(args)->buf.result)
  {
    /* result==NULL, return file format */
    data_ptr=(char *)malloc(buflen);
    /* FIXME: shouldn't there be some range checks here to see if it actually
              fits inside the buffer? */
    sprintf(data_ptr,"%s\t\t%d",proto->p_name,proto->p_proto);
    if (proto->p_aliases)
    {
      int i;
      for (i=0; proto->p_aliases[i]; i++)
      {
        strcat(data_ptr," ");
        strcat(data_ptr,proto->p_aliases[i]);
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

static nss_status_t _nss_nslcd_getprotobynumber_r(
        int number,struct protoent *result,char *buffer,
        size_t buflen,int *errnop)
{
  NSS_BYINT32(NSLCD_ACTION_PROTOCOL_BYNUMBER,buffer,buflen,
              number,
              read_protoent(fp,result,buffer,buflen,errnop));
  return retv;
}

static nss_status_t _xnss_ldap_getprotobynumber_r(nss_backend_t UNUSED(*be),void *args)
{
  struct protoent priv_proto;
  struct protoent *proto=NSS_ARGS(args)->buf.result?(struct protoent *)NSS_ARGS(args)->buf.result:&priv_proto;
  int number=NSS_ARGS(args)->key.number;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  char *data_ptr;
  nss_status_t status;
  if (NSS_ARGS(args)->buf.buflen<0)
  {
    NSS_ARGS(args)->erange=1;
    return NSS_STATUS_TRYAGAIN;
  }
  status=_nss_nslcd_getprotobynumber_r(number,proto,buffer,buflen,&errno);
  if (status!=NSS_STATUS_SUCCESS)
    return status;
  if (!NSS_ARGS(args)->buf.result)
  {
    /* result==NULL, return file format */
    data_ptr=(char *)malloc(buflen);
    sprintf(data_ptr,"%s\t\t%d",proto->p_name,proto->p_proto);
    if (proto->p_aliases)
    {
      int i;
      for (i=0; proto->p_aliases[i]; i++)
      {
        strcat(data_ptr," ");
        strcat(data_ptr,proto->p_aliases[i]);
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

static nss_status_t _xnss_ldap_setprotoent(nss_backend_t UNUSED(*be),void UNUSED(*args))
{
  NSS_SETENT(protoentfp);
}

static nss_status_t _nss_nslcd_getprotoent_r(
        struct protoent *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(protoentfp,NSLCD_ACTION_PROTOCOL_ALL,buffer,buflen,
             read_protoent(protoentfp,result,buffer,buflen,errnop));
  return retv;
}

static nss_status_t _xnss_ldap_getprotoent_r(nss_backend_t UNUSED(*be),void *args)
{
  struct protoent priv_proto;
  struct protoent *proto=NSS_ARGS(args)->buf.result?(struct protoent *)NSS_ARGS(args)->buf.result:&priv_proto;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  char *data_ptr;
  nss_status_t status;
  if (NSS_ARGS(args)->buf.buflen<0)
  {
    NSS_ARGS(args)->erange=1;
    return NSS_STATUS_TRYAGAIN;
  }
  status=_nss_nslcd_getprotoent_r(proto,buffer,buflen,&errno);
  if (status!=NSS_STATUS_SUCCESS)
    return status;
  if (!NSS_ARGS(args)->buf.result)
  {
    /* result==NULL, return file format */
    data_ptr=(char *)malloc(buflen);
    sprintf(data_ptr,"%s\t\t%d",proto->p_name,proto->p_proto);
    if (proto->p_aliases)
    {
      int i;
      for (i=0; proto->p_aliases[i]; i++)
      {
        strcat(data_ptr," ");
        strcat(data_ptr,proto->p_aliases[i]);
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

static nss_status_t _xnss_ldap_endprotoent(nss_backend_t UNUSED(*be),void UNUSED(*args))
{
  NSS_ENDENT(protoentfp);
}

static nss_status_t _xnss_ldap_protocols_destr(nss_backend_t *be,void UNUSED(*args))
{
  free(be);
  return NSS_STATUS_SUCCESS;
}

static nss_backend_op_t proto_ops[]={
  _xnss_ldap_protocols_destr,
  _xnss_ldap_endprotoent,
  _xnss_ldap_setprotoent,
  _xnss_ldap_getprotoent_r,
  _xnss_ldap_getprotobyname_r,
  _xnss_ldap_getprotobynumber_r
};

nss_backend_t *_nss_ldap_protocols_constr(const char UNUSED(*db_name),
                            const char UNUSED(*src_name),const char UNUSED(*cfg_args))
{
  nss_backend_t *be;
  if (!(be=(nss_backend_t *)malloc(sizeof(*be))))
    return NULL;
  be->ops=proto_ops;
  be->n_ops=sizeof(proto_ops)/sizeof(nss_backend_op_t);
  return (nss_backend_t *)be;
}

#endif /* NSS_FLAVOUR_SOLARIS */
