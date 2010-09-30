/*
   rpc.c - NSS lookup functions for rpc database

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

static nss_status_t read_rpcent(
        TFILE *fp,struct rpcent *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  size_t bufptr=0;
  READ_BUF_STRING(fp,result->r_name);
  READ_BUF_STRINGLIST(fp,result->r_aliases);
  READ_INT32(fp,result->r_number);
  return NSS_STATUS_SUCCESS;
}

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_nslcd_getrpcbyname_r(
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_getrpcbyname_r(
#endif /* HAVE_NSSWITCH_H */
        const char *name,struct rpcent *result,char *buffer,
        size_t buflen,int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_RPC_BYNAME,
             name,
             read_rpcent(fp,result,buffer,buflen,errnop));
}

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_nslcd_getrpcbynumber_r(
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_getrpcbynumber_r(
#endif /* HAVE_NSSWITCH_H */
        int number,struct rpcent *result,char *buffer,
        size_t buflen,int *errnop)
{
  NSS_BYINT32(NSLCD_ACTION_RPC_BYNUMBER,
              number,
              read_rpcent(fp,result,buffer,buflen,errnop));
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *protoentfp;

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_ldap_setrpcent(nss_backend_t *rpc_context,void *args)
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_setrpcent(int UNUSED(stayopen))
#endif /* HAVE_NSSWITCH_H */
{
  NSS_SETENT(protoentfp);
}

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_nslcd_getrpcent_r(
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_getrpcent_r(
#endif /* HAVE_NSSWITCH_H */
        struct rpcent *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(protoentfp,NSLCD_ACTION_RPC_ALL,
             read_rpcent(protoentfp,result,buffer,buflen,errnop));
}

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_ldap_endrpcent(nss_backend_t *rpc_context,void *args)
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_endrpcent(void)
#endif /* HAVE_NSSWITCH_H */
{
  NSS_ENDENT(protoentfp);
}

#ifdef HAVE_NSSWITCH_H

static nss_status_t _nss_ldap_getrpcbyname_r(nss_backend_t *be,void *args)
{
  struct rpcent priv_rpc;
  struct rpcent *rpc=NSS_ARGS(args)->buf.result?(struct rpcent *)NSS_ARGS(args)->buf.result:&priv_rpc;
  char *name=NSS_ARGS(args)->key.name;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  char *data_ptr;
  nss_status_t status;
  if (NSS_ARGS(args)->buf.buflen < 0)
  {
    NSS_ARGS(args)->erange=1;
    return NSS_STATUS_TRYAGAIN;
  }
  status=_nss_nslcd_getrpcbyname_r(name,rpc,buffer,buflen,&errno);
  if (status!=NSS_STATUS_SUCCESS)
    return status;
  if (!NSS_ARGS(args)->buf.result)
  {
    /* result==NULL, return file format */
    data_ptr=(char *)malloc(buflen);
    sprintf(data_ptr,"%s %d",rpc->r_name,rpc->r_number);
    if (rpc->r_aliases)
    {
      int i;
      for (i=0; rpc->r_aliases[i]; i++)
      {
        strcat(data_ptr," ");
        strcat(data_ptr,rpc->r_aliases[i]);
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

static nss_status_t _nss_ldap_getrpcbynumber_r(nss_backend_t *be,void *args)
{
  struct rpcent priv_rpc;
  struct rpcent *rpc=NSS_ARGS(args)->buf.result?(struct rpcent *)NSS_ARGS(args)->buf.result:&priv_rpc;
  int number=NSS_ARGS(args)->key.number;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  char *data_ptr;
  nss_status_t status;
  if (NSS_ARGS(args)->buf.buflen < 0)
  {
    NSS_ARGS(args)->erange=1;
    return NSS_STATUS_TRYAGAIN;
  }
  status=_nss_nslcd_getrpcbynumber_r(number,rpc,buffer,buflen,&errno);
  if (status!=NSS_STATUS_SUCCESS)
    return status;
  if (!NSS_ARGS(args)->buf.result)
  {
    /* result==NULL, return file format */
    data_ptr=(char *)malloc(buflen);
    sprintf(data_ptr,"%s %d",rpc->r_name,rpc->r_number);
    if (rpc->r_aliases)
    {
      int i;
      for (i=0; rpc->r_aliases[i]; i++)
      {
        strcat(data_ptr," ");
        strcat(data_ptr,rpc->r_aliases[i]);
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

static nss_status_t _nss_ldap_getrpcent_r(nss_backend_t *rpc_context,void *args)
{
  struct rpcent priv_rpc;
  struct rpcent *rpc=NSS_ARGS(args)->buf.result?(struct rpcent *)NSS_ARGS(args)->buf.result:&priv_rpc;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  char *data_ptr;
  nss_status_t status;
  if (NSS_ARGS(args)->buf.buflen < 0)
  {
    NSS_ARGS(args)->erange=1;
    return NSS_STATUS_TRYAGAIN;
  }
  status=_nss_nslcd_getrpcent_r(rpc,buffer,buflen,&errno);
  if (status!=NSS_STATUS_SUCCESS)
    return status;
  if (!NSS_ARGS(args)->buf.result)
  {
    /* result==NULL, return file format */
    data_ptr=(char *)malloc(buflen);
    sprintf(data_ptr,"%s %d",rpc->r_name,rpc->r_number);
    if (rpc->r_aliases)
    {
      int i;
      for (i=0; rpc->r_aliases[i]; i++)
      {
        strcat(data_ptr," ");
        strcat(data_ptr,rpc->r_aliases[i]);
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

static nss_status_t _nss_ldap_rpc_destr(nss_backend_t *rpc_context,void *args)
{
  return _nss_ldap_default_destr(rpc_context,args);
}

static nss_backend_op_t rpc_ops[]={
  _nss_ldap_rpc_destr,
  _nss_ldap_endrpcent,
  _nss_ldap_setrpcent,
  _nss_ldap_getrpcent_r,
  _nss_ldap_getrpcbyname_r,
  _nss_ldap_getrpcbynumber_r
};

nss_backend_t *_nss_ldap_rpc_constr(const char *db_name,
                      const char *src_name,const char *cfg_args)
{
  nss_ldap_backend_t *be;
  if (!(be=(nss_ldap_backend_t *)malloc(sizeof(*be))))
    return NULL;
  be->ops=rpc_ops;
  be->n_ops=sizeof(rpc_ops)/sizeof(nss_backend_op_t);
  if (_nss_ldap_default_constr(be)!=NSS_STATUS_SUCCESS)
    return NULL;
  return (nss_backend_t *)be;
}

#endif /* HAVE_NSSWITCH_H */
