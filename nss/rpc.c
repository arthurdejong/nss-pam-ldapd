/*
   rpc.c - NSS lookup functions for rpc database

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

/* read a sinlge rpc entry from the stream */
static nss_status_t read_rpcent(
        TFILE *fp,struct rpcent *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  size_t bufptr=0;
  memset(result,0,sizeof(struct rpcent));
  READ_BUF_STRING(fp,result->r_name);
  READ_BUF_STRINGLIST(fp,result->r_aliases);
  READ_INT32(fp,result->r_number);
  return NSS_STATUS_SUCCESS;
}

#ifdef NSS_FLAVOUR_GLIBC

/* get a rpc entry by name */
nss_status_t _nss_ldap_getrpcbyname_r(
        const char *name,struct rpcent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_RPC_BYNAME,
             name,
             read_rpcent(fp,result,buffer,buflen,errnop));
}

/* get a rpc entry by number */
nss_status_t _nss_ldap_getrpcbynumber_r(
        int number,struct rpcent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYINT32(NSLCD_ACTION_RPC_BYNUMBER,
              number,
              read_rpcent(fp,result,buffer,buflen,errnop));
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *rpcentfp;

/* request a stream to list all rpc entries */
nss_status_t _nss_ldap_setrpcent(int UNUSED(stayopen))
{
  NSS_SETENT(rpcentfp);
}

/* get an rpc entry from the list */
nss_status_t _nss_ldap_getrpcent_r(
        struct rpcent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(rpcentfp,NSLCD_ACTION_RPC_ALL,
             read_rpcent(rpcentfp,result,buffer,buflen,errnop));
}

/* close the stream opened by setrpcent() above */
nss_status_t _nss_ldap_endrpcent(void)
{
  NSS_ENDENT(rpcentfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN

static nss_status_t read_rpcstring(TFILE *fp,nss_XbyY_args_t *args)
{
  struct rpcent result;
  nss_status_t retv;
  char *buffer;
  size_t buflen;
  int i;
  /* read the rpcent */
  retv=read_rpcent(fp,&result,NSS_ARGS(args)->buf.buffer,args->buf.buflen,&NSS_ARGS(args)->erange);
  if (retv!=NSS_STATUS_SUCCESS)
    return retv;
  /* allocate a temporary buffer */
  buflen=args->buf.buflen;
  buffer=(char *)malloc(buflen);
  /* build the formatted string */
  /* FIXME: implement proper buffer size checking */
  sprintf(buffer,"%s %d",result.r_name,result.r_number);
  if (result.r_aliases)
    for (i=0; result.r_aliases[i]; i++)
    {
      strcat(buffer," ");
      strcat(buffer,result.r_aliases[i]);
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
    read_rpcent(fp,(struct rpcent *)NSS_ARGS(args)->buf.result,NSS_ARGS(args)->buf.buffer,NSS_ARGS(args)->buf.buflen,&NSS_ARGS(args)->erange): \
    read_rpcstring(fp,args); \
  if ((NSS_ARGS(args)->buf.result)&&(retv==NSS_STATUS_SUCCESS)) \
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;

#else /* not HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

#define READ_RESULT(fp) \
  read_rpcent(fp,(struct rpcent *)NSS_ARGS(args)->buf.result,NSS_ARGS(args)->buf.buffer,NSS_ARGS(args)->buf.buflen,&NSS_ARGS(args)->erange); \
  if (retv==NSS_STATUS_SUCCESS) \
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;

#endif /* not HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

static nss_status_t rpc_getrpcbyname(nss_backend_t UNUSED(*be),void *args)
{
  NSS_BYNAME(NSLCD_ACTION_RPC_BYNAME,
             NSS_ARGS(args)->key.name,
             READ_RESULT(fp));
}

static nss_status_t rpc_getrpcbynumber(nss_backend_t UNUSED(*be),void *args)
{
  NSS_BYINT32(NSLCD_ACTION_RPC_BYNUMBER,
              NSS_ARGS(args)->key.number,
              READ_RESULT(fp));
}

static nss_status_t rpc_setrpcent(nss_backend_t *be,void UNUSED(*args))
{
  NSS_SETENT(LDAP_BE(be)->fp);
}

static nss_status_t rpc_getrpcent(nss_backend_t *be,void *args)
{
  NSS_GETENT(LDAP_BE(be)->fp,NSLCD_ACTION_RPC_ALL,
             READ_RESULT(LDAP_BE(be)->fp));
}

static nss_status_t rpc_endrpcent(nss_backend_t *be,void UNUSED(*args))
{
  NSS_ENDENT(LDAP_BE(be)->fp);
}

static nss_backend_op_t rpc_ops[]={
  nss_ldap_destructor,
  rpc_endrpcent,
  rpc_setrpcent,
  rpc_getrpcent,
  rpc_getrpcbyname,
  rpc_getrpcbynumber
};

nss_backend_t *_nss_ldap_rpc_constr(const char UNUSED(*db_name),
                  const char UNUSED(*src_name),const char UNUSED(*cfg_args))
{
  return nss_ldap_constructor(rpc_ops,sizeof(rpc_ops));
}

#endif /* NSS_FLAVOUR_SOLARIS */
