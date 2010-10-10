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

/* read a single protocol entry from the stream */
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

/* get a protocol entry by name */
nss_status_t _nss_ldap_getprotobyname_r(
        const char *name,struct protoent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_PROTOCOL_BYNAME,
             name,
             read_protoent(fp,result,buffer,buflen,errnop));
}

/* get a protocol entry by number */
nss_status_t _nss_ldap_getprotobynumber_r(
        int number,struct protoent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYINT32(NSLCD_ACTION_PROTOCOL_BYNUMBER,
              number,
              read_protoent(fp,result,buffer,buflen,errnop));
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *protoentfp;

/* start a request to read all protocol entries */
nss_status_t _nss_ldap_setprotoent(int UNUSED(stayopen))
{
  NSS_SETENT(protoentfp);
}

/* get a single protocol entry */
nss_status_t _nss_ldap_getprotoent_r(
        struct protoent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(protoentfp,NSLCD_ACTION_PROTOCOL_ALL,
             read_protoent(protoentfp,result,buffer,buflen,errnop));
}

/* close the stream opened by setprotoent() above */
nss_status_t _nss_ldap_endprotoent(void)
{
  NSS_ENDENT(protoentfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

static nss_status_t read_protostring(TFILE *fp,nss_XbyY_args_t *args)
{
  struct protoent result;
  nss_status_t retv;
  char *buffer;
  size_t buflen;
  int i;
  /* read the protoent */
  retv=read_protoent(fp,&result,NSS_ARGS(args)->buf.buffer,args->buf.buflen,&errno);
  if (retv!=NSS_STATUS_SUCCESS)
    return retv;
  /* allocate a temporary buffer */
  buflen=args->buf.buflen;
  buffer=(char *)malloc(buflen);
  /* build the formatted string */
  /* FIXME: implement proper buffer size checking */
  sprintf(buffer,"%s\t\t%d",result.p_name,result.p_proto);
  if (result.p_aliases)
    for (i=0; result.p_aliases[i]; i++)
    {
      strcat(buffer," ");
      strcat(buffer,result.p_aliases[i]);
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
    read_protoent(fp,(struct protoent *)NSS_ARGS(args)->buf.result,NSS_ARGS(args)->buf.buffer,NSS_ARGS(args)->buf.buflen,&errno): \
    read_protostring(fp,args); \
  if (NSS_ARGS(args)->buf.result) \
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result

static nss_status_t get_getprotobyname(nss_backend_t UNUSED(*be),void *args)
{
  NSS_BYNAME(NSLCD_ACTION_PROTOCOL_BYNAME,
             NSS_ARGS(args)->key.name,
             READ_RESULT(fp));
}

static nss_status_t get_getprotobynumber(nss_backend_t UNUSED(*be),void *args)
{
  NSS_BYINT32(NSLCD_ACTION_PROTOCOL_BYNUMBER,
              NSS_ARGS(args)->key.number,
              READ_RESULT(fp));
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *protoentfp;

static nss_status_t get_setprotoent(nss_backend_t UNUSED(*be),void UNUSED(*args))
{
  NSS_SETENT(protoentfp);
}

static nss_status_t get_getprotoent(nss_backend_t UNUSED(*be),void *args)
{
  NSS_GETENT(protoentfp,NSLCD_ACTION_PROTOCOL_ALL,
             READ_RESULT(protoentfp));
}

static nss_status_t get_endprotoent(nss_backend_t UNUSED(*be),void UNUSED(*args))
{
  NSS_ENDENT(protoentfp);
}

static nss_status_t destructor(nss_backend_t *be,void UNUSED(*args))
{
  free(be);
  return NSS_STATUS_SUCCESS;
}

static nss_backend_op_t proto_ops[]={
  destructor,
  get_endprotoent,
  get_setprotoent,
  get_getprotoent,
  get_getprotobyname,
  get_getprotobynumber
};

nss_backend_t *_nss_ldap_protocols_constr(const char UNUSED(*db_name),
        const char UNUSED(*src_name),const char UNUSED(*cfg_args))
{
  nss_backend_t *be;
  be=(nss_backend_t *)malloc(sizeof(*be));
  if (be==NULL)
    return NULL;
  be->ops=proto_ops;
  be->n_ops=sizeof(proto_ops)/sizeof(nss_backend_op_t);
  return (nss_backend_t *)be;
}

#endif /* NSS_FLAVOUR_SOLARIS */
