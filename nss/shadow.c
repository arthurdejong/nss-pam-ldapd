/*
   shadow.c - NSS lookup functions for shadow database

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

/* read a single shadow entry from the stream */
static nss_status_t read_spwd(
        TFILE *fp,struct spwd *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32;
  size_t bufptr=0;
  READ_BUF_STRING(fp,result->sp_namp);
  READ_BUF_STRING(fp,result->sp_pwdp);
  READ_INT32(fp,result->sp_lstchg);
  READ_INT32(fp,result->sp_min);
  READ_INT32(fp,result->sp_max);
  READ_INT32(fp,result->sp_warn);
  READ_INT32(fp,result->sp_inact);
  READ_INT32(fp,result->sp_expire);
  READ_INT32(fp,result->sp_flag);
  return NSS_STATUS_SUCCESS;
}

#ifdef NSS_FLAVOUR_GLIBC

/* get a shadow entry by name */
nss_status_t _nss_ldap_getspnam_r(
        const char *name,struct spwd *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_SHADOW_BYNAME,
             name,
             read_spwd(fp,result,buffer,buflen,errnop));
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *spentfp;

/* start listing all shadow users */
nss_status_t _nss_ldap_setspent(int UNUSED(stayopen))
{
  NSS_SETENT(spentfp);
}

/* return a single shadow entry read from the stream */
nss_status_t _nss_ldap_getspent_r(
        struct spwd *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(spentfp,NSLCD_ACTION_SHADOW_ALL,
             read_spwd(spentfp,result,buffer,buflen,errnop));
}

/* close the stream opened by setspent() above */
nss_status_t _nss_ldap_endspent(void)
{
  NSS_ENDENT(spentfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN

static nss_status_t read_spwdstring(TFILE *fp,nss_XbyY_args_t *args)
{
  struct spwd result;
  nss_status_t retv;
  char *buffer;
  char field_buf[128];
  size_t buflen;
  /* read the spwd */
  retv=read_spwd(fp,&result,NSS_ARGS(args)->buf.buffer,args->buf.buflen,&errno);
  if (retv!=NSS_STATUS_SUCCESS)
    return retv;
  /* allocate a temporary buffer */
  buflen=args->buf.buflen;
  buffer=(char *)malloc(buflen);
  /* build the formatted string */
  /* FIXME: implement proper buffer size checking */
  sprintf(buffer,"%s:%s:",result.sp_namp,result.sp_pwdp);
  if (result.sp_lstchg >= 0)
    sprintf(field_buf,"%d:",result.sp_lstchg);
  else
    sprintf(field_buf,":");
  strcat(buffer,field_buf);
  if (result.sp_min >= 0)
    sprintf(field_buf,"%d:",result.sp_min);
  else
    sprintf(field_buf,":");
  strcat(buffer,field_buf);
  if (result.sp_max >= 0)
    sprintf(field_buf,"%d:",result.sp_max);
  else
    sprintf(field_buf,":");
  strcat(buffer,field_buf);
  if (result.sp_warn >= 0)
    sprintf(field_buf,"%d:",result.sp_warn);
  else
    sprintf(field_buf,":");
  strcat(buffer,field_buf);
  if (result.sp_inact >= 0)
    sprintf(field_buf,"%d:",result.sp_inact);
  else
    sprintf(field_buf,":");
  strcat(buffer,field_buf);
  if (result.sp_expire >= 0)
    sprintf(field_buf,"%d:",result.sp_expire);
  else
    sprintf(field_buf,":");
  strcat(buffer,field_buf);
  if (result.sp_flag >= 0)
    sprintf(field_buf,"%x",result.sp_flag);
  else
    sprintf(field_buf,":");
  strcat(buffer,field_buf);
  /* copy the result back to the result buffer and free the temporary one */
  strcpy(NSS_ARGS(args)->buf.buffer,buffer);
  free(buffer);
  NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.buffer;
  NSS_ARGS(args)->returnlen=strlen(NSS_ARGS(args)->buf.buffer);
  return NSS_STATUS_SUCCESS;
}

#define READ_RESULT(fp) \
  NSS_ARGS(args)->buf.result? \
    read_spwd(fp,(struct spwd *)NSS_ARGS(args)->buf.result,NSS_ARGS(args)->buf.buffer,NSS_ARGS(args)->buf.buflen,&errno): \
    read_spwdstring(fp,args); \
  if ((NSS_ARGS(args)->buf.result)&&(retv==NSS_STATUS_SUCCESS)) \
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;

#else /* not HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

#define READ_RESULT(fp) \
  read_spwd(fp,(struct spwd *)NSS_ARGS(args)->buf.result,NSS_ARGS(args)->buf.buffer,NSS_ARGS(args)->buf.buflen,&errno); \
  if (retv==NSS_STATUS_SUCCESS) \
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;

#endif /* not HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

static nss_status_t get_getspnam_r(nss_backend_t UNUSED(*be),void *args)
{
  NSS_BYNAME(NSLCD_ACTION_SHADOW_BYNAME,
             NSS_ARGS(args)->key.name,
             READ_RESULT(fp));
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *spentfp;

static nss_status_t get_setspent(nss_backend_t UNUSED(*be),void UNUSED(*args))
{
  NSS_SETENT(spentfp);
}

static nss_status_t get_getspent_r(nss_backend_t UNUSED(*be),void *args)
{
  NSS_GETENT(spentfp,NSLCD_ACTION_SHADOW_ALL,
             READ_RESULT(spentfp));
}

static nss_status_t get_endspent(nss_backend_t UNUSED(*be),void UNUSED(*args))
{
  NSS_ENDENT(spentfp);
}

static nss_status_t destructor(nss_backend_t *be,void UNUSED(*args))
{
  free(be);
  return NSS_STATUS_SUCCESS;
}

static nss_backend_op_t shadow_ops[]={
  destructor,
  get_endspent,         /* NSS_DBOP_ENDENT */
  get_setspent,         /* NSS_DBOP_SETENT */
  get_getspent_r,       /* NSS_DBOP_GETENT */
  get_getspnam_r        /* NSS_DBOP_SHADOW_BYNAME */
};

nss_backend_t *_nss_ldap_shadow_constr(const char UNUSED(*db_name),
                         const char UNUSED(*src_name),const char UNUSED(*cfg_args))
{
  nss_backend_t *be;
  if (!(be=(nss_backend_t *)malloc(sizeof(*be))))
    return NULL;
  be->ops=shadow_ops;
  be->n_ops=sizeof(shadow_ops)/sizeof(nss_backend_op_t);
  return (nss_backend_t *)be;
}

#endif /* NSS_FLAVOUR_SOLARIS */
