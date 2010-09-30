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

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_nslcd_getspnam_r(
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_getspnam_r(
#endif /* HAVE_NSSWITCH_H */
        const char *name,struct spwd *result,char *buffer,
        size_t buflen,int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_SHADOW_BYNAME,
             name,
             read_spwd(fp,result,buffer,buflen,errnop));
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *spentfp;

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_ldap_setspent(nss_backend_t *be,void *args)
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_setspent(int UNUSED(stayopen))
#endif /* HAVE_NSSWITCH_H */
{
  NSS_SETENT(spentfp);
}

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_nslcd_getspent_r(
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_getspent_r(
#endif /* HAVE_NSSWITCH_H */
        struct spwd *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(spentfp,NSLCD_ACTION_SHADOW_ALL,
             read_spwd(spentfp,result,buffer,buflen,errnop));
}

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_ldap_endspent(nss_backend_t *sp_context,void *args)
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_endspent(void)
#endif /* HAVE_NSSWITCH_H */
{
  NSS_ENDENT(spentfp);
}

#ifdef HAVE_NSSWITCH_H
static nss_status_t _nss_ldap_getspnam_r(nss_backend_t *be,void *args)
{
  struct spwd priv_spwd;
  struct spwd *sp=NSS_ARGS(args)->buf.result?(struct spwd *)NSS_ARGS(args)->buf.result:&priv_spwd;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  char *name=(char *)NSS_ARGS(args)->key.name;
  char *data_ptr;
  nss_status_t status;
  if (NSS_ARGS(args)->buf.buflen < 0)
  {
    NSS_ARGS(args)->erange=1;
    return NSS_STATUS_TRYAGAIN;
  }
  status=_nss_nslcd_getspnam_r(name,sp,buffer,buflen,&errno);
  if (status!=NSS_STATUS_SUCCESS)
    return status;
  if (!NSS_ARGS(args)->buf.result)
  {
    /* result==NULL, return file format */
    data_ptr=(char *)malloc(buflen);
    char field_buf[128];
    sprintf(data_ptr,"%s:%s:",sp->sp_namp,sp->sp_pwdp);
    if (sp->sp_lstchg >= 0)
      sprintf(field_buf,"%d:",sp->sp_lstchg);
    else
      sprintf(field_buf,":");
    strcat(data_ptr,field_buf);
    if (sp->sp_min >= 0)
      sprintf(field_buf,"%d:",sp->sp_min);
    else
      sprintf(field_buf,":");
    strcat(data_ptr,field_buf);
    if (sp->sp_max >= 0)
      sprintf(field_buf,"%d:",sp->sp_max);
    else
      sprintf(field_buf,":");
    strcat(data_ptr,field_buf);
    if (sp->sp_warn >= 0)
      sprintf(field_buf,"%d:",sp->sp_warn);
    else
      sprintf(field_buf,":");
    strcat(data_ptr,field_buf);
    if (sp->sp_inact >= 0)
      sprintf(field_buf,"%d:",sp->sp_inact);
    else
      sprintf(field_buf,":");
    strcat(data_ptr,field_buf);
    if (sp->sp_expire >= 0)
      sprintf(field_buf,"%d:",sp->sp_expire);
    else
      sprintf(field_buf,":");
    strcat(data_ptr,field_buf);
    if (sp->sp_flag >= 0)
      sprintf(field_buf,"%x",sp->sp_flag);
    else
      sprintf(field_buf,":");
    strcat(data_ptr,field_buf);
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

static nss_status_t _nss_ldap_getspent_r(nss_backend_t *sp_context,void *args)
{
  struct spwd priv_spwd;
  struct spwd *sp=NSS_ARGS(args)->buf.result?(struct spwd *)NSS_ARGS(args)->buf.result:&priv_spwd;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  char *data_ptr;
  nss_status_t status;
  if (NSS_ARGS(args)->buf.buflen < 0)
  {
    NSS_ARGS(args)->erange=1;
    return NSS_STATUS_TRYAGAIN;
  }
  status=_nss_nslcd_getspent_r(sp,buffer,buflen,&errno);
  if (status!=NSS_STATUS_SUCCESS)
    return status;
  if (!NSS_ARGS(args)->buf.result)
  {
    /* result==NULL, return file format */
    data_ptr=(char *)malloc(buflen);
    char field_buf[128];
    sprintf(data_ptr,"%s:%s:",sp->sp_namp,sp->sp_pwdp);
    if (sp->sp_lstchg >= 0)
      sprintf(field_buf,"%d:",sp->sp_lstchg);
    else
      sprintf(field_buf,":");
    strcat(data_ptr,field_buf);
    if (sp->sp_min >= 0)
      sprintf(field_buf,"%d:",sp->sp_min);
    else
      sprintf(field_buf,":");
    strcat(data_ptr,field_buf);
    if (sp->sp_max >= 0)
      sprintf(field_buf,"%d:",sp->sp_max);
    else
      sprintf(field_buf,":");
    strcat(data_ptr,field_buf);
    if (sp->sp_warn >= 0)
      sprintf(field_buf,"%d:",sp->sp_warn);
    else
      sprintf(field_buf,":");
    strcat(data_ptr,field_buf);
    if (sp->sp_inact >= 0)
      sprintf(field_buf,"%d:",sp->sp_inact);
    else
      sprintf(field_buf,":");
    strcat(data_ptr,field_buf);
    if (sp->sp_expire >= 0)
      sprintf(field_buf,"%d:",sp->sp_expire);
    else
      sprintf(field_buf,":");
    strcat(data_ptr,field_buf);
    if (sp->sp_flag >= 0)
      sprintf(field_buf,"%x",sp->sp_flag);
    else
      sprintf(field_buf,":");
    strcat(data_ptr,field_buf);
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

static nss_status_t _nss_ldap_shadow_destr(nss_backend_t *sp_context,void *args)
{
  return _nss_ldap_default_destr(sp_context,args);
}

static nss_backend_op_t shadow_ops[]={
  _nss_ldap_shadow_destr,
  _nss_ldap_endspent,         /* NSS_DBOP_ENDENT */
  _nss_ldap_setspent,         /* NSS_DBOP_SETENT */
  _nss_ldap_getspent_r,       /* NSS_DBOP_GETENT */
  _nss_ldap_getspnam_r        /* NSS_DBOP_SHADOW_BYNAME */
};

nss_backend_t *_nss_ldap_shadow_constr(const char *db_name,
                         const char *src_name,const char *cfg_args)
{
  nss_ldap_backend_t *be;
  if (!(be=(nss_ldap_backend_t *)malloc(sizeof(*be))))
    return NULL;
  be->ops=shadow_ops;
  be->n_ops=sizeof(shadow_ops)/sizeof(nss_backend_op_t);
  if (_nss_ldap_default_constr(be)!=NSS_STATUS_SUCCESS)
    return NULL;
  return (nss_backend_t *)be;
}

#endif /* HAVE_NSSWITCH_H */
