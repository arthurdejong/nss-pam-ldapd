/*
   passwd.c - NSS lookup functions for passwd database

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

/* read a passwd entry from the stream */
static nss_status_t read_passwd(
        TFILE *fp,struct passwd *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32;
  size_t bufptr=0;
  READ_BUF_STRING(fp,result->pw_name);
  READ_BUF_STRING(fp,result->pw_passwd);
  READ_TYPE(fp,result->pw_uid,uid_t);
  READ_TYPE(fp,result->pw_gid,gid_t);
  READ_BUF_STRING(fp,result->pw_gecos);
  READ_BUF_STRING(fp,result->pw_dir);
  READ_BUF_STRING(fp,result->pw_shell);
  return NSS_STATUS_SUCCESS;
}

#ifdef NSS_FLAVOUR_GLIBC

/* get a single passwd entry by name */
nss_status_t _nss_ldap_getpwnam_r(
        const char *name,struct passwd *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_PASSWD_BYNAME,buffer,buflen,
             name,
             read_passwd(fp,result,buffer,buflen,errnop));
  return retv;
}

/* get a single passwd entry by uid */
nss_status_t _nss_ldap_getpwuid_r(
        uid_t uid,struct passwd *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYTYPE(NSLCD_ACTION_PASSWD_BYUID,buffer,buflen,
             uid,uid_t,
             read_passwd(fp,result,buffer,buflen,errnop));
  return retv;
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *pwentfp;

/* open a connection to read all passwd entries */
nss_status_t _nss_ldap_setpwent(int UNUSED(stayopen))
{
  NSS_SETENT(pwentfp);
}

/* read password data from an opened stream */
nss_status_t _nss_ldap_getpwent_r(
        struct passwd *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(pwentfp,NSLCD_ACTION_PASSWD_ALL,buffer,buflen,
             read_passwd(pwentfp,result,buffer,buflen,errnop));
  return retv;
}

/* close the stream opened with setpwent() above */
nss_status_t _nss_ldap_endpwent(void)
{
  NSS_ENDENT(pwentfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

static nss_status_t _nss_nslcd_getpwnam_r(
        const char *name,struct passwd *result,char *buffer,size_t buflen,
        int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_PASSWD_BYNAME,buffer,buflen,
             name,
             read_passwd(fp,result,buffer,buflen,errnop));
  return retv;
}

static nss_status_t _xnss_ldap_getpwnam_r(nss_backend_t UNUSED(*be),void *args)
{
  struct passwd priv_pw;
  struct passwd *pw=NSS_ARGS(args)->buf.result?(struct passwd *)NSS_ARGS(args)->buf.result:&priv_pw;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  char *data_ptr;
  nss_status_t status;
  if (NSS_ARGS(args)->buf.buflen<0)
  {
    NSS_ARGS(args)->erange=1;
    status=NSS_STATUS_TRYAGAIN;
    return status;
  }
  status=_nss_nslcd_getpwnam_r(NSS_ARGS(args)->key.name,pw,buffer,buflen,&errno);
  if (status!=NSS_STATUS_SUCCESS)
    return status;
  if (!NSS_ARGS(args)->buf.result)
  {
     /* result==NULL, return file format */
     data_ptr=(char *)malloc(buflen);
     sprintf(data_ptr,"%s:%s:%d:%d:%s:%s:%s",
       pw->pw_name,"x",(int) pw->pw_uid,(int) pw->pw_gid,pw->pw_gecos,
       pw->pw_dir,pw->pw_shell);
     /* copy file-format data to buffer provided by front-end */
     strcpy(buffer,data_ptr);
     if (data_ptr)
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

static nss_status_t _nss_nslcd_getpwuid_r(
        uid_t uid,struct passwd *result,char *buffer,
        size_t buflen,int *errnop)
{
  NSS_BYTYPE(NSLCD_ACTION_PASSWD_BYUID,buffer,buflen,
             uid,uid_t,
             read_passwd(fp,result,buffer,buflen,errnop));
  return retv;
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *pwentfp;

/* open a connection to the nslcd and write the request */
static nss_status_t _xnss_ldap_setpwent(nss_backend_t UNUSED(*be),void UNUSED(*args))
{
  NSS_SETENT(pwentfp);
}

/* read password data from an opened stream */
static nss_status_t _nss_nslcd_getpwent_r(
        struct passwd *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(pwentfp,NSLCD_ACTION_PASSWD_ALL,buffer,buflen,
             read_passwd(pwentfp,result,buffer,buflen,errnop));
  return retv;
}

/* close the stream opened with setpwent() above */
static nss_status_t _xnss_ldap_endpwent(nss_backend_t UNUSED(*be),void UNUSED(*args))
{
  NSS_ENDENT(pwentfp);
}

static nss_status_t _xnss_ldap_getpwuid_r(nss_backend_t UNUSED(*be),void *args)
{
  struct passwd priv_pw;
  struct passwd *pw=NSS_ARGS(args)->buf.result ?
                NSS_ARGS(args)->buf.result : &priv_pw;
  uid_t uid=NSS_ARGS(args)->key.uid;
  char *data_ptr;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  nss_status_t status;
  status=_nss_nslcd_getpwuid_r(uid,pw,buffer,buflen,&errno);
  if (status!=NSS_STATUS_SUCCESS)
    return status;
  if (!NSS_ARGS(args)->buf.result)
  {
    /* result==NULL, return file format */
    data_ptr=(char *)malloc((size_t) buflen);
    sprintf(data_ptr,"%s:%s:%d:%d:%s:%s:%s",
            pw->pw_name,"x",(int) pw->pw_uid,(int) pw->pw_gid,pw->pw_gecos,
            pw->pw_dir,pw->pw_shell);
    /* copy file-format data to buffer provided by front-end */
    strcpy(buffer,data_ptr);
    if (data_ptr)
      free((void *)data_ptr);
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.buffer;
    NSS_ARGS(args)->returnlen=strlen(NSS_ARGS(args)->buf.buffer);
  }
  else
  {
     NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;
  }
  return status;
}

static nss_status_t _xnss_ldap_getpwent_r(nss_backend_t UNUSED(*be),void *args)
{
  struct passwd priv_pw;
  struct passwd *pw=NSS_ARGS(args)->buf.result?(struct passwd *)NSS_ARGS(args)->buf.result:&priv_pw;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  char *data_ptr;
  nss_status_t status;
  status=_nss_nslcd_getpwent_r(pw,buffer,buflen,&errno);
  if (status!=NSS_STATUS_SUCCESS)
    return status;
  if (!NSS_ARGS(args)->buf.result)
  {
     /* result==NULL, return file format */
     data_ptr=(char *)malloc(buflen);
     sprintf(data_ptr,"%s:%s:%d:%d:%s:%s:%s",
       pw->pw_name,"x",(int) pw->pw_uid,(int) pw->pw_gid,pw->pw_gecos,
       pw->pw_dir,pw->pw_shell);
     /* copy file-format data to buffer provided by front-end */
     strcpy(buffer,data_ptr);
     if (data_ptr)
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

static nss_status_t _xnss_ldap_passwd_destr(nss_backend_t *be,void UNUSED(*args))
{
  free(be);
  return NSS_STATUS_SUCCESS;
}

static nss_backend_op_t passwd_ops[]={
  _xnss_ldap_passwd_destr,
  _xnss_ldap_endpwent,         /* NSS_DBOP_ENDENT */
  _xnss_ldap_setpwent,         /* NSS_DBOP_SETENT */
  _xnss_ldap_getpwent_r,       /* NSS_DBOP_GETENT */
  _xnss_ldap_getpwnam_r,       /* NSS_DBOP_PASSWD_BYNAME */
  _xnss_ldap_getpwuid_r        /* NSS_DBOP_PASSWD_BYUID */
};

nss_backend_t *_nss_ldap_passwd_constr(const char UNUSED(*db_name),
                         const char UNUSED(*src_name),const char UNUSED(*cfg_args))
{
  nss_backend_t *be;
  if (!(be=(nss_backend_t *)malloc(sizeof(*be))))
    return NULL;
  be->ops=passwd_ops;
  be->n_ops=sizeof(passwd_ops)/sizeof(nss_backend_op_t);
  return (nss_backend_t *)be;
}

#endif /* NSS_FLAVOUR_SOLARIS */
