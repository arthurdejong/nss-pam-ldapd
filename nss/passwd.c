/*
   passwd.c - NSS lookup functions for passwd database

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

/* read a passwd entry from the stream */
static nss_status_t read_passwd(
        TFILE *fp,struct passwd *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32;
  size_t bufptr=0;
  memset(result,0,sizeof(struct passwd));
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
  NSS_BYNAME(NSLCD_ACTION_PASSWD_BYNAME,
             name,
             read_passwd(fp,result,buffer,buflen,errnop));
}

/* get a single passwd entry by uid */
nss_status_t _nss_ldap_getpwuid_r(
        uid_t uid,struct passwd *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYTYPE(NSLCD_ACTION_PASSWD_BYUID,
             uid,uid_t,
             read_passwd(fp,result,buffer,buflen,errnop));
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
  NSS_GETENT(pwentfp,NSLCD_ACTION_PASSWD_ALL,
             read_passwd(pwentfp,result,buffer,buflen,errnop));
}

/* close the stream opened with setpwent() above */
nss_status_t _nss_ldap_endpwent(void)
{
  NSS_ENDENT(pwentfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN
static nss_status_t read_passwdstring(TFILE *fp,nss_XbyY_args_t *args)
{
  struct passwd result;
  char buffer[NSS_BUFLEN_PASSWD];
  nss_status_t retv;
  /* read the passwd */
  retv=read_passwd(fp,&result,buffer,sizeof(buffer),&NSS_ARGS(args)->erange);
  if (retv!=NSS_STATUS_SUCCESS)
    return retv;
  /* build the formatted string */
  res=snprintf(args->buf.buffer,args->buf.buflen,"%s:%s:%d:%d:%s:%s:%s",
     result.pw_name,result.pw_passwd,(int)result.pw_uid,(int)result.pw_gid,result.pw_gecos,
     result.pw_dir,result.pw_shell);
  if ((res<0)||(res>=NSS_ARGS(args)->buf.buflen))
  {
    NSS_ARGS(args)->erange=1;
    return NSS_NOTFOUND;
  }
  /* return the string as a result */
  args->returnval=args->buf.buffer;
  args->returnlen=strlen(args->returnval);
  return NSS_STATUS_SUCCESS;
}
#endif /* not HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

static nss_status_t read_result(TFILE *fp,nss_XbyY_args_t *args)
{
  nss_status_t retv;
#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN
  /* try to return in string format if requested */
  if (args->buf.result==NULL)
    return read_passwdstring(fp,args);
#endif /* not HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */
  /* read the entry */
  retv=read_passwd(fp,args->buf.result,args->buf.buffer,args->buf.buflen,&NSS_ARGS(args)->erange);
  if (retv!=NSS_STATUS_SUCCESS)
    return retv;
  args->returnval=args->buf.result;
  return NSS_STATUS_SUCCESS;
}

static nss_status_t passwd_getpwnam(nss_backend_t UNUSED(*be),void *args)
{
  NSS_BYNAME(NSLCD_ACTION_PASSWD_BYNAME,
             NSS_ARGS(args)->key.name,
             read_result(fp,args));
}

static nss_status_t passwd_getpwuid(nss_backend_t UNUSED(*be),void *args)
{
  NSS_BYTYPE(NSLCD_ACTION_PASSWD_BYUID,
             NSS_ARGS(args)->key.uid,uid_t,
             read_result(fp,args));
}

/* open a connection to the nslcd and write the request */
static nss_status_t passwd_setpwent(nss_backend_t *be,void UNUSED(*args))
{
  NSS_SETENT(LDAP_BE(be)->fp);
}

/* read password data from an opened stream */
static nss_status_t passwd_getpwent(nss_backend_t *be,void *args)
{
  NSS_GETENT(LDAP_BE(be)->fp,NSLCD_ACTION_PASSWD_ALL,
             READ_RESULT(LDAP_BE(be)->fp));
}

/* close the stream opened with setpwent() above */
static nss_status_t passwd_endpwent(nss_backend_t *be,void UNUSED(*args))
{
  NSS_ENDENT(LDAP_BE(be)->fp);
}

static nss_backend_op_t passwd_ops[]={
  nss_ldap_destructor,
  passwd_endpwent,
  passwd_setpwent,
  passwd_getpwent,
  passwd_getpwnam,
  passwd_getpwuid
};

nss_backend_t *_nss_ldap_passwd_constr(const char UNUSED(*db_name),
                  const char UNUSED(*src_name),const char UNUSED(*cfg_args))
{
  return nss_ldap_constructor(passwd_ops,sizeof(passwd_ops));
}

#endif /* NSS_FLAVOUR_SOLARIS */
