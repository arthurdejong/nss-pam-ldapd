/*
   passwd.c - NSS lookup functions for passwd database

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006-2015 Arthur de Jong
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
static nss_status_t read_passwd(TFILE *fp, struct passwd *result,
                                char *buffer, size_t buflen, int *errnop)
{
  int32_t tmpint32;
  size_t bufptr = 0;
  memset(result, 0, sizeof(struct passwd));
  READ_BUF_STRING(fp, result->pw_name);
  READ_BUF_STRING(fp, result->pw_passwd);
  READ_INT32(fp, result->pw_uid);
  READ_INT32(fp, result->pw_gid);
  READ_BUF_STRING(fp, result->pw_gecos);
  READ_BUF_STRING(fp, result->pw_dir);
  READ_BUF_STRING(fp, result->pw_shell);
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
  READ_BUF_STRING(fp, result->pw_class);
#endif /* HAVE_STRUCT_PASSWD_PW_CLASS */
  return NSS_STATUS_SUCCESS;
}

#ifdef NSS_FLAVOUR_GLIBC

/* get a single passwd entry by name */
nss_status_t NSS_NAME(getpwnam_r)(const char *name, struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop)
{
  NSS_GETONE(NSLCD_ACTION_PASSWD_BYNAME,
             WRITE_STRING(fp, name),
             read_passwd(fp, result, buffer, buflen, errnop));
}

/* get a single passwd entry by uid */
nss_status_t NSS_NAME(getpwuid_r)(uid_t uid, struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop)
{
  NSS_GETONE(NSLCD_ACTION_PASSWD_BYUID,
             WRITE_INT32(fp, uid),
             read_passwd(fp, result, buffer, buflen, errnop));
}

/* thread-local file pointer to an ongoing request */
static TLS TFILE *pwentfp;

/* open a connection to read all passwd entries */
nss_status_t NSS_NAME(setpwent)(int UNUSED(stayopen))
{
  NSS_SETENT(pwentfp);
}

/* read password data from an opened stream */
nss_status_t NSS_NAME(getpwent_r)(struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop)
{
  NSS_GETENT(pwentfp, NSLCD_ACTION_PASSWD_ALL,
             read_passwd(pwentfp, result, buffer, buflen, errnop));
}

/* close the stream opened with setpwent() above */
nss_status_t NSS_NAME(endpwent)(void)
{
  NSS_ENDENT(pwentfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN
static char *passwd2str(struct passwd *result, char *buffer, size_t buflen)
{
  int res;
  res = snprintf(buffer, buflen, "%s:%s:%d:%d:%s:%s:%s",
                 result->pw_name, result->pw_passwd, (int)result->pw_uid,
                 (int)result->pw_gid, result->pw_gecos, result->pw_dir,
                 result->pw_shell);
  if ((res < 0) || (res >= (int)buflen))
    return NULL;
  return buffer;
}
#endif /* HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

static nss_status_t read_result(TFILE *fp, nss_XbyY_args_t *args)
{
  READ_RESULT(passwd, &args->erange);
}

static nss_status_t passwd_getpwnam(nss_backend_t UNUSED(*be), void *args)
{
  NSS_GETONE(NSLCD_ACTION_PASSWD_BYNAME,
             WRITE_STRING(fp, NSS_ARGS(args)->key.name),
             read_result(fp, args));
}

static nss_status_t passwd_getpwuid(nss_backend_t UNUSED(*be), void *args)
{
  NSS_GETONE(NSLCD_ACTION_PASSWD_BYUID,
             WRITE_INT32(fp, NSS_ARGS(args)->key.uid),
             read_result(fp, args));
}

/* open a connection to the nslcd and write the request */
static nss_status_t passwd_setpwent(nss_backend_t *be, void UNUSED(*args))
{
  NSS_SETENT(LDAP_BE(be)->fp);
}

/* read password data from an opened stream */
static nss_status_t passwd_getpwent(nss_backend_t *be, void *args)
{
  NSS_GETENT(LDAP_BE(be)->fp, NSLCD_ACTION_PASSWD_ALL,
             read_result(LDAP_BE(be)->fp, args));
}

/* close the stream opened with setpwent() above */
static nss_status_t passwd_endpwent(nss_backend_t *be, void UNUSED(*args))
{
  NSS_ENDENT(LDAP_BE(be)->fp);
}

static nss_backend_op_t passwd_ops[] = {
  nss_ldap_destructor,
  passwd_endpwent,
  passwd_setpwent,
  passwd_getpwent,
  passwd_getpwnam,
  passwd_getpwuid
};

nss_backend_t *NSS_NAME(passwd_constr)(const char UNUSED(*db_name),
                                       const char UNUSED(*src_name),
                                       const char UNUSED(*cfg_args))
{
  return nss_ldap_constructor(passwd_ops, sizeof(passwd_ops));
}

#endif /* NSS_FLAVOUR_SOLARIS */
