/*
   passwd.c - NSS lookup functions for passwd database

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006 Arthur de Jong

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
   MA 02110-1301 USA
*/

#include "config.h"

#include <string.h>
#include <nss.h>
#include <errno.h>

#include "prototypes.h"
#include "common.h"

/* Macros for expanding the NSLCD_PASSWD macro. */
#define NSLCD_STRING(field)    READ_STRING_BUF(fp,field)
#define NSLCD_TYPE(field,type) READ_TYPE(fp,field,type)
#define PASSWD_NAME   result->pw_name
#define PASSWD_PASSWD result->pw_passwd
#define PASSWD_UID    result->pw_uid
#define PASSWD_GID    result->pw_gid
#define PASSWD_GECOS  result->pw_gecos
#define PASSWD_DIR    result->pw_dir
#define PASSWD_SHELL  result->pw_shell


static enum nss_status read_passwd(
        FILE *fp,struct passwd *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32;
  size_t bufptr=0;
  NSLCD_PASSWD;
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_getpwnam_r(const char *name,struct passwd *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_PASSWD_BYNAME,name,read_passwd);
}

enum nss_status _nss_ldap_getpwuid_r(uid_t uid,struct passwd *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_BYTYPE(NSLCD_ACTION_PASSWD_BYUID,uid,uid_t,read_passwd);
}

/* thread-local file pointer to an ongoing request */
static __thread FILE *pwentfp;

/* open a connection to the nslcd and write the request */
enum nss_status _nss_ldap_setpwent(int stayopen)
{
  NSS_SETENT(pwentfp,NSLCD_ACTION_PASSWD_ALL);
}

/* read password data from an opened stream */
enum nss_status _nss_ldap_getpwent_r(struct passwd *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(pwentfp,read_passwd);
}

/* close the stream opened with setpwent() above */
enum nss_status _nss_ldap_endpwent(void)
{
  NSS_ENDENT(pwentfp);
}
