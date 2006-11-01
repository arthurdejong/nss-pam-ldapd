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

#include "exports.h"
#include "nslcd-client.h"
#include "common.h"

/* Macros for expanding the LDF_PASSWD macro. */
#define LDF_STRING(field)    READ_STRING_BUF(fp,field)
#define LDF_TYPE(field,type) READ_TYPE(fp,field,type)
#define PASSWD_NAME   result->pw_name
#define PASSWD_PASSWD result->pw_passwd
#define PASSWD_UID    result->pw_uid
#define PASSWD_GID    result->pw_gid
#define PASSWD_GECOS  result->pw_gecos
#define PASSWD_DIR    result->pw_dir
#define PASSWD_SHELL  result->pw_shell

enum nss_status _nss_ldap_getpwnam_r(const char *name,struct passwd *result,char *buffer,size_t buflen,int *errnop)
{
  FILE *fp;
  size_t bufptr=0;
  int32_t tmpint32;
  /* open socket and write request */
  OPEN_SOCK(fp);
  WRITE_REQUEST(fp,NSLCD_RT_GETPWBYNAME);
  WRITE_STRING(fp,name);
  WRITE_FLUSH(fp);
  /* read response header */
  READ_RESPONSEHEADER(fp,NSLCD_RT_GETPWBYNAME);
  /* read response */
  READ_RESPONSE(fp);
  LDF_PASSWD;
  /* close socket and we're done */
  fclose(fp);
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_getpwuid_r(uid_t uid,struct passwd *result,char *buffer,size_t buflen,int *errnop)
{
  FILE *fp;
  size_t bufptr=0;
  int32_t tmpint32;
  /* open socket and write request */
  OPEN_SOCK(fp);
  WRITE_REQUEST(fp,NSLCD_RT_GETPWBYUID);
  WRITE_TYPE(fp,uid,uid_t);
  WRITE_FLUSH(fp);
  /* read response header */
  READ_RESPONSEHEADER(fp,NSLCD_RT_GETPWBYUID);
  /* read response */
  READ_RESPONSE(fp);
  LDF_PASSWD;
  /* close socket and we're done */
  fclose(fp);
  return NSS_STATUS_SUCCESS;
}

/* thread-local file pointer to an ongoing request */
static __thread FILE *pwentfp;
#define fp pwentfp

/* open a connection to the nslcd and write the request */
enum nss_status _nss_ldap_setpwent(void)
{
  int32_t tmpint32;
  /* this is to satisfy our macros */
  int errnocp;
  int *errnop;
  errnop=&errnocp;
  /* close the existing stream if it is still open */
  if (fp!=NULL)
    _nss_ldap_endpwent();
  /* open a new stream and write the request */
  OPEN_SOCK(fp);
  WRITE_REQUEST(fp,NSLCD_RT_GETPWALL);
  WRITE_FLUSH(fp);
  /* read response header */
  READ_RESPONSEHEADER(fp,NSLCD_RT_GETPWALL);
  return NSS_STATUS_SUCCESS;
}

/* read password data from an opened stream */
enum nss_status _nss_ldap_getpwent_r(struct passwd *result,char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32;
  size_t bufptr=0;
  /* check that we have a valid file descriptor */
  if (fp==NULL)
  {
    *errnop=ENOENT;
    return NSS_STATUS_UNAVAIL;
  }
  /* read a response */
  READ_RESPONSE(fp);
  LDF_PASSWD;
  return NSS_STATUS_SUCCESS;
}

/* close the stream opened with setpwent() above */
enum nss_status _nss_ldap_endpwent(void)
{
  if (fp==NULL)
    return NSS_STATUS_SUCCESS;
  fclose(fp);
  return NSS_STATUS_SUCCESS;
}
