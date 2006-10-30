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

#include <string.h>
#include <nss.h>
#include <errno.h>

#include "exports.h"
#include "nslcd-client.h"
#include "common.h"

/* Macros for expanding the LDF_PASSWD macro. */
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
  int32_t sz;

  /* open socket */
  OPEN_SOCK(fp);

  /* write request to nslcd */
  if (nslcd_client_writerequest(fp,NSLCD_RT_GETPWBYNAME,name,strlen(name)))
    ERROR_OUT(fp,NSS_STATUS_UNAVAIL,ENOENT);
  
  /* read response header */
  if ((sz=nslcd_client_readresponse(fp,NSLCD_RT_GETPWBYNAME))!=NSLCD_RS_SUCCESS)
    ERROR_OUT(fp,nslcd2nss(sz),ENOENT);
  
  /* read struct passwd */
  LDF_PASSWD;
  
  /* close socket and we're done */
  fclose(fp);
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_getpwuid_r(uid_t uid,struct passwd *result,char *buffer,size_t buflen,int *errnop)
{
  *errnop=ENOENT;
  return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_ldap_setpwent(void)
{
  return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_ldap_getpwent_r(struct passwd *result,char *buffer,size_t buflen,int *errnop)
{
  *errnop=ENOENT;
  return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_ldap_endpwent(void)
{
  return NSS_STATUS_UNAVAIL;
}
