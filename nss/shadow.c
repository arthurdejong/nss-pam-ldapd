/*
   shadow.c - NSS lookup functions for shadow database

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

/* Macros for expanding the LDF_SHADOW macro. */
#define LDF_STRING(field)    READ_STRING_BUF(fp,field)
#define LDF_INT32(field)     READ_INT32(fp,field)
#define SHADOW_NAME          result->sp_namp
#define SHADOW_PASSWD        result->sp_pwdp
#define SHADOW_LASTCHANGE    result->sp_lstchg
#define SHADOW_MINDAYS       result->sp_min
#define SHADOW_MAXDAYS       result->sp_max
#define SHADOW_WARN          result->sp_warn
#define SHADOW_INACT         result->sp_inact
#define SHADOW_EXPIRE        result->sp_expire
#define SHADOW_FLAG          result->sp_flag

enum nss_status _nss_ldap_getspnam_r(const char *name,struct spwd *result,char *buffer,size_t buflen,int *errnop)
{
  FILE *fp;
  size_t bufptr=0;
  int32_t tmpint32;
  /* open socket and write request */
  OPEN_SOCK(fp);
  WRITE_REQUEST(fp,NSLCD_ACTION_SHADOW_BYNAME);
  WRITE_STRING(fp,name);
  WRITE_FLUSH(fp);
  /* read response header */
  READ_RESPONSEHEADER(fp,NSLCD_ACTION_SHADOW_BYNAME);
  /* read response */
  READ_RESPONSE_CODE(fp);
  LDF_SHADOW;
  /* close socket and we're done */
  fclose(fp);
  return NSS_STATUS_SUCCESS;
}

/* thread-local file pointer to an ongoing request */
static __thread FILE *spentfp;
#define fp spentfp

enum nss_status _nss_ldap_setspent(int stayopen)
{
  NSS_SETENT(NSLCD_ACTION_SHADOW_ALL);
}

enum nss_status _nss_ldap_getspent_r(struct spwd *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(LDF_SHADOW);
}

enum nss_status _nss_ldap_endspent(void)
{
  NSS_ENDENT();
}
