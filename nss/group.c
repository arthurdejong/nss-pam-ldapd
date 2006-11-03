/*
   group.c - NSS lookup functions for group database

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

/* macros for expanding the LDF_GROUP macro */
#define LDF_STRING(field)    READ_STRING_BUF(fp,field)
#define LDF_TYPE(field,type) READ_TYPE(fp,field,type)
#define LDF_LOOP(field)      READ_LOOP_NULLTERM(fp,result->gr_mem,field)
#define GROUP_NAME   result->gr_name
#define GROUP_PASSWD result->gr_passwd
#define GROUP_GID    result->gr_gid
#define GROUP_MEMBER result->gr_mem[tmp2int32]

enum nss_status _nss_ldap_getgrnam_r(const char *name,struct group *result,char *buffer,size_t buflen,int *errnop)
{
  FILE *fp;
  size_t bufptr=0;
  int32_t tmpint32,tmp2int32;
  /* open socket and write request */
  OPEN_SOCK(fp);
  WRITE_REQUEST(fp,NSLCD_ACTION_GROUP_BYNAME);
  WRITE_STRING(fp,name);
  WRITE_FLUSH(fp);
  /* read response */
  READ_RESPONSEHEADER(fp,NSLCD_ACTION_GROUP_BYNAME);
  READ_RESPONSE_CODE(fp);
  LDF_GROUP;
  /* close socket and we're done */
  fclose(fp);
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_getgrgid_r(gid_t gid,struct group *result,char *buffer,size_t buflen,int *errnop)
{
  FILE *fp;
  size_t bufptr=0;
  int32_t tmpint32,tmp2int32;
  /* open socket and write request */
  OPEN_SOCK(fp);
  WRITE_REQUEST(fp,NSLCD_ACTION_GROUP_BYGID);
  WRITE_TYPE(fp,gid,gid_t);
  WRITE_FLUSH(fp);
  /* read response */
  READ_RESPONSEHEADER(fp,NSLCD_ACTION_GROUP_BYGID);
  READ_RESPONSE_CODE(fp);
  LDF_GROUP;
  /* close socket and we're done */
  fclose(fp);
  return NSS_STATUS_SUCCESS;
}

/* this function returns a list of groups */ 
enum nss_status _nss_ldap_initgroups_dyn(
        const char *user,gid_t group,long int *start,
        long int *size,gid_t **groupsp,long int limit,int *errnop)
{
  return NSS_STATUS_UNAVAIL;
  /* TODO: implement skipping of entries as we're only interested in gids */
}

/* thread-local file pointer to an ongoing request */
static __thread FILE *pwentfp;
#define fp pwentfp

enum nss_status _nss_ldap_setgrent(void)
{
  NSS_SETENT(NSLCD_ACTION_GROUP_ALL);
}

enum nss_status _nss_ldap_getgrent_r(struct group *result,char *buffer,size_t buflen,int *errnop)
{
  int32_t tmp2int32;
  NSS_GETENT(LDF_GROUP);
}

enum nss_status _nss_ldap_endgrent(void)
{
  NSS_ENDENT();
}
