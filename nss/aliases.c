/*
   aliases.c - NSS lookup functions for aliases database

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

/* macros for expanding the LDF_ALIAS macro */
#define LDF_STRING(field)     READ_STRING_BUF(fp,field)
#define LDF_STRINGLIST(field) READ_STRINGLIST_NUM(fp,field,result->alias_members_len)
#define ALIAS_NAME            result->alias_name
#define ALIAS_RCPTS           result->alias_members

enum nss_status _nss_ldap_getaliasbyname_r(
        const char *name,struct aliasent *result,
        char *buffer,size_t buflen,int *errnop)
{
  FILE *fp;
  size_t bufptr=0;
  int32_t tmpint32,tmp2int32;
  /* open socket and write request */
  OPEN_SOCK(fp);
  WRITE_REQUEST(fp,NSLCD_ACTION_ALIAS_BYNAME);
  WRITE_STRING(fp,name);
  WRITE_FLUSH(fp);
  /* read response header */
  READ_RESPONSEHEADER(fp,NSLCD_ACTION_ALIAS_BYNAME);
  /* read response */
  READ_RESPONSE_CODE(fp);
  LDF_ALIAS;
  /* fill in remaining gaps in struct */
  result->alias_local=0;
  /* close socket and we're done */
  fclose(fp);
  return NSS_STATUS_SUCCESS;
}

/* thread-local file pointer to an ongoing request */
static __thread FILE *pwentfp;
#define fp pwentfp

enum nss_status _nss_ldap_setaliasent(void)
{
  NSS_SETENT(NSLCD_ACTION_ALIAS_ALL);
}

enum nss_status _nss_ldap_getaliasent_r(struct aliasent *result,char *buffer,size_t buflen,int *errnop)
{
  int32_t tmp2int32;
  NSS_GETENT(LDF_ALIAS);
}

enum nss_status _nss_ldap_endaliasent(void)
{
  NSS_ENDENT();
}
