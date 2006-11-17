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

#include "prototypes.h"
#include "nslcd-client.h"
#include "common.h"

/* macros for expanding the LDF_ALIAS macro */
#define LDF_STRING(field)     READ_STRING_BUF(fp,field)
#define LDF_STRINGLIST(field) READ_STRINGLIST_NUM(fp,field,result->alias_members_len)
#define ALIAS_NAME            result->alias_name
#define ALIAS_RCPTS           result->alias_members

static enum nss_status read_aliasent(
        FILE *fp,struct aliasent *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32,tmp2int32;
  size_t bufptr=0;
  /* auto-genereted read code */
  LDF_ALIAS;
  /* fill in remaining gaps in struct */
  result->alias_local=0;
  /* we're done */
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_getaliasbyname_r(
        const char *name,struct aliasent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_ALIAS_BYNAME,name,read_aliasent);
}

/* thread-local file pointer to an ongoing request */
static __thread FILE *aliasentfp;

enum nss_status _nss_ldap_setaliasent(void)
{
  NSS_SETENT(aliasentfp,NSLCD_ACTION_ALIAS_ALL);
}

enum nss_status _nss_ldap_getaliasent_r(struct aliasent *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(aliasentfp,read_aliasent);
}

enum nss_status _nss_ldap_endaliasent(void)
{
  NSS_ENDENT(aliasentfp);
}
