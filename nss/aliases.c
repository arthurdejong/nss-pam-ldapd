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

/* generic macros in development here */
#define READ_LOOP(fp,num,arr,opr) \
  READ_TYPE(fp,tmpint32,int32_t); \
  (num)=tmpint32; \
  /* allocate room for *char[num] */ \
  tmpint32*=sizeof(char *); \
  if ((bufptr+(size_t)tmpint32)>buflen) \
    { ERROR_OUT_BUFERROR(fp) } /* will not fit */ \
  (arr)=(char **)(buffer+bufptr); \
  bufptr+=(size_t)tmpint32; \
  for (tmp2int32=0;tmp2int32<(num);tmp2int32++) \
  { \
    opr \
  }

/* macros for expanding the LDF_ALIAS macro */
#define LDF_STRING(field)    READ_STRING_BUF(fp,field)
#define LDF_LOOP(field)      READ_LOOP(fp,result->alias_members_len,result->alias_members,field)
#define ALIAS_NAME    result->alias_name
#define ALIAS_RCPT    result->alias_members[tmp2int32]

enum nss_status _nss_ldap_getaliasbyname_r(
        const char *name,struct aliasent *result,
        char *buffer,size_t buflen,int *errnop)
{
  FILE *fp;
  size_t bufptr=0;
  int32_t tmpint32,tmp2int32;
  /* open socket and write request */
  OPEN_SOCK(fp);
  WRITE_REQUEST(fp,NSLCD_RT_ALIAS_BYNAME);
  WRITE_STRING(fp,name);
  WRITE_FLUSH(fp);
  /* read response header */
  READ_RESPONSEHEADER(fp,NSLCD_RT_ALIAS_BYNAME);
  /* read response */
  READ_RESPONSE(fp);
  LDF_ALIAS;
  /* fill in remaining gaps in struct */
  result->alias_local=0;
  /* close socket and we're done */
  fclose(fp);
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_setaliasent(void)
{
  return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_ldap_getaliasent_r(struct aliasent *result,char *buffer,size_t buflen,int *errnop)
{
  *errnop=ENOENT;
  return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_ldap_endaliasent(void)
{
  return NSS_STATUS_UNAVAIL;
}
