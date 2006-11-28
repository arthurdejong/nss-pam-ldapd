/*
   protocols.c - NSS lookup functions for protocol database

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

/* macros for expanding the NSLCD_PROTOCOL macro */
#define NSLCD_STRING(field)     READ_STRING_BUF(fp,field)
#define NSLCD_STRINGLIST(field) READ_STRINGLIST_NULLTERM(fp,field)
#define NSLCD_INT32(field)      READ_INT32(fp,field)
#define PROTOCOL_NAME         result->p_name
#define PROTOCOL_ALIASES      result->p_aliases
#define PROTOCOL_NUMBER       result->p_proto

static enum nss_status read_protoent(
        FILE *fp,struct protoent *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  size_t bufptr=0;
  /* auto-genereted read code */
  NSLCD_PROTOCOL;
  /* we're done */
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_getprotobyname_r(const char *name,struct protoent *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_PROTOCOL_BYNAME,name,read_protoent);
}

enum nss_status _nss_ldap_getprotobynumber_r(int number,struct protoent *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_BYINT32(NSLCD_ACTION_PROTOCOL_BYNUMBER,number,read_protoent);
}

/* thread-local file pointer to an ongoing request */
static __thread FILE *protoentfp;

enum nss_status _nss_ldap_setprotoent(int stayopen)
{
  NSS_SETENT(protoentfp,NSLCD_ACTION_PROTOCOL_ALL);
}

enum nss_status _nss_ldap_getprotoent_r(struct protoent *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(protoentfp,read_protoent);
}

enum nss_status _nss_ldap_endprotoent(void)
{
  NSS_ENDENT(protoentfp);
}
