/*
   netgroup.c - NSS lookup functions for netgroup entries

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

#include <stdlib.h>
#include <string.h>
#include <nss.h>
#include <errno.h>

#include "prototypes.h"
#include "nslcd-client.h"
#include "common.h"

/* macros for expanding the LDF_AUTOMOUNT macro */
#define LDF_STRING(field)     READ_STRING_BUF(fp,field)
#define NETGROUP_HOST         result->val.triple.host
#define NETGROUP_USER         result->val.triple.user
#define NETGROUP_DOMAIN       result->val.triple.domain

static enum nss_status read_netgrent(
        FILE *fp,struct __netgrent *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32;
  size_t bufptr=0;
  /* auto-genereted read code */
  LDF_NETGROUP;
  /* fix other fields */
  result->type=triple_val;
  /* FIXME: detect NULL or match-any values */
  /* we're done */
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_setnetgrent(const char *group,struct __netgrent *result)
{
  int32_t tmpint32;
  int errnocp;
  int *errnop;
  errnop=&errnocp;
  /* close the existing stream if it is still open */
  if (result->data!=NULL)
    fclose(result->data);
  /* open a new stream and write the request */
  OPEN_SOCK(result->data);
  WRITE_REQUEST(result->data,NSLCD_NETGROUP_BYNAME);
  WRITE_STRING(result->data,group);
  WRITE_FLUSH(result->data);
  /* read response header */
  READ_RESPONSEHEADER(result->data,NSLCD_NETGROUP_BYNAME);
  return NSS_STATUS_SUCCESS;
/* fixme: this should probably also set result->known_groups */  
}

enum nss_status _nss_ldap_getnetgrent_r(struct __netgrent *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(result->data,read_netgrent);
}

enum nss_status _nss_ldap_endnetgrent(struct __netgrent *result)
{
  NSS_ENDENT(result->data);
}
