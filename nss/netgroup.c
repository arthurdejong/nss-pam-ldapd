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

static enum nss_status read_netgrent(
        FILE *fp,struct __netgrent *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32;
  int type;
  size_t bufptr=0;
  /* read netgroup type */
  READ_INT32(fp,type);
  if (type==NETGROUP_TYPE_NETGROUP)
  {
    /* the response is a reference to another netgroup */
    result->type=group_val;
    READ_STRING_BUF(fp,result->val.group);

  }
  else if (type==NETGROUP_TYPE_TRIPLE)
  {
    /* the response is a host/user/domain triple */
    result->type=triple_val;
    /* read host and revert to NULL on empty string */
    READ_STRING_BUF(fp,result->val.triple.host);
    if (result->val.triple.host[0]=='\0')
    {
      result->val.triple.host=NULL;
      bufptr--; /* free unused space */
    }
    /* read user and revert to NULL on empty string */
    READ_STRING_BUF(fp,result->val.triple.user);
    if (result->val.triple.user[0]=='\0')
    {
      result->val.triple.user=NULL;
      bufptr--; /* free unused space */
    }
    /* read domain and revert to NULL on empty string */
    READ_STRING_BUF(fp,result->val.triple.domain);
    if (result->val.triple.domain[0]=='\0')
    {
      result->val.triple.domain=NULL;
      bufptr--; /* free unused space */
    }
  }
  else
    return NSS_STATUS_UNAVAIL;
  /* we're done */
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_setnetgrent(const char *group,struct __netgrent *result)
{
  int32_t tmpint32;
  int errnocp;
  int *errnop;
  errnop=&errnocp;
  /* check parameter */
  if ((group==NULL)||(group[0]=='\0'))
    return NSS_STATUS_UNAVAIL;
  /* open a new stream and write the request */
  OPEN_SOCK(result->data);
  WRITE_REQUEST(result->data,NSLCD_ACTION_NETGROUP_BYNAME);
  WRITE_STRING(result->data,group);
  WRITE_FLUSH(result->data);
  /* read response header */
  READ_RESPONSEHEADER(result->data,NSLCD_ACTION_NETGROUP_BYNAME);
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
