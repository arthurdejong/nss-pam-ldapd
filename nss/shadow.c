/*
   shadow.c - NSS lookup functions for shadow database

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007, 2008, 2010 Arthur de Jong

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301 USA
*/

#include "config.h"

#include <string.h>
#include <errno.h>

#include "prototypes.h"
#include "common.h"
#include "compat/attrs.h"

/* read a single shadow entry from the stream */
static nss_status_t read_spwd(
        TFILE *fp,struct spwd *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32;
  size_t bufptr=0;
  READ_BUF_STRING(fp,result->sp_namp);
  READ_BUF_STRING(fp,result->sp_pwdp);
  READ_INT32(fp,result->sp_lstchg);
  READ_INT32(fp,result->sp_min);
  READ_INT32(fp,result->sp_max);
  READ_INT32(fp,result->sp_warn);
  READ_INT32(fp,result->sp_inact);
  READ_INT32(fp,result->sp_expire);
  READ_INT32(fp,result->sp_flag);
  return NSS_STATUS_SUCCESS;
}

/* get a shadow entry by name */
nss_status_t _nss_ldap_getspnam_r(
        const char *name,struct spwd *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_SHADOW_BYNAME,
             name,
             read_spwd(fp,result,buffer,buflen,errnop));
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *spentfp;

/* start listing all shadow users */
nss_status_t _nss_ldap_setspent(int UNUSED(stayopen))
{
  NSS_SETENT(spentfp);
}

/* return a single shadow entry read from the stream */
nss_status_t _nss_ldap_getspent_r(
        struct spwd *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(spentfp,NSLCD_ACTION_SHADOW_ALL,
             read_spwd(spentfp,result,buffer,buflen,errnop));
}

/* close the stream opened by setspent() above */
nss_status_t _nss_ldap_endspent(void)
{
  NSS_ENDENT(spentfp);
}
