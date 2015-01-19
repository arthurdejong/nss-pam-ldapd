/*
   shadow.c - NSS lookup functions for shadow database

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006-2015 Arthur de Jong
   Copyright (C) 2010 Symas Corporation

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
static nss_status_t read_spwd(TFILE *fp, struct spwd *result,
                              char *buffer, size_t buflen, int *errnop)
{
  int32_t tmpint32;
  size_t bufptr = 0;
  memset(result, 0, sizeof(struct spwd));
  READ_BUF_STRING(fp, result->sp_namp);
  READ_BUF_STRING(fp, result->sp_pwdp);
  READ_INT32(fp, result->sp_lstchg);
  READ_INT32(fp, result->sp_min);
  READ_INT32(fp, result->sp_max);
  READ_INT32(fp, result->sp_warn);
  READ_INT32(fp, result->sp_inact);
  READ_INT32(fp, result->sp_expire);
  READ_INT32(fp, result->sp_flag);
  return NSS_STATUS_SUCCESS;
}

#ifdef NSS_FLAVOUR_GLIBC

/* get a shadow entry by name */
nss_status_t NSS_NAME(getspnam_r)(const char *name, struct spwd *result,
                                  char *buffer, size_t buflen, int *errnop)
{
  NSS_GETONE(NSLCD_ACTION_SHADOW_BYNAME,
             WRITE_STRING(fp, name),
             read_spwd(fp, result, buffer, buflen, errnop));
}

/* thread-local file pointer to an ongoing request */
static TLS TFILE *spentfp;

/* start listing all shadow users */
nss_status_t NSS_NAME(setspent)(int UNUSED(stayopen))
{
  NSS_SETENT(spentfp);
}

/* return a single shadow entry read from the stream */
nss_status_t NSS_NAME(getspent_r)(struct spwd *result,
                                  char *buffer, size_t buflen, int *errnop)
{
  NSS_GETENT(spentfp, NSLCD_ACTION_SHADOW_ALL,
             read_spwd(spentfp, result, buffer, buflen, errnop));
}

/* close the stream opened by setspent() above */
nss_status_t NSS_NAME(endspent)(void)
{
  NSS_ENDENT(spentfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN
static char *spwd2str(struct spwd *result, char *buffer, size_t buflen)
{
  /* snprintf writes a terminating \0 on Solaris */
  snprintf(buffer, buflen, "%s:%s:", result->sp_namp, result->sp_pwdp);
  if (result->sp_lstchg >= 0)
    snprintf(buffer, buflen - strlen(buffer) - 1, "%d", result->sp_lstchg);
  strlcat(buffer, ":", buflen);
  if (result->sp_min >= 0)
    snprintf(buffer, buflen - strlen(buffer) - 1, "%d", result->sp_min);
  strlcat(buffer, ":", buflen);
  if (result->sp_max >= 0)
    snprintf(buffer, buflen - strlen(buffer) - 1, "%d", result->sp_max);
  strlcat(buffer, ":", buflen);
  if (result->sp_warn >= 0)
    snprintf(buffer, buflen - strlen(buffer) - 1, "%d", result->sp_warn);
  strlcat(buffer, ":", buflen);
  if (result->sp_inact >= 0)
    snprintf(buffer, buflen - strlen(buffer) - 1, "%d", result->sp_inact);
  strlcat(buffer, ":", buflen);
  if (result->sp_expire >= 0)
    snprintf(buffer, buflen - strlen(buffer) - 1, "%d", result->sp_expire);
  strlcat(buffer, ":", buflen);
  if (result->sp_flag > 0)
    snprintf(buffer, buflen - strlen(buffer) - 1, "%x", result->sp_flag);
  if (strlen(buffer) >= buflen - 1)
    return NULL;
  return buffer;
}
#endif /* HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

static nss_status_t read_result(TFILE *fp, nss_XbyY_args_t *args)
{
  READ_RESULT(spwd, &args->erange);
}

static nss_status_t shadow_getspnam(nss_backend_t UNUSED(*be), void *args)
{
  NSS_GETONE(NSLCD_ACTION_SHADOW_BYNAME,
             WRITE_STRING(fp, NSS_ARGS(args)->key. name),
             read_result(fp, args));
}

static nss_status_t shadow_setspent(nss_backend_t *be, void UNUSED(*args))
{
  NSS_SETENT(LDAP_BE(be)->fp);
}

static nss_status_t shadow_getspent(nss_backend_t *be, void *args)
{
  NSS_GETENT(LDAP_BE(be)->fp, NSLCD_ACTION_SHADOW_ALL,
             read_result(LDAP_BE(be)->fp, args));
}

static nss_status_t shadow_endspent(nss_backend_t *be, void UNUSED(*args))
{
  NSS_ENDENT(LDAP_BE(be)->fp);
}

static nss_backend_op_t shadow_ops[] = {
  nss_ldap_destructor,
  shadow_endspent,
  shadow_setspent,
  shadow_getspent,
  shadow_getspnam
};

nss_backend_t *NSS_NAME(shadow_constr)(const char UNUSED(*db_name),
                                       const char UNUSED(*src_name),
                                       const char UNUSED(*cfg_args))
{
  return nss_ldap_constructor(shadow_ops, sizeof(shadow_ops));
}

#endif /* NSS_FLAVOUR_SOLARIS */
