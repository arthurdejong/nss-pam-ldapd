/*
   protocols.c - NSS lookup functions for protocol database

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

/* read a single protocol entry from the stream */
static nss_status_t read_protoent(TFILE *fp, struct protoent *result,
                                  char *buffer, size_t buflen, int *errnop)
{
  int32_t tmpint32, tmp2int32, tmp3int32;
  size_t bufptr = 0;
  memset(result, 0, sizeof(struct protoent));
  READ_BUF_STRING(fp, result->p_name);
  READ_BUF_STRINGLIST(fp, result->p_aliases);
  READ_INT32(fp, result->p_proto);
  return NSS_STATUS_SUCCESS;
}

#ifdef NSS_FLAVOUR_GLIBC

/* get a protocol entry by name */
nss_status_t NSS_NAME(getprotobyname_r)(const char *name,
                                        struct protoent *result,
                                        char *buffer, size_t buflen,
                                        int *errnop)
{
  NSS_GETONE(NSLCD_ACTION_PROTOCOL_BYNAME,
             WRITE_STRING(fp, name),
             read_protoent(fp, result, buffer, buflen, errnop));
}

/* get a protocol entry by number */
nss_status_t NSS_NAME(getprotobynumber_r)(int number, struct protoent *result,
                                          char *buffer, size_t buflen,
                                          int *errnop)
{
  NSS_GETONE(NSLCD_ACTION_PROTOCOL_BYNUMBER,
             WRITE_INT32(fp, number),
             read_protoent(fp, result, buffer, buflen, errnop));
}

/* thread-local file pointer to an ongoing request */
static TLS TFILE *protoentfp;

/* start a request to read all protocol entries */
nss_status_t NSS_NAME(setprotoent)(int UNUSED(stayopen))
{
  NSS_SETENT(protoentfp);
}

/* get a single protocol entry */
nss_status_t NSS_NAME(getprotoent_r)(struct protoent *result,
                                     char *buffer, size_t buflen, int *errnop)
{
  NSS_GETENT(protoentfp, NSLCD_ACTION_PROTOCOL_ALL,
             read_protoent(protoentfp, result, buffer, buflen, errnop));
}

/* close the stream opened by setprotoent() above */
nss_status_t NSS_NAME(endprotoent)(void)
{
  NSS_ENDENT(protoentfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN
static char *protoent2str(struct protoent *result, char *buffer, size_t buflen)
{
  int res, i;
  res = snprintf(buffer, buflen, "%s\t\t%d", result->p_name, result->p_proto);
  if ((res < 0) || (res >= (int)buflen))
    return NULL;
  if (result->p_aliases)
    for (i = 0; result->p_aliases[i]; i++)
    {
      strlcat(buffer, " ", buflen);
      strlcat(buffer, result->p_aliases[i], buflen);
    }
  if (strlen(buffer) >= buflen - 1)
    return NULL;
  return buffer;
}
#endif /* HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

static nss_status_t read_result(TFILE *fp, nss_XbyY_args_t *args)
{
  READ_RESULT(protoent, &args->erange);
}

static nss_status_t protocols_getprotobyname(nss_backend_t UNUSED(*be), void *args)
{
  NSS_GETONE(NSLCD_ACTION_PROTOCOL_BYNAME,
             WRITE_STRING(fp, NSS_ARGS(args)->key.name),
             read_result(fp, args));
}

static nss_status_t protocols_getprotobynumber(nss_backend_t UNUSED(*be), void *args)
{
  NSS_GETONE(NSLCD_ACTION_PROTOCOL_BYNUMBER,
             WRITE_INT32(fp, NSS_ARGS(args)->key.number),
             read_result(fp, args));
}

static nss_status_t protocols_setprotoent(nss_backend_t *be, void UNUSED(*args))
{
  NSS_SETENT(LDAP_BE(be)->fp);
}

static nss_status_t protocols_getprotoent(nss_backend_t *be, void *args)
{
  NSS_GETENT(LDAP_BE(be)->fp, NSLCD_ACTION_PROTOCOL_ALL,
             read_result(LDAP_BE(be)->fp, args));
}

static nss_status_t protocols_endprotoent(nss_backend_t *be, void UNUSED(*args))
{
  NSS_ENDENT(LDAP_BE(be)->fp);
}

static nss_backend_op_t protocols_ops[] = {
  nss_ldap_destructor,
  protocols_endprotoent,
  protocols_setprotoent,
  protocols_getprotoent,
  protocols_getprotobyname,
  protocols_getprotobynumber
};

nss_backend_t *NSS_NAME(protocols_constr)(const char UNUSED(*db_name),
                                          const char UNUSED(*src_name),
                                          const char UNUSED(*cfg_args))
{
  return nss_ldap_constructor(protocols_ops, sizeof(protocols_ops));
}

#endif /* NSS_FLAVOUR_SOLARIS */
