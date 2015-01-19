/*
   rpc.c - NSS lookup functions for rpc database

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

/* read a sinlge rpc entry from the stream */
static nss_status_t read_rpcent(TFILE *fp, struct rpcent *result,
                                char *buffer, size_t buflen, int *errnop)
{
  int32_t tmpint32, tmp2int32, tmp3int32;
  size_t bufptr = 0;
  memset(result, 0, sizeof(struct rpcent));
  READ_BUF_STRING(fp, result->r_name);
  READ_BUF_STRINGLIST(fp, result->r_aliases);
  READ_INT32(fp, result->r_number);
  return NSS_STATUS_SUCCESS;
}

#ifdef NSS_FLAVOUR_GLIBC

/* get a rpc entry by name */
nss_status_t NSS_NAME(getrpcbyname_r)(const char *name,
                                      struct rpcent *result, char *buffer,
                                      size_t buflen, int *errnop)
{
  NSS_GETONE(NSLCD_ACTION_RPC_BYNAME,
             WRITE_STRING(fp, name),
             read_rpcent(fp, result, buffer, buflen, errnop));
}

/* get a rpc entry by number */
nss_status_t NSS_NAME(getrpcbynumber_r)(int number, struct rpcent *result,
                                        char *buffer, size_t buflen,
                                        int *errnop)
{
  NSS_GETONE(NSLCD_ACTION_RPC_BYNUMBER,
             WRITE_INT32(fp, number),
             read_rpcent(fp, result, buffer, buflen, errnop));
}

/* thread-local file pointer to an ongoing request */
static TLS TFILE *rpcentfp;

/* request a stream to list all rpc entries */
nss_status_t NSS_NAME(setrpcent)(int UNUSED(stayopen))
{
  NSS_SETENT(rpcentfp);
}

/* get an rpc entry from the list */
nss_status_t NSS_NAME(getrpcent_r)(struct rpcent *result,
                                   char *buffer, size_t buflen, int *errnop)
{
  NSS_GETENT(rpcentfp, NSLCD_ACTION_RPC_ALL,
             read_rpcent(rpcentfp, result, buffer, buflen, errnop));
}

/* close the stream opened by setrpcent() above */
nss_status_t NSS_NAME(endrpcent)(void)
{
  NSS_ENDENT(rpcentfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN
static char *rpcent2str(struct rpcent *result, char *buffer, size_t buflen)
{
  int res, i;
  res = snprintf(buffer, buflen, "%s %d", result->r_name, result->r_number);
  if ((res < 0) || (res >= (int)buflen))
    return NULL;
  if (result->r_aliases)
    for (i = 0; result->r_aliases[i]; i++)
    {
      strlcat(buffer, " ", buflen);
      strlcat(buffer, result->r_aliases[i], buflen);
    }
  if (strlen(buffer) >= buflen - 1)
    return NULL;
  return buffer;
}
#endif /* HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

static nss_status_t read_result(TFILE *fp, nss_XbyY_args_t *args)
{
  READ_RESULT(rpcent, &args->erange);
}

static nss_status_t rpc_getrpcbyname(nss_backend_t UNUSED(*be), void *args)
{
  NSS_GETONE(NSLCD_ACTION_RPC_BYNAME,
             WRITE_STRING(fp, NSS_ARGS(args)->key.name),
             read_result(fp, args));
}

static nss_status_t rpc_getrpcbynumber(nss_backend_t UNUSED(*be), void *args)
{
  NSS_GETONE(NSLCD_ACTION_RPC_BYNUMBER,
             WRITE_INT32(fp, NSS_ARGS(args)->key.number),
             read_result(fp, args));
}

static nss_status_t rpc_setrpcent(nss_backend_t *be, void UNUSED(*args))
{
  NSS_SETENT(LDAP_BE(be)->fp);
}

static nss_status_t rpc_getrpcent(nss_backend_t *be, void *args)
{
  NSS_GETENT(LDAP_BE(be)->fp, NSLCD_ACTION_RPC_ALL,
             read_result(LDAP_BE(be)->fp, args));
}

static nss_status_t rpc_endrpcent(nss_backend_t *be, void UNUSED(*args))
{
  NSS_ENDENT(LDAP_BE(be)->fp);
}

static nss_backend_op_t rpc_ops[] = {
  nss_ldap_destructor,
  rpc_endrpcent,
  rpc_setrpcent,
  rpc_getrpcent,
  rpc_getrpcbyname,
  rpc_getrpcbynumber
};

nss_backend_t *NSS_NAME(rpc_constr)(const char UNUSED(*db_name),
                                    const char UNUSED(*src_name),
                                    const char UNUSED(*cfg_args))
{
  return nss_ldap_constructor(rpc_ops, sizeof(rpc_ops));
}

#endif /* NSS_FLAVOUR_SOLARIS */
