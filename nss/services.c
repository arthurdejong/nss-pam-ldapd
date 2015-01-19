/*
   service.c - NSS lookup functions for services database

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

/* read a single services result entry from the stream */
static nss_status_t read_servent(TFILE *fp, struct servent *result,
                                 char *buffer, size_t buflen, int *errnop)
{
  int32_t tmpint32, tmp2int32, tmp3int32;
  size_t bufptr = 0;
  memset(result, 0, sizeof(struct servent));
  READ_BUF_STRING(fp, result->s_name);
  READ_BUF_STRINGLIST(fp, result->s_aliases);
  /* store port number in network byte order */
  READ_INT32(fp, tmp2int32);
  result->s_port = htons((uint16_t)tmp2int32);
  READ_BUF_STRING(fp, result->s_proto);
  /* we're done */
  return NSS_STATUS_SUCCESS;
}

#ifdef NSS_FLAVOUR_GLIBC

/* get a service entry by name and protocol */
nss_status_t NSS_NAME(getservbyname_r)(const char *name, const char *protocol,
                                       struct servent *result, char *buffer,
                                       size_t buflen, int *errnop)
{
  NSS_GETONE(NSLCD_ACTION_SERVICE_BYNAME,
             WRITE_STRING(fp, name);
             WRITE_STRING(fp, protocol),
             read_servent(fp, result, buffer, buflen, errnop));
}

/* get a service entry by port and protocol */
nss_status_t NSS_NAME(getservbyport_r)(int port, const char *protocol,
                                       struct servent *result, char *buffer,
                                       size_t buflen, int *errnop)
{
  /* port is already in network byte order */
  NSS_GETONE(NSLCD_ACTION_SERVICE_BYNUMBER,
             tmpint32 = ntohs(port);
             WRITE_INT32(fp, tmpint32);
             WRITE_STRING(fp, protocol),
             read_servent(fp, result, buffer, buflen, errnop));
}

/* thread-local file pointer to an ongoing request */
static TLS TFILE *serventfp;

/* open request to get all services */
nss_status_t NSS_NAME(setservent)(int UNUSED(stayopen))
{
  NSS_SETENT(serventfp);
}

/* read a single returned service definition */
nss_status_t NSS_NAME(getservent_r)(struct servent *result,
                                    char *buffer, size_t buflen, int *errnop)
{
  NSS_GETENT(serventfp, NSLCD_ACTION_SERVICE_ALL,
             read_servent(serventfp, result, buffer, buflen, errnop));
}

/* close the stream opened by setservent() above */
nss_status_t NSS_NAME(endservent)(void)
{
  NSS_ENDENT(serventfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN
static char *servent2str(struct servent *result, char *buffer, size_t buflen)
{
  int res, i;
  res = snprintf(buffer, buflen, "%s %d/%s", result->s_name, ntohs(result->s_port),
                 result->s_proto);
  if ((res < 0) || (res >= (int)buflen))
    return NULL;
  if (result->s_aliases)
    for (i = 0; result->s_aliases[i]; i++)
    {
      strlcat(buffer, " ", buflen);
      strlcat(buffer, result->s_aliases[i], buflen);
    }
  if (strlen(buffer) >= buflen - 1)
    return NULL;
  return buffer;
}
#endif /* HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

static nss_status_t read_result(TFILE *fp, nss_XbyY_args_t *args)
{
  READ_RESULT(servent, &args->erange);
}

static nss_status_t services_getservbyname(nss_backend_t UNUSED(*be), void *args)
{
  NSS_GETONE(NSLCD_ACTION_SERVICE_BYNAME,
             WRITE_STRING(fp, NSS_ARGS(args)->key.serv.serv.name);
             WRITE_STRING(fp, NSS_ARGS(args)->key.serv.proto),
             read_result(fp, args));
}

static nss_status_t services_getservbyport(nss_backend_t UNUSED(*be), void *args)
{
  NSS_GETONE(NSLCD_ACTION_SERVICE_BYNUMBER,
             WRITE_INT32(fp, ntohs(NSS_ARGS(args)->key.serv.serv.port));
             WRITE_STRING(fp, NSS_ARGS(args)->key.serv.proto),
             read_result(fp, args));
}

static nss_status_t services_setservent(nss_backend_t *be, void UNUSED(*args))
{
  NSS_SETENT(LDAP_BE(be)->fp);
}

static nss_status_t services_getservent(nss_backend_t *be, void *args)
{
  NSS_GETENT(LDAP_BE(be)->fp, NSLCD_ACTION_SERVICE_ALL,
             read_result(LDAP_BE(be)->fp, args));
}

static nss_status_t services_endservent(nss_backend_t *be, void UNUSED(*args))
{
  NSS_ENDENT(LDAP_BE(be)->fp);
}

static nss_backend_op_t services_ops[] = {
  nss_ldap_destructor,
  services_endservent,
  services_setservent,
  services_getservent,
  services_getservbyname,
  services_getservbyport
};

nss_backend_t *NSS_NAME(services_constr)(const char UNUSED(*db_name),
                                         const char UNUSED(*src_name),
                                         const char UNUSED(*cfg_args))
{
  return nss_ldap_constructor(services_ops, sizeof(services_ops));
}

#endif /* NSS_FLAVOUR_SOLARIS */
