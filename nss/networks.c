/*
   networks.c - NSS lookup functions for networks database

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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "prototypes.h"
#include "common.h"
#include "compat/attrs.h"

/* Redefine some ERROR_OUT macros as we also want to set h_errnop. */

#undef ERROR_OUT_OPENERROR
#define ERROR_OUT_OPENERROR                                                 \
  *errnop = ENOENT;                                                         \
  *h_errnop = HOST_NOT_FOUND;                                               \
  return (errno == EAGAIN) ? NSS_STATUS_TRYAGAIN : NSS_STATUS_UNAVAIL;

#undef ERROR_OUT_READERROR
#define ERROR_OUT_READERROR(fp)                                             \
  (void)tio_close(fp);                                                      \
  fp = NULL;                                                                \
  *errnop = ENOENT;                                                         \
  *h_errnop = NO_RECOVERY;                                                  \
  return NSS_STATUS_UNAVAIL;

#undef ERROR_OUT_BUFERROR
#define ERROR_OUT_BUFERROR(fp)                                              \
  *errnop = ERANGE;                                                         \
  *h_errnop = NETDB_INTERNAL;                                               \
  return NSS_STATUS_TRYAGAIN;

#undef ERROR_OUT_WRITEERROR
#define ERROR_OUT_WRITEERROR(fp)                                            \
  ERROR_OUT_READERROR(fp)

/* read a single network entry from the stream, ignoring entries
   that are not AF_INET (IPv4), result is stored in result */
static nss_status_t read_netent(TFILE *fp, struct netent *result,
                                char *buffer, size_t buflen, int *errnop,
                                int *h_errnop)
{
  int32_t tmpint32, tmp2int32, tmp3int32;
  int32_t numaddr;
  int readaf;
  size_t bufptr = 0;
  nss_status_t retv = NSS_STATUS_NOTFOUND;
  memset(result, 0, sizeof(struct netent));
  /* read the network entry */
  READ_BUF_STRING(fp, result->n_name);
  READ_BUF_STRINGLIST(fp, result->n_aliases);
  result->n_addrtype = AF_INET;
  /* read number of addresses to follow */
  READ_INT32(fp, numaddr);
  /* go through the address list and filter on af */
  while (--numaddr >= 0)
  {
    /* read address family and size */
    READ_INT32(fp, readaf);
    READ_INT32(fp, tmp2int32); /* address length */
    if ((readaf == AF_INET) && (tmp2int32 == 4))
    {
      /* read address and translate to host byte order */
      READ_INT32(fp, result->n_net);
      /* signal that we've read a proper entry */
      retv = NSS_STATUS_SUCCESS;
      /* don't return here to not upset the stream */
    }
    else
    {
      /* skip unsupported address families */
      SKIP(fp, tmpint32);
    }
  }
  return retv;
}

/* write an address value */
/* version 2.10 of glibc changed the address from network to host order
   (changelog entry 2009-07-01) */
#define WRITE_ADDRESS(fp, addr)                                             \
  WRITE_INT32(fp, AF_INET);                                                 \
  WRITE_INT32(fp, 4);                                                       \
  WRITE_INT32(fp, addr);

#ifdef NSS_FLAVOUR_GLIBC

/* get a network entry by name */
nss_status_t NSS_NAME(getnetbyname_r)(const char *name,
                                      struct netent *result, char *buffer,
                                      size_t buflen, int *errnop,
                                      int *h_errnop)
{
  NSS_GETONE(NSLCD_ACTION_NETWORK_BYNAME,
             WRITE_STRING(fp, name),
             read_netent(fp, result, buffer, buflen, errnop, h_errnop));
}

/* Note: the af parameter is ignored and is assumed to be AF_INET */
/* TODO: implement handling of af parameter */
nss_status_t NSS_NAME(getnetbyaddr_r)(uint32_t addr, int UNUSED(af),
                                      struct netent *result, char *buffer,
                                      size_t buflen, int *errnop,
                                      int *h_errnop)
{
  NSS_GETONE(NSLCD_ACTION_NETWORK_BYADDR,
             WRITE_ADDRESS(fp, addr),
             read_netent(fp, result, buffer, buflen, errnop, h_errnop));
}

/* thread-local file pointer to an ongoing request */
static TLS TFILE *netentfp;

/* start a request to read all networks */
nss_status_t NSS_NAME(setnetent)(int UNUSED(stayopen))
{
  NSS_SETENT(netentfp);
}

/* get a single network entry from the stream */
nss_status_t NSS_NAME(getnetent_r)(struct netent *result,
                                   char *buffer, size_t buflen, int *errnop,
                                   int *h_errnop)
{
  NSS_GETENT(netentfp, NSLCD_ACTION_NETWORK_ALL,
             read_netent(netentfp, result, buffer, buflen, errnop, h_errnop));
}

/* close the stream opened by setnetent() above */
nss_status_t NSS_NAME(endnetent)(void)
{
  NSS_ENDENT(netentfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN
static char *netent2str(struct netent *result, char *buffer, size_t buflen)
{
  int i, res;
  struct in_addr priv_in_addr;
  priv_in_addr.s_addr = htonl(result->n_net);
  res = snprintf(buffer, buflen, "%s %s", result->n_name, inet_ntoa(priv_in_addr));
  if ((res < 0) || (res >= (int)buflen))
    return NULL;
  if (result->n_aliases)
    for (i = 0; result->n_aliases[i]; i++)
    {
      strlcat(buffer, " ", buflen);
      strlcat(buffer, result->n_aliases[i], buflen);
    }
  if (strlen(buffer) >= buflen - 1)
    return NULL;
  return buffer;
}
#endif /* HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

static nss_status_t read_result(TFILE *fp, nss_XbyY_args_t *args)
{
  READ_RESULT(netent, &args->erange, &args->h_errno);
}

/* more of a dirty hack */
#define h_errnop (&(NSS_ARGS(args)->h_errno))

static nss_status_t networks_getnetbyname(nss_backend_t UNUSED(*be), void *args)
{
  NSS_GETONE(NSLCD_ACTION_NETWORK_BYNAME,
             WRITE_STRING(fp, NSS_ARGS(args)->key.name),
             read_result(fp, args));
}

static nss_status_t networks_getnetbyaddr(nss_backend_t UNUSED(*be), void *args)
{
  NSS_GETONE(NSLCD_ACTION_NETWORK_BYADDR,
             WRITE_ADDRESS(fp, NSS_ARGS(args)->key.netaddr.net),
             read_result(fp, args));
}

static nss_status_t networks_setnetent(nss_backend_t *be, void UNUSED(*args))
{
  NSS_SETENT(LDAP_BE(be)->fp);
}

static nss_status_t networks_getnetent(nss_backend_t *be, void *args)
{
  NSS_GETENT(LDAP_BE(be)->fp, NSLCD_ACTION_NETWORK_ALL,
             read_result(LDAP_BE(be)->fp, args));
}

static nss_status_t networks_endnetent(nss_backend_t *be, void UNUSED(*args))
{
  NSS_ENDENT(LDAP_BE(be)->fp);
}

static nss_backend_op_t networks_ops[] = {
  nss_ldap_destructor,
  networks_endnetent,
  networks_setnetent,
  networks_getnetent,
  networks_getnetbyname,
  networks_getnetbyaddr
};

nss_backend_t *NSS_NAME(networks_constr)(const char UNUSED(*db_name),
                                         const char UNUSED(*src_name),
                                         const char UNUSED(*cfg_args))
{
  return nss_ldap_constructor(networks_ops, sizeof(networks_ops));
}

#endif /* NSS_FLAVOUR_SOLARIS */
