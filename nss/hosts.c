/*
   hosts.c - NSS lookup functions for hosts database

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

/* read a single host entry from the stream, filtering on the
   specified address family, result is stored in result
   it will an empty entry if no addresses in the address family
   were available */
static nss_status_t read_one_hostent(TFILE *fp, struct hostent *result,
                                     char *buffer, size_t buflen, int *errnop,
                                     int *h_errnop, int af)
{
  int32_t tmpint32, tmp2int32, tmp3int32;
  int32_t numaddr;
  int i;
  int readaf;
  size_t bufptr = 0;
  memset(result, 0, sizeof(struct hostent));
  /* read the host entry */
  READ_BUF_STRING(fp, result->h_name);
  READ_BUF_STRINGLIST(fp, result->h_aliases);
  result->h_addrtype = af;
  result->h_length = 0;
  /* read number of addresses to follow */
  READ_INT32(fp, numaddr);
  /* allocate memory for array */
  /* Note: this may allocate too much memory (e.g. also for address records
           of other address families) but this is a simple way to do it */
  BUF_ALLOC(fp, result->h_addr_list, char *, numaddr + 1);
  /* go through the address list and filter on af */
  i = 0;
  while (--numaddr >= 0)
  {
    /* read address family and size */
    READ_INT32(fp, readaf);
    READ_INT32(fp, tmp2int32);
    if (readaf == af)
    {
      /* read the address */
      result->h_length = tmp2int32;
      READ_BUF(fp, result->h_addr_list[i++], tmp2int32);
    }
    else
    {
      SKIP(fp, tmp2int32);
    }
  }
  /* null-terminate address list */
  result->h_addr_list[i] = NULL;
  return NSS_STATUS_SUCCESS;
}

/* this is a wrapper around read_one_hostent() that checks whether the read
   address list is empty and tries the next result if available if
   retry is set */
static nss_status_t read_hostent(TFILE *fp, struct hostent *result,
                                 char *buffer, size_t buflen, int *errnop,
                                 int *h_errnop, int af, int retry)
{
  int32_t tmpint32;
  nss_status_t retv;
  /* check until we read an non-empty entry, error or */
  while (1)
  {
    retv = read_one_hostent(fp, result, buffer, buflen, errnop, h_errnop, af);
    /* check result */
    if ((retv != NSS_STATUS_SUCCESS) || (result->h_addr_list[0] != NULL))
      return retv;
    /* error of if we are not retrying */
    if (!retry)
    {
      *errnop = ENOENT;
      *h_errnop = NO_ADDRESS;
      (void)tio_close(fp);
      return NSS_STATUS_NOTFOUND;
    }
    /* skip to the next entry */
    READ_RESPONSE_CODE(fp);
  }
}

/* write an address value */
#define WRITE_ADDRESS(fp, af, len, addr)                                    \
  WRITE_INT32(fp, af);                                                      \
  WRITE_INT32(fp, len);                                                     \
  WRITE(fp, addr, len);

#ifdef NSS_FLAVOUR_GLIBC

/* this function looks up a single host entry and returns all the addresses
   associated with the host in a single address familiy
   name            - IN  - hostname to lookup
   af              - IN  - address familty to present results for
   result          - OUT - entry found
   buffer,buflen   - OUT - buffer to store allocated stuff on
   errnop,h_errnop - OUT - for reporting errors */
nss_status_t NSS_NAME(gethostbyname2_r)(const char *name, int af,
                                        struct hostent *result, char *buffer,
                                        size_t buflen, int *errnop,
                                        int *h_errnop)
{
  NSS_GETONE(NSLCD_ACTION_HOST_BYNAME,
             WRITE_STRING(fp, name),
             read_hostent(fp, result, buffer, buflen, errnop, h_errnop, af, 0));
}

/* this function just calls the gethostbyname2() variant with the address
   family set */
nss_status_t NSS_NAME(gethostbyname_r)(const char *name,
                                       struct hostent *result, char *buffer,
                                       size_t buflen, int *errnop,
                                       int *h_errnop)
{
  return NSS_NAME(gethostbyname2_r)(name, AF_INET, result, buffer, buflen,
                                    errnop, h_errnop);
}

/* this function looks up a single host entry and returns all the addresses
   associated with the host in a single address family
   addr            - IN  - the address to look up
   len             - IN  - the size of the addr struct
   af              - IN  - address family the address is specified as
   result          - OUT - entry found
   buffer,buflen   - OUT - buffer to store allocated stuff on
   errnop,h_errnop - OUT - for reporting errors */
nss_status_t NSS_NAME(gethostbyaddr_r)(const void *addr, socklen_t len,
                                       int af, struct hostent *result,
                                       char *buffer, size_t buflen,
                                       int *errnop, int *h_errnop)
{
  NSS_GETONE(NSLCD_ACTION_HOST_BYADDR,
             WRITE_ADDRESS(fp, af, len, addr),
             read_hostent(fp, result, buffer, buflen, errnop, h_errnop, af, 0));
}

/* thread-local file pointer to an ongoing request */
static TLS TFILE *hostentfp;

nss_status_t NSS_NAME(sethostent)(int UNUSED(stayopen))
{
  NSS_SETENT(hostentfp);
}

/* this function only returns addresses of the AF_INET address family */
nss_status_t NSS_NAME(gethostent_r)(struct hostent *result,
                                    char *buffer, size_t buflen, int *errnop,
                                    int *h_errnop)
{
  NSS_GETENT(hostentfp, NSLCD_ACTION_HOST_ALL,
             read_hostent(hostentfp, result, buffer, buflen, errnop, h_errnop,
                          AF_INET, 1));
}

/* close the stream opened with sethostent() above */
nss_status_t NSS_NAME(endhostent)(void)
{
  NSS_ENDENT(hostentfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN
static char *hostent2str(struct hostent *result, char *buffer, size_t buflen)
{
  int i, j;
  /* build the formatted string, one line per address */
  buffer[0] = '\0';
  if (result->h_addr_list != NULL)
  {
    for (i = 0; result->h_addr_list[i]; i++)
    {
      if (i > 0)
        strlcat(buffer, "\n", buflen);
      /* snprintf writes a terminating \0 on Solaris */
      snprintf(buffer, buflen - strlen(buffer) - 1,
               "%s %s",
               inet_ntoa(*((struct in_addr *)result->h_addr_list[i])),
               result->h_name);
      /* add aliases for first line only */
      if ((i == 0) && (result->h_aliases))
      {
        for (j = 0; result->h_aliases[j]; j++)
        {
          strlcat(buffer, " ", buflen);
          strlcat(buffer, result->h_aliases[j], buflen);
        }
      }
    }
  }
  if (strlen(buffer) >= buflen - 1)
    return NULL;
  return buffer;
}
#endif /* HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

static nss_status_t read_result(TFILE *fp, int af, int retry,
                                nss_XbyY_args_t *args)
{
  READ_RESULT(hostent, &args->erange, &args->h_errno, af, retry);
}

/* hack to set the correct h_errno */
#define h_errnop &(NSS_ARGS(args)->h_errno)

static nss_status_t hosts_gethostbyname(nss_backend_t UNUSED(*be), void *args)
{
  NSS_GETONE(NSLCD_ACTION_HOST_BYNAME,
             WRITE_STRING(fp, NSS_ARGS(args)->key.name),
             read_result(fp, AF_INET, 0, args));
}

static nss_status_t hosts_gethostbyaddr(nss_backend_t UNUSED(*be), void *args)
{
  NSS_GETONE(NSLCD_ACTION_HOST_BYADDR,
             WRITE_ADDRESS(fp, NSS_ARGS(args)->key.hostaddr.type,
                           NSS_ARGS(args)->key.hostaddr.len,
                           NSS_ARGS(args)->key.hostaddr.addr),
             read_result(fp, NSS_ARGS(args)->key.hostaddr.type, 0, args));
}

static nss_status_t hosts_sethostent(nss_backend_t *be, void UNUSED(*args))
{
  NSS_SETENT(LDAP_BE(be)->fp);
}

static nss_status_t hosts_gethostent(nss_backend_t *be, void *args)
{
  NSS_GETENT(LDAP_BE(be)->fp, NSLCD_ACTION_HOST_ALL,
             read_result(LDAP_BE(be)->fp, AF_INET, 1, args));
}

static nss_status_t hosts_endhostent(nss_backend_t *be, void UNUSED(*args))
{
  NSS_ENDENT(LDAP_BE(be)->fp);
}

static nss_backend_op_t hosts_ops[] = {
  nss_ldap_destructor,
  hosts_endhostent,
  hosts_sethostent,
  hosts_gethostent,
  hosts_gethostbyname,
  hosts_gethostbyaddr
};

nss_backend_t *NSS_NAME(hosts_constr)(const char UNUSED(*db_name),
                                      const char UNUSED(*src_name),
                                      const char UNUSED(*cfg_args))
{
  return nss_ldap_constructor(hosts_ops, sizeof(hosts_ops));
}

#endif /* NSS_FLAVOUR_SOLARIS */
