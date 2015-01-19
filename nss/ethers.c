/*
   ethers.c - NSS lookup functions for ethers database

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

/* read an ethernet entry from the stream */
static nss_status_t read_etherent(TFILE *fp, struct etherent *result,
                                  char *buffer, size_t buflen, int *errnop)
{
  int32_t tmpint32;
  size_t bufptr = 0;
  memset(result, 0, sizeof(struct etherent));
  READ_BUF_STRING(fp, result->e_name);
  READ(fp, &(result->e_addr), sizeof(uint8_t[6]));
  return NSS_STATUS_SUCCESS;
}

#ifdef NSS_FLAVOUR_GLIBC

/* map a hostname to the corresponding ethernet address */
nss_status_t NSS_NAME(gethostton_r)(const char *name,
                                    struct etherent *result, char *buffer,
                                    size_t buflen, int *errnop)
{
  NSS_GETONE(NSLCD_ACTION_ETHER_BYNAME,
             WRITE_STRING(fp, name),
             read_etherent(fp, result, buffer, buflen, errnop));
}

/* map an ethernet address to the corresponding hostname */
nss_status_t NSS_NAME(getntohost_r)(const struct ether_addr *addr,
                                    struct etherent *result, char *buffer,
                                    size_t buflen, int *errnop)
{
  NSS_GETONE(NSLCD_ACTION_ETHER_BYETHER,
             WRITE(fp, addr, sizeof(uint8_t[6])),
             read_etherent(fp, result, buffer, buflen, errnop));
}

/* thread-local file pointer to an ongoing request */
static TLS TFILE *etherentfp;

/* open a connection to read all ether entries */
nss_status_t NSS_NAME(setetherent)(int UNUSED(stayopen))
{
  NSS_SETENT(etherentfp);
}

/* read a single ethernet entry from the stream */
nss_status_t NSS_NAME(getetherent_r)(struct etherent *result,
                                     char *buffer, size_t buflen, int *errnop)
{
  NSS_GETENT(etherentfp, NSLCD_ACTION_ETHER_ALL,
             read_etherent(etherentfp, result, buffer, buflen, errnop));
}

/* close the stream opened with setetherent() above */
nss_status_t NSS_NAME(endetherent)(void)
{
  NSS_ENDENT(etherentfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

/* we disable NSS_BUFCHECK because these functions do not use the buffer */
#undef NSS_BUFCHECK
#define NSS_BUFCHECK ;

/* provide a fallback definition */
#ifndef NSS_BUFLEN_ETHERS
#define NSS_BUFLEN_ETHERS HOST_NAME_MAX
#endif /* NSS_BUFLEN_ETHERS */

#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN
static char *etherent2str(struct etherent *result, char *buffer,
                          size_t buflen)
{
  int res;
  res = snprintf(buffer, buflen, "%s %s", ether_ntoa(&result->e_addr),
                 result->e_name);
  if ((res < 0) || (res >= (int)buflen))
    return NULL;
  return buffer;
}
#endif /* HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

static nss_status_t read_result(TFILE *fp, nss_XbyY_args_t *args, int wantname)
{
  struct etherent result;
  char buffer[NSS_BUFLEN_ETHERS];
  nss_status_t retv;
  /* read the result entry from the stream */
  retv = read_etherent(fp, &result, buffer, sizeof(buffer), &args->erange);
  if (retv != NSS_STATUS_SUCCESS)
    return retv;
#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN
  /* try to return in string format if requested */
  if ((args->buf.buffer != NULL) && (args->buf.buflen > 0))
  {
    if (etherent2str(&result, args->buf.buffer, args->buf.buflen) == NULL)
    {
      args->erange = 1;
      return NSS_NOTFOUND;
    }
    args->returnval = args->buf.buffer;
    args->returnlen = strlen(args->returnval);
    return NSS_SUCCESS;
  }
#endif /* HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */
  /* return the result entry */
  if (wantname)
  {
    /* we expect the buffer to have enough room for the name (buflen == 0) */
    strcpy(args->buf.buffer, result.e_name);
    args->returnval = args->buf.buffer;
  }
  else /* address */
  {
    memcpy(args->buf.result, &result.e_addr, sizeof(result.e_addr));
    args->returnval = args->buf.result;
  }
  return NSS_SUCCESS;
}

/* map a hostname to the corresponding ethernet address */
static nss_status_t ethers_gethostton(nss_backend_t UNUSED(*be), void *args)
{
  NSS_GETONE(NSLCD_ACTION_ETHER_BYNAME,
             WRITE_STRING(fp, NSS_ARGS(args)->key.name),
             read_result(fp, args, 0));
}

/* map an ethernet address to the corresponding hostname */
static nss_status_t ethers_getntohost(nss_backend_t UNUSED(*be), void *args)
{
  struct ether_addr *addr = (struct ether_addr *)(NSS_ARGS(args)->key.ether);
  NSS_GETONE(NSLCD_ACTION_ETHER_BYETHER,
             WRITE(fp, addr, sizeof(uint8_t[6])),
             read_result(fp, args, 1));
}

static nss_backend_op_t ethers_ops[] = {
  nss_ldap_destructor,
  ethers_gethostton,
  ethers_getntohost
};

nss_backend_t *NSS_NAME(ethers_constr)(const char UNUSED(*db_name),
                                       const char UNUSED(*src_name),
                                       const char UNUSED(*cfg_args))
{
  return nss_ldap_constructor(ethers_ops, sizeof(ethers_ops));
}

#endif /* NSS_FLAVOUR_SOLARIS */
