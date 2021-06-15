/*
   common.h - common functions for NSS lookups

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006-2015 Arthur de Jong

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

#ifndef NSS__COMMON_H
#define NSS__COMMON_H 1

#include <stdio.h>
#include <stdlib.h>

#include "nslcd.h"
#include "common/nslcd-prot.h"
#include "compat/attrs.h"
#include "compat/nss_compat.h"

/* Tolerate missing definitions for NETDB_INTERNAL and NETDB_SUCCESS */
#ifndef NETDB_INTERNAL
#define NETDB_INTERNAL -1
#endif

#ifndef NETDB_SUCCESS
#define NETDB_SUCCESS 0
#endif

#ifdef NSS_FLAVOUR_SOLARIS
#include "solnss.h"
#endif /* NSS_FLAVOUR_SOLARIS */

/* If not TLS (thread local storage) is available on the platform
   don't use it. This should not be a problem on most platforms because
   get*ent() is not expected to be thread-safe (at least not on Glibc). */
#ifndef TLS
#define TLS
#endif /* not TLS */

/* skip timeout determines the maximum time to wait when closing the
   connection and reading whatever data that is available */
#define SKIP_TIMEOUT 500

/* These are macros for handling read and write problems, they are
   NSS specific due to the return code so are defined here. They
   generally close the open file, set an error code and return with
   an error status. */

/* Macro is called to handle errors in opening a client connection. */
#define ERROR_OUT_OPENERROR                                                 \
  *errnop = ENOENT;                                                         \
  return (errno == EAGAIN) ? NSS_STATUS_TRYAGAIN : NSS_STATUS_UNAVAIL;

/* Macro is called to handle errors on read operations. */
#define ERROR_OUT_READERROR(fp)                                             \
  (void)tio_close(fp);                                                      \
  fp = NULL;                                                                \
  *errnop = ENOENT;                                                         \
  return NSS_STATUS_UNAVAIL;

/* Macro is called to handle problems with too small a buffer.
   This triggers the caller to call the function with a larger
   buffer (see NSS_GETENT below). */
#define ERROR_OUT_BUFERROR(fp)                                              \
  *errnop = ERANGE;                                                         \
  return NSS_STATUS_TRYAGAIN;

/* This macro is called if there was a problem with a write
   operation. */
#define ERROR_OUT_WRITEERROR(fp)                                            \
  ERROR_OUT_READERROR(fp)

/* This macro is called if the read status code is not
   NSLCD_RESULT_BEGIN. */
#define ERROR_OUT_NOSUCCESS(fp)                                             \
  (void)tio_close(fp);                                                      \
  fp = NULL;                                                                \
  return NSS_STATUS_NOTFOUND;

/* These are some general macros that are used to build parts of the
   general macros below. */

/* check to see if we should answer NSS requests */
#define NSS_AVAILCHECK                                                      \
  if (!NSS_NAME(enablelookups))                                             \
    return NSS_STATUS_UNAVAIL;

#ifdef NSS_FLAVOUR_GLIBC

/* extra definitions we need (nothing for Glibc) */
#define NSS_EXTRA_DEFS ;

/* check validity of passed buffer (Glibc flavour) */
#define NSS_BUFCHECK                                                        \
  if (buffer == NULL)                                                       \
  {                                                                         \
    *errnop = EINVAL;                                                       \
    return NSS_STATUS_UNAVAIL;                                              \
  }                                                                         \
  if (buflen == 0)                                                          \
  {                                                                         \
    *errnop = ERANGE;                                                       \
    return NSS_STATUS_TRYAGAIN;                                             \
  }

#endif /* NSS_FLAVOUR_GLIBC */

/* The following macros to automatically generate get..byname(),
   get..bynumber(), setent(), getent() and endent() function
   bodies. These functions have very common code so this can
   easily be reused. */

/* This is a generic get..by..() generation macro. The action
   parameter is the NSLCD_ACTION_.. action, the writefn is the
   operation for writing the parameters and readfn is the function
   name for reading a single result entry. The function is assumed
   to have result, buffer, buflen and errnop parameters that define
   the result structure, the user buffer with length and the
   errno to return. This macro should be called through some of
   the customized ones below. */
#define NSS_GETONE(action, writefn, readfn)                                 \
  TFILE *fp;                                                                \
  int32_t tmpint32;                                                         \
  nss_status_t retv;                                                        \
  NSS_EXTRA_DEFS;                                                           \
  NSS_AVAILCHECK;                                                           \
  NSS_BUFCHECK;                                                             \
  /* open socket and write request */                                       \
  NSLCD_REQUEST(fp, action, writefn);                                       \
  /* read response */                                                       \
  READ_RESPONSE_CODE(fp);                                                   \
  retv = readfn;                                                            \
  /* close socket and we're done */                                         \
  if ((retv == NSS_STATUS_SUCCESS) || (retv == NSS_STATUS_TRYAGAIN))        \
  {                                                                         \
    (void)tio_skipall(fp, SKIP_TIMEOUT);                                    \
    (void)tio_close(fp);                                                    \
  }                                                                         \
  return retv;

/* This macro generates a simple setent() function body. This closes any
   open streams so that NSS_GETENT() can open a new file. */
#define NSS_SETENT(fp)                                                      \
  NSS_AVAILCHECK;                                                           \
  if (fp != NULL)                                                           \
  {                                                                         \
    (void)tio_close(fp);                                                    \
    fp = NULL;                                                              \
  }                                                                         \
  return NSS_STATUS_SUCCESS;

/* This macro generates a getent() function body. If the stream is not yet
   open, a new one is opened, a request is written and a check is done for
   a response header. A single entry is read with the readfn() function. */
#define NSS_GETENT(fp, action, readfn)                                      \
  int32_t tmpint32;                                                         \
  nss_status_t retv;                                                        \
  NSS_EXTRA_DEFS;                                                           \
  NSS_AVAILCHECK;                                                           \
  NSS_BUFCHECK;                                                             \
  /* check that we have a valid file descriptor */                          \
  if (fp == NULL)                                                           \
  {                                                                         \
    /* open a new stream and write the request */                           \
    NSLCD_REQUEST(fp, action, /* no writefn */ ;);                          \
  }                                                                         \
  /* prepare for buffer errors */                                           \
  tio_mark(fp);                                                             \
  /* read a response */                                                     \
  READ_RESPONSE_CODE(fp);                                                   \
  retv = readfn;                                                            \
  /* check read result */                                                   \
  if (retv == NSS_STATUS_TRYAGAIN)                                          \
  {                                                                         \
    /* if we have a full buffer try to reset the stream */                  \
    if (tio_reset(fp))                                                      \
    {                                                                       \
      /* reset failed, we close and give up with a permanent error          \
         because we cannot retry just the getent() call because it          \
         may not be only the first entry that failed */                     \
      tio_close(fp);                                                        \
      fp = NULL;                                                            \
      *errnop = EINVAL;                                                     \
      return NSS_STATUS_UNAVAIL;                                            \
    }                                                                       \
  }                                                                         \
  else if (retv != NSS_STATUS_SUCCESS)                                      \
    fp = NULL; /* file should be closed by now */                           \
  return retv;

/* This macro generates an endent() function body. This just closes
   the stream. */
#define NSS_ENDENT(fp)                                                      \
  NSS_AVAILCHECK;                                                           \
  if (fp != NULL)                                                           \
  {                                                                         \
    (void)tio_skipall(fp, SKIP_TIMEOUT);                                    \
    (void)tio_close(fp);                                                    \
    fp = NULL;                                                              \
  }                                                                         \
  return NSS_STATUS_SUCCESS;

#endif /* not NSS__COMMON_H */
