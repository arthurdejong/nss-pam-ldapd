/*
   common.h - common functions for NSS lookups

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007, 2008, 2009, 2010 Arthur de Jong

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

#include "nslcd.h"
#include "common/nslcd-prot.h"
#include "compat/attrs.h"
#include "compat/nss_compat.h"

/* These are macros for handling read and write problems, they are
   NSS specific due to the return code so are defined here. They
   genrally close the open file, set an error code and return with
   an error status. */

/* Macro is called to handle errors in opening a client connection. */
#define ERROR_OUT_OPENERROR \
  *errnop=ENOENT; \
  return (errno==EAGAIN)?NSS_STATUS_TRYAGAIN:NSS_STATUS_UNAVAIL;

/* Macro is called to handle errors on read operations. */
#define ERROR_OUT_READERROR(fp) \
  (void)tio_close(fp); \
  fp=NULL; \
  *errnop=ENOENT; \
  return NSS_STATUS_UNAVAIL;

/* Macro is called to handle problems with too small a buffer.
   This triggers the caller to call the function with a larger
   buffer (see NSS_GETENT below). */
#define ERROR_OUT_BUFERROR(fp) \
  *errnop=ERANGE; \
  return NSS_STATUS_TRYAGAIN;

/* This macro is called if there was a problem with a write
   operation. */
#define ERROR_OUT_WRITEERROR(fp) \
  ERROR_OUT_READERROR(fp)

/* This macro is called if the read status code is not
   NSLCD_RESULT_BEGIN. */
#define ERROR_OUT_NOSUCCESS(fp) \
  (void)tio_close(fp); \
  fp=NULL; \
  return NSS_STATUS_NOTFOUND;

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
#define NSS_BYGEN(action,writefn,readfn) \
  TFILE *fp; \
  int32_t tmpint32; \
  enum nss_status retv; \
  if (!_nss_ldap_enablelookups) \
    return NSS_STATUS_UNAVAIL; \
  /* check that we have a valid buffer */ \
  if ((buffer==NULL)||(buflen<=0)) \
  { \
      *errnop=EINVAL; \
      return NSS_STATUS_UNAVAIL; \
  } \
  /* open socket and write request */ \
  NSLCD_REQUEST(fp,action,writefn); \
  /* read response */ \
  READ_RESPONSE_CODE(fp); \
  retv=readfn; \
  /* close socket and we're done */ \
  if ((retv==NSS_STATUS_SUCCESS)||(retv==NSS_STATUS_TRYAGAIN)) \
    (void)tio_close(fp); \
  return retv;

/* This macro can be used to generate a get..byname() function
   body. */
#define NSS_BYNAME(action,name,readfn) \
  NSS_BYGEN(action,WRITE_STRING(fp,name),readfn)

/* This macro can be used to generate a get..by..() function
   body where the value that is the key has the specified type. */
#define NSS_BYTYPE(action,val,type,readfn) \
  NSS_BYGEN(action,WRITE_TYPE(fp,val,type),readfn)

/* This macro can be used to generate a get..by..() function
   body where the value should be passed as an int32_t. */
#define NSS_BYINT32(action,val,readfn) \
  NSS_BYGEN(action,WRITE_INT32(fp,val),readfn)

/* This macro generates a simple setent() function body. This closes any
   open streams so that NSS_GETENT() can open a new file. */
#define NSS_SETENT(fp) \
  if (!_nss_ldap_enablelookups) \
    return NSS_STATUS_UNAVAIL; \
  if (fp!=NULL) \
  { \
    (void)tio_close(fp); \
    fp=NULL; \
  } \
  return NSS_STATUS_SUCCESS;

/* This macro generates a getent() function body. If the stream is not yet
   open, a new one is opened, a request is written and a check is done for
   a response header. A single entry is read with the readfn() function. */
#define NSS_GETENT(fp,action,readfn) \
  int32_t tmpint32; \
  enum nss_status retv; \
  if (!_nss_ldap_enablelookups) \
    return NSS_STATUS_UNAVAIL; \
  /* check that we have a valid buffer */ \
  if ((buffer==NULL)||(buflen<=0)) \
  { \
      /* close stream */ \
      if (fp!=NULL) \
      { \
        (void)tio_close(fp); \
        fp=NULL; \
      } \
      /* indicate error */ \
      *errnop=EINVAL; \
      return NSS_STATUS_UNAVAIL; \
  } \
  /* check that we have a valid file descriptor */ \
  if (fp==NULL) \
  { \
    /* open a new stream and write the request */ \
    NSLCD_REQUEST(fp,action,/* no writefn */;); \
  } \
  /* prepare for buffer errors */ \
  tio_mark(fp); \
  /* read a response */ \
  READ_RESPONSE_CODE(fp); \
  retv=readfn; \
  /* check read result */ \
  if (retv==NSS_STATUS_TRYAGAIN) \
  { \
    /* if we have a full buffer try to reset the stream */ \
    if (tio_reset(fp)) \
    { \
      tio_close(fp); \
      fp=NULL; \
      /* fail with permanent error to prevent retries */ \
      *errnop=EINVAL; \
      return NSS_STATUS_UNAVAIL; \
    } \
  } \
  else if (retv!=NSS_STATUS_SUCCESS) \
    fp=NULL; /* file should be closed by now */ \
  return retv;

/* This macro generates a endent() function body. This just closes
   the stream. */
#define NSS_ENDENT(fp) \
  if (!_nss_ldap_enablelookups) \
    return NSS_STATUS_UNAVAIL; \
  if (fp!=NULL) \
  { \
    (void)tio_close(fp); \
    fp=NULL; \
  } \
  return NSS_STATUS_SUCCESS;

#endif /* not NSS__COMMON_H */
