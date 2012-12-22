/*
   common.h - common functions for PAM lookups

   Copyright (C) 2009, 2010, 2011, 2012 Arthur de Jong

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

#ifndef PAM__COMMON_H
#define PAM__COMMON_H 1

#include <stdio.h>

#include "nslcd.h"
#include "common/nslcd-prot.h"
#include "compat/attrs.h"

/* These are macros for handling read and write problems, they are
   PAM specific due to the return code so are defined here. They
   genrally close the open file, set an error code and return with
   an error status. */

/* Macro is called to handle errors in opening a client connection. */
#define ERROR_OUT_OPENERROR                                                 \
  pam_syslog(pamh, LOG_ERR, "error opening connection to nslcd: %s",        \
             strerror(errno));                                              \
  return PAM_AUTHINFO_UNAVAIL;

/* Macro is called to handle errors on read operations. */
#define ERROR_OUT_READERROR(fp)                                             \
  pam_syslog(pamh, LOG_ERR, "error reading from nslcd: %s",                 \
             strerror(errno));                                              \
  (void)tio_close(fp);                                                      \
  return PAM_AUTHINFO_UNAVAIL;

/* Macro is called to handle problems with too small a buffer. */
#define ERROR_OUT_BUFERROR(fp)                                              \
  pam_syslog(pamh, LOG_CRIT, "buffer %d bytes too small", tmpint32);        \
  (void)tio_close(fp);                                                      \
  return PAM_SYSTEM_ERR;

/* This macro is called if there was a problem with a write
   operation. */
#define ERROR_OUT_WRITEERROR(fp)                                            \
  pam_syslog(pamh, LOG_ERR, "error writing to nslcd: %s",                   \
             strerror(errno));                                              \
  (void)tio_close(fp);                                                      \
  return PAM_AUTHINFO_UNAVAIL;

/* This macro is called if the read status code is not
   NSLCD_RESULT_BEGIN. */
#define ERROR_OUT_NOSUCCESS(fp)                                             \
  (void)tio_close(fp);                                                      \
  if (cfg->debug)                                                           \
    pam_syslog(pamh, LOG_DEBUG, "user not handled by nslcd");               \
  return PAM_USER_UNKNOWN;

/* This is a generic PAM request generation macro. The action
   parameter is the NSLCD_ACTION_.. action, the writefn is the
   operation for writing the parameter and readfn is the function
   name for reading a single result entry. The function is assumed
   to have result, buffer, buflen and errnop parameters that define
   the result structure, the user buffer with length and the
   errno to return. This macro should be called through some of
   the customized ones below. */
#define PAM_REQUEST(action, debuglog, writefn, readfn)                      \
  TFILE *fp;                                                                \
  int32_t tmpint32;                                                         \
  if (cfg->debug)                                                           \
    debuglog;                                                               \
  /* open socket and write request */                                       \
  NSLCD_REQUEST(fp, action, writefn);                                       \
  /* read response code */                                                  \
  READ_RESPONSE_CODE(fp);                                                   \
  /* read the response */                                                   \
  readfn;                                                                   \
  /* close socket and we're done */                                         \
  (void)tio_close(fp);                                                      \
  return PAM_SUCCESS;

/* helper macro to read PAM status code (auto-translated from NSLCD PAM
   status code */
#define READ_PAM_CODE(fp, i)                                                \
  READ(fp, &tmpint32, sizeof(int32_t));                                     \
  (i) = nslcd2pam_rc(pamh, ntohl(tmpint32));

#endif /* not PAM__COMMON_H */
