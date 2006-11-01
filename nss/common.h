/*
   common.h - common functions for NSS lookups

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006 Arthur de Jong

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
   MA 02110-1301 USA
*/

#ifndef _NSS_COMMON_H
#define _NSS_COMMON_H 1

#include <nss.h>

/* translates a nslcd return code (as defined in nslcd.h) to
   a nss code (as defined in nss.h) */
enum nss_status nslcd2nss(int code);

/* macros for handling read and write problems, they are
   NSS specific due to the return codes */

#define ERROR_OUT_OPENERROR \
  *errnop=ENOENT; \
  return NSS_STATUS_UNAVAIL;

#define ERROR_OUT_READERROR(fp) \
  fclose(fp); \
  fp=NULL; \
  *errnop=ENOENT; \
  return NSS_STATUS_UNAVAIL;

#define ERROR_OUT_BUFERROR(fp) \
  fclose(fp); \
  fp=NULL; \
  *errnop=ERANGE; \
  return NSS_STATUS_TRYAGAIN;

#define ERROR_OUT_WRITEERROR(fp) \
  ERROR_OUT_READERROR(fp)

#define ERROR_OUT_NOSUCCESS(fp,retv) \
  fclose(fp); \
  fp=NULL; \
  *errnop=ENOENT; \
  return nslcd2nss(retv);

#endif /* not _NSS_COMMON_H */
