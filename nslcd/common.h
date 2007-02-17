/*
   common.h - common server code routines
   This file is part of the nss-ldapd library.

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006 Arthur de Jong

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

#ifndef _SERVER_COMMON_H
#define _SERVER_COMMON_H 1

#include "nslcd.h"
#include "nslcd-common.h"
#include "compat/attrs.h"


/* translates a nss code (as defined in nss.h) to a
   nslcd return code (as defined in nslcd.h) */
/* FIXME: this is a temporary hack, get rid of it */
#include <nss.h>
int nss2nslcd(enum nss_status code)
  PURE MUST_USE;


/* macros for basic read and write operations, the following
   ERROR_OUT* marcos define the action taken on errors
   the stream is not closed because the caller closes the
   stream */

#define ERROR_OUT_WRITEERROR(fp) \
  log_log(LOG_WARNING,"error writing to client"); \
  return -1;

#define ERROR_OUT_READERROR(fp) \
  log_log(LOG_WARNING,"error reading from client"); \
  return -1;

#define ERROR_OUT_BUFERROR(fp) \
  log_log(LOG_WARNING,"client supplied argument too large"); \
  return -1;


/* these are the different functions that handle the database
   specific actions, see nslcd.h for the action descriptions */
int nslcd_alias_byname(FILE *fp);
int nslcd_alias_all(FILE *fp);
int nslcd_ether_byname(FILE *fp);
int nslcd_ether_byether(FILE *fp);
int nslcd_ether_all(FILE *fp);
int nslcd_group_byname(FILE *fp);
int nslcd_group_bygid(FILE *fp);
int nslcd_group_bymember(FILE *fp);
int nslcd_group_all(FILE *fp);
int nslcd_host_byname(FILE *fp);
int nslcd_host_byaddr(FILE *fp);
int nslcd_host_all(FILE *fp);
int nslcd_netgroup_byname(FILE *fp);
int nslcd_network_byname(FILE *fp);
int nslcd_network_byaddr(FILE *fp);
int nslcd_network_all(FILE *fp);
int nslcd_passwd_byname(FILE *fp);
int nslcd_passwd_byuid(FILE *fp);
int nslcd_passwd_all(FILE *fp);
int nslcd_protocol_byname(FILE *fp);
int nslcd_protocol_bynumber(FILE *fp);
int nslcd_protocol_all(FILE *fp);
int nslcd_rpc_byname(FILE *fp);
int nslcd_rpc_bynumber(FILE *fp);
int nslcd_rpc_all(FILE *fp);
int nslcd_service_byname(FILE *fp);
int nslcd_service_bynumber(FILE *fp);
int nslcd_service_all(FILE *fp);
int nslcd_shadow_byname(FILE *fp);
int nslcd_shadow_all(FILE *fp);

#endif /* not _SERVER_COMMON_H */
