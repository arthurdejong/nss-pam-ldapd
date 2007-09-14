/*
   common.h - common server code routines
   This file is part of the nss-ldapd library.

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007 Arthur de Jong

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
#include "common/tio.h"
#include "compat/attrs.h"
#include "ldap-nss.h"

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

/* a simple wrapper around snprintf,
   returns 0 if ok, -1 on error */
int mysnprintf(char *buffer,size_t buflen,const char *format, ...)
  LIKE_PRINTF(3,4);

/* these are the different functions that handle the database
   specific actions, see nslcd.h for the action descriptions */
int nslcd_alias_byname(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_alias_all(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_ether_byname(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_ether_byether(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_ether_all(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_group_byname(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_group_bygid(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_group_bymember(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_group_all(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_host_byname(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_host_byaddr(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_host_all(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_netgroup_byname(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_network_byname(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_network_byaddr(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_network_all(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_passwd_byname(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_passwd_byuid(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_passwd_all(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_protocol_byname(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_protocol_bynumber(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_protocol_all(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_rpc_byname(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_rpc_bynumber(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_rpc_all(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_service_byname(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_service_bynumber(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_service_all(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_shadow_byname(TFILE *fp,MYLDAP_SESSION *session);
int nslcd_shadow_all(TFILE *fp,MYLDAP_SESSION *session);

/* Note that our caller has to free the returned value with ldap_free() */
char *passwd_username2dn(MYLDAP_SESSION *session,const char *username);

#endif /* not _SERVER_COMMON_H */
