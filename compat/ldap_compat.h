/*
   ldap_compat.h - provide a replacement definitions for some ldap functions

   Copyright (C) 2009, 2010, 2012, 2013 Arthur de Jong

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

#ifndef COMPAT__LDAP_COMPAT_H
#define COMPAT__LDAP_COMPAT_H 1

#include <lber.h>
#include <ldap.h>

/* compatibility macros */
#ifndef LDAP_CONST
#define LDAP_CONST const
#endif /* not LDAP_CONST */
#ifndef LDAP_MSG_ONE
#define LDAP_MSG_ONE 0x00
#endif /* not LDAP_MSG_ONE */

#ifndef HAVE_LDAP_INITIALIZE
/* provide a wrapper around ldap_init() if the system doesn't have
   ldap_initialize() */
int ldap_initialize(LDAP **ldp, const char *url);
#endif /* not HAVE_LDAP_INITIALIZE */

#ifndef HAVE_LDAP_CREATE_PAGE_CONTROL
int ldap_create_page_control(LDAP *ld, unsigned long pagesize,
                             struct berval *cookiep, int iscritical,
                             LDAPControl **ctrlp);
#endif /* not HAVE_LDAP_CREATE_PAGE_CONTROL */

#ifndef HAVE_LDAP_PARSE_PAGE_CONTROL
int ldap_parse_page_control(LDAP *ld, LDAPControl **ctrls,
                            unsigned long *list_countp,
                            struct berval **cookiep);
#endif /* not HAVE_LDAP_PARSE_PAGE_CONTROL */

#ifndef HAVE_LDAP_PASSWD_S
int ldap_passwd_s(LDAP *ld, struct berval *user, struct berval *oldpw,
                  struct berval *newpw, struct berval *newpasswd,
                  LDAPControl **sctrls, LDAPControl **cctrls);
#endif /* not HAVE_LDAP_PASSWD_S */

/* compatibility definition */
#ifndef LDAP_SASL_QUIET
#define LDAP_SASL_QUIET 2U
#endif /* not LDAP_SASL_QUIET */

/* on some systems LDAP_OPT_DIAGNOSTIC_MESSAGE isn't there but
   LDAP_OPT_ERROR_STRING is */
#ifndef LDAP_OPT_DIAGNOSTIC_MESSAGE
#ifdef LDAP_OPT_ERROR_STRING
#define LDAP_OPT_DIAGNOSTIC_MESSAGE LDAP_OPT_ERROR_STRING
#endif /* LDAP_OPT_ERROR_STRING */
#endif /* not LDAP_OPT_DIAGNOSTIC_MESSAGE */

/* provide replacement oid definitions */
#ifndef LDAP_CONTROL_PWEXPIRED
#define LDAP_CONTROL_PWEXPIRED "2.16.840.1.113730.3.4.4"
#endif /* LDAP_CONTROL_PWEXPIRED */
#ifndef LDAP_CONTROL_PWEXPIRING
#define LDAP_CONTROL_PWEXPIRING "2.16.840.1.113730.3.4.5"
#endif /* LDAP_CONTROL_PWEXPIRING */
#ifndef LDAP_CONTROL_PASSWORDPOLICYREQUEST
#define LDAP_CONTROL_PASSWORDPOLICYREQUEST "1.3.6.1.4.1.42.2.27.8.5.1"
#endif /* LDAP_CONTROL_PASSWORDPOLICYREQUEST */
#ifndef LDAP_CONTROL_PASSWORDPOLICYRESPONSE
#define LDAP_CONTROL_PASSWORDPOLICYRESPONSE "1.3.6.1.4.1.42.2.27.8.5.1"
#endif /* LDAP_CONTROL_PASSWORDPOLICYRESPONSE */

#endif /* COMPAT__LDAP_COMPAT_H */
