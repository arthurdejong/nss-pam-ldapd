/*
   ldap_compat.h - provide a replacement definitions for some ldap functions

   Copyright (C) 2009-2013 Arthur de Jong

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

#ifndef HAVE_LDAP_PARSE_PASSWORDPOLICY_CONTROL
/* definition lifted from ldap.h */
typedef enum passpolicyerror_enum {
  PP_passwordExpired = 0,
  PP_accountLocked = 1,
  PP_changeAfterReset = 2,
  PP_passwordModNotAllowed = 3,
  PP_mustSupplyOldPassword = 4,
  PP_insufficientPasswordQuality = 5,
  PP_passwordTooShort = 6,
  PP_passwordTooYoung = 7,
  PP_passwordInHistory = 8,
  PP_noError = 65535
} LDAPPasswordPolicyError;
int ldap_parse_passwordpolicy_control(LDAP *ld, LDAPControl *ctrl,
                                      ber_int_t *expirep, ber_int_t *gracep,
                                      LDAPPasswordPolicyError *errorp);
#endif /* HAVE_LDAP_PARSE_PASSWORDPOLICY_CONTROL */

#ifndef HAVE_LDAP_PASSWORDPOLICY_ERR2TXT
const char *ldap_passwordpolicy_err2txt(LDAPPasswordPolicyError error);
#endif /* HAVE_LDAP_PASSWORDPOLICY_ERR2TXT */

#ifdef REPLACE_LDAP_CREATE_DEREF_CONTROL
/* provide a replacement implementation of ldap_create_deref_control() */
int replacement_ldap_create_deref_control(LDAP *ld, LDAPDerefSpec *ds,
      int iscritical, LDAPControl **ctrlp);
#define ldap_create_deref_control(ld, dc, iscritical, ctrlp) \
      replacement_ldap_create_deref_control(ld, dc, iscritical, ctrlp)
#endif /* REPLACE_LDAP_CREATE_DEREF_CONTROL */

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
#ifndef LDAP_CONTROL_X_DEREF
#define LDAP_CONTROL_X_DEREF "1.3.6.1.4.1.4203.666.5.16"
#endif /* LDAP_CONTROL_X_DEREF */

#endif /* COMPAT__LDAP_COMPAT_H */
