/*
   ldap_compat.h - provide a replacement definitions for some ldap functions

   Copyright (C) 2009 Arthur de Jong

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
int ldap_initialize(LDAP **ldp,const char *url);
#endif /* not HAVE_LDAP_INITIALIZE */

#ifndef HAVE_LDAP_CREATE_PAGE_CONTROL
int ldap_create_page_control(LDAP *ld,unsigned long pagesize,
                             struct berval *cookiep,int iscritical,
                             LDAPControl **ctrlp);
#endif /* not HAVE_LDAP_CREATE_PAGE_CONTROL */

#ifndef HAVE_LDAP_PARSE_PAGE_CONTROL
int ldap_parse_page_control(LDAP *ld,LDAPControl **ctrls,
                            unsigned long *list_countp,
                            struct berval **cookiep);
#endif /* not HAVE_LDAP_PARSE_PAGE_CONTROL */

#ifndef HAVE_LDAP_PASSWD_S
int ldap_passwd_s(LDAP *ld,struct berval *user,struct berval *oldpw,
                  struct berval *newpw,struct berval *newpasswd,
                  LDAPControl **sctrls,LDAPControl **cctrls);
#endif /* not HAVE_LDAP_PASSWD_S */


#endif /* COMPAT__LDAP_COMPAT_H */
