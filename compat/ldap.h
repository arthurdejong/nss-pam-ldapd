/*
   ldap.h - wrapper macros for LDAP library compatibility
            (include this file after including ldap.h)
   This file is part of the nss-ldapd library.

   Copyright (C) 2007 Arthur de Jong

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

#ifndef _COMPAT_LDAP_H
#define _COMPAT_LDAP_H 1

/* how many messages to retrieve results for */
#ifndef LDAP_MSG_ONE
#define LDAP_MSG_ONE            0x00
#endif
#ifndef LDAP_MSG_ALL
#define LDAP_MSG_ALL            0x01
#endif
#ifndef LDAP_MSG_RECEIVED
#define LDAP_MSG_RECEIVED       0x02
#endif

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
extern int ldap_ld_free (LDAP * ld, int close, LDAPControl **,
                         LDAPControl **);
#else
extern int ldap_ld_free (LDAP * ld, int close);
#endif /* OPENLDAP 2.x */

#endif /* not _COMPAT_LDAP_H */
