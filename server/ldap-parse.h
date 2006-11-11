/*
   ldap-parse.h - helper macros for lookup functions
   This file was part of the nss-ldap library which has been
   forked into the nss-ldapd library.

   Copyright (C) 1997-2005 Luke Howard
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

#ifndef _LDAP_NSS_LDAP_LDAP_PARSE_H
#define _LDAP_NSS_LDAP_LDAP_PARSE_H

#define LOOKUP_NAME(name, result, buffer, buflen, errnop, filter, selector, parser, req_buflen) \
        struct ldap_args a; \
        if (buflen < req_buflen) { \
                *errnop = ERANGE; \
                return NSS_STATUS_TRYAGAIN; \
        } \
        LA_INIT(a); \
        LA_STRING(a) = name; \
        LA_TYPE(a) = LA_TYPE_STRING; \
        return _nss_ldap_getbyname(&a, result, buffer, buflen, errnop, filter, selector, parser);

#define LOOKUP_NUMBER(number, result, buffer, buflen, errnop, filter, selector, parser, req_buflen) \
        struct ldap_args a; \
        if (buflen < req_buflen) { \
                *errnop = ERANGE; \
                return NSS_STATUS_TRYAGAIN; \
        } \
        LA_INIT(a); \
        LA_NUMBER(a) = number; \
        LA_TYPE(a) = LA_TYPE_NUMBER; \
        return _nss_ldap_getbyname(&a, result, buffer, buflen, errnop, filter, selector, parser)

#define LOOKUP_SETENT(key) \
        if (_nss_ldap_ent_context_init(&key) == NULL) \
                return NSS_STATUS_UNAVAIL; \
        return NSS_STATUS_SUCCESS

#define LOOKUP_GETENT(key, result, buffer, buflen, errnop, filter, selector, parser, req_buflen) \
        if (buflen < req_buflen) { \
                *errnop = ERANGE; \
                return NSS_STATUS_TRYAGAIN; \
        } \
        return _nss_ldap_getent(&key, result, buffer, buflen, errnop, filter, selector, parser)

#define LOOKUP_ENDENT(key) \
        _nss_ldap_enter(); \
        _nss_ldap_ent_context_release(key); \
        _nss_ldap_leave(); \
        return NSS_STATUS_SUCCESS

#endif /* _LDAP_NSS_LDAP_LDAP_PARSE_H */
