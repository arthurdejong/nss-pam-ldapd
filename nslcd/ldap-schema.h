/*
   ldap-schema.h - LDAP schema information functions and definitions
   This file was part of the nss_ldap library which has been
   forked into the nss-ldapd library.

   Copyright (C) 1997-2005 Luke Howard
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

#ifndef _LDAP_NSS_LDAP_LDAP_SCHEMA_H
#define _LDAP_NSS_LDAP_LDAP_SCHEMA_H

/**
 * function to initialize global lookup filters.
 */
void _nss_ldap_init_filters(void);

/**
 * make filters formerly declared in ldap-*.h globally available.
 */

/* rfc822 mail aliases */
extern char _nss_ldap_filt_getaliasent[];

/* MAC address mappings */
extern char _nss_ldap_filt_getetherent[];

/* groups */
extern char _nss_ldap_filt_getgrent[];
extern char _nss_ldap_filt_getgroupsbymemberanddn[];
extern char _nss_ldap_filt_getgroupsbydn[];
extern char _nss_ldap_filt_getgroupsbymember[];

/* IP hosts */
extern char _nss_ldap_filt_gethostent[];

/* IP networks */
extern char _nss_ldap_filt_getnetent[];

/* IP protocols */
extern char _nss_ldap_filt_getprotoent[];

/* users */
extern char _nss_ldap_filt_getpwent[];

/* RPCs */
extern char _nss_ldap_filt_getrpcent[];

/* IP services */
extern char _nss_ldap_filt_getservent[];

/* shadow users */
extern char _nss_ldap_filt_getspent[];

#endif /* _LDAP_NSS_LDAP_LDAP_SCHEMA_H */
