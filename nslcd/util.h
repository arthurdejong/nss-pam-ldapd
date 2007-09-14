/*
   util.h - LDAP utility functions
   This file was part of the nss_ldap library which has been
   forked into the nss-ldapd library.

   Copyright (C) 1997-2005 Luke Howard
   Copyright (C) 2006, 2007 West Consulting
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

#ifndef _LDAP_NSS_LDAP_UTIL_H
#define _LDAP_NSS_LDAP_UTIL_H

/*
 * get the RDN's value: eg. if the RDN was cn=lukeh, getrdnvalue(entry)
 * would return lukeh.
 */
enum nss_status _nss_ldap_getrdnvalue(
        MYLDAP_SESSION *session,LDAPMessage *entry,const char *rdntype,
        char **rval,char **buffer,size_t * buflen);

/*
 * map a distinguished name to a login name, or group entry
 */
enum nss_status _nss_ldap_dn2uid(
        MYLDAP_SESSION *session,const char *dn,char **uid,char **buffer,
        size_t *buflen,int *pIsNestedGroup,LDAPMessage **pRes);

/*
 * Escape '*' in a string for use as a filter
 */
int _nss_ldap_escape_string(const char *src,char *buffer,size_t buflen);

/* foreward compatibility hack */
#define myldap_escape _nss_ldap_escape_string

#endif /* _LDAP_NSS_LDAP_UTIL_H */
