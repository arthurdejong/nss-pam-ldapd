/*
   ldap-nss.c - main file for NSS interface
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

#ifndef _LDAP_NSS_LDAP_LDAP_NSS_H
#define _LDAP_NSS_LDAP_LDAP_NSS_H

#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/in.h>
#include <nss.h>
#include <ldap.h>

#include "cfg.h"
#include "myldap.h"

#ifdef __GNUC__
#define alignof(ptr) __alignof__(ptr)
#elif defined(HAVE_ALIGNOF_H)
#include <alignof.h>
#else
#define alignof(ptr) (sizeof(char *))
#endif /* __GNUC__ */

#define align(ptr, blen, TYPE)\
  { \
      char *qtr = ptr; \
      ptr += alignof(TYPE) - 1; \
      ptr -= ((ptr - (char *)NULL) % alignof(TYPE)); \
      blen -= (ptr - qtr); \
  }

/* worst case */
#define bytesleft(ptr, blen, TYPE) \
  ( (blen < alignof(TYPE)) ? 0 : (blen - alignof(TYPE) + 1))

/* parsing utility functions */

enum nss_status _nss_ldap_assign_attrvals (
        MYLDAP_ENTRY *entry,
        const char *attr, /* IN */
        const char *omitvalue,    /* IN */
        char ***valptr,   /* OUT */
        char **pbuffer,    /* IN/OUT */
        size_t * pbuflen,  /* IN/OUT */
        size_t * pvalcount /* OUT */ );

enum nss_status _nss_ldap_assign_attrval(
        MYLDAP_ENTRY *entry,
        const char *attr,  /* IN */
        char **valptr,     /* OUT */
        char **buffer,     /* IN/OUT */
        size_t * buflen /* IN/OUT */ );

enum nss_status _nss_ldap_assign_userpassword(
        MYLDAP_ENTRY *entry,
        const char *attr,     /* IN */
        char **valptr,        /* OUT */
        char **buffer,        /* IN/OUT */
        size_t * buflen);     /* IN/OUT */

/*
 * get the RDN's value: eg. if the RDN was cn=lukeh, getrdnvalue(entry)
 * would return lukeh.
 */
enum nss_status _nss_ldap_getrdnvalue(
        MYLDAP_ENTRY *entry,const char *rdntype,
        char **rval,char **buffer,size_t * buflen);

#endif /* _LDAP_NSS_LDAP_LDAP_NSS_H */
