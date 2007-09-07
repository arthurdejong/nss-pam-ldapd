/*
   ldap-schema.c - LDAP schema information functions and definitions
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

#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif
#if defined(HAVE_THREAD_H)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include "ldap-nss.h"
#include "ldap-schema.h"
#include "util.h"
#include "attmap.h"
#include "cfg.h"

/* max number of attributes per object class */
#define ATTRTAB_SIZE    15

/**
 * declare filters formerly declared in ldap-*.h
 */

/* rfc822 mail aliases */
char _nss_ldap_filt_getaliasent[LDAP_FILT_MAXSIZ];

/* MAC address mappings */
char _nss_ldap_filt_getetherent[LDAP_FILT_MAXSIZ];

/* groups */
char _nss_ldap_filt_getgrent[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getgroupsbymemberanddn[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getgroupsbydn[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getgroupsbymember[LDAP_FILT_MAXSIZ];

/* IP hosts */
char _nss_ldap_filt_gethostent[LDAP_FILT_MAXSIZ];

/* IP networks */
char _nss_ldap_filt_getnetent[LDAP_FILT_MAXSIZ];

/* IP protocols */
char _nss_ldap_filt_getprotoent[LDAP_FILT_MAXSIZ];

/* users */
char _nss_ldap_filt_getpwent[LDAP_FILT_MAXSIZ];

/* RPCs */
char _nss_ldap_filt_getrpcent[LDAP_FILT_MAXSIZ];

/* IP services */
char _nss_ldap_filt_getservent[LDAP_FILT_MAXSIZ];

/* shadow users */
char _nss_ldap_filt_getspent[LDAP_FILT_MAXSIZ];

/**
 * lookup filter initialization
 */
void
_nss_ldap_init_filters ()
{
  /* rfc822 mail aliases */
  snprintf (_nss_ldap_filt_getaliasent, LDAP_FILT_MAXSIZ,
            "(%s=%s)", attmap_objectClass, attmap_alias_objectClass);

  /* MAC address mappings */
  snprintf (_nss_ldap_filt_getetherent, LDAP_FILT_MAXSIZ, "(%s=%s)",
            attmap_objectClass, attmap_ether_objectClass);

  /* groups */
  snprintf (_nss_ldap_filt_getgrent, LDAP_FILT_MAXSIZ, "(&(%s=%s))",
            attmap_objectClass, attmap_group_objectClass);
  snprintf (_nss_ldap_filt_getgroupsbymemberanddn, LDAP_FILT_MAXSIZ,
            "(&(%s=%s)(|(%s=%s)(%s=%s)))",
            attmap_objectClass, attmap_group_objectClass, attmap_group_memberUid, "%s", attmap_group_uniqueMember, "%s");
  snprintf (_nss_ldap_filt_getgroupsbydn, LDAP_FILT_MAXSIZ,
            "(&(%s=%s)(%s=%s))",
            attmap_objectClass, attmap_group_objectClass, attmap_group_uniqueMember, "%s");
  snprintf (_nss_ldap_filt_getgroupsbymember, LDAP_FILT_MAXSIZ,
            "(&(%s=%s)(%s=%s))", attmap_objectClass, attmap_group_objectClass, attmap_group_memberUid,
            "%s");

  /* IP hosts */
  snprintf (_nss_ldap_filt_gethostent, LDAP_FILT_MAXSIZ, "(%s=%s)",
            attmap_objectClass, attmap_host_objectClass);

  /* IP networks */
  snprintf (_nss_ldap_filt_getnetent, LDAP_FILT_MAXSIZ, "(%s=%s)",
            attmap_objectClass, attmap_network_objectClass);

  /* IP protocols */
  snprintf (_nss_ldap_filt_getprotoent, LDAP_FILT_MAXSIZ, "(%s=%s)",
            attmap_objectClass, attmap_protocol_objectClass);

  /* users */
  snprintf (_nss_ldap_filt_getpwent, LDAP_FILT_MAXSIZ,
            "(%s=%s)", attmap_objectClass, attmap_passwd_objectClass);

  /* RPCs */
  snprintf (_nss_ldap_filt_getrpcent, LDAP_FILT_MAXSIZ, "(%s=%s)",
            attmap_objectClass, attmap_rpc_objectClass);

  /* IP services */
  snprintf (_nss_ldap_filt_getservent, LDAP_FILT_MAXSIZ, "(%s=%s)",
            attmap_objectClass, attmap_service_objectClass);

  /* shadow users */
  snprintf (_nss_ldap_filt_getspent, LDAP_FILT_MAXSIZ,
            "(%s=%s)", attmap_objectClass, attmap_shadow_objectClass);

}
