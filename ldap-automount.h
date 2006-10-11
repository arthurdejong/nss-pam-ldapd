/* Copyright (C) 2005 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@padl.com>, 2005.

   The nss_ldap library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The nss_ldap library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the nss_ldap library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   $Id: ldap-automount.h,v 1.5 2006/01/12 10:19:20 lukeh Exp $
 */

#ifndef _LDAP_NSS_LDAP_LDAP_AUTOMOUNT_H
#define _LDAP_NSS_LDAP_LDAP_AUTOMOUNT_H

/* Linux only for now */
struct ldap_automount_context {
  /* Enumeration state */
  ent_context_t *lac_state;

  /* DNs of containers representing automount map */
  char **lac_dn_list;
  size_t lac_dn_size;
  size_t lac_dn_count;
  size_t lac_dn_index;
};

typedef struct ldap_automount_context ldap_automount_context_t;

NSS_STATUS _nss_ldap_am_context_alloc(ldap_automount_context_t **pContext);
void _nss_ldap_am_context_free(ldap_automount_context_t **pContext);
NSS_STATUS _nss_ldap_am_context_init(const char *mapname, ldap_automount_context_t **pContext);

#ifdef HAVE_NSS_H
NSS_STATUS _nss_ldap_setautomntent(const char *mapname, void **context);
NSS_STATUS _nss_ldap_getautomntent(void *context, const char **key, const char **value,
				   char *buffer, size_t buflen, int *errnop);
NSS_STATUS _nss_ldap_endautomntent(void **context);
NSS_STATUS _nss_ldap_getautomntbyname_r(void *private, const char *key,
					const char **canon_key, const char **value,
					char *buffer, size_t buflen, int *errnop);
#endif /* HAVE_NSS_H */

#endif /* _LDAP_NSS_LDAP_LDAP_AUTOMOUNT_H */
