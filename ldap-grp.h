/* Copyright (C) 1997-2005 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@padl.com>, 1997.

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

   $Id: ldap-grp.h,v 2.22 2005/05/20 05:30:40 lukeh Exp $
 */

#ifndef _LDAP_NSS_LDAP_LDAP_GRP_H
#define _LDAP_NSS_LDAP_LDAP_GRP_H

static NSS_STATUS _nss_ldap_parse_gr (LDAPMessage * e,
				      ldap_state_t * pvt,
				      void *result,
				      char *buffer, size_t buflen);

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS _nss_ldap_endgrent_r (nss_backend_t * be, void *fakeargs);
static NSS_STATUS _nss_ldap_setgrent_r (nss_backend_t * be, void *fakeargs);
static NSS_STATUS _nss_ldap_getgrent_r (nss_backend_t * be, void *fakeargs);
static NSS_STATUS _nss_ldap_getgrnam_r (nss_backend_t * be, void *fakeargs);
static NSS_STATUS _nss_ldap_getgrgid_r (nss_backend_t * be, void *fakeargs);

nss_backend_t *_nss_ldap_group_constr (const char *db_name,
				       const char *src_name,
				       const char *cfg_args);
#endif

#endif /* _LDAP_NSS_LDAP_LDAP_GRP_H */
