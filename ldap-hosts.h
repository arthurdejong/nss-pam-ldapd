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
 */

#ifndef _LDAP_NSS_LDAP_LDAP_HOSTS_H
#define _LDAP_NSS_LDAP_LDAP_HOSTS_H

/*
 * It's critical that we support IPv6 both in the IRS and the NSS modules.
 * For code, check out the BIND IRS and the glibc as it stands. Both support
 * NIS lookups for IPv6 addresses.
 *
 */


#if defined(HAVE_NSSWITCH_H) || defined(DL_NSS)
/* XXX Fixme */
#ifndef INADDRSZ
#define INADDRSZ (sizeof(u_long))
#endif
#endif


static NSS_STATUS _nss_ldap_parse_host (LDAPMessage * e,
					ldap_state_t * pvt,
					void *result,
					char *buffer, size_t buflen, int af);

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS _nss_ldap_gethostbyname_r (nss_backend_t * be,
					     void *fakeargs);
static NSS_STATUS _nss_ldap_gethostbyaddr_r (nss_backend_t * be,
					     void *fakeargs);
static NSS_STATUS _nss_ldap_gethostent_r (nss_backend_t * be, void *fakeargs);
static NSS_STATUS _nss_ldap_sethostent_r (nss_backend_t * be, void *fakeargs);
static NSS_STATUS _nss_ldap_endhostent_r (nss_backend_t * be, void *fakeargs);

nss_backend_t *_nss_ldap_hosts_constr (const char *db_name,
				       const char *src_name,
				       const char *cfg_args);
#endif

#endif /* _LDAP_NSS_LDAP_LDAP_HOSTS_H */
