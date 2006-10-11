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

   $Id: ldap-service.h,v 2.17 2005/05/20 05:30:42 lukeh Exp $
 */

#ifndef _LDAP_NSS_LDAP_LDAP_SERVICE_H
#define _LDAP_NSS_LDAP_LDAP_SERVICE_H

/*
 * Determine the canonical name of the service with _nss_ldap_getrdnvalue(),
 * and assign any values of "cn" which do NOT match this canonical name
 * as aliases.
 *
 * You can use the ec_state in the context to derive multiple service
 * entries from one LDAP entry. See the example in draft-...-nis-schema-xx.txt.
 *
 */


static NSS_STATUS _nss_ldap_parse_serv (LDAPMessage * e,
					ldap_state_t * pvt,
					void *result,
					char *buffer, size_t buflen);

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS _nss_ldap_getservbyname_r (nss_backend_t * be,
					     void *fakeargs);
static NSS_STATUS _nss_ldap_getservbyport_r (nss_backend_t * be,
					     void *fakeargs);
static NSS_STATUS _nss_ldap_setservent_r (nss_backend_t * be, void *fakeargs);
static NSS_STATUS _nss_ldap_endservent_r (nss_backend_t * be, void *fakeargs);
static NSS_STATUS _nss_ldap_getservent_r (nss_backend_t * be, void *fakeargs);

nss_backend_t *_nss_ldap_services_constr (const char *db_name,
					  const char *src_name,
					  const char *cfg_args);
#endif /* !HAVE_NSS_H */

#endif /* _LDAP_NSS_LDAP_LDAP_SERVICE_H */
