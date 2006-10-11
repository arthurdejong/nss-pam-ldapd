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

   $Id: irs-nss.h,v 2.20 2005/05/20 05:30:40 lukeh Exp $
 */

#ifndef _LDAP_NSS_LDAP_IRS_H
#define _LDAP_NSS_LDAP_IRS_H

#ifdef HAVE_IRS_H
/*
 * This header is only needed when using the BSD Information 
 * Retrieval Service. It is not necessary for the Solaris or
 * GNU nameservice switch modules.
 */
#include <irs.h>
#endif

struct irs_gr *irs_ldap_gr __P ((struct irs_acc *));
struct irs_pw *irs_ldap_pw __P ((struct irs_acc *));
struct irs_sv *irs_ldap_sv __P ((struct irs_acc *));
struct irs_pr *irs_ldap_pr __P ((struct irs_acc *));
struct irs_ho *irs_ldap_ho __P ((struct irs_acc *));
struct irs_nw *irs_ldap_nw __P ((struct irs_acc *));
/* not done yet */
struct irs_ng *irs_ldap_ng __P ((struct irs_acc *));

/* Keep namespace clean. */
#define irs_ldap_acc	__irs_ldap_acc

struct irs_acc *irs_ldap_acc __P ((const char *));

#define make_group_list __make_group_list

extern int make_group_list (struct irs_gr *, const char *,
			    gid_t, gid_t *, int *);

#ifdef HAVE_USERSEC_H /* aka AIX */
#define IRS_EXPORT
#else
#define IRS_EXPORT static
#endif

#endif /* _LDAP_NSS_LDAP_IRS_H */
