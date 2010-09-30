/*
   ldap-nss.h - compatibility definitions
   Parts of this file were part of the nss_ldap library (as ldap-nss.h)
   which has been forked into the nss-pam-ldapd library.

   Copyright (C) 1997-2005 Luke Howard
   Copyright (C) 2010 Arthur de Jong
   Copyright (C) 2010 Symas Corporation

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

/* from ldap-parse.h */
#define NSS_ARGS(args)((nss_XbyY_args_t *)args)

#ifndef NSS_BUFSIZ
#define NSS_BUFSIZ              1024
#endif

#ifndef HAVE_NSSWITCH_H
#define NSS_BUFLEN_NETGROUP(MAXHOSTNAMELEN * 2 + LOGNAME_MAX + 3)
#define NSS_BUFLEN_ETHERS       NSS_BUFSIZ
#endif /* HAVE_NSSWITCH_H */

#ifdef HAVE_NSSWITCH_H
/*
 *thread specific context: result chain,and state data
 */
struct ent_context
{
   void *first_entry;
   void *curr_entry;
};

typedef struct ent_context ent_context_t;

#endif /* HAVE_NSSWITCH_H */

struct name_list
{
  char *name;
  struct name_list *next;
};

#ifdef HAVE_NSSWITCH_H

struct nss_ldap_backend
{
  nss_backend_op_t *ops;
  int n_ops;
  ent_context_t *state;
};

typedef struct nss_ldap_backend nss_ldap_backend_t;

struct nss_ldap_netgr_backend
{
  nss_backend_op_t *ops;
  int n_ops;
  ent_context_t *state;
  struct name_list *known_groups; /* netgroups seen,for loop detection */
  struct name_list *needed_groups; /* nested netgroups to chase */
};

typedef struct nss_ldap_netgr_backend nss_ldap_netgr_backend_t;

#elif defined(HAVE_IRS_H)

struct nss_ldap_netgr_backend
{
  char buffer[NSS_BUFLEN_NETGROUP];
  ent_context_t *state;
  struct name_list *known_groups; /* netgroups seen,for loop detection */
  struct name_list *needed_groups; /* nested netgroups to chase */
};

typedef struct nss_ldap_netgr_backend nss_ldap_netgr_backend_t;

#endif /* HAVE_NSSWITCH_H */

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_ldap_default_destr(nss_backend_t *,void *);
#endif

/*
 *context management routines.
 *_nss_ldap_default_constr() is called once in the constructor
 */
#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_ldap_default_constr(nss_ldap_backend_t *be);
#endif

#endif /* _LDAP_NSS_LDAP_LDAP_NSS_H */
