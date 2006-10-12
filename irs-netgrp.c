/* Copyright (C) 2004 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@padl.com>, 2004.

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

#ifdef HAVE_IRS_H

#include <errno.h>
#include "irs-nss.h"

/* $Id$ */

#ifdef HAVE_USERSEC_H
void *ng_pvtinit (void);
#endif
IRS_EXPORT void ng_close (struct irs_ng *);
IRS_EXPORT int ng_next (struct irs_ng *, char **, char **, char **);
IRS_EXPORT int ng_test (struct irs_ng *, const char *, const char *,
			const char *, const char *);
IRS_EXPORT void ng_rewind (struct irs_ng *, const char *);
IRS_EXPORT void ng_minimize (struct irs_ng *);

IRS_EXPORT int
ng_test (struct irs_ng *this,
	 const char *name, const char *host,
	 const char *user, const char *domain)
{
  NSS_STATUS parseStat;
  ldap_innetgr_args_t li_args;

  li_args.lia_netgroup = name;
  li_args.lia_netgr_status = NSS_NETGR_NO;
  li_args.lia_depth = 0;
  li_args.lia_erange = 0;

  _nss_ldap_enter ();

  /* fall through to NSS implementation */
  parseStat = do_innetgr (&li_args, host, user, domain);
  if (parseStat != NSS_SUCCESS && parseStat != NSS_NOTFOUND)
    {
      if (li_args.lia_erange)
	errno = ERANGE;
      _nss_ldap_leave ();

      return 0;
    }

  _nss_ldap_leave ();

  return (li_args.lia_netgr_status == NSS_NETGR_FOUND);
}

IRS_EXPORT void
ng_rewind (struct irs_ng *this, const char *group)
{
  nss_ldap_netgr_backend_t *ngbe;
  ldap_args_t a;
  NSS_STATUS stat;

  ngbe = (nss_ldap_netgr_backend_t *) this->private;

  /* clear out old state */
  _nss_ldap_namelist_destroy (&ngbe->known_groups);
  _nss_ldap_namelist_destroy (&ngbe->needed_groups);

  LA_INIT (a);
  LA_TYPE (a) = LA_TYPE_STRING;
  LA_STRING (a) = group;

  if (_nss_ldap_ent_context_init (&ngbe->state) == NULL)
    return;

  _nss_ldap_enter ();
  stat = _nss_ldap_search_s (&a, _nss_ldap_filt_getgrent,
			     LM_NETGROUP, NULL, 1, &ngbe->state->ec_res);

  if (stat == NSS_SUCCESS)
    _nss_ldap_namelist_push (&ngbe->known_groups, group);

  if (stat != NSS_SUCCESS)
    _nss_ldap_ent_context_release (ngbe->state);

  _nss_ldap_leave ();
}

IRS_EXPORT int
ng_next (struct irs_ng *this, char **machine, char **user, char **domain)
{
  nss_ldap_netgr_backend_t *ngbe = (nss_ldap_netgr_backend_t *) this->private;
  enum nss_netgr_status netgr_stat;
  NSS_STATUS stat;

  if (ngbe->state == NULL)
    return 0;

  _nss_ldap_enter ();

  stat = do_getnetgrent (ngbe,
			 ngbe->buffer,
			 NSS_BUFLEN_NETGROUP,
			 &netgr_stat,
			 machine,
			 user,
			 domain);

  _nss_ldap_leave ();

  return (stat == NSS_SUCCESS);
}

IRS_EXPORT void
ng_minimize (struct irs_ng *this)
{
}

IRS_EXPORT void
ng_close (struct irs_ng *this)
{
#ifdef HAVE_USERSEC_H
  nss_ldap_netgr_backend_t *ngbe;

  ngbe = (nss_ldap_netgr_backend_t *) this->private;
  if (ngbe != NULL)
    {
      if (ngbe->state != NULL)
	{
	  _nss_ldap_enter ();
	  _nss_ldap_ent_context_release (ngbe->state);
	  free (ngbe->state);
	  _nss_ldap_leave ();
	}

      _nss_ldap_namelist_destroy (&ngbe->known_groups);
      _nss_ldap_namelist_destroy (&ngbe->needed_groups);

      free (ngbe);
    }

  free (this);
#endif /* HAVE_USERSEC_H */
}

#ifdef HAVE_USERSEC_H
void *
ng_pvtinit (void)
#else
struct irs_ng *
irs_ldap_ng (struct irs_acc *this)
#endif
{
  struct irs_ng *ng;
  nss_ldap_netgr_backend_t *pvt;

  ng = calloc (1, sizeof (*ng));
  if (ng == NULL)
    return NULL;

  pvt = calloc (1, sizeof (*pvt));
  if (pvt == NULL)
    {
      free (ng);
      return NULL;
    }

  pvt->state = NULL;
  ng->private = pvt;
  ng->close = ng_close;
  ng->next = ng_next;
  ng->test = ng_test;
  ng->rewind = ng_rewind;
  ng->minimize = ng_minimize;
  return ng;
}

#endif /*HAVE_IRS_H */
