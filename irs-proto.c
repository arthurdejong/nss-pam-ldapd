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

#ifdef HAVE_IRS_H

#include <errno.h>
#include "irs-nss.h"

/* $Id: irs-proto.c,v 2.23 2005/05/20 05:30:40 lukeh Exp $ */

#ifdef HAVE_USERSEC_H
void *pr_pvtinit (void);
#endif
IRS_EXPORT void pr_close (struct irs_pr *);
IRS_EXPORT struct protoent *pr_byname (struct irs_pr *, const char *);
IRS_EXPORT struct protoent *pr_bynumber (struct irs_pr *, int);
IRS_EXPORT struct protoent *pr_next (struct irs_pr *);
IRS_EXPORT void pr_rewind (struct irs_pr *);
IRS_EXPORT void pr_minimize (struct irs_pr *);

struct pvt
{
  struct protoent result;
  char buffer[NSS_BUFLEN_PROTOCOLS];
  ent_context_t *state;
};

IRS_EXPORT struct protoent *
pr_byname (struct irs_pr *this, const char *name)
{
  LOOKUP_NAME (name, this, _nss_ldap_filt_getprotobyname, LM_PROTOCOLS,
	       _nss_ldap_parse_proto, LDAP_NSS_BUFLEN_DEFAULT);
}

IRS_EXPORT struct protoent *
pr_bynumber (struct irs_pr *this, int num)
{
  LOOKUP_NUMBER (num, this, _nss_ldap_filt_getprotobynumber, LM_PROTOCOLS,
		 _nss_ldap_parse_proto, LDAP_NSS_BUFLEN_DEFAULT);
}

IRS_EXPORT void
pr_close (struct irs_pr *this)
{
  LOOKUP_ENDENT (this);
#ifdef HAVE_USERSEC_H
  free (this->private);
  free (this);
#endif
}

IRS_EXPORT struct protoent *
pr_next (struct irs_pr *this)
{
  LOOKUP_GETENT (this, _nss_ldap_filt_getprotoent, LM_PROTOCOLS,
		 _nss_ldap_parse_proto, LDAP_NSS_BUFLEN_DEFAULT);
}

IRS_EXPORT void
pr_rewind (struct irs_pr *this)
{
  LOOKUP_SETENT (this);
}

IRS_EXPORT void
pr_minimize (struct irs_pr *this)
{
}

#ifdef HAVE_USERSEC_H
void *
pr_pvtinit (void)
#else
struct irs_pr *
irs_ldap_pr (struct irs_acc *this)
#endif
{
  struct irs_pr *pr;
  struct pvt *pvt;

  pr = calloc (1, sizeof (*pr));
  if (pr == NULL)
    return NULL;

  pvt = calloc (1, sizeof (*pvt));
  if (pvt == NULL)
    {
      free (pr);
      return NULL;
    }

  pvt->state = NULL;
  pr->private = pvt;
  pr->close = pr_close;
  pr->next = pr_next;
  pr->byname = pr_byname;
  pr->bynumber = pr_bynumber;
  pr->rewind = pr_rewind;
  pr->minimize = pr_minimize;
  return pr;
}

#endif /*HAVE_IRS_H */
