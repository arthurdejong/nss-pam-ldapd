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

/* $Id: irs-network.c,v 2.25 2005/05/20 05:30:39 lukeh Exp $ */

#ifdef HAVE_USERSEC_H
void *nw_pvtinit (void);
#endif
IRS_EXPORT void nw_close (struct irs_nw *);
IRS_EXPORT struct nwent *nw_byname (struct irs_nw *, const char *, int);
IRS_EXPORT struct nwent *nw_byaddr (struct irs_nw *, void *, int, int);
IRS_EXPORT struct nwent *nw_next (struct irs_nw *);
IRS_EXPORT void nw_rewind (struct irs_nw *);
IRS_EXPORT void nw_minimize (struct irs_nw *);

struct pvt
{
  struct nwent result;
  char buffer[NSS_BUFLEN_NETWORKS];
  ent_context_t *state;
};

IRS_EXPORT struct nwent *
nw_byname (struct irs_nw *this, const char *name, int af)
{
  NSS_STATUS s;
  struct pvt *pvt = (struct pvt *) this->private;
  ldap_args_t a;

  LA_INIT (a);
  LA_STRING (a) = name;
  LA_TYPE (a) = LA_TYPE_STRING;

  if (af != AF_INET)
    {
      h_errno = NETDB_INTERNAL;
      errno = EAFNOSUPPORT;
      return (NULL);
    }

  s = _nss_ldap_getbyname (&a,
			   &pvt->result,
			   pvt->buffer,
			   sizeof (pvt->buffer),
			   &errno,
			   _nss_ldap_filt_getnetbyname,
			   LM_NETWORKS, _nss_ldap_parse_net);

  if (s != NSS_SUCCESS)
    {
      MAP_H_ERRNO (s, h_errno);
      return NULL;
    }
  return &pvt->result;
}

IRS_EXPORT struct nwent *
nw_byaddr (struct irs_nw *this, void *net, int length, int af)
{
  ldap_args_t a;
  NSS_STATUS s;
  struct pvt *pvt = (struct pvt *) this->private;
  char tmp[sizeof "255.255.255.255/32"], *t;

  if (af != AF_INET)
    {
      h_errno = NETDB_INTERNAL;
      errno = EAFNOSUPPORT;
      return (NULL);
    }

  /* Try it with /CIDR first. */
  if (inet_net_ntop (AF_INET, net, length, tmp, sizeof tmp) == NULL)
    {
      h_errno = NETDB_INTERNAL;
      return (NULL);
    }

  LA_INIT (a);
  LA_STRING (a) = tmp;
  LA_TYPE (a) = LA_TYPE_STRING;

  s = _nss_ldap_getbyname (&a,
			   &pvt->result,
			   pvt->buffer,
			   sizeof (pvt->buffer),
			   &errno,
			   _nss_ldap_filt_getnetbyaddr,
			   LM_NETWORKS, _nss_ldap_parse_net);

  if (s != NSS_SUCCESS)
    {
      if ((t = strchr (tmp, '/')) != NULL)
	{
	  *t = '\0';
	  s = _nss_ldap_getbyname (&a,
				   &pvt->result,
				   pvt->buffer,
				   sizeof (pvt->buffer),
				   &errno,
				   _nss_ldap_filt_getnetbyaddr,
				   LM_NETWORKS, _nss_ldap_parse_net);
	  if (s != NSS_SUCCESS)
	    {
	      MAP_H_ERRNO (s, h_errno);
	      return (NULL);
	    }
	}
    }

  return &pvt->result;
}

IRS_EXPORT void
nw_close (struct irs_nw *this)
{
  LOOKUP_ENDENT (this);
#ifdef HAVE_USERSEC_H
  free (this->private);
  free (this);
#endif
}

IRS_EXPORT struct nwent *
nw_next (struct irs_nw *this)
{
  struct pvt *pvt = (struct pvt *) this->private;
  NSS_STATUS s;

  s = _nss_ldap_getent (&pvt->state,
			&pvt->result,
			pvt->buffer,
			sizeof (pvt->buffer),
			&errno,
			_nss_ldap_filt_getnetent,
			LM_NETWORKS, _nss_ldap_parse_net);

  if (s != NSS_SUCCESS)
    {
      MAP_H_ERRNO (s, h_errno);
      return NULL;
    }
  return &pvt->result;
}

IRS_EXPORT void
nw_rewind (struct irs_nw *this)
{
  LOOKUP_SETENT (this);
}

IRS_EXPORT void
nw_minimize (struct irs_nw *this)
{
}

#ifdef HAVE_USERSEC_H
void *
nw_pvtinit (void)
#else
struct irs_nw *
irs_ldap_nw (struct irs_acc *this)
#endif
{
  struct irs_nw *nw;
  struct pvt *pvt;

  nw = calloc (1, sizeof (*nw));
  if (nw == NULL)
    return NULL;

  pvt = calloc (1, sizeof (*pvt));
  if (pvt == NULL)
    {
      free (nw);
      return NULL;
    }

  pvt->state = NULL;
  nw->private = pvt;
  nw->close = nw_close;
  nw->next = nw_next;
  nw->byname = nw_byname;
/*      nw->byname2 = nw_byname2; */
  nw->byaddr = nw_byaddr;
  nw->rewind = nw_rewind;
  nw->minimize = nw_minimize;
  return nw;
}

#endif /*HAVE_IRS_H */
