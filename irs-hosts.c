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

/* $Id: irs-hosts.c,v 2.26 2005/05/20 05:30:39 lukeh Exp $ */

#ifdef HAVE_USERSEC_H
void *ho_pvtinit (void);
#endif
IRS_EXPORT void ho_close (struct irs_ho *this);
IRS_EXPORT struct hostent *ho_byname (struct irs_ho *this, const char *name);
IRS_EXPORT struct hostent *ho_byname2 (struct irs_ho *this, const char *name,
				       int af);
IRS_EXPORT struct hostent *ho_byaddr (struct irs_ho *this, const void *addr,
				      int len, int af);
IRS_EXPORT struct hostent *ho_next (struct irs_ho *this);
IRS_EXPORT void ho_rewind (struct irs_ho *this);
IRS_EXPORT void ho_minimize (struct irs_ho *this);


static const u_char mapped[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
static const u_char tunnelled[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

struct pvt
{
  struct hostent result;
  char buffer[NSS_BUFLEN_HOSTS];
  ent_context_t *state;
};

IRS_EXPORT struct hostent *
ho_byname (struct irs_ho *this, const char *name)
{
  NSS_STATUS s;
  struct pvt *pvt = (struct pvt *) this->private;
  ldap_args_t a;

  LA_INIT (a);
  LA_STRING (a) = name;
  LA_TYPE (a) = LA_TYPE_STRING;

  s = _nss_ldap_getbyname (&a,
			   &pvt->result,
			   pvt->buffer,
			   sizeof (pvt->buffer),
			   &errno,
			   _nss_ldap_filt_gethostbyname,
			   LM_HOSTS, _nss_ldap_parse_hostv4);

  if (s != NSS_SUCCESS)
    {
      MAP_H_ERRNO (s, h_errno);
      return NULL;
    }
  return &pvt->result;
}

IRS_EXPORT struct hostent *
ho_byaddr (struct irs_ho *this, const void *addr, int len, int af)
{
  struct pvt *pvt = (struct pvt *) this->private;
  char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
  const u_char *uaddr = addr;
  NSS_STATUS s;
  ldap_args_t a;

  if (af == AF_INET6 && len == IN6ADDRSZ
      && (!memcmp (uaddr, mapped, sizeof mapped) ||
	  !memcmp (uaddr, tunnelled, sizeof tunnelled)))
    {
      /* Unmap. */
      addr = (u_char *) addr + sizeof mapped;
      uaddr += sizeof mapped;
      af = AF_INET;
      len = INADDRSZ;
    }
  if (inet_ntop (af, uaddr, tmp, sizeof tmp) == NULL)
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
			   _nss_ldap_filt_gethostbyaddr,
			   LM_HOSTS, _nss_ldap_parse_hostv4);

  if (s != NSS_SUCCESS)
    {
      MAP_H_ERRNO (s, h_errno);
      return NULL;
    }
  return &pvt->result;
}

IRS_EXPORT void
ho_close (struct irs_ho *this)
{
  LOOKUP_ENDENT (this);
#ifdef HAVE_USERSEC_H
  free (this->private);
  free (this);
#endif
}

IRS_EXPORT struct hostent *
ho_next (struct irs_ho *this)
{
  struct pvt *pvt = (struct pvt *) this->private;
  NSS_STATUS s;

  s = _nss_ldap_getent (&pvt->state,
			&pvt->result,
			pvt->buffer,
			sizeof (pvt->buffer),
			&errno,
			_nss_ldap_filt_gethostent,
			LM_HOSTS, _nss_ldap_parse_hostv4);

  if (s != NSS_SUCCESS)
    {
      MAP_H_ERRNO (s, h_errno);
      return NULL;
    }
  return &pvt->result;
}

IRS_EXPORT void
ho_rewind (struct irs_ho *this)
{
  LOOKUP_SETENT (this);
}

IRS_EXPORT void
ho_minimize (struct irs_ho *this)
{
}

#ifdef HAVE_USERSEC_H
void *
ho_pvtinit (void)
#else
struct irs_ho *
irs_ldap_ho (struct irs_acc *this)
#endif
{
  struct irs_ho *ho;
  struct pvt *pvt;

  ho = calloc (1, sizeof (*ho));
  if (ho == NULL)
    return NULL;

  pvt = calloc (1, sizeof (*pvt));
  if (pvt == NULL)
    {
      free (ho);
      return NULL;
    }

  pvt->state = NULL;
  ho->private = pvt;
  ho->close = ho_close;
  ho->next = ho_next;
  ho->byname = ho_byname;
/*      ho->byname2 = ho_byname2; */
  ho->byaddr = ho_byaddr;
  ho->rewind = ho_rewind;
  ho->minimize = ho_minimize;
  return ho;
}

#endif /*HAVE_IRS_H */
