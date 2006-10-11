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

/* $Id: irs-service.c,v 2.26 2005/05/20 05:30:40 lukeh Exp $ */

#ifdef HAVE_USERSEC_H
void *sv_pvtinit (void);
#endif
IRS_EXPORT void sv_close (struct irs_sv *);
IRS_EXPORT struct servent *sv_next (struct irs_sv *);
IRS_EXPORT struct servent *sv_byname (struct irs_sv *, const char *,
				      const char *);
IRS_EXPORT struct servent *sv_byport (struct irs_sv *, int, const char *);
IRS_EXPORT void sv_rewind (struct irs_sv *);
IRS_EXPORT void sv_minimize (struct irs_sv *);

struct pvt
{
  struct servent result;
  char buffer[NSS_BUFLEN_SERVICES];
  ent_context_t *state;
};

IRS_EXPORT struct servent *
sv_byname (struct irs_sv *this, const char *name, const char *proto)
{
  ldap_args_t a;
  struct pvt *pvt = (struct pvt *) this->private;
  NSS_STATUS s;

  LA_INIT (a);
  LA_STRING (a) = name;
  LA_TYPE (a) = (proto == NULL) ? LA_TYPE_STRING : LA_TYPE_STRING_AND_STRING;
  LA_STRING2 (a) = proto;
  s =
    _nss_ldap_getbyname (&a, &pvt->result, pvt->buffer, sizeof (pvt->buffer),
			 &errno,
			 (proto ==
			  NULL) ? _nss_ldap_filt_getservbyname :
			 _nss_ldap_filt_getservbynameproto,
			 LM_SERVICES, _nss_ldap_parse_serv);

  if (s != NSS_SUCCESS)
    {
      MAP_ERRNO (s, errno);
      return NULL;
    }
  return &pvt->result;
}

IRS_EXPORT struct servent *
sv_byport (struct irs_sv *this, int port, const char *proto)
{
  ldap_args_t a;
  struct pvt *pvt = (struct pvt *) this->private;
  NSS_STATUS s;

  LA_INIT (a);
  LA_NUMBER (a) = port;
  LA_TYPE (a) = (proto == NULL) ? LA_TYPE_NUMBER : LA_TYPE_NUMBER_AND_STRING;
  LA_STRING2 (a) = proto;
  s =
    _nss_ldap_getbyname (&a, &pvt->result, pvt->buffer, sizeof (pvt->buffer),
			 &errno,
			 (proto ==
			  NULL) ? _nss_ldap_filt_getservbyport :
			 _nss_ldap_filt_getservbyportproto,
			 LM_SERVICES, _nss_ldap_parse_serv);

  if (s != NSS_SUCCESS)
    {
      MAP_ERRNO (s, errno);
      return NULL;
    }
  return &pvt->result;
}

IRS_EXPORT void
sv_close (struct irs_sv *this)
{
  LOOKUP_ENDENT (this);
#ifdef HAVE_USERSEC_H
  free (this->private);
  free (this);
#endif
}

IRS_EXPORT struct servent *
sv_next (struct irs_sv *this)
{
  LOOKUP_GETENT (this, _nss_ldap_filt_getservent, LM_SERVICES,
		 _nss_ldap_parse_serv, LDAP_NSS_BUFLEN_DEFAULT);
}

IRS_EXPORT void
sv_rewind (struct irs_sv *this)
{
  LOOKUP_SETENT (this);
}

IRS_EXPORT void
sv_minimize (struct irs_sv *this)
{
}

#ifdef HAVE_USERSEC_H
void *
sv_pvtinit (void)
#else
struct irs_sv *
irs_ldap_sv (struct irs_acc *this)
#endif
{
  struct irs_sv *sv;
  struct pvt *pvt;

  sv = calloc (1, sizeof (*sv));
  if (sv == NULL)
    return NULL;

  pvt = calloc (1, sizeof (*pvt));
  if (pvt == NULL)
    {
      free (sv);
      return NULL;
    }

  pvt->state = NULL;
  sv->private = pvt;
  sv->close = sv_close;
  sv->next = sv_next;
  sv->byname = sv_byname;
  sv->byport = sv_byport;
  sv->rewind = sv_rewind;
  sv->minimize = sv_minimize;
  return sv;
}

#endif /*HAVE_IRS_H */
