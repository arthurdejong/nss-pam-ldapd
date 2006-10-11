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

/* $Id: irs-pwd.c,v 2.24 2005/05/20 05:30:40 lukeh Exp $ */

#ifdef HAVE_USERSEC_H
void *pw_pvtinit (void);
#endif
IRS_EXPORT void pw_close (struct irs_pw *);
IRS_EXPORT struct passwd *pw_next (struct irs_pw *);
IRS_EXPORT struct passwd *pw_byname (struct irs_pw *, const char *);
IRS_EXPORT struct passwd *pw_byuid (struct irs_pw *, uid_t);
IRS_EXPORT void pw_rewind (struct irs_pw *);
IRS_EXPORT void pw_minimize (struct irs_pw *);

struct pvt
{
  struct passwd result;
  char buffer[NSS_BUFLEN_PASSWD];
  ent_context_t *state;
};

IRS_EXPORT struct passwd *
pw_byname (struct irs_pw *this, const char *name)
{
  LOOKUP_NAME (name, this, _nss_ldap_filt_getpwnam, LM_PASSWD,
	       _nss_ldap_parse_pw, LDAP_NSS_BUFLEN_DEFAULT);
}

IRS_EXPORT struct passwd *
pw_byuid (struct irs_pw *this, uid_t uid)
{
  LOOKUP_NUMBER (uid, this, _nss_ldap_filt_getpwuid, LM_PASSWD,
		 _nss_ldap_parse_pw, LDAP_NSS_BUFLEN_DEFAULT);
}

IRS_EXPORT void
pw_close (struct irs_pw *this)
{
  LOOKUP_ENDENT (this);
#ifdef HAVE_USERSEC_H
  free (this->private);
  free (this);
#endif
}

IRS_EXPORT struct passwd *
pw_next (struct irs_pw *this)
{
  LOOKUP_GETENT (this, _nss_ldap_filt_getpwent, LM_PASSWD,
		 _nss_ldap_parse_pw, LDAP_NSS_BUFLEN_DEFAULT);
}

IRS_EXPORT void
pw_rewind (struct irs_pw *this)
{
  LOOKUP_SETENT (this);
}

IRS_EXPORT void
pw_minimize (struct irs_pw *this)
{
}

#ifdef HAVE_USERSEC_H
void *
pw_pvtinit (void)
#else
struct irs_pw *
irs_ldap_pw (struct irs_acc *this)
#endif
{
  struct irs_pw *pw;
  struct pvt *pvt;

  pw = calloc (1, sizeof (*pw));
  if (pw == NULL)
    return NULL;

  pvt = calloc (1, sizeof (*pvt));
  if (pvt == NULL)
    {
      free (pw);
      return NULL;
    }

  pvt->state = NULL;
  pw->private = pvt;
  pw->close = pw_close;
  pw->next = pw_next;
  pw->byname = pw_byname;
  pw->byuid = pw_byuid;
  pw->rewind = pw_rewind;
  pw->minimize = pw_minimize;
  return pw;
}

#endif /*HAVE_IRS_H */
