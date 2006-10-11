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

   $Id: ldap-alias.c,v 2.31 2006/01/11 18:03:48 lukeh Exp $
 */


static char rcsId[] =
  "$Id: ldap-alias.c,v 2.31 2006/01/11 18:03:48 lukeh Exp $";

#include "config.h"

#ifdef HAVE_PORT_BEFORE_H
#include <port_before.h>
#endif

#if defined(HAVE_THREAD_H) && !defined(_AIX)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lber.h>
#include <ldap.h>

#ifdef HAVE_ALIASES_H
#include <aliases.h>

#include "ldap-nss.h"
#include "ldap-alias.h"
#include "util.h"

#ifdef HAVE_PORT_AFTER_H
#include <port_after.h>
#endif

#ifdef HAVE_NSS_H
static ent_context_t *alias_context = NULL;

static NSS_STATUS
_nss_ldap_parse_alias (LDAPMessage * e,
		       ldap_state_t * pvt,
		       void *result, char *buffer, size_t buflen)
{

  struct aliasent *alias = (struct aliasent *) result;
  NSS_STATUS stat;

  stat =
    _nss_ldap_getrdnvalue (e, ATM (LM_ALIASES, cn), &alias->alias_name,
                           &buffer, &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrvals (e, AT (rfc822MailMember), NULL,
			       &alias->alias_members, &buffer, &buflen,
			       &alias->alias_members_len);

  alias->alias_local = 0;

  return stat;
}

NSS_STATUS
_nss_ldap_getaliasbyname_r (const char *name, struct aliasent * result,
			    char *buffer, size_t buflen, int *errnop)
{
  LOOKUP_NAME (name, result, buffer, buflen, errnop,
	       _nss_ldap_filt_getaliasbyname, LM_ALIASES,
	       _nss_ldap_parse_alias, LDAP_NSS_BUFLEN_DEFAULT);
}

NSS_STATUS _nss_ldap_setaliasent (void)
{
  LOOKUP_SETENT (alias_context);
}

NSS_STATUS _nss_ldap_endaliasent (void)
{
  LOOKUP_ENDENT (alias_context);
}

NSS_STATUS
_nss_ldap_getaliasent_r (struct aliasent *result, char *buffer, size_t buflen,
			 int *errnop)
{
  LOOKUP_GETENT (alias_context, result, buffer, buflen, errnop,
		 _nss_ldap_filt_getaliasent, LM_ALIASES,
		 _nss_ldap_parse_alias, LDAP_NSS_BUFLEN_DEFAULT);
}

#endif /* HAVE_NSS_H */
#endif /* HAVE_ALIASES_H */
