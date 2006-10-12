/* Copyright (C) 1997-2005 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@padl.com>, 1997.
   (The author maintains a non-exclusive licence to distribute this file
   under their own conditions.)

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

/*
 * Support DNS SRV records. I look up the SRV record for
 * _ldap._tcp.gnu.org.
 * and build the DN DC=gnu,DC=org.
 * Thanks to Assar & co for resolve.[ch].
 */

static char rcsId[] =
  "$Id$";

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>
#include <netdb.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#ifndef HAVE_SNPRINTF
#include "snprintf.h"
#endif

#include "ldap-nss.h"
#include "util.h"
#include "resolve.h"
#include "dnsconfig.h"


/* map gnu.org into DC=gnu,DC=org */
NSS_STATUS
_nss_ldap_getdnsdn (char *src_domain,
		    char **rval, char **buffer, size_t * buflen)
{
  char *p;
  int len = 0;
#ifdef HAVE_STRTOK_R
  char *st = NULL;
#endif
  char *bptr;
  char *domain, *domain_copy;

  /* we need to take a copy of domain, because strtok() modifies
   * it in place. Bad.
   */
  domain_copy = strdup (src_domain);
  if (domain_copy == NULL)
    {
      return NSS_TRYAGAIN;
    }

  domain = domain_copy;

  bptr = *rval = *buffer;
  **rval = '\0';

#ifndef HAVE_STRTOK_R
  while ((p = strtok (domain, ".")))
#else
  while ((p = strtok_r (domain, ".", &st)))
#endif
    {
      len = strlen (p);

      if (*buflen < (size_t) (len + DC_ATTR_AVA_LEN + 1 /* D C = [,|\0] */ ))
	{
	  free (domain_copy);
	  return NSS_TRYAGAIN;
	}

      if (domain == NULL)
	{
	  strcpy (bptr, ",");
	  bptr++;
	}
      else
	{
	  domain = NULL;
	}

      strcpy (bptr, DC_ATTR_AVA);
      bptr += DC_ATTR_AVA_LEN;

      strcpy (bptr, p);
      bptr += len;		/* don't include comma */
      *buffer += len + DC_ATTR_AVA_LEN + 1;
      *buflen -= len + DC_ATTR_AVA_LEN + 1;
    }

  if (bptr != NULL)
    {
      (*rval)[bptr - *rval] = '\0';
    }

  free (domain_copy);

  return NSS_SUCCESS;
}

NSS_STATUS
_nss_ldap_mergeconfigfromdns (ldap_config_t * result,
			      char **buffer, size_t *buflen)
{
  NSS_STATUS stat = NSS_SUCCESS;
  struct dns_reply *r;
  struct resource_record *rr;
  char domain[MAXHOSTNAMELEN + 1];
  char *pDomain;
  char uribuf[NSS_BUFSIZ];

  if ((_res.options & RES_INIT) == 0 && res_init () == -1)
    {
      return NSS_UNAVAIL;
    }

  if (result->ldc_srv_domain != NULL)
    pDomain = result->ldc_srv_domain;
  else
    {
      snprintf (domain, sizeof (domain), "_ldap._tcp.%s.", _res.defdname);
      pDomain = domain;
    }

  r = dns_lookup (pDomain, "srv");
  if (r == NULL)
    {
      return NSS_NOTFOUND;
    }

  /* XXX sort by priority */
  for (rr = r->head; rr != NULL; rr = rr->next)
    {
      if (rr->type == T_SRV)
	{
	  snprintf (uribuf, sizeof(uribuf), "ldap%s:%s:%d",
	    (rr->u.srv->port == LDAPS_PORT) ? "s" : "",
	    rr->u.srv->target,
	    rr->u.srv->port);

	  stat = _nss_ldap_add_uri (result, uribuf, buffer, buflen);
	  if (stat != NSS_SUCCESS)
	    {
	      break;
	    }
	}
    }

  dns_free_data (r);
  stat = NSS_SUCCESS;

  if (result->ldc_base == NULL)
    {
      stat = _nss_ldap_getdnsdn (_res.defdname, &result->ldc_base,
				 buffer, buflen);
    }

  return stat;
}

