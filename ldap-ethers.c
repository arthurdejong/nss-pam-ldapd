/* 
   Copyright (C) 1997-2005 Luke Howard
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

   $Id$
*/

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
#include <netdb.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>
#endif
#include <net/if.h>
#include <netinet/in.h>

#ifdef HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif

#ifdef HAVE_NETINET_ETHER_H
#include <netinet/ether.h>
#endif

#include "ldap-nss.h"
#include "ldap-ethers.h"
#include "util.h"

#ifdef HAVE_PORT_AFTER_H
#include <port_after.h>
#endif

#ifndef NSS_BUFLEN_ETHERS
/* for HP-UX */
#define NSS_BUFLEN_ETHERS 1024
#endif /* NSS_BUFLEN_ETHERS */


static ent_context_t *ether_context = NULL;

static enum nss_status
_nss_ldap_parse_ether (LDAPMessage * e,
		       ldap_state_t * pvt,
		       void *result, char *buffer, size_t buflen)
{
  struct ether *ether = (struct ether *) result;
  char *saddr;
  enum nss_status stat;
  struct ether_addr *addr;

  stat = _nss_ldap_assign_attrval (e, ATM (LM_ETHERS, cn),
				   &ether->e_name, &buffer, &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

  stat = _nss_ldap_assign_attrval (e, AT (macAddress), &saddr,
				   &buffer, &buflen);

  if (stat != NSS_SUCCESS || ((addr = ether_aton (saddr)) == NULL))
    return NSS_NOTFOUND;

  memcpy (&ether->e_addr, addr, sizeof (*addr));

  return NSS_SUCCESS;
}

enum nss_status
_nss_ldap_gethostton_r (const char *name, struct ether * result,
			char *buffer, size_t buflen, int *errnop)
{
  LOOKUP_NAME (name, result, buffer, buflen, errnop,
	       _nss_ldap_filt_gethostton, LM_ETHERS, _nss_ldap_parse_ether,
	       LDAP_NSS_BUFLEN_DEFAULT);
}

enum nss_status
_nss_ldap_getntohost_r (struct ether_addr * addr, struct ether * result,
			char *buffer, size_t buflen, int *errnop)
{
/* The correct ether_ntoa call would have a struct ether instead of whatever
   result->e_addr is */

  LOOKUP_NAME (ether_ntoa ((struct ether_addr *) (&result->e_addr)), result,
	       buffer, buflen, errnop, _nss_ldap_filt_getntohost, LM_ETHERS,
	       _nss_ldap_parse_ether, LDAP_NSS_BUFLEN_DEFAULT);
}

     enum nss_status _nss_ldap_setetherent (void)
{
  LOOKUP_SETENT (ether_context);
}

     enum nss_status _nss_ldap_endetherent (void)
{
  LOOKUP_ENDENT (ether_context);
}

enum nss_status
_nss_ldap_getetherent_r (struct ether * result, char *buffer, size_t buflen,
			 int *errnop)
{
  LOOKUP_GETENT (ether_context, result, buffer, buflen, errnop,
		 _nss_ldap_filt_getetherent, LM_ETHERS,
		 _nss_ldap_parse_ether, LDAP_NSS_BUFLEN_DEFAULT);
}
