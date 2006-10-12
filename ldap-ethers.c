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

   $Id$
 */


static char rcsId[] =
  "$Id$";

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

#if defined(HAVE_NSSWITCH_H) || defined(HAVE_NSS_H)

#ifdef HAVE_NSSWITCH_H
#ifdef HAVE_ETHER_ATON
extern struct ether_addr *ether_aton (const char *s);
#else
static struct ether_addr *ether_aton (const char *s);
#endif /* HAVE_ETHER_ATON */
#ifdef HAVE_ETHER_NTOA
extern char *ether_ntoa (const struct ether_addr *e);
#else
static char *ether_ntoa (const struct ether_addr *e);
#endif /* HAVE_ETHER_NTOA */
#endif /* HAVE_NSSWITCH_H */

#ifdef HAVE_NSS_H
static ent_context_t *ether_context = NULL;
#endif

static NSS_STATUS
_nss_ldap_parse_ether (LDAPMessage * e,
		       ldap_state_t * pvt,
		       void *result, char *buffer, size_t buflen)
{
  struct ether *ether = (struct ether *) result;
  char *saddr;
  NSS_STATUS stat;
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

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_gethostton_r (nss_backend_t * be, void *args)
{
  struct ether result;
  ldap_args_t a;
  char buffer[NSS_BUFLEN_ETHERS];
  NSS_STATUS status;

  LA_INIT (a);
  LA_STRING (a) = NSS_ARGS (args)->key.name;
  LA_TYPE (a) = LA_TYPE_STRING;

  status = _nss_ldap_getbyname (&a,
				&result,
				buffer,
				sizeof (buffer),
				&NSS_ARGS (args)->erange,
				_nss_ldap_filt_gethostton,
				LM_ETHERS, _nss_ldap_parse_ether);

  if (status == NSS_SUCCESS)
    {
      memcpy (NSS_ARGS (args)->buf.result, &result.e_addr,
	      sizeof (result.e_addr));
      NSS_ARGS (args)->returnval = NSS_ARGS (args)->buf.result;
    }

  return status;
}
#elif defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_gethostton_r (const char *name, struct ether * result,
			char *buffer, size_t buflen, int *errnop)
{
  LOOKUP_NAME (name, result, buffer, buflen, errnop,
	       _nss_ldap_filt_gethostton, LM_ETHERS, _nss_ldap_parse_ether,
	       LDAP_NSS_BUFLEN_DEFAULT);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_getntohost_r (nss_backend_t * be, void *args)
{
  struct ether result;
  char *addr;
  ldap_args_t a;
  char buffer[NSS_BUFLEN_ETHERS];
  NSS_STATUS status;

  addr = ether_ntoa ((struct ether_addr *) (NSS_ARGS (args)->key.ether));

  LA_INIT (a);
  LA_STRING (a) = addr;
  LA_TYPE (a) = LA_TYPE_STRING;

  status = _nss_ldap_getbyname (&a,
				&result,
				buffer,
				sizeof (buffer),
				&NSS_ARGS (args)->erange,
				_nss_ldap_filt_getntohost,
				LM_ETHERS, _nss_ldap_parse_ether);

  if (status == NSS_SUCCESS)
    {
      memcpy (NSS_ARGS (args)->buf.buffer, result.e_name,
	      strlen (result.e_name) + 1);
      NSS_ARGS (args)->returnval = NSS_ARGS (args)->buf.result =
				   NSS_ARGS (args)->buf.buffer;
      NSS_ARGS (args)->buf.buflen = strlen (result.e_name);
    }
  else
    {
      NSS_ARGS (args)->returnval = NULL;
    }

  return status;
}
#elif defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_getntohost_r (struct ether_addr * addr, struct ether * result,
			char *buffer, size_t buflen, int *errnop)
{
/* The correct ether_ntoa call would have a struct ether instead of whatever
   result->e_addr is */

  LOOKUP_NAME (ether_ntoa ((struct ether_addr *) (&result->e_addr)), result,
	       buffer, buflen, errnop, _nss_ldap_filt_getntohost, LM_ETHERS,
	       _nss_ldap_parse_ether, LDAP_NSS_BUFLEN_DEFAULT);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_setetherent_r (nss_backend_t * ether_context, void *fakeargs)
#elif defined(HAVE_NSS_H)
     NSS_STATUS _nss_ldap_setetherent (void)
#endif
#if defined(HAVE_NSSWITCH_H) || defined(HAVE_NSS_H)
{
  LOOKUP_SETENT (ether_context);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_endetherent_r (nss_backend_t * ether_context, void *fakeargs)
#elif defined(HAVE_NSS_H)
     NSS_STATUS _nss_ldap_endetherent (void)
#endif
#if defined(HAVE_NSS_H) || defined(HAVE_NSSWITCH_H)
{
  LOOKUP_ENDENT (ether_context);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_getetherent_r (nss_backend_t * ether_context, void *args)
{
  struct ether result;
  NSS_STATUS status;

  status = _nss_ldap_getent (&((nss_ldap_backend_t *) ether_context)->state,
			     &result,
			     NSS_ARGS (args)->buf.buffer,
			     NSS_ARGS (args)->buf.buflen,
			     &NSS_ARGS (args)->erange,
			     _nss_ldap_filt_getetherent,
			     LM_ETHERS, _nss_ldap_parse_ether);

  if (status == NSS_SUCCESS)
    {
      memcpy (NSS_ARGS (args)->buf.result, &result.e_addr,
	      sizeof (result.e_addr));
      NSS_ARGS (args)->returnval = NSS_ARGS (args)->buf.result;
    }
  else
    {
      NSS_ARGS (args)->returnval = NULL;
    }

  return status;
}
#elif defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_getetherent_r (struct ether * result, char *buffer, size_t buflen,
			 int *errnop)
{
  LOOKUP_GETENT (ether_context, result, buffer, buflen, errnop,
		 _nss_ldap_filt_getetherent, LM_ETHERS,
		 _nss_ldap_parse_ether, LDAP_NSS_BUFLEN_DEFAULT);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_ethers_destr (nss_backend_t * ether_context, void *args)
{
  return _nss_ldap_default_destr (ether_context, args);
}

static nss_backend_op_t ethers_ops[] = {
  _nss_ldap_ethers_destr,
  _nss_ldap_gethostton_r,
  _nss_ldap_getntohost_r
};

nss_backend_t *
_nss_ldap_ethers_constr (const char *db_name,
			 const char *src_name, const char *cfg_args)
{
  nss_ldap_backend_t *be;

  if (!(be = (nss_ldap_backend_t *) malloc (sizeof (*be))))
    return NULL;

  be->ops = ethers_ops;
  be->n_ops = sizeof (ethers_ops) / sizeof (nss_backend_op_t);

  if (_nss_ldap_default_constr (be) != NSS_SUCCESS)
    return NULL;

  return (nss_backend_t *) be;

}

#endif /* !HAVE_NSS_H */

#ifdef HAVE_NSSWITCH_H

#ifndef HAVE_ETHER_ATON
static struct ether_addr *ether_aton (const char *s)
{
	static struct ether_addr ep;
	register int i;
	unsigned int t[6];
        
	i = sscanf(s, " %x:%x:%x:%x:%x:%x",
		&t[0], &t[1], &t[2], &t[3], &t[4], &t[5]);
	if (i != 6)
		return NULL;
	for (i = 0; i < 6; i++)
		ep.ether_addr_octet[i] = t[i];

	return &ep;
}
#endif /* !HAVE_ETHER_ATON */

#ifndef HAVE_ETHER_NTOA
#define EI(i)	(unsigned int)(e->ether_addr_octet[(i)])
static char *ether_ntoa (const struct ether_addr *e)
{
	static char s[18];

	s[0] = 0;
	sprintf(s, "%x:%x:%x:%x:%x:%x",
		EI(0), EI(1), EI(2), EI(3), EI(4), EI(5));

	return s;
}
#endif /* !HAVE_ETHER_NTOA */

#endif /* HAVE_NSSWITCH_H */

#endif /* !HAVE_IRS_H */
