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

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#ifdef INET6
#include <resolv/mapv4v6addr.h>
#endif

#ifndef MAXALIASES
#define MAXALIASES 35
#endif

#include "ldap-nss.h"
#include "ldap-hosts.h"
#include "util.h"

#ifdef HAVE_PORT_AFTER_H
#include <port_after.h>
#endif

#ifdef HAVE_NSS_H
static ent_context_t *hosts_context = NULL;
#endif

static NSS_STATUS
_nss_ldap_parse_hostv4 (LDAPMessage * e,
			ldap_state_t * pvt,
			void *result, char *buffer, size_t buflen)
{
  return _nss_ldap_parse_host (e, pvt, result, buffer, buflen,
			       AF_INET);
}

#ifdef INET6
static NSS_STATUS
_nss_ldap_parse_hostv6 (LDAPMessage * e,
			ldap_state_t * pvt,
			void *result, char *buffer, size_t buflen)
{
  return _nss_ldap_parse_host (e, pvt, result, buffer, buflen,
			       AF_INET6);
}
#endif

static NSS_STATUS
_nss_ldap_parse_host (LDAPMessage * e,
		      ldap_state_t * pvt,
		      void *result, char *buffer, size_t buflen,
		      int af)
{
  /* this code needs reviewing. XXX */
  struct hostent *host = (struct hostent *) result;
  NSS_STATUS stat;
#ifdef INET6
  char addressbuf[sizeof ("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") *
		  MAXALIASES];
#else
  char addressbuf[sizeof ("255.255.255.255") * MAXALIASES];
#endif
  char *p_addressbuf = addressbuf;
  char **addresses = NULL;
  size_t addresslen = sizeof (addressbuf);
  size_t addresscount = 0;
  char **host_addresses = NULL;
  int i;

  *addressbuf = *buffer = '\0';

  stat = _nss_ldap_assign_attrval (e, ATM (LM_HOSTS, cn), &host->h_name,
				   &buffer, &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrvals (e, ATM (LM_HOSTS, cn), host->h_name,
                               &host->h_aliases, &buffer, &buflen, NULL);
  if (stat != NSS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrvals (e, AT (ipHostNumber), NULL, &addresses,
			       &p_addressbuf, &addresslen, &addresscount);
  if (stat != NSS_SUCCESS)
    return stat;
  if (addresscount == 0)
    return NSS_NOTFOUND;

#ifdef INET6
  if (af == AF_INET6)
    {
      if (bytesleft (buffer, buflen, char *) <
	  (size_t) ((addresscount + 1) * IN6ADDRSZ))
	  return NSS_TRYAGAIN;
    }
  else
    {
      if (bytesleft (buffer, buflen, char *) <
	  (size_t) ((addresscount + 1) * INADDRSZ))
	  return NSS_TRYAGAIN;
    }
#else
  if (bytesleft (buffer, buflen, char *) <
      (size_t) ((addresscount + 1) * INADDRSZ))
      return NSS_TRYAGAIN;
#endif

  align (buffer, buflen, char *);
  host_addresses = (char **) buffer;
  host->h_addr_list = host_addresses;
  host_addresses[addresscount] = NULL;

  buffer += (addresscount + 1) * sizeof (char *);
  buflen -= (addresscount + 1) * sizeof (char *);
#ifdef INET6
  host->h_addrtype = 0;
  host->h_length = 0;
#else
  host->h_addrtype = AF_INET;
  host->h_length = INADDRSZ;
#endif

  for (i = 0; i < (int) addresscount; i++)
    {
#ifdef INET6
      char *addr = addresses[i];
      char entdata[16];
      /* from glibc NIS parser. Thanks, Uli. */

      if (af == AF_INET && inet_pton (AF_INET, addr, entdata) > 0)
	{
	  if (_res.options & RES_USE_INET6)
	    {
	      map_v4v6_address ((char *) entdata,
				(char *) entdata);
	      host->h_addrtype = AF_INET6;
	      host->h_length = IN6ADDRSZ;
	    }
	  else
	    {
	      host->h_addrtype = AF_INET;
	      host->h_length = INADDRSZ;
	    }
	}
      else if (af == AF_INET6
	       && inet_pton (AF_INET6, addr, entdata) > 0)
	{
	  host->h_addrtype = AF_INET6;
	  host->h_length = IN6ADDRSZ;
	}
      else
	/* Illegal address: ignore line.  */
	continue;

#else
      unsigned long haddr;
      haddr = inet_addr (addresses[i]);
#endif

      if (buflen < (size_t) host->h_length)
	return NSS_TRYAGAIN;

#ifdef INET6
      memcpy (buffer, entdata, host->h_length);
      *host_addresses = buffer;
      buffer += host->h_length;
      buflen -= host->h_length;
#else
      memcpy (buffer, &haddr, INADDRSZ);
      *host_addresses = buffer;
      buffer += INADDRSZ;
      buflen -= INADDRSZ;
#endif

      host_addresses++;
      *host_addresses = NULL;
    }

#ifdef INET6
  /* if host->h_addrtype is not changed, this entry does not
     have the right IP address.  */
  if (host->h_addrtype == 0)
    return NSS_NOTFOUND;
#endif

  return NSS_SUCCESS;
}

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_gethostbyname_r (nss_backend_t * be, void *args)
{
  ldap_args_t a;
  NSS_STATUS status;

  LA_INIT (a);
  LA_STRING (a) = NSS_ARGS (args)->key.name;
  LA_TYPE (a) = LA_TYPE_STRING;

  status = _nss_ldap_getbyname (&a,
				NSS_ARGS (args)->buf.result,
				NSS_ARGS (args)->buf.buffer,
				NSS_ARGS (args)->buf.buflen,
				&NSS_ARGS (args)->erange,
				_nss_ldap_filt_gethostbyname,
				LM_HOSTS, _nss_ldap_parse_hostv4);

  if (status == NSS_SUCCESS)
    NSS_ARGS (args)->returnval = NSS_ARGS (args)->buf.result;

  MAP_H_ERRNO (status, NSS_ARGS (args)->h_errno);

  return status;
}
#elif defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_gethostbyname2_r (const char *name, int af, struct hostent * result,
			    char *buffer, size_t buflen, int *errnop,
			    int *h_errnop)
{
  NSS_STATUS status;
  ldap_args_t a;

  LA_INIT (a);
  LA_STRING (a) = name;
  LA_TYPE (a) = LA_TYPE_STRING;

  status = _nss_ldap_getbyname (&a,
				result,
				buffer,
				buflen,
				errnop,
				_nss_ldap_filt_gethostbyname,
				LM_HOSTS,
#ifdef INET6
				(af == AF_INET6) ?
				_nss_ldap_parse_hostv6 :
#endif
				_nss_ldap_parse_hostv4);

  MAP_H_ERRNO (status, *h_errnop);

  return status;
}

NSS_STATUS
_nss_ldap_gethostbyname_r (const char *name, struct hostent * result,
			   char *buffer, size_t buflen, int *errnop,
			   int *h_errnop)
{
  return _nss_ldap_gethostbyname2_r (name,
#ifdef INET6
				     (_res.options & RES_USE_INET6) ?
				     AF_INET6 :
#endif
				     AF_INET, result, buffer, buflen,
				     errnop, h_errnop);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_gethostbyaddr_r (nss_backend_t * be, void *args)
{
  struct in_addr iaddr;
  ldap_args_t a;
  NSS_STATUS status;

  memcpy (&iaddr.s_addr, NSS_ARGS (args)->key.hostaddr.addr,
	  NSS_ARGS (args)->key.hostaddr.len);
  LA_INIT (a);
  LA_STRING (a) = inet_ntoa (iaddr);
  LA_TYPE (a) = LA_TYPE_STRING;

  status = _nss_ldap_getbyname (&a,
				NSS_ARGS (args)->buf.result,
				NSS_ARGS (args)->buf.buffer,
				NSS_ARGS (args)->buf.buflen,
				&NSS_ARGS (args)->erange,
				_nss_ldap_filt_gethostbyaddr,
				LM_HOSTS, _nss_ldap_parse_hostv4);

  if (status == NSS_SUCCESS)
    NSS_ARGS (args)->returnval = NSS_ARGS (args)->buf.result;

  MAP_H_ERRNO (status, NSS_ARGS (args)->h_errno);

  return status;
}
#elif defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_gethostbyaddr_r (struct in_addr * addr, int len, int type,
			   struct hostent * result, char *buffer,
			   size_t buflen, int *errnop, int *h_errnop)
{
  NSS_STATUS status;
  ldap_args_t a;

  /* if querying by IPv6 address, make sure the address is "normalized" --
   * it should contain no leading zeros and all components of the address.
   * still we can't fit an IPv6 address in an int, so who cares for now.
   */

  LA_INIT (a);
  LA_STRING (a) = inet_ntoa (*addr);
  LA_TYPE (a) = LA_TYPE_STRING;

  status = _nss_ldap_getbyname (&a,
				result,
				buffer,
				buflen,
				errnop,
				_nss_ldap_filt_gethostbyaddr,
				LM_HOSTS,
#ifdef INET6
				(type == AF_INET6) ?
				_nss_ldap_parse_hostv6 :
#endif
				_nss_ldap_parse_hostv4);

  MAP_H_ERRNO (status, *h_errnop);

  return status;
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_sethostent_r (nss_backend_t * hosts_context, void *fakeargs)
#elif defined(HAVE_NSS_H)
     NSS_STATUS _nss_ldap_sethostent (void)
#endif
#if defined(HAVE_NSS_H) || defined(HAVE_NSSWITCH_H)
{
  LOOKUP_SETENT (hosts_context);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_endhostent_r (nss_backend_t * hosts_context, void *fakeargs)
#elif defined(HAVE_NSS_H)
     NSS_STATUS _nss_ldap_endhostent (void)
#endif
#if defined(HAVE_NSS_H) || defined(HAVE_NSSWITCH_H)
{
  LOOKUP_ENDENT (hosts_context);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_gethostent_r (nss_backend_t * hosts_context, void *args)
{
  NSS_STATUS status = _nss_ldap_getent (&((nss_ldap_backend_t *)
					  hosts_context)->state,
					NSS_ARGS (args)->buf.result,
					NSS_ARGS (args)->buf.buffer,
					NSS_ARGS (args)->buf.buflen,
					&NSS_ARGS (args)->erange,
					_nss_ldap_filt_gethostent,
					LM_HOSTS,
					_nss_ldap_parse_hostv4);

  if (status == NSS_SUCCESS)
    NSS_ARGS (args)->returnval = NSS_ARGS (args)->buf.result;

  MAP_H_ERRNO (status, NSS_ARGS (args)->h_errno);

  return status;
}
#elif defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_gethostent_r (struct hostent * result, char *buffer, size_t buflen,
			int *errnop, int *h_errnop)
{
  NSS_STATUS status;

  status = _nss_ldap_getent (&hosts_context,
			     result,
			     buffer,
			     buflen,
			     errnop,
			     _nss_ldap_filt_gethostent, LM_HOSTS,
#ifdef INET6
			     (_res.options & RES_USE_INET6) ?
			     _nss_ldap_parse_hostv6 :
#endif
			     _nss_ldap_parse_hostv4);

  MAP_H_ERRNO (status, *h_errnop);

  return status;
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_hosts_destr (nss_backend_t * hosts_context, void *args)
{
  return _nss_ldap_default_destr (hosts_context, args);
}

static nss_backend_op_t host_ops[] = {
  _nss_ldap_hosts_destr,
  _nss_ldap_endhostent_r,
  _nss_ldap_sethostent_r,
  _nss_ldap_gethostent_r,
  _nss_ldap_gethostbyname_r,
  _nss_ldap_gethostbyaddr_r
};

nss_backend_t *
_nss_ldap_hosts_constr (const char *db_name,
			const char *src_name, const char *cfg_args)
{
  nss_ldap_backend_t *be;

  if (!(be = (nss_ldap_backend_t *) malloc (sizeof (*be))))
    return NULL;

  be->ops = host_ops;
  be->n_ops = sizeof (host_ops) / sizeof (nss_backend_op_t);

  if (_nss_ldap_default_constr (be) != NSS_SUCCESS)
    return NULL;

  return (nss_backend_t *) be;
}

#endif /* !HAVE_NSS_H */

#ifdef HAVE_IRS_H
#include "irs-hosts.c"
#endif
