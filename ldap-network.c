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

/* parts based on nss_nis */

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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <sys/socket.h>
#include <errno.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#include "ldap-nss.h"
#include "ldap-network.h"
#include "util.h"

#if defined(HAVE_IRS_H) || defined(HAVE_USERSEC_H)
#define MAXALIASES 35
#define MAXADDRSIZE 4
#endif /* HAVE_IRS_H || HAVE_USERSEC_H */

#ifdef HAVE_PORT_AFTER_H
#include <port_after.h>
#endif

#ifdef HAVE_NSS_H
static ent_context_t *net_context = NULL;
#endif

static NSS_STATUS
_nss_ldap_parse_net (LDAPMessage * e,
		     ldap_state_t * pvt,
		     void *result, char *buffer, size_t buflen)
{

  char *tmp;
#ifdef HAVE_IRS_H
  struct nwent *network = (struct nwent *) result;
  unsigned char *addr;
#else
  struct netent *network = (struct netent *) result;
#endif
  NSS_STATUS stat;

  /* IPv6 support ? XXX */
  network->n_addrtype = AF_INET;

  stat = _nss_ldap_assign_attrval (e, ATM (LM_NETWORKS, cn), &network->n_name,
				   &buffer, &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrval (e, AT (ipNetworkNumber), &tmp, &buffer,
			      &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

#ifdef HAVE_IRS_H
  if (buflen < MAXADDRSIZE)
    return NSS_TRYAGAIN;
  addr = buffer;
  buffer += MAXADDRSIZE;
  buffer -= MAXADDRSIZE;
  network->n_length = inet_net_pton (AF_INET, tmp, &addr, MAXADDRSIZE);
  network->n_addr = addr;
#else
  network->n_net = inet_network (tmp);
#endif

  stat =
    _nss_ldap_assign_attrvals (e, ATM (LM_NETWORKS, cn), network->n_name,
			       &network->n_aliases, &buffer, &buflen, NULL);
  if (stat != NSS_SUCCESS)
    return stat;

  return NSS_SUCCESS;
}

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_getnetbyname_r (nss_backend_t * be, void *args)
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
				_nss_ldap_filt_getnetbyname,
				LM_NETWORKS, _nss_ldap_parse_net);

  if (status == NSS_SUCCESS)
    NSS_ARGS (args)->returnval = NSS_ARGS (args)->buf.result;

  MAP_H_ERRNO (status, NSS_ARGS (args)->h_errno);

  return status;
}
#elif defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_getnetbyname_r (const char *name, struct netent * result,
			  char *buffer, size_t buflen, int *errnop,
			  int *herrnop)
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
				_nss_ldap_filt_getnetbyname,
				LM_NETWORKS, _nss_ldap_parse_net);

  MAP_H_ERRNO (status, *herrnop);

  return status;
}
#endif

#if defined(HAVE_NSSWITCH_H) || defined(HAVE_NSS_H)
#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_getnetbyaddr_r (nss_backend_t * be, void *args)
#else
NSS_STATUS
_nss_ldap_getnetbyaddr_r (unsigned long addr, int type,
			  struct netent * result, char *buffer, size_t buflen,
			  int *errnop, int *herrnop)
#endif
{
  struct in_addr in;
  char buf[256];
  int blen;
  ldap_args_t a;
  NSS_STATUS retval = NSS_NOTFOUND;

  LA_INIT (a);
  LA_TYPE (a) = LA_TYPE_STRING;

#ifdef HAVE_NSSWITCH_H
  in = inet_makeaddr (NSS_ARGS (args)->key.netaddr.net, 0);
#else
  in = inet_makeaddr (addr, 0);
#endif
  strcpy (buf, inet_ntoa (in));
  blen = strlen (buf);
  LA_STRING (a) = buf;

  while (1)
    {
#ifdef HAVE_NSSWITCH_H
      retval =
	_nss_ldap_getbyname (&a, NSS_ARGS (args)->buf.result,
			     NSS_ARGS (args)->buf.buffer,
			     NSS_ARGS (args)->buf.buflen,
			     &NSS_ARGS (args)->erange,
#else
      retval = _nss_ldap_getbyname (&a, result, buffer, buflen, errnop,
#endif
				    _nss_ldap_filt_getnetbyaddr,
				    LM_NETWORKS, _nss_ldap_parse_net);

      if (retval != NSS_SUCCESS)
	{
	  if (retval == NSS_NOTFOUND)
	    {
	      if (buf[blen - 2] == '.' && buf[blen - 1] == '\0')
		{
		  buf[blen - 2] = '\0';
		  blen -= 2;
		  continue;
		}
	      else
		{
#ifdef HAVE_NSSWITCH_H
		  NSS_ARGS (args)->returnval = NULL;
		  MAP_H_ERRNO (retval, NSS_ARGS (args)->h_errno);
#else
		  MAP_H_ERRNO (retval, *herrnop);
#endif
		  return NSS_NOTFOUND;
		}
	    }
	  else
	    {
#ifdef HAVE_NSSWITCH_H
	      NSS_ARGS (args)->returnval = NULL;
	      MAP_H_ERRNO (retval, NSS_ARGS (args)->h_errno);
#else
	      MAP_H_ERRNO (retval, *herrnop);
#endif
	      return retval;
	    }
	}
      else
	{
	  /* retval == NSS_SUCCESS */
	  break;
	}
    }

#ifdef HAVE_NSSWITCH_H
  NSS_ARGS (args)->returnval = NSS_ARGS (args)->buf.result;
  MAP_H_ERRNO (retval, NSS_ARGS (args)->h_errno);
#else
  MAP_H_ERRNO (NSS_SUCCESS, *herrnop);
#endif

  return retval;
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_setnetent_r (nss_backend_t * net_context, void *fakeargs)
#elif defined(HAVE_NSS_H)
     NSS_STATUS _nss_ldap_setnetent (void)
#endif
#if defined(HAVE_NSS_H) || defined(HAVE_NSSWITCH_H)
{
  LOOKUP_SETENT (net_context);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_endnetent_r (nss_backend_t * net_context, void *fakeargs)
#elif defined(HAVE_NSS_H)
     NSS_STATUS _nss_ldap_endnetent (void)
#endif
#if defined(HAVE_NSS_H) || defined(HAVE_NSSWITCH_H)
{
  LOOKUP_ENDENT (net_context);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_getnetent_r (nss_backend_t * net_context, void *args)
{
  NSS_STATUS status =
    _nss_ldap_getent (&((nss_ldap_backend_t *) net_context)->state,
		      NSS_ARGS (args)->buf.result,
		      NSS_ARGS (args)->buf.buffer,
		      NSS_ARGS (args)->buf.buflen,
		      &NSS_ARGS (args)->erange,
		      _nss_ldap_filt_getnetent,
		      LM_NETWORKS,
		      _nss_ldap_parse_net);

  if (status == NSS_SUCCESS)
    NSS_ARGS (args)->returnval = NSS_ARGS (args)->buf.result;

  return status;
}
#elif defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_getnetent_r (struct netent * result, char *buffer, size_t buflen,
		       int *errnop, int *herrnop)
{
  NSS_STATUS status;

  status = _nss_ldap_getent (&net_context,
			     result,
			     buffer,
			     buflen,
			     errnop,
			     _nss_ldap_filt_getnetent,
			     LM_NETWORKS, _nss_ldap_parse_net);

  MAP_H_ERRNO (status, *herrnop);

  return status;
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_networks_destr (nss_backend_t * net_context, void *args)
{
  return _nss_ldap_default_destr (net_context, args);
}

static nss_backend_op_t net_ops[] = {
  _nss_ldap_networks_destr,
  _nss_ldap_endnetent_r,
  _nss_ldap_setnetent_r,
  _nss_ldap_getnetent_r,
  _nss_ldap_getnetbyname_r,
  _nss_ldap_getnetbyaddr_r
};

nss_backend_t *
_nss_ldap_networks_constr (const char *db_name,
			   const char *src_name, const char *cfg_args)
{
  nss_ldap_backend_t *be;

  if (!(be = (nss_ldap_backend_t *) malloc (sizeof (*be))))
    return NULL;

  be->ops = net_ops;
  be->n_ops = sizeof (net_ops) / sizeof (nss_backend_op_t);

  if (_nss_ldap_default_constr (be) != NSS_SUCCESS)
    return NULL;

  return (nss_backend_t *) be;
}

#endif /* !HAVE_NSS_H */

#ifdef HAVE_IRS_H
#include "irs-network.c"
#endif
