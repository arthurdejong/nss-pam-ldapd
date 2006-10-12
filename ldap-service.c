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

/*
   Determine the canonical name of the RPC with _nss_ldap_getrdnvalue(),
   and assign any values of "cn" which do NOT match this canonical name
   as aliases.
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
#include <netinet/in.h>

#ifdef HAVE_SYS_BYTEORDER_H
#include <sys/byteorder.h>
#endif

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#include "ldap-nss.h"
#include "ldap-service.h"
#include "util.h"

#ifdef HAVE_PORT_AFTER_H
#include <port_after.h>
#endif

#ifdef HAVE_NSS_H
static ent_context_t *serv_context = NULL;
#endif

static NSS_STATUS
_nss_ldap_parse_serv (LDAPMessage * e,
		      ldap_state_t * state,
		      void *result, char *buffer, size_t buflen)
{
  struct servent *service = (struct servent *) result;
  char *port;
  NSS_STATUS stat = NSS_SUCCESS;

  /* this is complicated and ugly, because some git (me) specified that service
   * entries should expand to two entities (or more) if they have multi-valued
   * ipServiceProtocol fields.
   */

  if (state->ls_type == LS_TYPE_KEY)
    {
      if (state->ls_info.ls_key == NULL)
	{
	  /* non-deterministic behaviour is ok */
	  stat =
	    _nss_ldap_assign_attrval (e, AT (ipServiceProtocol),
				      &service->s_proto, &buffer, &buflen);
	  if (stat != NSS_SUCCESS)
	    {
	      return stat;
	    }
	}
      else
	{
	  register int len;
	  len = strlen (state->ls_info.ls_key);
	  if (buflen < (size_t) (len + 1))
	    {
	      return NSS_TRYAGAIN;
	    }
	  strncpy (buffer, state->ls_info.ls_key, len);
	  buffer[len] = '\0';
	  service->s_proto = buffer;
	  buffer += len + 1;
	  buflen -= len + 1;
	}
    }
  else
    {
      char **vals = _nss_ldap_get_values (e, AT (ipServiceProtocol));
      int len;
      if (vals == NULL)
	{
	  state->ls_info.ls_index = -1;
	  return NSS_NOTFOUND;
	}

      switch (state->ls_info.ls_index)
	{
	case 0:
	  /* last time. decrementing ls_index to -1 AND returning !NSS_SUCCESS
	     will force this entry to be discarded.
	   */
	  stat = NSS_NOTFOUND;
	  break;
	case -1:
	  /* first time */
	  state->ls_info.ls_index = ldap_count_values (vals);
	  /* fall off to default ... */
	default:
	  len = strlen (vals[state->ls_info.ls_index - 1]);
	  if (buflen < (size_t) (len + 1))
	    {
	      return NSS_TRYAGAIN;
	    }
	  strncpy (buffer, vals[state->ls_info.ls_index - 1], len);
	  buffer[len] = '\0';
	  service->s_proto = buffer;
	  buffer += len + 1;
	  buflen -= len + 1;
	  stat = NSS_SUCCESS;
	}

      ldap_value_free (vals);
      state->ls_info.ls_index--;
    }

  if (stat != NSS_SUCCESS)
    {
      return stat;
    }

  stat =
    _nss_ldap_getrdnvalue (e, ATM (LM_SERVICES, cn), &service->s_name,
                           &buffer, &buflen);
  if (stat != NSS_SUCCESS)
    {
      return stat;
    }

  stat =
    _nss_ldap_assign_attrvals (e, ATM (LM_SERVICES, cn), service->s_name,
			       &service->s_aliases, &buffer, &buflen, NULL);
  if (stat != NSS_SUCCESS)
    {
      return stat;
    }

  stat =
    _nss_ldap_assign_attrval (e, AT (ipServicePort), &port, &buffer,
			      &buflen);
  if (stat != NSS_SUCCESS)
    {
      return stat;
    }

  service->s_port = htons (atoi (port));

  return NSS_SUCCESS;
}

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_getservbyname_r (nss_backend_t * be, void *args)
{
  ldap_args_t a;
  NSS_STATUS status;

  LA_INIT (a);
  LA_STRING (a) = NSS_ARGS (args)->key.serv.serv.name;
  LA_TYPE (a) = (NSS_ARGS (args)->key.serv.proto == NULL) ?
    LA_TYPE_STRING : LA_TYPE_STRING_AND_STRING;
  LA_STRING2 (a) = NSS_ARGS (args)->key.serv.proto;

  status = _nss_ldap_getbyname (&a,
				NSS_ARGS (args)->buf.result,
				NSS_ARGS (args)->buf.buffer,
				NSS_ARGS (args)->buf.buflen,
				&NSS_ARGS (args)->erange,
				(NSS_ARGS (args)->key.serv.proto == NULL) ?
				_nss_ldap_filt_getservbyname :
				_nss_ldap_filt_getservbynameproto, LM_SERVICES,
				_nss_ldap_parse_serv);

  if (status == NSS_SUCCESS)
    NSS_ARGS (args)->returnval = NSS_ARGS (args)->buf.result;

  return status;
}
#elif defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_getservbyname_r (const char *name,
			   const char *proto,
			   struct servent * result,
			   char *buffer, size_t buflen, int *errnop)
{
  ldap_args_t a;

  LA_INIT (a);
  LA_STRING (a) = name;
  LA_TYPE (a) = (proto == NULL) ? LA_TYPE_STRING : LA_TYPE_STRING_AND_STRING;
  LA_STRING2 (a) = proto;

  return _nss_ldap_getbyname (&a, result, buffer, buflen, errnop,
			      ((proto == NULL) ? _nss_ldap_filt_getservbyname
			       : _nss_ldap_filt_getservbynameproto),
			      LM_SERVICES, _nss_ldap_parse_serv);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_getservbyport_r (nss_backend_t * be, void *args)
{
  ldap_args_t a;
  NSS_STATUS status;

  LA_INIT (a);
  LA_NUMBER (a) = htons (NSS_ARGS (args)->key.serv.serv.port);
  LA_TYPE (a) = (NSS_ARGS (args)->key.serv.proto == NULL) ?
    LA_TYPE_NUMBER : LA_TYPE_NUMBER_AND_STRING;
  LA_STRING2 (a) = NSS_ARGS (args)->key.serv.proto;

  status = _nss_ldap_getbyname (&a,
				NSS_ARGS (args)->buf.result,
				NSS_ARGS (args)->buf.buffer,
				NSS_ARGS (args)->buf.buflen,
				&NSS_ARGS (args)->erange,
				(NSS_ARGS (args)->key.serv.proto == NULL) ?
				_nss_ldap_filt_getservbyport :
				_nss_ldap_filt_getservbyportproto, LM_SERVICES,
				_nss_ldap_parse_serv);

  if (status == NSS_SUCCESS)
    NSS_ARGS (args)->returnval = NSS_ARGS (args)->buf.result;

  return status;
}
#elif defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_getservbyport_r (int port,
			   const char *proto,
			   struct servent * result,
			   char *buffer, size_t buflen, int *errnop)
{
  ldap_args_t a;

  LA_INIT (a);
  LA_NUMBER (a) = htons (port);
  LA_TYPE (a) = (proto == NULL) ? LA_TYPE_NUMBER : LA_TYPE_NUMBER_AND_STRING;
  LA_STRING2 (a) = proto;
  return _nss_ldap_getbyname (&a, result, buffer, buflen, errnop,
			      (proto ==
			       NULL) ? _nss_ldap_filt_getservbyport :
			      _nss_ldap_filt_getservbyportproto,
			      LM_SERVICES, _nss_ldap_parse_serv);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_setservent_r (nss_backend_t * serv_context, void *args)
#elif defined(HAVE_NSS_H)
     NSS_STATUS _nss_ldap_setservent (void)
#endif
#if defined(HAVE_NSS_H) || defined(HAVE_NSSWITCH_H)
{
  LOOKUP_SETENT (serv_context);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_endservent_r (nss_backend_t * serv_context, void *args)
#elif defined(HAVE_NSS_H)
     NSS_STATUS _nss_ldap_endservent (void)
#endif
#if defined(HAVE_NSS_H) || defined(HAVE_NSSWITCH_H)
{
  LOOKUP_ENDENT (serv_context);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_getservent_r (nss_backend_t * serv_context, void *args)
{
  LOOKUP_GETENT (args, serv_context, _nss_ldap_filt_getservent, LM_SERVICES,
		 _nss_ldap_parse_serv, LDAP_NSS_BUFLEN_DEFAULT);
}
#elif defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_getservent_r (struct servent *result, char *buffer, size_t buflen,
			int *errnop)
{
  LOOKUP_GETENT (serv_context, result, buffer, buflen, errnop,
		 _nss_ldap_filt_getservent, LM_SERVICES,
		 _nss_ldap_parse_serv, LDAP_NSS_BUFLEN_DEFAULT);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_services_destr (nss_backend_t * serv_context, void *args)
{
  return _nss_ldap_default_destr (serv_context, args);
}

static nss_backend_op_t services_ops[] = {
  _nss_ldap_services_destr,
  _nss_ldap_endservent_r,
  _nss_ldap_setservent_r,
  _nss_ldap_getservent_r,
  _nss_ldap_getservbyname_r,
  _nss_ldap_getservbyport_r
};

nss_backend_t *
_nss_ldap_services_constr (const char *db_name,
			   const char *src_name, const char *cfg_args)
{
  nss_ldap_backend_t *be;

  if (!(be = (nss_ldap_backend_t *) malloc (sizeof (*be))))
    return NULL;

  be->ops = services_ops;
  be->n_ops = sizeof (services_ops) / sizeof (nss_backend_op_t);

  if (_nss_ldap_default_constr (be) != NSS_SUCCESS)
    return NULL;

  return (nss_backend_t *) be;
}

#endif /* !HAVE_NSS_H */

#ifdef HAVE_IRS_H
#include "irs-service.c"
#endif
