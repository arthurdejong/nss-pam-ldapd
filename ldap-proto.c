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

   $Id: ldap-proto.c,v 2.30 2006/01/11 18:03:49 lukeh Exp $
 */

/*
   Determine the canonical name of the RPC with _nss_ldap_getrdnvalue(),
   and assign any values of "cn" which do NOT match this canonical name
   as aliases.
 */


static char rcsId[] =
  "$Id: ldap-proto.c,v 2.30 2006/01/11 18:03:49 lukeh Exp $";

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

#include "ldap-nss.h"
#include "ldap-proto.h"
#include "util.h"

#ifdef HAVE_PORT_AFTER_H
#include <port_after.h>
#endif

#ifdef HAVE_NSS_H
static ent_context_t *proto_context = NULL;
#endif

static NSS_STATUS
_nss_ldap_parse_proto (LDAPMessage * e,
		       ldap_state_t * pvt,
		       void *result, char *buffer, size_t buflen)
{

  struct protoent *proto = (struct protoent *) result;
  char *number;
  NSS_STATUS stat;

  stat =
    _nss_ldap_getrdnvalue (e, ATM (LM_PROTOCOLS, cn), &proto->p_name,
                           &buffer, &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrval (e, AT (ipProtocolNumber), &number, &buffer,
			      &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

  proto->p_proto = atoi (number);

  stat =
    _nss_ldap_assign_attrvals (e, ATM (LM_PROTOCOLS, cn), proto->p_name,
			       &proto->p_aliases, &buffer, &buflen, NULL);
  if (stat != NSS_SUCCESS)
    return stat;

  return NSS_SUCCESS;
}

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_getprotobyname_r (nss_backend_t * be, void *args)
{
  LOOKUP_NAME (args, _nss_ldap_filt_getprotobyname, LM_PROTOCOLS,
	       _nss_ldap_parse_proto, LDAP_NSS_BUFLEN_DEFAULT);
}
#elif defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_getprotobyname_r (const char *name, struct protoent *result,
			    char *buffer, size_t buflen, int *errnop)
{
  LOOKUP_NAME (name, result, buffer, buflen, errnop,
	       _nss_ldap_filt_getprotobyname, LM_PROTOCOLS,
	       _nss_ldap_parse_proto, LDAP_NSS_BUFLEN_DEFAULT);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_getprotobynumber_r (nss_backend_t * be, void *args)
{
  LOOKUP_NUMBER (args, key.number, _nss_ldap_filt_getprotobynumber,
		 LM_PROTOCOLS, _nss_ldap_parse_proto, LDAP_NSS_BUFLEN_DEFAULT);
}
#elif defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_getprotobynumber_r (int number, struct protoent *result,
			      char *buffer, size_t buflen, int *errnop)
{
  LOOKUP_NUMBER (number, result, buffer, buflen, errnop,
		 _nss_ldap_filt_getprotobynumber, LM_PROTOCOLS,
		 _nss_ldap_parse_proto, LDAP_NSS_BUFLEN_DEFAULT);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_setprotoent_r (nss_backend_t * proto_context, void *fakeargs)
#elif defined(HAVE_NSS_H)
     NSS_STATUS _nss_ldap_setprotoent (void)
#endif
#if defined(HAVE_NSS_H) || defined(HAVE_NSSWITCH_H)
{
  LOOKUP_SETENT (proto_context);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_endprotoent_r (nss_backend_t * proto_context, void *fakeargs)
#elif defined(HAVE_NSS_H)
     NSS_STATUS _nss_ldap_endprotoent (void)
#endif
#if defined(HAVE_NSS_H) || defined(HAVE_NSSWITCH_H)
{
  LOOKUP_ENDENT (proto_context);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_getprotoent_r (nss_backend_t * proto_context, void *args)
{
  LOOKUP_GETENT (args, proto_context, _nss_ldap_filt_getprotoent,
		 LM_PROTOCOLS, _nss_ldap_parse_proto, LDAP_NSS_BUFLEN_DEFAULT);
}
#elif defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_getprotoent_r (struct protoent *result, char *buffer, size_t buflen,
			 int *errnop)
{
  LOOKUP_GETENT (proto_context, result, buffer, buflen, errnop,
		 _nss_ldap_filt_getprotoent, LM_PROTOCOLS,
		 _nss_ldap_parse_proto, LDAP_NSS_BUFLEN_DEFAULT);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_protocols_destr (nss_backend_t * proto_context, void *args)
{
  return _nss_ldap_default_destr (proto_context, args);
}

static nss_backend_op_t proto_ops[] = {
  _nss_ldap_protocols_destr,
  _nss_ldap_endprotoent_r,
  _nss_ldap_setprotoent_r,
  _nss_ldap_getprotoent_r,
  _nss_ldap_getprotobyname_r,
  _nss_ldap_getprotobynumber_r
};

nss_backend_t *
_nss_ldap_protocols_constr (const char *db_name,
			    const char *src_name, const char *cfg_args)
{
  nss_ldap_backend_t *be;

  if (!(be = (nss_ldap_backend_t *) malloc (sizeof (*be))))
    return NULL;

  be->ops = proto_ops;
  be->n_ops = sizeof (proto_ops) / sizeof (nss_backend_op_t);

  if (_nss_ldap_default_constr (be) != NSS_SUCCESS)
    return NULL;

  return (nss_backend_t *) be;
}

#endif /* !HAVE_NSS_H */

#ifdef HAVE_IRS_H
#include "irs-proto.c"
#endif
