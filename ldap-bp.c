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

   $Id: ldap-bp.c,v 2.27 2006/01/11 18:03:48 lukeh Exp $
 */


static char rcsId[] = "$Id: ldap-bp.c,v 2.27 2006/01/11 18:03:48 lukeh Exp $";

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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#include "ldap-nss.h"
#include "ldap-bp.h"
#include "util.h"

#ifdef HAVE_PORT_AFTER_H
#include <port_after.h>
#endif

#if defined(HAVE_NSSWITCH_H) || defined(HAVE_NSS_H)

#ifdef HAVE_NSS_H
static ent_context_t *bp_context = NULL;
#endif

static NSS_STATUS
_nss_ldap_parse_bp (LDAPMessage * e,
		    ldap_state_t * pvt,
		    void *result, char *buffer, size_t buflen)
{
  struct bootparams *bp = (struct bootparams *) result;
  NSS_STATUS stat;

  stat =
    _nss_ldap_assign_attrval (e, ATM (LM_BOOTPARAMS, cn), &bp->bp_name,
                              &buffer, &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrvals (e, AT (bootParameter), NULL,
			       &bp->bp_params, &buffer, &buflen, NULL);
  if (stat != NSS_SUCCESS)
    return stat;

  return NSS_SUCCESS;
}

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_getbootparamsbyname_r (nss_backend_t * be, void *args)
{
  LOOKUP_NAME (args, _nss_ldap_filt_getbootparamsbyname, LM_BOOTPARAMS,
	       _nss_ldap_parse_bp, LDAP_NSS_BUFLEN_DEFAULT);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_bootparams_destr (nss_backend_t * bp_context, void *args)
{
  return _nss_ldap_default_destr (bp_context, args);
}

static nss_backend_op_t bp_ops[] = {
  _nss_ldap_bootparams_destr,
  _nss_ldap_getbootparamsbyname_r
};

nss_backend_t *
_nss_ldap_bootparams_constr (const char *db_name,
			     const char *src_name, const char *cfg_args)
{
  nss_ldap_backend_t *be;

/*
   if (!(be = (nss_ldap_backend_t *)malloc(sizeof(*be))))
   return NULL;

   be->ops = bp_ops;
   be->n_ops = sizeof(bp_ops) / sizeof(nss_backend_op_t);

   if (_nss_ldap_default_constr(be) != NSS_SUCCESS)
   return NULL;

   return (nss_backend_t *)be;
 */

  /* this is a noop until we figure it out properly */
  return NULL;
}

#endif /* HAVE_NSSWITCH_H */

#endif /* !HAVE_IRS_H */
