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

static char rcsId[] =
  "$Id$";

#include "config.h"

#ifdef HAVE_SHADOW_H

#ifdef HAVE_PORT_BEFORE_H
#include <port_before.h>
#endif

#if defined(HAVE_THREAD_H) && !defined(_AIX)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include <stdlib.h>
#include <string.h>
#ifdef HAVE_PROT_H
#define _PROT_INCLUDED
#endif
#include <shadow.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#include "ldap-nss.h"
#include "ldap-spwd.h"

#ifdef HAVE_PORT_AFTER_H
#include <port_after.h>
#endif

#if defined(HAVE_NSSWITCH_H) || defined(HAVE_NSS_H)

#ifdef HAVE_NSS_H
static ent_context_t *sp_context = NULL;
#endif

static NSS_STATUS
_nss_ldap_parse_sp (LDAPMessage * e,
		    ldap_state_t * pvt,
		    void *result, char *buffer, size_t buflen)
{
  struct spwd *sp = (struct spwd *) result;
  NSS_STATUS stat;
  char *tmp = NULL;

  stat =
    _nss_ldap_assign_userpassword (e, ATM (LM_SHADOW, userPassword),
                                   &sp->sp_pwdp, &buffer, &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrval (e, ATM (LM_SHADOW, uid), &sp->sp_namp, &buffer,
			      &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrval (e, AT (shadowLastChange), &tmp, &buffer,
			      &buflen);
  sp->sp_lstchg = (stat == NSS_SUCCESS) ? _nss_ldap_shadow_date (tmp) : -1;

  stat =
    _nss_ldap_assign_attrval (e, AT (shadowMax), &tmp, &buffer, &buflen);
  sp->sp_max = (stat == NSS_SUCCESS) ? atol (tmp) : -1;

  stat =
    _nss_ldap_assign_attrval (e, AT (shadowMin), &tmp, &buffer, &buflen);
  sp->sp_min = (stat == NSS_SUCCESS) ? atol (tmp) : -1;

  stat =
    _nss_ldap_assign_attrval (e, AT (shadowWarning), &tmp, &buffer,
			      &buflen);
  sp->sp_warn = (stat == NSS_SUCCESS) ? atol (tmp) : -1;

  stat =
    _nss_ldap_assign_attrval (e, AT (shadowInactive), &tmp, &buffer,
			      &buflen);
  sp->sp_inact = (stat == NSS_SUCCESS) ? atol (tmp) : -1;

  stat =
    _nss_ldap_assign_attrval (e, AT (shadowExpire), &tmp, &buffer,
			      &buflen);
  sp->sp_expire = (stat == NSS_SUCCESS) ? _nss_ldap_shadow_date (tmp) : -1;

  stat =
    _nss_ldap_assign_attrval (e, AT (shadowFlag), &tmp, &buffer, &buflen);
  sp->sp_flag = (stat == NSS_SUCCESS) ? atol (tmp) : 0;

  _nss_ldap_shadow_handle_flag(sp);

  return NSS_SUCCESS;
}

#ifdef HAVE_NSS_H
NSS_STATUS
_nss_ldap_getspnam_r (const char *name,
		      struct spwd * result,
		      char *buffer, size_t buflen, int *errnop)
{
  LOOKUP_NAME (name, result, buffer, buflen, errnop, _nss_ldap_filt_getspnam,
	       LM_SHADOW, _nss_ldap_parse_sp, LDAP_NSS_BUFLEN_DEFAULT);
}
#elif defined(HAVE_NSSWITCH_H)
static NSS_STATUS
_nss_ldap_getspnam_r (nss_backend_t * be, void *args)
{
  LOOKUP_NAME (args, _nss_ldap_filt_getspnam, LM_SHADOW, _nss_ldap_parse_sp,
	       LDAP_NSS_BUFLEN_DEFAULT);
}
#endif /* HAVE_NSS_H */

#if defined(HAVE_NSS_H)
NSS_STATUS _nss_ldap_setspent (void)
#else
static NSS_STATUS
_nss_ldap_setspent_r (nss_backend_t * sp_context, void *args)
#endif
#if defined(HAVE_NSS_H) || defined(HAVE_NSSWITCH_H)
{
  LOOKUP_SETENT (sp_context);
}
#endif

#if defined(HAVE_NSS_H)
NSS_STATUS _nss_ldap_endspent (void)
#else
static NSS_STATUS
_nss_ldap_endspent_r (nss_backend_t * sp_context, void *args)
#endif
#if defined(HAVE_NSS_H) || defined(HAVE_NSSWITCH_H)
{
  LOOKUP_ENDENT (sp_context);
}
#endif

#ifdef HAVE_NSS_H
NSS_STATUS
_nss_ldap_getspent_r (struct spwd *result,
		      char *buffer, size_t buflen, int *errnop)
{
  LOOKUP_GETENT (sp_context, result, buffer, buflen, errnop,
		 _nss_ldap_filt_getspent, LM_SHADOW, _nss_ldap_parse_sp,
		 LDAP_NSS_BUFLEN_DEFAULT);
}
#elif defined(HAVE_NSSWITCH_H)
static NSS_STATUS
_nss_ldap_getspent_r (nss_backend_t * sp_context, void *args)
{
  LOOKUP_GETENT (args, sp_context, _nss_ldap_filt_getspent, LM_SHADOW,
		 _nss_ldap_parse_sp, LDAP_NSS_BUFLEN_DEFAULT);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_shadow_destr (nss_backend_t * sp_context, void *args)
{
  return _nss_ldap_default_destr (sp_context, args);
}

static nss_backend_op_t shadow_ops[] = {
  _nss_ldap_shadow_destr,
  _nss_ldap_endspent_r,		/* NSS_DBOP_ENDENT */
  _nss_ldap_setspent_r,		/* NSS_DBOP_SETENT */
  _nss_ldap_getspent_r,		/* NSS_DBOP_GETENT */
  _nss_ldap_getspnam_r		/* NSS_DBOP_SHADOW_BYNAME */
};


nss_backend_t *
_nss_ldap_shadow_constr (const char *db_name,
			 const char *src_name, const char *cfg_args)
{
  nss_ldap_backend_t *be;

  if (!(be = (nss_ldap_backend_t *) malloc (sizeof (*be))))
    return NULL;

  be->ops = shadow_ops;
  be->n_ops = sizeof (shadow_ops) / sizeof (nss_backend_op_t);

  if (_nss_ldap_default_constr (be) != NSS_SUCCESS)
    return NULL;

  return (nss_backend_t *) be;
}

#endif /* !HAVE_NSS_H */
#endif

#endif /* HAVE_SHADOW_H */
