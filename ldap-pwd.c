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

#ifdef HAVE_PORT_BEFORE_H
#include <port_before.h>
#endif

#if defined(HAVE_THREAD_H) && !defined(_AIX)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include <stdlib.h>
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include <pwd.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#include "ldap-nss.h"
#include "ldap-pwd.h"
#include "util.h"

#ifdef HAVE_PORT_AFTER_H
#include <port_after.h>
#endif

#ifdef HAVE_NSS_H
static ent_context_t *pw_context = NULL;
#endif

static INLINE NSS_STATUS _nss_ldap_assign_emptystring (char **valptr,
						       char **buffer,
						       size_t * buflen);

static INLINE NSS_STATUS
_nss_ldap_assign_emptystring (char **valptr, char **buffer, size_t * buflen)
{
  if (*buflen < 2)
    return NSS_TRYAGAIN;

  *valptr = *buffer;

  **valptr = '\0';

  (*buffer)++;
  (*buflen)--;

  return NSS_SUCCESS;
}

static NSS_STATUS
_nss_ldap_parse_pw (LDAPMessage * e,
		    ldap_state_t * pvt,
		    void *result, char *buffer, size_t buflen)
{
  struct passwd *pw = (struct passwd *) result;
  char *uid, *gid;
  NSS_STATUS stat;
  char tmpbuf[ sizeof( uid_t ) * 8 / 3 + 2 ];
  size_t tmplen;
  char *tmp;
  
  tmpbuf[ sizeof(tmpbuf) - 1 ] = '\0';

  if (_nss_ldap_oc_check (e, "shadowAccount") == NSS_SUCCESS)
    {
      /* don't include password for shadowAccount */
      if (buflen < 3)
	return NSS_TRYAGAIN;

      pw->pw_passwd = buffer;
      strcpy (buffer, "x");
      buffer += 2;
      buflen -= 2;
    }
  else
    {
      stat =
	_nss_ldap_assign_userpassword (e, ATM (LM_PASSWD, userPassword),
				       &pw->pw_passwd, &buffer, &buflen);
      if (stat != NSS_SUCCESS)
	return stat;
    }

  stat =
    _nss_ldap_assign_attrval (e, ATM (LM_PASSWD, uid), &pw->pw_name, &buffer,
			      &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

  tmp = tmpbuf;
  tmplen = sizeof (tmpbuf) - 1;
  stat =
    _nss_ldap_assign_attrval (e, AT (uidNumber), &uid, &tmp, &tmplen);
  if (stat != NSS_SUCCESS)
    return stat;
  pw->pw_uid = (*uid == '\0') ? UID_NOBODY : (uid_t) atol (uid);

  tmp = tmpbuf;
  tmplen = sizeof (tmpbuf) - 1;
  stat =
    _nss_ldap_assign_attrval (e, ATM (LM_PASSWD, gidNumber), &gid, &tmp,
                              &tmplen);
  if (stat != NSS_SUCCESS)
    return stat;
  pw->pw_gid = (*gid == '\0') ? GID_NOBODY : (gid_t) atol (gid);

  stat =
    _nss_ldap_assign_attrval (e, AT (gecos), &pw->pw_gecos, &buffer,
			      &buflen);
  if (stat != NSS_SUCCESS)
    {
      pw->pw_gecos = NULL;
      stat =
	_nss_ldap_assign_attrval (e, ATM (LM_PASSWD, cn), &pw->pw_gecos,
                                  &buffer, &buflen);
      if (stat != NSS_SUCCESS)
	return stat;
    }

  stat =
    _nss_ldap_assign_attrval (e, AT (homeDirectory), &pw->pw_dir, &buffer,
			      &buflen);
  if (stat != NSS_SUCCESS)
    (void) _nss_ldap_assign_emptystring (&pw->pw_dir, &buffer, &buflen);

  stat =
    _nss_ldap_assign_attrval (e, AT (loginShell), &pw->pw_shell, &buffer,
			      &buflen);
  if (stat != NSS_SUCCESS)
    (void) _nss_ldap_assign_emptystring (&pw->pw_shell, &buffer, &buflen);

#ifdef HAVE_NSSWITCH_H
  stat =
    _nss_ldap_assign_attrval (e, ATM (LM_PASSWD, description),
                              &pw->pw_comment, &buffer, &buflen);
  if (stat != NSS_SUCCESS)
    {
      /* 
       * Fix for recall #233
       */
      pw->pw_comment = pw->pw_gecos;
    }
  (void) _nss_ldap_assign_emptystring (&pw->pw_age, &buffer, &buflen);
#endif /* HAVE_NSSWITCH_H */

#ifdef HAVE_PASSWD_PW_CHANGE
 tmp = NULL;
  stat =
    _nss_ldap_assign_attrval (e, AT (shadowMax), &tmp, &buffer, &buflen);
  pw->pw_change = (stat == NSS_SUCCESS) ? atol(tmp) * (24*60*60) : 0;

  if (pw->pw_change > 0)
    {
      tmp = NULL;
      stat =
        _nss_ldap_assign_attrval (e, AT (shadowLastChange), &tmp, &buffer,
		    	          &buflen);
      if (stat == NSS_SUCCESS)
        pw->pw_change += atol(tmp);
      else
	pw->pw_change = 0;
    }
#endif /* HAVE_PASSWD_PW_CHANGE */

#ifdef HAVE_PASSWD_PW_EXPIRE
  tmp = NULL;
  stat =
    _nss_ldap_assign_attrval (e, AT (shadowExpire), &tmp, &buffer, &buflen);
  pw->pw_expire = (stat == NSS_SUCCESS) ? atol(tmp) * (24*60*60) : 0;
#endif /* HAVE_PASSWD_PW_EXPIRE */

  return NSS_SUCCESS;
}

#ifdef HAVE_NSS_H
NSS_STATUS
_nss_ldap_getpwnam_r (const char *name,
		      struct passwd * result,
		      char *buffer, size_t buflen, int *errnop)
{
  LOOKUP_NAME (name, result, buffer, buflen, errnop, _nss_ldap_filt_getpwnam,
	       LM_PASSWD, _nss_ldap_parse_pw, LDAP_NSS_BUFLEN_DEFAULT);
}
#elif defined(HAVE_NSSWITCH_H)
static NSS_STATUS
_nss_ldap_getpwnam_r (nss_backend_t * be, void *args)
{
  LOOKUP_NAME (args, _nss_ldap_filt_getpwnam, LM_PASSWD, _nss_ldap_parse_pw,
	       LDAP_NSS_BUFLEN_DEFAULT);
}
#endif /* HAVE_NSS_H */

#ifdef HAVE_NSS_H
NSS_STATUS
_nss_ldap_getpwuid_r (uid_t uid,
		      struct passwd *result,
		      char *buffer, size_t buflen, int *errnop)
{
  LOOKUP_NUMBER (uid, result, buffer, buflen, errnop, _nss_ldap_filt_getpwuid,
		 LM_PASSWD, _nss_ldap_parse_pw, LDAP_NSS_BUFLEN_DEFAULT);
}
#elif defined(HAVE_NSSWITCH_H)
static NSS_STATUS
_nss_ldap_getpwuid_r (nss_backend_t * be, void *args)
{
  LOOKUP_NUMBER (args, key.uid, _nss_ldap_filt_getpwuid, LM_PASSWD,
		 _nss_ldap_parse_pw, LDAP_NSS_BUFLEN_DEFAULT);
}
#endif

#if defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_setpwent (void)
{
  LOOKUP_SETENT (pw_context);
}
#elif defined(HAVE_NSSWITCH_H)
static NSS_STATUS
_nss_ldap_setpwent_r (nss_backend_t * be, void *args)
{
  LOOKUP_SETENT (be);
}
#endif

#if defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_endpwent (void)
{
  LOOKUP_ENDENT (pw_context);
}
#elif defined(HAVE_NSSWITCH_H)
static NSS_STATUS
_nss_ldap_endpwent_r (nss_backend_t * be, void *args)
{
  LOOKUP_ENDENT (be);
}
#endif

#ifdef HAVE_NSS_H
NSS_STATUS
_nss_ldap_getpwent_r (struct passwd *result,
		      char *buffer, size_t buflen, int *errnop)
{
  LOOKUP_GETENT (pw_context, result, buffer, buflen, errnop,
		 _nss_ldap_filt_getpwent, LM_PASSWD, _nss_ldap_parse_pw,
		 LDAP_NSS_BUFLEN_DEFAULT);
}
#elif defined(HAVE_NSSWITCH_H)
static NSS_STATUS
_nss_ldap_getpwent_r (nss_backend_t * be, void *args)
{
  LOOKUP_GETENT (args, be, _nss_ldap_filt_getpwent, LM_PASSWD,
		 _nss_ldap_parse_pw, LDAP_NSS_BUFLEN_DEFAULT);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_passwd_destr (nss_backend_t * pw_context, void *args)
{
  return _nss_ldap_default_destr (pw_context, args);
}

static nss_backend_op_t passwd_ops[] = {
  _nss_ldap_passwd_destr,
  _nss_ldap_endpwent_r,		/* NSS_DBOP_ENDENT */
  _nss_ldap_setpwent_r,		/* NSS_DBOP_SETENT */
  _nss_ldap_getpwent_r,		/* NSS_DBOP_GETENT */
  _nss_ldap_getpwnam_r,		/* NSS_DBOP_PASSWD_BYNAME */
  _nss_ldap_getpwuid_r		/* NSS_DBOP_PASSWD_BYUID */
};

nss_backend_t *
_nss_ldap_passwd_constr (const char *db_name,
			 const char *src_name, const char *cfg_args)
{
  nss_ldap_backend_t *be;

  if (!(be = (nss_ldap_backend_t *) malloc (sizeof (*be))))
    return NULL;

  be->ops = passwd_ops;
  be->n_ops = sizeof (passwd_ops) / sizeof (nss_backend_op_t);

  if (_nss_ldap_default_constr (be) != NSS_SUCCESS)
    return NULL;

  return (nss_backend_t *) be;
}


#endif /* !HAVE_NSS_H */

#ifdef HAVE_IRS_H
#include "irs-pwd.c"
#endif /* HAVE_IRS_H */
