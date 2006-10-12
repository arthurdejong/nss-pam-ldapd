/* Copyright (C) 2002-2005 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@padl.com>, 2002.

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
 * Shim to support AIX loadable authentication modules
 */

#include "config.h"

static char rcsId[] =
  "$Id$";

#ifdef HAVE_USERSEC_H

#include <stdlib.h>
#include <string.h>
#include <usersec.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#include "ldap-nss.h"
#include "util.h"

#define TABLE_KEY_ALL	"ALL"
#define TABLE_USER	"user"
#define TABLE_GROUP	"group"

#define S_LDAPDN	"ldapdn"

static struct irs_gr *uess_gr_be = NULL;
static struct irs_pw *uess_pw_be = NULL;

extern void *gr_pvtinit (void); /* irs-grp.c */
extern void *pw_pvtinit (void); /* irs-pwd.c */

/* from ldap-grp.c */
extern char *_nss_ldap_getgrset (char *user);

/* search arguments for getentry method */
typedef struct ldap_uess_args
{
  /* argument block */
  const char *lua_key;
  const char *lua_table;
  char **lua_attributes;
  attrval_t *lua_results;
  int lua_size;

  /* private */
  ldap_map_selector_t lua_map;
  size_t lua__bufsiz;
  size_t lua__buflen;
  char *lua__buffer;
  const char *lua_naming_attribute;
}
ldap_uess_args_t;

static NSS_STATUS uess_get_char (LDAPMessage * e, ldap_uess_args_t * arg, int index);
static NSS_STATUS uess_get_char_ex (LDAPMessage * e, ldap_uess_args_t * arg, int index, const char *attribute);
static NSS_STATUS uess_get_int (LDAPMessage * e, ldap_uess_args_t * arg, int index);
static NSS_STATUS uess_get_pgrp (LDAPMessage * e, ldap_uess_args_t * arg, int index);
static NSS_STATUS uess_get_groupsids (LDAPMessage * e, ldap_uess_args_t * arg, int index);
static NSS_STATUS uess_get_gecos (LDAPMessage * e, ldap_uess_args_t * arg, int index);
static NSS_STATUS uess_get_pwd (LDAPMessage * e, ldap_uess_args_t * arg, int index);
static NSS_STATUS uess_get_dn (LDAPMessage * e, ldap_uess_args_t * arg, int index);

/* dispatch table for retrieving UESS attribute from an LDAP entry */
struct ldap_uess_fn
{
  const char *luf_attribute;
  NSS_STATUS (*luf_translator) (LDAPMessage * e,
				ldap_uess_args_t *, int);
}
ldap_uess_fn_t;

static struct ldap_uess_fn __uess_fns[] = {
  {S_GECOS, uess_get_gecos},
  {S_GROUPSIDS, uess_get_groupsids},
  {S_HOME, uess_get_char},
  {S_ID, uess_get_int},
  {S_PWD, uess_get_pwd},
  {S_SHELL, uess_get_char},
  {S_PGRP, uess_get_pgrp},
  {SEC_PASSWD, uess_get_char},
  {SEC_LASTUP, uess_get_int},
  {S_MAXAGE, uess_get_int},
  {S_MINAGE, uess_get_int},
  {S_MAXEXPIRED, uess_get_int},
  {S_PWDWARNTIME, uess_get_int},
  /* add additional attributes we know about here */
  {S_LDAPDN, uess_get_dn},
  {NULL, NULL}
};

#define GR_PVTINIT()	do { \
		if (uess_gr_be == NULL) { \
			uess_gr_be = (struct irs_gr *) gr_pvtinit (); \
			if (uess_gr_be == NULL) \
				return NULL; \
		} \
	} while (0)

#define PW_PVTINIT()	do { \
		if (uess_pw_be == NULL) { \
			uess_pw_be = (struct irs_pw *) pw_pvtinit (); \
			if (uess_pw_be == NULL) \
				return NULL; \
		} \
	} while (0)
	
static void *
_nss_ldap_uess_open (const char *name, const char *domain,
		     const int mode, char *options)
{
  /* Currently we do not use the above parameters */
  GR_PVTINIT();
  PW_PVTINIT();

  return NULL;
}

static void
_nss_ldap_uess_close (void *token)
{
  if (uess_gr_be != NULL)
    {
      (uess_gr_be->close) (uess_gr_be);
      uess_gr_be = NULL;
    }

  if (uess_pw_be != NULL)
    {
      (uess_pw_be->close) (uess_pw_be);
      uess_pw_be = NULL;
    }
}

static struct group *
_nss_ldap_getgrgid (gid_t gid)
{
  GR_PVTINIT ();

  return (uess_gr_be->bygid) (uess_gr_be, gid);
}

static struct group *
_nss_ldap_getgrnam (const char *name)
{
  GR_PVTINIT ();

  return (uess_gr_be->byname) (uess_gr_be, name);
}

static struct passwd *
_nss_ldap_getpwuid (uid_t uid)
{
  PW_PVTINIT ();

  return (uess_pw_be->byuid) (uess_pw_be, uid);
}

static struct passwd *
_nss_ldap_getpwnam (const char *name)
{
  PW_PVTINIT ();

  return (uess_pw_be->byname) (uess_pw_be, name);
}

static struct group *
_nss_ldap_getgracct (void *id, int type)
{
  GR_PVTINIT ();

  if (type == SEC_INT)
    return (uess_gr_be->bygid) (uess_gr_be, *(gid_t *) id);
  else
    return (uess_gr_be->byname) (uess_gr_be, (char *) id);
}

static int
_nss_ldap_authenticate (char *user, char *response, int *reenter,
			char **message)
{
  NSS_STATUS stat;
  int rc;

  debug ("==> _nss_ldap_authenticate");

  *reenter = FALSE;
  *message = NULL;

  stat = _nss_ldap_proxy_bind (user, response);

  switch (stat)
    {
    case NSS_TRYAGAIN:
      rc = AUTH_FAILURE;
      break;
    case NSS_NOTFOUND:
      rc = AUTH_NOTFOUND;
      break;
    case NSS_SUCCESS:
      rc = AUTH_SUCCESS;
      break;
    default:
    case NSS_UNAVAIL:
      rc = AUTH_UNAVAIL;
      break;
    }

  debug ("<== _nss_ldap_authenticate");

  return rc;
}

/*
 * Support this for when proxy authentication is disabled.
 * There may be some re-entrancy issues here; not sure
 * if we are supposed to return allocated memory or not,
 * this is not documented. I am assuming not in line with
 * the other APIs.
 */
static char *
_nss_ldap_getpasswd (char *user)
{
  struct passwd *pw;
  static char pwdbuf[32];
  char *p = NULL;

  debug ("==> _nss_ldap_getpasswd");

  pw = _nss_ldap_getpwnam (user);
  if (pw != NULL)
    {
      if (strlen (pw->pw_passwd) > sizeof (pwdbuf) - 1)
	{
	  errno = ERANGE;
	}
      else
	{
	  strcpy (pwdbuf, pw->pw_passwd);
	  p = pwdbuf;
	}
    }
  else
    {
      errno = ENOENT;		/* user does not exist */
    }

  debug ("<== _nss_ldap_getpasswd");

  return p;
}

/*
 * Convert a UESS table string to an nss_ldap map type
 */
static ldap_map_selector_t
table2map (const char *table)
{
  if (strcmp (table, TABLE_USER) == 0)
    return LM_PASSWD;
  else if (strcmp (table, TABLE_GROUP) == 0)
    return LM_GROUP;

  return LM_NONE;
}

/*
 * Convert a UESS key to an nss_ldap internal search query
 */
static ldap_args_t *
key2filter (char *key, ldap_map_selector_t map,
	    ldap_args_t * a, const char **filter)
{
  if (strcmp (key, TABLE_KEY_ALL) == 0)
    {
      if (map == LM_PASSWD)
	*filter = _nss_ldap_filt_getpwent;
      else
	*filter = _nss_ldap_filt_getgrent;

      return NULL;		/* indicates enumeration */
    }

  LA_INIT (*a);
  LA_TYPE (*a) = LA_TYPE_STRING;
  LA_STRING (*a) = key;

  if (map == LM_PASSWD)
    *filter = _nss_ldap_filt_getpwnam;
  else
    *filter = _nss_ldap_filt_getgrnam;

  return a;
}

/*
 * Map a UESS attribute to an LDAP attribute
 */
static const char *
uess2ldapattr (ldap_map_selector_t map, const char *attribute)
{
  if (strcmp (attribute, "username") == 0)
    return ATM (LM_PASSWD, uid);
  else if (strcmp (attribute, "groupname") == 0)
    return ATM (LM_GROUP, cn);
  else if (strcmp (attribute, S_ID) == 0)
    {
      if (map == LM_PASSWD)
	return ATM (LM_PASSWD, uidNumber);
      else
	return ATM (LM_GROUP, gidNumber);
    }
  else if (strcmp (attribute, S_PWD) == 0)
    return ATM (LM_PASSWD, userPassword);
  else if (strcmp (attribute, S_HOME) == 0)
    return ATM (LM_PASSWD, homeDirectory);
  else if (strcmp (attribute, S_SHELL) == 0)
    return ATM (LM_PASSWD, loginShell);
  else if (strcmp (attribute, S_GECOS) == 0)
    return ATM (LM_PASSWD, gecos);
  else if (strcmp (attribute, SEC_PASSWD) == 0)
    return ATM (LM_SHADOW, userPassword);
  else if (strcmp (attribute, SEC_LASTUP) == 0)
    return ATM (LM_SHADOW, shadowLastChange);
  else if (strcmp (attribute, S_MAXAGE) == 0)
    return ATM (LM_SHADOW, shadowMax);
  else if (strcmp (attribute, S_MINAGE) == 0)
    return ATM (LM_SHADOW, shadowMin);
  else if (strcmp (attribute, S_MAXEXPIRED) == 0)
    return ATM (LM_SHADOW, shadowExpire);
  else if (strcmp (attribute, S_PWDWARNTIME) == 0)
    return ATM (LM_SHADOW, shadowWarning);
  else if (strcmp (attribute, S_PGRP) == 0)
    return ATM (LM_GROUP, cn);
  else if (strcmp (attribute, S_USERS) == 0)
    return ATM (LM_GROUP, memberUid);

  return NULL;
}

/*
 * Get primary group name for a user
 */
static NSS_STATUS
uess_get_pgrp (LDAPMessage * e, ldap_uess_args_t * lua, int i)
{
  char **vals;
  LDAPMessage *res;
  const char *attrs[2];
  NSS_STATUS stat;
  ldap_args_t a;

  vals = _nss_ldap_get_values (e, ATM (LM_PASSWD, gidNumber));
  if (vals == NULL)
    return NSS_NOTFOUND;

  LA_INIT (a);
  LA_TYPE (a) = LA_TYPE_NUMBER;
  LA_NUMBER (a) = atol(vals[0]);

  attrs[0] = ATM (LM_GROUP, cn);
  attrs[1] = NULL;

  stat = _nss_ldap_search_s (&a, _nss_ldap_filt_getgrgid, LM_GROUP,
			     attrs, 1, &res);
  if (stat != NSS_SUCCESS)
    {
      ldap_value_free (vals);
      return NSS_NOTFOUND;
    }

  ldap_value_free (vals);

  e = _nss_ldap_first_entry (res);
  if (e == NULL)
    {
      ldap_msgfree (res);
      return NSS_NOTFOUND;
    }

  stat = uess_get_char_ex (e, lua, i, attrs[0]);

  ldap_msgfree (res);

  return stat;
}

/*
 * Get groups to which a user belongs 
 */
static NSS_STATUS
uess_get_groupsids (LDAPMessage * e, ldap_uess_args_t * lua, int i)
{
  char *p, *q;
  size_t len;

  p = _nss_ldap_getgrset ((char *) lua->lua_key);
  if (p == NULL)
    return NSS_NOTFOUND;

  len = strlen (p);
  q = malloc (len + 2);
  if (q == NULL)
    {
      errno = ENOMEM;
      return NSS_NOTFOUND;
    }

  memcpy (q, p, len + 1);
  q[len + 1] = '\0';

  free (p);
  p = NULL;

  for (p = q; *p != '\0'; p++)
    {
      if (*p == ',')
	*p++ = '\0';
    }

  lua->lua_results[i].attr_un.au_char = q;

  return NSS_SUCCESS;
}

/*
 * Get a mapped UESS string attribute
 */
static NSS_STATUS
uess_get_char (LDAPMessage * e, ldap_uess_args_t * lua, int i)
{
  const char *attribute;

  attribute = uess2ldapattr (lua->lua_map, lua->lua_attributes[i]);
  if (attribute == NULL)
    return NSS_NOTFOUND;

  return uess_get_char_ex (e, lua, i, attribute);
}

/*
 * Get a specific LDAP attribute
 */
static NSS_STATUS
uess_get_char_ex (LDAPMessage * e,
		  ldap_uess_args_t * lua, int i, const char *attribute)
{
  char **vals;
  attrval_t *av = &lua->lua_results[i];

  vals = _nss_ldap_get_values (e, attribute);
  if (vals == NULL)
    return NSS_NOTFOUND;

  if (vals[0] == NULL)
    {
      ldap_value_free (vals);
      return NSS_NOTFOUND;
    }

  av->attr_un.au_char = strdup (vals[0]);
  if (av->attr_un.au_char == NULL)
    {
      ldap_value_free (vals);
      return NSS_TRYAGAIN;
    }

  ldap_value_free (vals);
  return NSS_SUCCESS;
}

/*
 * Get an encoded crypt password
 */
static NSS_STATUS
uess_get_pwd (LDAPMessage * e, ldap_uess_args_t * lua, int i)
{
  char **vals;
  attrval_t *av = &lua->lua_results[i];
  const char *pwd;
  const char *attribute;

  attribute = uess2ldapattr (lua->lua_map, lua->lua_attributes[i]);
  if (attribute == NULL)
    return NSS_NOTFOUND;

  vals = _nss_ldap_get_values (e, attribute);
  pwd = _nss_ldap_locate_userpassword (vals);

  av->attr_un.au_char = strdup (pwd);
  if (vals != NULL)
    ldap_value_free (vals);

  return (av->attr_un.au_char == NULL) ? NSS_TRYAGAIN : NSS_SUCCESS;
}

/*
 * Get a UESS integer attribute
 */
static NSS_STATUS
uess_get_int (LDAPMessage * e, ldap_uess_args_t * lua, int i)
{
  const char *attribute;
  char **vals;
  attrval_t *av = &lua->lua_results[i];

  attribute = uess2ldapattr (lua->lua_map, lua->lua_attributes[i]);
  if (attribute == NULL)
    return NSS_NOTFOUND;

  vals = _nss_ldap_get_values (e, attribute);
  if (vals == NULL)
    return NSS_NOTFOUND;

  if (vals[0] == NULL)
    {
      ldap_value_free (vals);
      return NSS_NOTFOUND;
    }

  av->attr_un.au_int = atoi (vals[0]);
  ldap_value_free (vals);
  return NSS_SUCCESS;
}

/*
 * Get the GECOS/cn attribute
 */
static NSS_STATUS
uess_get_gecos (LDAPMessage * e, ldap_uess_args_t * lua, int i)
{
  NSS_STATUS stat;

  stat = uess_get_char (e, lua, i);
  if (stat == NSS_NOTFOUND)
    {
      stat = uess_get_char_ex (e, lua, i, ATM (LM_PASSWD, cn));
    }

  return stat;
}

/*
 * Get the DN 
 */
static NSS_STATUS
uess_get_dn (LDAPMessage * e, ldap_uess_args_t * lua, int i)
{
  lua->lua_results[i].attr_un.au_char = _nss_ldap_get_dn (e);
  if (lua->lua_results[i].attr_un.au_char == NULL)
    return NSS_NOTFOUND;

  return NSS_SUCCESS;
}

static NSS_STATUS
do_parse_uess_getentry (LDAPMessage * e,
			ldap_state_t * pvt, void *result,
			char *buffer, size_t buflen)
{
  ldap_uess_args_t *lua = (ldap_uess_args_t *) result;
  int i;
  char **vals;
  size_t len;
  NSS_STATUS stat;

  /* If a buffer is supplied, then we are enumerating. */
  if (lua->lua__buffer != NULL)
    {
      attrval_t *av = lua->lua_results;

      vals = _nss_ldap_get_values (e, lua->lua_naming_attribute);
      if (vals == NULL)
	return NSS_NOTFOUND;

      if (vals[0] == NULL)
	{
	  ldap_value_free (vals);
	  return NSS_NOTFOUND;
	}

      len = strlen (vals[0]) + 1;	/* for string terminator */

      if (lua->lua__buflen < len + 1)	/* for list terminator */
	{
	  size_t grow = len + 1;
	  size_t offset = (lua->lua__buffer - av->attr_un.au_char);

	  grow += NSS_BUFSIZ - 1;
	  grow -= (grow % NSS_BUFSIZ);

	  av->attr_un.au_char =
	    realloc (lua->lua__buffer, lua->lua__bufsiz + grow);
	  if (av->attr_un.au_char == NULL)
	    {
	      ldap_value_free (vals);
	      return NSS_TRYAGAIN;
	    }
	  /* reset buffer pointer in case realloc() returned a new region */
	  lua->lua__buffer = &av->attr_un.au_char[offset];
	  lua->lua__buflen += grow;
	  lua->lua__bufsiz += grow;
	}

      memcpy (lua->lua__buffer, vals[0], len);
      lua->lua__buflen -= len;
      lua->lua__buffer += len;
      ldap_value_free (vals);

      lua->lua__buffer[0] = '\0';	/* ensure _list_ is always terminated */

      if (av->attr_flag != 0)
	av->attr_flag = 0;

      return NSS_NOTFOUND; /* trick caller into calling us again */
    }
  else
    {
      for (i = 0; i < lua->lua_size; i++)
	{
	  int j;
	  attrval_t *av = &lua->lua_results[i];

	  av->attr_flag = -1;
	  av->attr_un.au_char = NULL;

	  for (j = 0; __uess_fns[j].luf_attribute != NULL; j++)
	    {
	      if (strcmp (__uess_fns[j].luf_attribute, lua->lua_attributes[i])
		  == 0)
		{
		  stat = (__uess_fns[j].luf_translator) (e, lua, i);
		  switch (stat)
		    {
		    case NSS_SUCCESS:
		      av->attr_flag = 0;
		      break;
		    case NSS_TRYAGAIN:
		      return NSS_TRYAGAIN;
		      break;
		    default:
		      break;
		    }
		}
	    }
	}
    }

  return NSS_SUCCESS;
}

static int
_nss_ldap_getentry (char *key, char *table, char *attributes[],
		    attrval_t results[], int size)
{
  NSS_STATUS stat;
  ent_context_t *ctx = NULL;
  ldap_args_t a, *ap;
  const char *filter;
  int erange = 0;
  ldap_uess_args_t lua;
  const char *namingAttributes[2];

  debug ("==> _nss_ldap_getentry (key=%s table=%s attributes[0]=%s size=%d)",
	 (key != NULL) ? key : "(null)",
	 (table != NULL) ? table : "(null)",
 	 (size >= 1) ? attributes[0] : "(null)",
	 size);

  lua.lua_key = key;
  lua.lua_table = table;
  lua.lua_attributes = attributes;
  lua.lua_results = results;
  lua.lua_size = size;
  lua.lua_naming_attribute = NULL;

  lua.lua_map = table2map (table);
  if (lua.lua_map == LM_NONE)
    {
      errno = ENOSYS;
      debug ("<== _nss_ldap_getentry (no such map)");
      return -1;
    }

  lua.lua__buffer = NULL;
  lua.lua__bufsiz = 0;
  lua.lua__buflen = 0;

  ap = key2filter (key, lua.lua_map, &a, &filter);
  if (ap == NULL)		/* enumeration */
    {
      const char **attrs;

      if (size != 1)
	{
	  errno = EINVAL;
	  debug ("<== _nss_ldap_getentry (size != 1)");
	  return -1;
	}

      debug (":== _nss_ldap_getentry filter=%s attribute=%s",
	     filter, lua.lua_attributes[0]);

      lua.lua__bufsiz = NSS_BUFSIZ;
      lua.lua__buflen = lua.lua__bufsiz;
      lua.lua__buffer = results[0].attr_un.au_char = malloc (lua.lua__bufsiz);
      if (lua.lua__buffer == NULL)
	{
	  errno = ENOMEM;
	  debug ("<== _nss_ldap_getentry (no memory)");
	  return -1;
	}
      results[0].attr_flag = -1;

      /* just request the naming attributes */
      attrs = _nss_ldap_get_attributes (lua.lua_map);
      if (attrs == NULL || attrs[0] == NULL)
	{
	  errno = ENOENT;
	  debug ("<== _nss_ldap_getentry (could not read schema)");
	  return -1;
	}

      lua.lua_naming_attribute = attrs[0];
      namingAttributes[0] = lua.lua_naming_attribute;
      namingAttributes[1] = NULL;
    }
  else
    {
      /* Check at least one attribute is mapped before searching */
      int i, found = 0;

      for (i = 0; i < size; i++)
	{
	  if (uess2ldapattr (lua.lua_map, lua.lua_attributes[i]) != NULL)
	    {
	      found++;
	      break;
	    }
	}

      if (!found)
	{
	  errno = ENOENT;
	  debug ("<== _nss_ldap_getentry (no mappable attribute requested)");
	  return -1;
	}
    }

  _nss_ldap_enter ();
  if (_nss_ldap_ent_context_init_locked (&ctx) == NULL)
    {
      _nss_ldap_leave ();
      if (results[0].attr_un.au_char != NULL)
	free (results[0].attr_un.au_char);
      errno = ENOMEM;
      debug ("<== _nss_ldap_getentry (ent_context_init failed)");
      return -1;
    }

  stat = _nss_ldap_getent_ex (ap, &ctx, (void *) &lua, NULL, 0,
			      &erange, filter, lua.lua_map,
			      (ap == NULL) ? namingAttributes : NULL,
			      do_parse_uess_getentry);

  _nss_ldap_ent_context_release (ctx);
  free (ctx);
  _nss_ldap_leave ();

  /*
   * Whilst enumerating, we have the parser always return
   * NSS_NOTFOUND so that it will be called for each entry.
   *
   * Although this is probably bogus overloading of the
   * _nss_ldap_getent_ex() API, it does allow us to share
   * the same code for matches and enumerations. However,
   * for the enumeration case we need to treat NSS_NOTFOUND
   * as a success code; hence, we use the attr_flag to
   * indicate failure.
   */
  if (ap == NULL)
    {
      if (stat == NSS_NOTFOUND && results[0].attr_flag == 0)
	stat = NSS_SUCCESS;
    }

  if (stat != NSS_SUCCESS)
    {
      if (stat == NSS_TRYAGAIN)
	errno = ERANGE;
      else
	errno = ENOENT;

      debug ("<== _nss_ldap_getentry (failed with stat=%d)", stat);
      return -1;
    }

  debug ("<== _nss_ldap_getentry (success)");
  return AUTH_SUCCESS;
}

/*
 *
 */
static NSS_STATUS
uess_get_pwuid(const char *user, uid_t *uid)
{
  char **vals;
  LDAPMessage *res, *e;
  const char *attrs[2];
  NSS_STATUS stat;
  ldap_args_t a;

  LA_INIT (a);
  LA_TYPE (a) = LA_TYPE_STRING;
  LA_STRING (a) = user;

  attrs[0] = ATM (LM_PASSWD, uidNumber);
  attrs[1] = NULL;

  stat = _nss_ldap_search_s (&a, _nss_ldap_filt_getpwuid, LM_PASSWD,
			     attrs, 1, &res);
  if (stat != NSS_SUCCESS)
      return stat;

  e = _nss_ldap_first_entry (res);
  if (e == NULL)
    {
      ldap_msgfree (res);
      return NSS_NOTFOUND;
    }

  vals = _nss_ldap_get_values (e, attrs[0]);
  if (vals == NULL)
    {
      ldap_msgfree (res);
      return NSS_NOTFOUND;
    }

  if (vals[0] == NULL || (vals[0])[0] == '\0')
    {
      ldap_value_free (vals);
      ldap_msgfree (res);
      return NSS_NOTFOUND;
    }

  *uid = atoi(vals[0]);

  ldap_value_free (vals);
  ldap_msgfree (res);

  return NSS_SUCCESS;
}

/*
 * Get membership for a group
 */
static int
_nss_ldap_getgrusers (char *group, void *result, int type, int *size)
{
  struct group *gr;
  struct irs_gr *be;
  char **memp;
  size_t i;

  be = (struct irs_gr *) gr_pvtinit ();
  if (be == NULL)
    {
      errno = ENOSYS;
      return -1;
    }

  gr = (be->byname) (be, group);
  if (gr == NULL)
    {
      (be->close) (be);
      errno = ENOENT;
      return -1;
    }

  if (gr->gr_mem == NULL)
    {
      (be->close) (be);
      *size = 0;
      return 0;
    }

  for (i = 0; gr->gr_mem[i] != NULL; i++)
    ;

  if (i > *size)
    {
      (be->close) (be);
      *size = i;
      errno = ERANGE;
      return -1;
    }

  _nss_ldap_enter ();

  for (i = 0, memp = gr->gr_mem; *memp != NULL; memp++)
    {
      if (type == SEC_INT)
	{
	  if (uess_get_pwuid(*memp, &(((uid_t *)result)[i])) != NSS_SUCCESS)
	    continue;
	}
      else
	{
	  ((char **)result)[i] = strdup(*memp);
	  if (((char **)result)[i] == NULL)
	    {
	      _nss_ldap_leave ();
	      (be->close) (be);
	      errno = ENOMEM;
	      return -1;
	    }
	}
      i++;
    }

  _nss_ldap_leave ();

  *size = i;

  (be->close) (be);

  return AUTH_SUCCESS;
}

#if 0
/*
 * Additional attributes supported
 */
static attrlist_t **
_nss_ldap_attrlist(void)
{
  attrlist_t **a;

  a = malloc(2 * sizeof(attrlist_t *) + sizeof(attrlist_t));
  if (a == NULL)
    {
      errno = ENOMEM;
      return NULL;
    }

  a[0] = (attrlist_t *)(a + 2);

  a[0]->al_name = strdup(S_LDAPDN);
  a[0]->al_flags = AL_USERATTR;
  a[0]->al_type = SEC_CHAR;

  a[1] = NULL;

  return a;
}
#endif /* notdef */

#if 0
/* not implemented yet */
static int
_nss_ldap_normalize (char *longname, char *shortname)
{
}
#endif

int
nss_ldap_initialize (struct secmethod_table *meths)
{
  memset (meths, 0, sizeof (*meths));

  /* Initialize schema */
  (void) _nss_ldap_init();

  /* Identification methods */
  meths->method_getpwnam = _nss_ldap_getpwnam;
  meths->method_getpwuid = _nss_ldap_getpwuid;
  meths->method_getgrnam = _nss_ldap_getgrnam;
  meths->method_getgrgid = _nss_ldap_getgrgid;
  meths->method_getgrset = _nss_ldap_getgrset;
  meths->method_getentry = _nss_ldap_getentry;
/*  meths->method_attrlist = _nss_ldap_attrlist; */
  meths->method_getgrusers = _nss_ldap_getgrusers;
/*  meths->method_normalize = _nss_ldap_normalize; */
  meths->method_getgracct = _nss_ldap_getgracct;
  meths->method_getpasswd = _nss_ldap_getpasswd;

  /* Support methods */
  meths->method_open = _nss_ldap_uess_open;
  meths->method_close = _nss_ldap_uess_close;

  /* Authentication methods */
  meths->method_authenticate = _nss_ldap_authenticate;

  return AUTH_SUCCESS;
}

#endif /* HAVE_USERSEC_H */
