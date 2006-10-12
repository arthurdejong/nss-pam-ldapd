/* Copyright (C) 2002-2005 Luke Howard.
   This file is part of the nss_ldap library.
   Linux support contributed by Larry Lile, <llile@dreamworks.com>, 2002.
   Solaris support contributed by Luke Howard, <lukeh@padl.com>, 2004.

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

#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>

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
#include <assert.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#ifndef HAVE_SNPRINTF
#include "snprintf.h"
#endif

#include "ldap-nss.h"
#include "ldap-netgrp.h"
#include "util.h"

#ifdef HAVE_PORT_AFTER_H
#include <port_after.h>
#endif

#ifdef HAVE_NSS_H
static ent_context_t *_ngbe = NULL;
#endif

#ifdef HAVE_IRS_H
enum nss_netgr_status {
	NSS_NETGR_FOUND,
	NSS_NETGR_NO,
	NSS_NETGR_NOMEM
};

struct pvt; /* forward declaration for IRS backend type */
#endif /* HAVE_IRS_H */

#ifdef HAVE_NSSWITCH_H
static nss_backend_op_t netgroup_ops[];
#endif

#if defined(HAVE_NSSWITCH_H) || defined(HAVE_IRS_H)
struct ldap_innetgr_args
{
  const char *lia_netgroup;
  enum nss_netgr_status lia_netgr_status;
  int lia_depth;
  int lia_erange;
};

typedef struct ldap_innetgr_args ldap_innetgr_args_t;

static NSS_STATUS do_innetgr_nested (ldap_innetgr_args_t * li_args,
				     const char *nested);
#endif /* HAVE_NSSWITCH_H || HAVE_IRS_H */

/*
 * I pulled the following macro (EXPAND), functions (strip_whitespace and
 * _nss_netgroup_parseline) and structures (name_list and __netgrent) from
 * glibc-2.2.x.  _nss_netgroup_parseline became _nss_ldap_parse_netgr after
 * some modification. 
 * 
 * The rest of the code is modeled on various other _nss_ldap functions.
 */

#define EXPAND(needed)                                                        \
  do                                                                          \
    {                                                                         \
      size_t old_cursor = result->cursor - result->data;                      \
                                                                              \
      result->data_size += 512 > 2 * needed ? 512 : 2 * needed;               \
      result->data = realloc (result->data, result->data_size);               \
                                                                              \
      if (result->data == NULL)                                               \
        {                                                                     \
          stat = NSS_UNAVAIL;                                                 \
          goto out;                                                           \
        }                                                                     \
                                                                              \
      result->cursor = result->data + old_cursor;                             \
    }                                                                         \
  while (0)

/* A netgroup can consist of names of other netgroups.  We have to
   track which netgroups were read and which still have to be read.  */


/* Dataset for iterating netgroups.  */
struct __netgrent
{
  enum
  { triple_val, group_val }
  type;

  union
  {
    struct
    {
      const char *host;
      const char *user;
      const char *domain;
    }
    triple;

    const char *group;
  }
  val;

  /* Room for the data kept between the calls to the netgroup
     functions.  We must avoid global variables.  */
  char *data;
  size_t data_size;
  char *cursor;
  int first;

  struct name_list *known_groups;
  struct name_list *needed_groups;
};

static char *
strip_whitespace (char *str)
{
  char *cp = str;

  /* Skip leading spaces.  */
  while (isspace ((int) *cp))
    cp++;

  str = cp;
  while (*cp != '\0' && !isspace ((int) *cp))
    cp++;

  /* Null-terminate, stripping off any trailing spaces.  */
  *cp = '\0';

  return *str == '\0' ? NULL : str;
}

static NSS_STATUS
_nss_ldap_parse_netgr (void *vresultp, char *buffer, size_t buflen)
{
  struct __netgrent *result = (struct __netgrent *) vresultp;
  char *cp = result->cursor;
  char *user, *host, *domain;

  /* The netgroup either doesn't exist or is empty. */
  if (cp == NULL)
    return NSS_RETURN;

  /* First skip leading spaces. */
  while (isspace ((int) *cp))
    ++cp;

  if (*cp != '(')
    {
      /* We have a list of other netgroups. */
      char *name = cp;

      while (*cp != '\0' && !isspace ((int) *cp))
	++cp;

      if (name != cp)
	{
	  /* It is another netgroup name. */
	  int last = *cp == '\0';

	  result->type = group_val;
	  result->val.group = name;
	  *cp = '\0';
	  if (!last)
	    ++cp;
	  result->cursor = cp;
	  result->first = 0;

	  return NSS_SUCCESS;
	}
      return result->first ? NSS_NOTFOUND : NSS_RETURN;
    }

  /* Match host name. */
  host = ++cp;
  while (*cp != ',')
    if (*cp++ == '\0')
      return result->first ? NSS_NOTFOUND : NSS_RETURN;

  /* Match user name. */
  user = ++cp;
  while (*cp != ',')
    if (*cp++ == '\0')
      return result->first ? NSS_NOTFOUND : NSS_RETURN;

  /* Match domain name. */
  domain = ++cp;
  while (*cp != ')')
    if (*cp++ == '\0')
      return result->first ? NSS_NOTFOUND : NSS_RETURN;
  ++cp;

  /* When we got here we have found an entry.  Before we can copy it
     to the private buffer we have to make sure it is big enough.  */
  if (cp - host > buflen)
    return NSS_TRYAGAIN;

  strncpy (buffer, host, cp - host);
  result->type = triple_val;

  buffer[(user - host) - 1] = '\0';
  result->val.triple.host = strip_whitespace (buffer);

  buffer[(domain - host) - 1] = '\0';
  result->val.triple.user = strip_whitespace (buffer + (user - host));

  buffer[(cp - host) - 1] = '\0';
  result->val.triple.domain = strip_whitespace (buffer + (domain - host));

  /* Remember where we stopped reading. */
  result->cursor = cp;
  result->first = 0;

  return NSS_SUCCESS;
}

#ifdef HAVE_NSS_H
static NSS_STATUS
_nss_ldap_load_netgr (LDAPMessage * e,
		      ldap_state_t * pvt,
		      void *vresultp, char *buffer, size_t buflen)
{
  int attr;
  int nvals;
  int valcount = 0;
  char **vals;
  char **valiter;
  struct __netgrent *result = vresultp;
  NSS_STATUS stat = NSS_SUCCESS;

  for (attr = 0; attr < 2; attr++)
    {
      switch (attr)
	{
	case 1:
	  vals = _nss_ldap_get_values (e, AT (nisNetgroupTriple));
	  break;
	default:
	  vals = _nss_ldap_get_values (e, AT (memberNisNetgroup));
	  break;
	}

      nvals = ldap_count_values (vals);

      if (vals == NULL)
	continue;

      if (nvals == 0)
	{
	  ldap_value_free (vals);
	  continue;
	}

      if (result->data_size > 0
	  && result->cursor - result->data + 1 > result->data_size)
	EXPAND (1);

      if (result->data_size > 0)
	*result->cursor++ = ' ';

      valcount += nvals;
      valiter = vals;

      while (*valiter != NULL)
	{
	  int curlen = strlen (*valiter);
	  if (result->cursor - result->data + curlen + 1 > result->data_size)
	    EXPAND (curlen + 1);
	  memcpy (result->cursor, *valiter, curlen + 1);
	  result->cursor += curlen;
	  valiter++;
	  if (*valiter != NULL)
	    *result->cursor++ = ' ';
	}
      ldap_value_free (vals);
    }

  result->first = 1;
  result->cursor = result->data;

out:

  return stat;
}

NSS_STATUS
_nss_ldap_endnetgrent (struct __netgrent * result)
{
  if (result->data != NULL)
    {
      free (result->data);
      result->data = NULL;
      result->data_size = 0;
      result->cursor = NULL;
    }

  LOOKUP_ENDENT (_ngbe);
}

NSS_STATUS
_nss_ldap_setnetgrent (char *group, struct __netgrent *result)
{
  int errnop = 0, buflen = 0;
  char *buffer = (char *) NULL;
  ldap_args_t a;
  NSS_STATUS stat = NSS_SUCCESS;

  if (group[0] == '\0')
    return NSS_UNAVAIL;

  if (result->data != NULL)
    free (result->data);
  result->data = result->cursor = NULL;
  result->data_size = 0;

  LA_INIT (a);
  LA_STRING (a) = group;
  LA_TYPE (a) = LA_TYPE_STRING;

  stat =
    _nss_ldap_getbyname (&a, result, buffer, buflen, &errnop,
			 _nss_ldap_filt_getnetgrent, LM_NETGROUP,
			 _nss_ldap_load_netgr);

  LOOKUP_SETENT (_ngbe);
}

NSS_STATUS
_nss_ldap_getnetgrent_r (struct __netgrent *result,
			 char *buffer, size_t buflen, int *errnop)
{
  return _nss_ldap_parse_netgr (result, buffer, buflen);
}
#endif /* HAVE_NSS_H */

#if defined(HAVE_NSSWITCH_H) || defined(HAVE_IRS_H)
/*
 * Chase nested netgroups. If we can't find a nested netgroup, we try
 * the next one - don't want to fail authoritatively because of bad
 * user data.
 */
static NSS_STATUS
nn_chase (nss_ldap_netgr_backend_t * ngbe, LDAPMessage ** pEntry)
{
  ldap_args_t a;
  NSS_STATUS stat = NSS_NOTFOUND;

  debug ("==> nn_chase");

  if (ngbe->state->ec_res != NULL)
    {
      ldap_msgfree (ngbe->state->ec_res);
      ngbe->state->ec_res = NULL;
    }

  while (ngbe->needed_groups != NULL)
    {
      /* If this netgroup has already been seen, avoid it  */
      if (_nss_ldap_namelist_find (ngbe->known_groups, ngbe->needed_groups->name))
	{
	  _nss_ldap_namelist_pop (&ngbe->needed_groups);
	  continue;
	}

      LA_INIT (a);
      LA_TYPE (a) = LA_TYPE_STRING;
      LA_STRING (a) = ngbe->needed_groups->name;

      debug (":== nn_chase: nested netgroup=%s", LA_STRING (a));

      _nss_ldap_enter ();
      stat = _nss_ldap_search_s (&a, _nss_ldap_filt_getnetgrent,
				 LM_NETGROUP, NULL, 1, &ngbe->state->ec_res);
      _nss_ldap_leave ();

      if (stat == NSS_SUCCESS)
	{
	  /* we have "seen" this netgroup; track it for loop detection */
	  stat = _nss_ldap_namelist_push (&ngbe->known_groups, ngbe->needed_groups->name);
	  if (stat != NSS_SUCCESS)
	    {
	      _nss_ldap_namelist_pop (&ngbe->needed_groups);
	      break;
	    }
	}

      _nss_ldap_namelist_pop (&ngbe->needed_groups);

      if (stat == NSS_SUCCESS)
	{
	  /* Check we got an entry, not just a result. */
	  *pEntry = _nss_ldap_first_entry (ngbe->state->ec_res);
	  if (*pEntry == NULL)
	    {
	      ldap_msgfree (ngbe->state->ec_res);
	      ngbe->state->ec_res = NULL;
	      stat = NSS_NOTFOUND;
	    }
	}

      if (stat == NSS_SUCCESS)
	{
	  /* found one. */
	  break;
	}
    }

  debug ("<== nn_chase result=%d", stat);

  return stat;
}
#endif /* HAVE_NSSWITCH_H || HAVE_IRS_H */

#if defined(HAVE_NSSWITCH_H) || defined(HAVE_IRS_H)
/*
 * getnetgrent() inner implementation, used by both Solaris NSS
 * and IRS/AIX
 */
static NSS_STATUS
do_getnetgrent (nss_ldap_netgr_backend_t *be,
		char *buffer, size_t buflen,
		enum nss_netgr_status *status,
		char **machine, char **user, char **domain)
{
  ent_context_t *ctx;
  NSS_STATUS parseStat = NSS_NOTFOUND;

  /*
   * This function is called with the pseudo-backend that
   * we created in _nss_ldap_setnetgrent() (see below)
   */
  debug ("==> do_getnetgrent");

  ctx = be->state;
  assert (ctx != NULL);

  *status = NSS_NETGR_NO;
  *machine = NULL;
  *user = NULL;
  *domain = NULL;

  do
    {
      NSS_STATUS resultStat = NSS_SUCCESS;
      char **vals, **p;
      ldap_state_t *state = &ctx->ec_state;
      struct __netgrent __netgrent;
      LDAPMessage *e;

      if (state->ls_retry == 0 && state->ls_info.ls_index == -1)
	{
	  resultStat = NSS_NOTFOUND;

	  if (ctx->ec_res != NULL)
	    {
	      e = _nss_ldap_first_entry (ctx->ec_res);
	      if (e != NULL)
		resultStat = NSS_SUCCESS;
	    }

	  if (resultStat != NSS_SUCCESS)
	    {
	      /* chase nested netgroups */
	      resultStat = nn_chase (be, &e);
	    }

	  if (resultStat != NSS_SUCCESS)
	    {
	      parseStat = resultStat;
	      break;
	    }

	  assert (e != NULL);

	  /* Push nested netgroups onto stack for deferred chasing */
	  vals = _nss_ldap_get_values (e, AT (memberNisNetgroup));
	  if (vals != NULL)
	    {
	      for (p = vals; *p != NULL; p++)
		{
		  parseStat = _nss_ldap_namelist_push (&be->needed_groups, *p);
		  if (parseStat != NSS_SUCCESS)
		    break;
		}
	      ldap_value_free (vals);

	      if (parseStat != NSS_SUCCESS)
		break;		/* out of memory */
	    }
	}
      else
	{
	  assert (ctx->ec_res != NULL);
	  e = _nss_ldap_first_entry (ctx->ec_res);
	  if (e == NULL)
	    {
	      /* This should never happen, but we fail gracefully. */
	      parseStat = NSS_UNAVAIL;
	      break;
	    }
	}

      /* We have an entry; now, try to parse it. */
      vals = _nss_ldap_get_values (e, AT (nisNetgroupTriple));
      if (vals == NULL)
	{
	  state->ls_info.ls_index = -1;
	  parseStat = NSS_NOTFOUND;
	  ldap_msgfree (ctx->ec_res);
	  ctx->ec_res = NULL;
	  continue;
	}

      switch (state->ls_info.ls_index)
	{
	case 0:
	  /* last time. decrementing ls_index to -1 AND returning
	   * an error code will force this entry to be discared.
	   */
	  parseStat = NSS_NOTFOUND;
	  break;
	case -1:
	  /* first time */
	  state->ls_info.ls_index = ldap_count_values (vals);
	  /* fall off to default... */
	default:
	  __netgrent.data = vals[state->ls_info.ls_index - 1];
	  __netgrent.data_size = strlen (vals[state->ls_info.ls_index - 1]);
	  __netgrent.cursor = __netgrent.data;
	  __netgrent.first = 1;

	  parseStat = _nss_ldap_parse_netgr (&__netgrent, buffer, buflen);
	  if (parseStat != NSS_SUCCESS)
	    {
	      break;
	    }
	  if (__netgrent.type != triple_val)
	    {
	      parseStat = NSS_NOTFOUND;
	      break;
	    }
	  *machine = (char *) __netgrent.val.triple.host;
	  *user = (char *) __netgrent.val.triple.user;
	  *domain = (char *) __netgrent.val.triple.domain;
	  break;
	}

      ldap_value_free (vals);
      state->ls_info.ls_index--;

      /* hold onto the state if we're out of memory XXX */
      state->ls_retry = (parseStat == NSS_TRYAGAIN ? 1 : 0);
      *status = (parseStat == NSS_SUCCESS) ? NSS_NETGR_FOUND : NSS_NETGR_NOMEM;

      if (state->ls_retry == 0 && state->ls_info.ls_index == -1)
	{
	  ldap_msgfree (ctx->ec_res);
	  ctx->ec_res = NULL;
	}
    }
  while (parseStat == NSS_NOTFOUND);

  if (parseStat == NSS_TRYAGAIN)
    {
      errno = ERANGE;
    }

  debug ("<== do_getnetgrent");

  return parseStat;
}

/*
 * Test a 4-tuple
 */
static NSS_STATUS
do_parse_innetgr (LDAPMessage * e, ldap_state_t * pvt,
		  void *result, char *buffer, size_t buflen)
{
  ldap_innetgr_args_t *li_args = (ldap_innetgr_args_t *) result;
  int count;
  char **values = NULL;
  NSS_STATUS stat = NSS_NOTFOUND;

  debug ("==> do_parse_innetgr");

  values = _nss_ldap_get_values (e, ATM (LM_NETGROUP, cn));
  if (values == NULL)
      return NSS_NOTFOUND;

  count = ldap_count_values (values);

  while (--count >= 0)
    {
      assert (values[count] != NULL);

      if (strcasecmp (li_args->lia_netgroup, values[count]) == 0)
	{
	  li_args->lia_netgr_status = NSS_NETGR_FOUND;
	  stat = NSS_SUCCESS;
	}
      else
	{
	  stat = do_innetgr_nested (li_args, values[count]);
	}

      if (stat == NSS_SUCCESS)
	break;
    }

  ldap_value_free (values);

  debug ("<== do_parse_innetgr");

  return stat;
}

/*
 * NB: caller has acquired the global lock
 */
static NSS_STATUS
do_innetgr_nested (ldap_innetgr_args_t * li_args, const char *nested)
{
  NSS_STATUS stat;
  ldap_args_t a;
  ent_context_t *ctx = NULL;

  debug ("==> do_innetgr_nested netgroup=%s assertion=%s",
	 li_args->lia_netgroup, nested);

  if (li_args->lia_depth >= LDAP_NSS_MAXNETGR_DEPTH)
    {
      debug ("<== do_innetgr_nested: maximum depth exceeded");
      return NSS_NOTFOUND;
    }

  LA_INIT (a);
  LA_TYPE (a) = LA_TYPE_STRING;
  LA_STRING (a) = nested;	/* memberNisNetgroup */

  if (_nss_ldap_ent_context_init_locked (&ctx) == NULL)
    {
      debug ("<== do_innetgr_nested: failed to initialize context");
      return NSS_UNAVAIL;
    }

  li_args->lia_depth++;

  stat = _nss_ldap_getent_ex (&a, &ctx, (void *) li_args, NULL, 0,
			      &li_args->lia_erange, _nss_ldap_filt_innetgr,
			      LM_NETGROUP, NULL, do_parse_innetgr);

  li_args->lia_depth--;

  _nss_ldap_ent_context_release (ctx);
  free (ctx);

  debug ("<== do_innetgr_nested status=%d netgr_status=%d",
	 stat, li_args->lia_netgr_status);

  return stat;
}

/*
 * NB: caller has acquired the global lock
 */
static NSS_STATUS
do_innetgr (ldap_innetgr_args_t * li_args,
	    const char *machine, const char *user, const char *domain)
{
  NSS_STATUS stat;
  ldap_args_t a;
  ent_context_t *ctx = NULL;

  debug ("==> do_innetgr netgroup=%s", li_args->lia_netgroup);

  /*
   * First, find which netgroup the 3-tuple belongs to.
   */
  LA_INIT (a);
  LA_TYPE (a) = LA_TYPE_TRIPLE;
  LA_TRIPLE (a).user = user;
  LA_TRIPLE (a).host = machine;
  LA_TRIPLE (a).domain = domain;

  if (_nss_ldap_ent_context_init_locked (&ctx) == NULL)
    {
      debug ("<== do_innetgr: failed to initialize context");
      return NSS_UNAVAIL;
    }

  stat = _nss_ldap_getent_ex (&a, &ctx, (void *) li_args, NULL, 0,
			      &li_args->lia_erange, NULL, LM_NETGROUP,
			      NULL, do_parse_innetgr);

  _nss_ldap_ent_context_release (ctx);
  free (ctx);

  debug ("<== do_innetgr status=%d netgr_status=%d",
	 stat, li_args->lia_netgr_status);

  return stat;
}
#endif /* HAVE_NSSWITCH_H || HAVE_IRS_H */

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_getnetgroup_endent (nss_backend_t * be, void *_args)
{
  LOOKUP_ENDENT (be);
}

static NSS_STATUS
_nss_ldap_getnetgroup_setent (nss_backend_t * be, void *_args)
{
  return NSS_SUCCESS;
}

static NSS_STATUS
_nss_ldap_getnetgroup_getent (nss_backend_t * _be, void *_args)
{
  nss_ldap_netgr_backend_t *be = (nss_ldap_netgr_backend_t *) _be;
  struct nss_getnetgrent_args *args = (struct nss_getnetgrent_args *) _args;
  NSS_STATUS stat;

  _nss_ldap_enter ();

  stat = do_getnetgrent (be,
			 args->buffer,
			 args->buflen,
			 &args->status,
			 &args->retp[NSS_NETGR_MACHINE],
			 &args->retp[NSS_NETGR_USER],
			 &args->retp[NSS_NETGR_DOMAIN]);

  _nss_ldap_leave ();

  return stat;
}

static NSS_STATUS
_nss_ldap_innetgr (nss_backend_t * be, void *_args)
{
  NSS_STATUS stat = NSS_NOTFOUND;
  struct nss_innetgr_args *args = (struct nss_innetgr_args *) _args;
  int i;

  /*
   * Enumerate the groups in args structure and see whether
   * any 4-tuple was satisfied. This really needs LDAP
   * component matching to be done efficiently.
   */

  debug
    ("==> _nss_ldap_innetgr MACHINE.argc=%d USER.argc=%d DOMAIN.argc=%d groups.argc=%d",
     args->arg[NSS_NETGR_MACHINE].argc, args->arg[NSS_NETGR_USER].argc,
     args->arg[NSS_NETGR_DOMAIN].argc, args->groups.argc);

  /* Presume these are harmonized -- this is a strange interface */
  assert (args->arg[NSS_NETGR_MACHINE].argc == 0 ||
	  args->arg[NSS_NETGR_MACHINE].argc == args->groups.argc);
  assert (args->arg[NSS_NETGR_USER].argc == 0 ||
	  args->arg[NSS_NETGR_USER].argc == args->groups.argc);
  assert (args->arg[NSS_NETGR_DOMAIN].argc == 0 ||
	  args->arg[NSS_NETGR_DOMAIN].argc == args->groups.argc);

  _nss_ldap_enter ();

  for (i = 0; i < args->groups.argc; i++)
    {
      NSS_STATUS parseStat;
      ldap_innetgr_args_t li_args;

      const char *machine = (args->arg[NSS_NETGR_MACHINE].argc != 0) ?
	args->arg[NSS_NETGR_MACHINE].argv[i] : NULL;
      const char *user = (args->arg[NSS_NETGR_USER].argc != 0) ?
	args->arg[NSS_NETGR_USER].argv[i] : NULL;
      const char *domain = (args->arg[NSS_NETGR_DOMAIN].argc != 0) ?
	args->arg[NSS_NETGR_DOMAIN].argv[i] : NULL;

      li_args.lia_netgroup = args->groups.argv[i];
      li_args.lia_netgr_status = NSS_NETGR_NO;
      li_args.lia_depth = 0;
      li_args.lia_erange = 0;

      parseStat = do_innetgr (&li_args, machine, user, domain);
      if (parseStat != NSS_SUCCESS && parseStat != NSS_NOTFOUND)
	{
	  /* fatal error */
	  if (li_args.lia_erange != 0)
	    errno = ERANGE;
	  break;
	}

      args->status = li_args.lia_netgr_status;

      if (args->status == NSS_NETGR_FOUND)
	{
	  stat = NSS_SUCCESS;
	}
    }

  _nss_ldap_leave ();

  debug ("<== _nss_ldap_innetgr");

  return stat;
}

/*
 * According to the "documentation", setnetgrent() is really
 * a getXXXbyYYY() operation that returns a pseudo-backend
 * through which one may enumerate the netgroup's members.
 *
 * ie. this is the constructor for the pseudo-backend.
 */
static NSS_STATUS
_nss_ldap_setnetgrent (nss_backend_t * be, void *_args)
{
  NSS_STATUS stat;
  struct nss_setnetgrent_args *args;
  nss_ldap_netgr_backend_t *ngbe;
  ldap_args_t a;

  debug ("==> _nss_ldap_setnetgrent");

  args = (struct nss_setnetgrent_args *) _args;
  args->iterator = NULL;	/* initialize */

  /*
   * This retrieves the top-level netgroup; nested netgroups
   * are chased inside the pseudo-backend.
   */

  LA_INIT (a);
  LA_TYPE (a) = LA_TYPE_STRING;
  LA_STRING (a) = args->netgroup;	/* cn */

  ngbe = (nss_ldap_netgr_backend_t *) malloc (sizeof (*ngbe));
  if (ngbe == NULL)
    {
      debug ("<== _nss_ldap_setnetgrent");
      return NSS_UNAVAIL;
    }

  ngbe->ops = netgroup_ops;
  ngbe->n_ops = 6;
  ngbe->state = NULL;
  ngbe->known_groups = NULL;
  ngbe->needed_groups = NULL;

  stat = _nss_ldap_default_constr ((nss_ldap_backend_t *) ngbe);
  if (stat != NSS_SUCCESS)
    {
      free (ngbe);
      debug ("<== _nss_ldap_setnetgrent");
      return stat;
    }

  if (_nss_ldap_ent_context_init (&ngbe->state) == NULL)
    {
      _nss_ldap_default_destr ((nss_backend_t *) ngbe, NULL);
      debug ("<== _nss_ldap_setnetgrent");
      return NSS_UNAVAIL;
    }

  assert (ngbe->state != NULL);
  assert (ngbe->state->ec_res == NULL);

  _nss_ldap_enter ();
  stat = _nss_ldap_search_s (&a, _nss_ldap_filt_getnetgrent,
			     LM_NETGROUP, NULL, 1, &ngbe->state->ec_res);
  _nss_ldap_leave ();

  if (stat == NSS_SUCCESS)
    {
      /* we have "seen" this netgroup; track it for loop detection */
      stat = _nss_ldap_namelist_push (&ngbe->known_groups, args->netgroup);
    }

  if (stat == NSS_SUCCESS)
    {
      args->iterator = (nss_backend_t *) ngbe;
    }
  else
    {
      _nss_ldap_default_destr ((nss_backend_t *) ngbe, NULL);
    }

  debug ("<== _nss_ldap_setnetgrent");

  return stat;
}

static NSS_STATUS
_nss_ldap_netgroup_destr (nss_backend_t * _ngbe, void *args)
{
  nss_ldap_netgr_backend_t *ngbe = (nss_ldap_netgr_backend_t *) _ngbe;

  /* free list of nested netgroups */
  _nss_ldap_namelist_destroy (&ngbe->known_groups);
  _nss_ldap_namelist_destroy (&ngbe->needed_groups);

  return _nss_ldap_default_destr (_ngbe, args);
}

static nss_backend_op_t netgroup_ops[] = {
  _nss_ldap_netgroup_destr,	/* NSS_DBOP_DESTRUCTOR */
  _nss_ldap_getnetgroup_endent,	/* NSS_DBOP_ENDENT */
  _nss_ldap_getnetgroup_setent,	/* NSS_DBOP_SETENT */
  _nss_ldap_getnetgroup_getent,	/* NSS_DBOP_GETENT */
  _nss_ldap_innetgr,		/* NSS_DBOP_NETGROUP_IN */
  _nss_ldap_setnetgrent		/* NSS_DBOP_NETGROUP_SET */
};

nss_backend_t *
_nss_ldap_netgroup_constr (const char *db_name,
			   const char *src_name, const char *cfg_args)
{
  nss_ldap_netgr_backend_t *be;

  if (!(be = (nss_ldap_netgr_backend_t *) malloc (sizeof (*be))))
    return NULL;

  be->ops = netgroup_ops;
  be->n_ops = sizeof (netgroup_ops) / sizeof (nss_backend_op_t);
  be->known_groups = NULL;
  be->needed_groups = NULL;

  if (_nss_ldap_default_constr ((nss_ldap_backend_t *) be) != NSS_SUCCESS)
    {
      free (be);
      return NULL;
    }

  return (nss_backend_t *) be;
}

#endif /* !HAVE_NSS_H */

#ifdef HAVE_IRS_H
#include "irs-netgrp.c"
#endif /* HAVE_IRS_H */
