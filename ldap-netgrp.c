/*
   Copyright (C) 2002-2005 Luke Howard
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

#include "config.h"

#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include <assert.h>
#if defined(HAVE_THREAD_H)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif
#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#include "ldap-nss.h"
#include "util.h"

static struct ent_context *_ngbe = NULL;

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
          stat = NSS_STATUS_UNAVAIL;                                                 \
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

static enum nss_status
_nss_ldap_parse_netgr (void *vresultp, char *buffer, size_t buflen)
{
  struct __netgrent *result = (struct __netgrent *) vresultp;
  char *cp = result->cursor;
  char *user, *host, *domain;

  /* The netgroup either doesn't exist or is empty. */
  if (cp == NULL)
    return NSS_STATUS_RETURN;

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

          return NSS_STATUS_SUCCESS;
        }
      return result->first ? NSS_STATUS_NOTFOUND : NSS_STATUS_RETURN;
    }

  /* Match host name. */
  host = ++cp;
  while (*cp != ',')
    if (*cp++ == '\0')
      return result->first ? NSS_STATUS_NOTFOUND : NSS_STATUS_RETURN;

  /* Match user name. */
  user = ++cp;
  while (*cp != ',')
    if (*cp++ == '\0')
      return result->first ? NSS_STATUS_NOTFOUND : NSS_STATUS_RETURN;

  /* Match domain name. */
  domain = ++cp;
  while (*cp != ')')
    if (*cp++ == '\0')
      return result->first ? NSS_STATUS_NOTFOUND : NSS_STATUS_RETURN;
  ++cp;

  /* When we got here we have found an entry.  Before we can copy it
     to the private buffer we have to make sure it is big enough.  */
  if (cp - host > buflen)
    return NSS_STATUS_TRYAGAIN;

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

  return NSS_STATUS_SUCCESS;
}

static enum nss_status
_nss_ldap_load_netgr (LDAPMessage * e,
                      struct ldap_state * pvt,
                      void *vresultp, char *buffer, size_t buflen)
{
  int attr;
  int nvals;
  int valcount = 0;
  char **vals;
  char **valiter;
  struct __netgrent *result = vresultp;
  enum nss_status stat = NSS_STATUS_SUCCESS;

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

enum nss_status
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

enum nss_status
_nss_ldap_setnetgrent (char *group, struct __netgrent *result)
{
  int errnop = 0, buflen = 0;
  char *buffer = (char *) NULL;
  struct ldap_args a;
  enum nss_status stat = NSS_STATUS_SUCCESS;

  if (group[0] == '\0')
    return NSS_STATUS_UNAVAIL;

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

enum nss_status
_nss_ldap_getnetgrent_r (struct __netgrent *result,
                         char *buffer, size_t buflen, int *errnop)
{
  return _nss_ldap_parse_netgr (result, buffer, buflen);
}
