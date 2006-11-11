/*
   automount.c - automounter maps lookup routines
   This file was part of the nss-ldap library (as ldap-automount.c)
   which has been forked into the nss-ldapd library.

   Copyright (C) 2005 Luke Howard
   Copyright (C) 2006 West Consulting
   Copyright (C) 2006 Arthur de Jong

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
   MA 02110-1301 USA
*/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
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
#if defined(HAVE_THREAD_H)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include "ldap-nss.h"
#include "util.h"

/* Linux only for now */
struct ldap_automount_context {
  /* Enumeration state */
  struct ent_context *lac_state;

  /* DNs of containers representing automount map */
  char **lac_dn_list;
  size_t lac_dn_size;
  size_t lac_dn_count;
  size_t lac_dn_index;
};

static enum nss_status
_nss_ldap_parse_automount (LDAPMessage * e,
                           struct ldap_state * pvt,
                           void *result, char *buffer, size_t buflen)
{
  enum nss_status stat;
  char ***keyval = result;

  stat =
    _nss_ldap_assign_attrval (e, AT (automountKey), keyval[0],
                              &buffer, &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrval (e, AT (automountInformation), keyval[1],
                              &buffer, &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  return NSS_STATUS_SUCCESS;
}

static enum nss_status
_nss_ldap_am_context_alloc(struct ldap_automount_context **pContext)
{
  struct ldap_automount_context *context;

  context = (struct ldap_automount_context *)malloc (sizeof(*context));
  if (context == NULL)
    {
      return NSS_STATUS_TRYAGAIN;
    }

  context->lac_state = NULL;

  context->lac_dn_size = 1;   /* number of slots allocated */
  context->lac_dn_count = 0;  /* number of slots used */
  context->lac_dn_index = 0;  /* enumeration index */

  /* List of DNs, grown on demand */
  context->lac_dn_list = (char **)malloc (context->lac_dn_size *
                                          sizeof(char *));
  if (context->lac_dn_list == NULL)
    {
      free (context);
      return NSS_STATUS_TRYAGAIN;
    }

  if (_nss_ldap_ent_context_init_locked (&context->lac_state) == NULL)
    {
      free (context->lac_dn_list);
      free (context);
      return NSS_STATUS_UNAVAIL;
    }

  *pContext = context;

  return NSS_STATUS_SUCCESS;
}

static void
_nss_ldap_am_context_free(struct ldap_automount_context **pContext)
{
  struct ldap_automount_context *context;
  size_t i;

  context = *pContext;

  if (context == NULL)
    return;

  if (context->lac_dn_list != NULL)
    {
      for (i = 0; i < context->lac_dn_count; i++)
        {
#ifdef HAVE_LDAP_MEMFREE
          ldap_memfree (context->lac_dn_list[i]);
#else
          free (context->lac_dn_list[i]);
#endif /* HAVE_LDAP_MEMFREE */
        }
      free (context->lac_dn_list);
    }

  if (context->lac_state != NULL)
    {
      _nss_ldap_ent_context_release (context->lac_state);
      free (context->lac_state);
    }

  memset (context, 0, sizeof (*context));
  free (context);

  *pContext = NULL;

  return;
}

static enum nss_status
am_context_add_dn (LDAPMessage * e,
                   struct ldap_state * pvt,
                   void *result, char *buffer, size_t buflen)
{
  struct ldap_automount_context *context = (struct ldap_automount_context *) result;
  char *dn;

  dn = _nss_ldap_get_dn (e);
  if (dn == NULL)
    {
      return NSS_STATUS_NOTFOUND;
    }

  if (context->lac_dn_count >= context->lac_dn_size)
    {
      char **new_dns;

      new_dns = (char **)realloc(context->lac_dn_list,
                                 2 * context->lac_dn_size * sizeof(char *));
      if (new_dns == NULL)
        {
#ifdef HAVE_LDAP_MEMFREE
          ldap_memfree (dn);
#else
          free (dn);
#endif /* HAVE_LDAP_MEMFREE */
          return NSS_STATUS_TRYAGAIN;
        }

      context->lac_dn_list = new_dns;
      context->lac_dn_size *= 2;
    }

  context->lac_dn_list[context->lac_dn_count++] = dn;

  return NSS_STATUS_SUCCESS;
}

static enum nss_status
_nss_ldap_am_context_init(const char *mapname, struct ldap_automount_context **pContext)
{
  enum nss_status stat;
  struct ldap_automount_context *context = NULL;
  const char *no_attrs[] = { NULL };
  struct ldap_args a;
  struct ent_context *key = NULL;
  int errnop;

  *pContext = NULL;

  stat = _nss_ldap_am_context_alloc (&context);
  if (stat != NSS_STATUS_SUCCESS)
      return stat;

  LA_INIT (a);
  LA_TYPE (a) = LA_TYPE_STRING;
  LA_STRING (a) = mapname;

  do
    {
      stat = _nss_ldap_getent_ex (&a, &key,
                                  (void *)context,
                                  NULL, 0, &errnop,
                                  _nss_ldap_filt_setautomntent,
                                  LM_AUTOMOUNT,
                                  no_attrs,
                                  am_context_add_dn);
    }
  while (stat == NSS_STATUS_SUCCESS);

  if (key != NULL)
    {
      _nss_ldap_ent_context_release (key);
      free (key);
    }

  if (context->lac_dn_count == 0)
    {
      _nss_ldap_am_context_free (&context);
      return NSS_STATUS_NOTFOUND;
    }
  else if (stat == NSS_STATUS_NOTFOUND)
    {
      stat = NSS_STATUS_SUCCESS;
    }

  context->lac_dn_index = 0;

  *pContext = context;
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_setautomntent(const char *mapname, void **private)
{
  struct ldap_automount_context *context = NULL;
  enum nss_status stat;

  debug ("==> _nss_ldap_setautomntent");

  _nss_ldap_enter ();

  stat = _nss_ldap_init ();
  if (stat != NSS_STATUS_SUCCESS)
    {
      _nss_ldap_leave ();
      debug ("<== _nss_ldap_setautomntent");
      return stat;
    }

  stat = _nss_ldap_am_context_init (mapname, &context);
  if (stat != NSS_STATUS_SUCCESS)
    {
      _nss_ldap_leave ();
      debug ("<== _nss_ldap_setautomntent");
      return stat;
    }

  *private = (void *)context;
  _nss_ldap_leave ();

  debug ("<== _nss_ldap_setautomntent");

  return stat;
}

enum nss_status _nss_ldap_getautomntent_r(void *private, const char **key, const char **value,
                                     char *buffer, size_t buflen, int *errnop)
{
  enum nss_status stat;
  struct ldap_automount_context *context = (struct ldap_automount_context *)private;
  struct ldap_args a;
  char **keyval[2];

  if (context == NULL)
    return NSS_STATUS_NOTFOUND;

  debug ("==> _nss_ldap_getautomntent_r");

  keyval[0] = (char **)key;
  keyval[1] = (char **)value;

  _nss_ldap_enter ();

  do
    {
      assert (context->lac_dn_index < context->lac_dn_count);

      LA_INIT (a);
      LA_TYPE (a) = LA_TYPE_NONE;
      LA_BASE (a) = context->lac_dn_list[context->lac_dn_index];

      stat = _nss_ldap_getent_ex (&a, &context->lac_state,
                                  (void *)keyval,
                                  buffer, buflen, errnop,
                                  _nss_ldap_filt_getautomntent,
                                  LM_AUTOMOUNT,
                                  NULL,
                                  _nss_ldap_parse_automount);
      if (stat == NSS_STATUS_NOTFOUND)
        {
          if (context->lac_dn_index < context->lac_dn_count - 1)
            context->lac_dn_index++;
          else
            break; /* move along, nothing more to see here */
        }
    }
  while (stat == NSS_STATUS_NOTFOUND);

  _nss_ldap_leave ();

  debug ("<== _nss_ldap_getautomntent_r");

  return stat;
}

enum nss_status _nss_ldap_endautomntent(void **private)
{
  struct ldap_automount_context **pContext = (struct ldap_automount_context **)private;

  debug ("==> _nss_ldap_endautomntent");

  _nss_ldap_enter ();
  _nss_ldap_am_context_free (pContext);
  /* workaround because Linux automounter spawns a lot of processes */
  _nss_ldap_close ();
  _nss_ldap_leave ();

  debug ("<== _nss_ldap_endautomntent");

  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_getautomntbyname_r(void *private, const char *key,
                                        const char **canon_key, const char **value,
                                        char *buffer, size_t buflen, int *errnop)
{
  enum nss_status stat = NSS_STATUS_NOTFOUND;
  struct ldap_automount_context *context = (struct ldap_automount_context *)private;
  struct ldap_args a;
  char **keyval[2];
  size_t i;

  if (context == NULL)
    return NSS_STATUS_NOTFOUND;

  debug ("==> _nss_ldap_getautomntbyname_r");

  keyval[0] = (char **)canon_key;
  keyval[1] = (char **)value;

  for (i = 0; i < context->lac_dn_count; i++)
    {
      LA_INIT (a);
      LA_TYPE (a) = LA_TYPE_STRING;
      LA_STRING (a) = key;
      LA_BASE (a) = context->lac_dn_list[i];

      /* we do not acquire lock in this case */
      stat = _nss_ldap_getbyname (&a,
                                  (void *)keyval,
                                  buffer, buflen, errnop,
                                  _nss_ldap_filt_getautomntbyname,
                                  LM_AUTOMOUNT,
                                  _nss_ldap_parse_automount);

      if (stat != NSS_STATUS_NOTFOUND)
        {
          break; /* on success or error other than not found */
        }
    }

  debug ("<== _nss_ldap_getautomntbyname_r");

  return stat;
}
