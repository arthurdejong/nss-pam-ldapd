/*
   service.c - service entry lookup routines
   This file was part of the nss-ldap library (as ldap-service.c)
   which has been forked into the nss-ldapd library.

   Copyright (C) 1997-2005 Luke Howard
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

/*
   Determine the canonical name of the RPC with _nss_ldap_getrdnvalue(),
   and assign any values of "cn" which do NOT match this canonical name
   as aliases.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>
#ifdef HAVE_SYS_BYTEORDER_H
#include <sys/byteorder.h>
#endif
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

static struct ent_context *serv_context = NULL;

static enum nss_status _nss_ldap_parse_serv (LDAPMessage *e,
                      struct ldap_state *state,
                      void *result,char *buffer,size_t buflen)
{
  struct servent *service = (struct servent *)result;
  char *port;
  enum nss_status stat = NSS_STATUS_SUCCESS;

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
          if (stat != NSS_STATUS_SUCCESS)
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
              return NSS_STATUS_TRYAGAIN;
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
          return NSS_STATUS_NOTFOUND;
        }

      switch (state->ls_info.ls_index)
        {
        case 0:
          /* last time. decrementing ls_index to -1 AND returning !NSS_STATUS_SUCCESS
             will force this entry to be discarded.
           */
          stat = NSS_STATUS_NOTFOUND;
          break;
        case -1:
          /* first time */
          state->ls_info.ls_index = ldap_count_values (vals);
          /* fall off to default ... */
        default:
          len = strlen (vals[state->ls_info.ls_index - 1]);
          if (buflen < (size_t) (len + 1))
            {
              return NSS_STATUS_TRYAGAIN;
            }
          strncpy (buffer, vals[state->ls_info.ls_index - 1], len);
          buffer[len] = '\0';
          service->s_proto = buffer;
          buffer += len + 1;
          buflen -= len + 1;
          stat = NSS_STATUS_SUCCESS;
        }

      ldap_value_free (vals);
      state->ls_info.ls_index--;
    }

  if (stat != NSS_STATUS_SUCCESS)
    {
      return stat;
    }

  stat =
    _nss_ldap_getrdnvalue (e, ATM (LM_SERVICES, cn), &service->s_name,
                           &buffer, &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    {
      return stat;
    }

  stat =
    _nss_ldap_assign_attrvals (e, ATM (LM_SERVICES, cn), service->s_name,
                               &service->s_aliases, &buffer, &buflen, NULL);
  if (stat != NSS_STATUS_SUCCESS)
    {
      return stat;
    }

  stat =
    _nss_ldap_assign_attrval (e, AT (ipServicePort), &port, &buffer,
                              &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    {
      return stat;
    }

  service->s_port = htons (atoi (port));

  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_getservbyname_r(const char *name,
                           const char *proto,
                           struct servent *result,
                           char *buffer,size_t buflen,int *errnop)
{
  struct ldap_args a;

  LA_INIT (a);
  LA_STRING (a) = name;
  LA_TYPE (a) = (proto == NULL) ? LA_TYPE_STRING : LA_TYPE_STRING_AND_STRING;
  LA_STRING2 (a) = proto;

  return _nss_ldap_getbyname (&a, result, buffer, buflen, errnop,
                              ((proto == NULL) ? _nss_ldap_filt_getservbyname
                               : _nss_ldap_filt_getservbynameproto),
                              LM_SERVICES, _nss_ldap_parse_serv);
}

enum nss_status _nss_ldap_getservbyport_r(int port,
                           const char *proto,
                           struct servent *result,
                           char *buffer,size_t buflen,int *errnop)
{
  struct ldap_args a;

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

enum nss_status _nss_ldap_setservent(void)
{
  LOOKUP_SETENT(serv_context);
}

enum nss_status _nss_ldap_getservent_r(struct servent *result,char *buffer,size_t buflen,
                        int *errnop)
{
  LOOKUP_GETENT(serv_context, result, buffer, buflen, errnop,
                _nss_ldap_filt_getservent, LM_SERVICES,
                _nss_ldap_parse_serv, LDAP_NSS_BUFLEN_DEFAULT);
}

enum nss_status _nss_ldap_endservent(void)
{
  LOOKUP_ENDENT(serv_context);
}
