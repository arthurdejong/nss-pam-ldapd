/* 
   Copyright (C) 1997-2005 Luke Howard
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

/* parts based on nss_nis */

#include "config.h"

#ifdef HAVE_PORT_BEFORE_H
#include <port_before.h>
#endif

#if defined(HAVE_THREAD_H)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <sys/socket.h>
#include <errno.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#include "ldap-nss.h"
#include "ldap-network.h"
#include "util.h"

#if defined(HAVE_USERSEC_H)
#define MAXALIASES 35
#define MAXADDRSIZE 4
#endif /* HAVE_USERSEC_H */

#ifdef HAVE_PORT_AFTER_H
#include <port_after.h>
#endif

static ent_context_t *net_context = NULL;

static enum nss_status
_nss_ldap_parse_net (LDAPMessage * e,
                     ldap_state_t * pvt,
                     void *result, char *buffer, size_t buflen)
{

  char *tmp;
  struct netent *network = (struct netent *) result;
  enum nss_status stat;

  /* IPv6 support ? XXX */
  network->n_addrtype = AF_INET;

  stat = _nss_ldap_assign_attrval (e, ATM (LM_NETWORKS, cn), &network->n_name,
                                   &buffer, &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrval (e, AT (ipNetworkNumber), &tmp, &buffer,
                              &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

  network->n_net = inet_network (tmp);

  stat =
    _nss_ldap_assign_attrvals (e, ATM (LM_NETWORKS, cn), network->n_name,
                               &network->n_aliases, &buffer, &buflen, NULL);
  if (stat != NSS_SUCCESS)
    return stat;

  return NSS_SUCCESS;
}

enum nss_status
_nss_ldap_getnetbyname_r (const char *name, struct netent * result,
                          char *buffer, size_t buflen, int *errnop,
                          int *herrnop)
{
  enum nss_status status;
  ldap_args_t a;

  LA_INIT (a);
  LA_STRING (a) = name;
  LA_TYPE (a) = LA_TYPE_STRING;

  status = _nss_ldap_getbyname (&a,
                                result,
                                buffer,
                                buflen,
                                errnop,
                                _nss_ldap_filt_getnetbyname,
                                LM_NETWORKS, _nss_ldap_parse_net);

  MAP_H_ERRNO (status, *herrnop);

  return status;
}

enum nss_status
_nss_ldap_getnetbyaddr_r (unsigned long addr, int type,
                          struct netent * result, char *buffer, size_t buflen,
                          int *errnop, int *herrnop)
{
  struct in_addr in;
  char buf[256];
  int blen;
  ldap_args_t a;
  enum nss_status retval = NSS_NOTFOUND;

  LA_INIT (a);
  LA_TYPE (a) = LA_TYPE_STRING;

  in = inet_makeaddr (addr, 0);
  strcpy (buf, inet_ntoa (in));
  blen = strlen (buf);
  LA_STRING (a) = buf;

  while (1)
    {
      retval = _nss_ldap_getbyname (&a, result, buffer, buflen, errnop,
                                    _nss_ldap_filt_getnetbyaddr,
                                    LM_NETWORKS, _nss_ldap_parse_net);

      if (retval != NSS_SUCCESS)
        {
          if (retval == NSS_NOTFOUND)
            {
              if (buf[blen - 2] == '.' && buf[blen - 1] == '\0')
                {
                  buf[blen - 2] = '\0';
                  blen -= 2;
                  continue;
                }
              else
                {
                  MAP_H_ERRNO (retval, *herrnop);
                  return NSS_NOTFOUND;
                }
            }
          else
            {
              MAP_H_ERRNO (retval, *herrnop);
              return retval;
            }
        }
      else
        {
          /* retval == NSS_SUCCESS */
          break;
        }
    }

  MAP_H_ERRNO (NSS_SUCCESS, *herrnop);

  return retval;
}

     enum nss_status _nss_ldap_setnetent (void)
{
  LOOKUP_SETENT (net_context);
}

     enum nss_status _nss_ldap_endnetent (void)
{
  LOOKUP_ENDENT (net_context);
}

enum nss_status
_nss_ldap_getnetent_r (struct netent * result, char *buffer, size_t buflen,
                       int *errnop, int *herrnop)
{
  enum nss_status status;

  status = _nss_ldap_getent (&net_context,
                             result,
                             buffer,
                             buflen,
                             errnop,
                             _nss_ldap_filt_getnetent,
                             LM_NETWORKS, _nss_ldap_parse_net);

  MAP_H_ERRNO (status, *herrnop);

  return status;
}
