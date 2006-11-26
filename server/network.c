/*
   network.c - network address entry lookup routines
   This file was part of the nss-ldap library (as ldap-network.c)
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

/* parts based on nss_nis */

#include "config.h"

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
#if defined(HAVE_THREAD_H)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include "ldap-nss.h"
#include "util.h"

#if defined(HAVE_USERSEC_H)
#define MAXALIASES 35
#define MAXADDRSIZE 4
#endif /* HAVE_USERSEC_H */

#define MAP_H_ERRNO(nss_status, herr)   do {    \
                switch ((nss_status)) {         \
                case NSS_STATUS_SUCCESS:               \
                        (herr) = 0;             \
                        break;                  \
                case NSS_STATUS_TRYAGAIN:              \
                        (herr) = TRY_AGAIN;     \
                        break;                  \
                case NSS_STATUS_NOTFOUND:              \
                        (herr) = HOST_NOT_FOUND;\
                        break;                  \
                case NSS_STATUS_UNAVAIL:               \
                default:                        \
                        (herr) = NO_RECOVERY;   \
                        break;                  \
                }                               \
        } while (0)

#define LOOKUP_SETENT(key) \
        if (_nss_ldap_ent_context_init(&key) == NULL) \
                return NSS_STATUS_UNAVAIL; \
        return NSS_STATUS_SUCCESS


#define LOOKUP_ENDENT(key) \
        _nss_ldap_enter(); \
        _nss_ldap_ent_context_release(key); \
        _nss_ldap_leave(); \
        return NSS_STATUS_SUCCESS

static struct ent_context *net_context = NULL;

static enum nss_status
_nss_ldap_parse_net (LDAPMessage * e,
                     struct ldap_state * pvt,
                     void *result, char *buffer, size_t buflen)
{

  char *tmp;
  struct netent *network = (struct netent *) result;
  enum nss_status stat;

  /* IPv6 support ? XXX */
  network->n_addrtype = AF_INET;

  stat = _nss_ldap_assign_attrval (e, ATM (LM_NETWORKS, cn), &network->n_name,
                                   &buffer, &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrval (e, AT (ipNetworkNumber), &tmp, &buffer,
                              &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  network->n_net = inet_network (tmp);

  stat =
    _nss_ldap_assign_attrvals (e, ATM (LM_NETWORKS, cn), network->n_name,
                               &network->n_aliases, &buffer, &buflen, NULL);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_getnetbyname_r(const char *name,struct netent *result,
                          char *buffer,size_t buflen,int *errnop,
                          int *herrnop)
{
  enum nss_status status;
  struct ldap_args a;

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

enum nss_status _nss_ldap_getnetbyaddr_r(unsigned long addr,int type,
                          struct netent *result,char *buffer,size_t buflen,
                          int *errnop,int *herrnop)
{
  struct in_addr in;
  char buf[256];
  int blen;
  struct ldap_args a;
  enum nss_status retval = NSS_STATUS_NOTFOUND;

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

      if (retval != NSS_STATUS_SUCCESS)
        {
          if (retval == NSS_STATUS_NOTFOUND)
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
                  return NSS_STATUS_NOTFOUND;
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
          /* retval == NSS_STATUS_SUCCESS */
          break;
        }
    }

  MAP_H_ERRNO (NSS_STATUS_SUCCESS, *herrnop);

  return retval;
}

enum nss_status _nss_ldap_setnetent(void)
{
  LOOKUP_SETENT (net_context);
}

enum nss_status _nss_ldap_getnetent_r(struct netent *result,char *buffer,size_t buflen,
                       int *errnop,int *herrnop)
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

enum nss_status _nss_ldap_endnetent(void)
{
  LOOKUP_ENDENT (net_context);
}
