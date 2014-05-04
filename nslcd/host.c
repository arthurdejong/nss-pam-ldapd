/*
   host.c - host name lookup routines
   Parts of this file were part of the nss_ldap library (as ldap-hosts.c)
   which has been forked into the nss-pam-ldapd library.

   Copyright (C) 1997-2005 Luke Howard
   Copyright (C) 2006 West Consulting
   Copyright (C) 2006-2014 Arthur de Jong

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301 USA
*/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "common.h"
#include "log.h"
#include "myldap.h"
#include "cfg.h"
#include "attmap.h"

/* ( nisSchema.2.6 NAME 'ipHost' SUP top AUXILIARY
 *   DESC 'Abstraction of a host, an IP device. The distinguished
 *         value of the cn attribute denotes the host's canonical
 *         name. Device SHOULD be used as a structural class'
 *   MUST ( cn $ ipHostNumber )
 *   MAY ( l $ description $ manager ) )
 */

/* the search base for searches */
const char *host_bases[NSS_LDAP_CONFIG_MAX_BASES] = { NULL };

/* the search scope for searches */
int host_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *host_filter = "(objectClass=ipHost)";

/* the attributes to request with searches */
const char *attmap_host_cn           = "cn";
const char *attmap_host_ipHostNumber = "ipHostNumber";

/* the attribute list to request with searches */
static const char *host_attrs[3];

/* create a search filter for searching a host entry
   by name, return -1 on errors */
static int mkfilter_host_byname(const char *name, char *buffer, size_t buflen)
{
  char safename[BUFLEN_HOSTNAME];
  /* escape attribute */
  if (myldap_escape(name, safename, sizeof(safename)))
  {
    log_log(LOG_ERR, "mkfilter_host_byname(): safename buffer too small");
    return -1;
  }
  /* build filter */
  return mysnprintf(buffer, buflen, "(&%s(%s=%s))",
                    host_filter, attmap_host_cn, safename);
}

static int mkfilter_host_byaddr(const char *addrstr,
                                char *buffer, size_t buflen)
{
  char safeaddr[64];
  /* escape attribute */
  if (myldap_escape(addrstr, safeaddr, sizeof(safeaddr)))
  {
    log_log(LOG_ERR, "mkfilter_host_byaddr(): safeaddr buffer too small");
    return -1;
  }
  /* build filter */
  return mysnprintf(buffer, buflen, "(&%s(%s=%s))",
                    host_filter, attmap_host_ipHostNumber, safeaddr);
}

void host_init(void)
{
  int i;
  /* set up search bases */
  if (host_bases[0] == NULL)
    for (i = 0; i < NSS_LDAP_CONFIG_MAX_BASES; i++)
      host_bases[i] = nslcd_cfg->bases[i];
  /* set up scope */
  if (host_scope == LDAP_SCOPE_DEFAULT)
    host_scope = nslcd_cfg->scope;
  /* set up attribute list */
  host_attrs[0] = attmap_host_cn;
  host_attrs[1] = attmap_host_ipHostNumber;
  host_attrs[2] = NULL;
}

/* write a single host entry to the stream */
static int write_host(TFILE *fp, MYLDAP_ENTRY *entry)
{
  int32_t tmpint32, tmp2int32, tmp3int32;
  int numaddr, i;
  const char *hostname;
  const char **hostnames;
  const char **addresses;
  /* get the most canonical name */
  hostname = myldap_get_rdn_value(entry, attmap_host_cn);
  /* get the other names for the host */
  hostnames = myldap_get_values(entry, attmap_host_cn);
  if ((hostnames == NULL) || (hostnames[0] == NULL))
  {
    log_log(LOG_WARNING, "%s: %s: missing",
            myldap_get_dn(entry), attmap_host_cn);
    return 0;
  }
  /* if the hostname is not yet found, get the first entry from hostnames */
  if (hostname == NULL)
    hostname = hostnames[0];
  /* get the addresses */
  addresses = myldap_get_values(entry, attmap_host_ipHostNumber);
  if ((addresses == NULL) || (addresses[0] == NULL))
  {
    log_log(LOG_WARNING, "%s: %s: missing",
            myldap_get_dn(entry), attmap_host_ipHostNumber);
    return 0;
  }
  /* write the entry */
  WRITE_INT32(fp, NSLCD_RESULT_BEGIN);
  WRITE_STRING(fp, hostname);
  WRITE_STRINGLIST_EXCEPT(fp, hostnames, hostname);
  for (numaddr = 0; addresses[numaddr] != NULL; numaddr++)
    /* noting */ ;
  WRITE_INT32(fp, numaddr);
  for (i = 0; i < numaddr; i++)
  {
    WRITE_ADDRESS(fp, entry, attmap_host_ipHostNumber, addresses[i]);
  }
  return 0;
}

NSLCD_HANDLE(
  host, byname, NSLCD_ACTION_HOST_BYNAME,
  char name[BUFLEN_HOSTNAME];
  char filter[BUFLEN_FILTER];
  READ_STRING(fp, name);
  log_setrequest("host=\"%s\"", name);,
  mkfilter_host_byname(name, filter, sizeof(filter)),
  write_host(fp, entry)
)

NSLCD_HANDLE(
  host, byaddr, NSLCD_ACTION_HOST_BYADDR,
  int af;
  char addr[64];
  int len = sizeof(addr);
  char addrstr[64];
  char filter[BUFLEN_FILTER];
  READ_ADDRESS(fp, addr, len, af);
  /* translate the address to a string */
  if (inet_ntop(af, addr, addrstr, sizeof(addrstr)) == NULL)
  {
    log_log(LOG_WARNING, "unable to convert address to string");
    return -1;
  }
  log_setrequest("host=%s", addrstr);,
  mkfilter_host_byaddr(addrstr, filter, sizeof(filter)),
  write_host(fp, entry)
)


NSLCD_HANDLE(
  host, all, NSLCD_ACTION_HOST_ALL,
  const char *filter;
  log_setrequest("host(all)");,
  (filter = host_filter, 0),
  write_host(fp, entry)
)
