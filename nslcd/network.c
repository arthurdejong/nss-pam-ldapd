/*
   network.c - network address entry lookup routines
   Parts of this file were part of the nss_ldap library (as ldap-network.c)
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

/* ( nisSchema.2.7 NAME 'ipNetwork' SUP top STRUCTURAL
 *   DESC 'Abstraction of a network. The distinguished value of
 *   MUST ( cn $ ipNetworkNumber )
 *   MAY ( ipNetmaskNumber $ l $ description $ manager ) )
 */

/* the search base for searches */
const char *network_bases[NSS_LDAP_CONFIG_MAX_BASES] = { NULL };

/* the search scope for searches */
int network_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *network_filter = "(objectClass=ipNetwork)";

/* the attributes used in searches */
const char *attmap_network_cn              = "cn";
const char *attmap_network_ipNetworkNumber = "ipNetworkNumber";

/* the attribute list to request with searches */
static const char *network_attrs[3];

/* create a search filter for searching a network entry
   by name, return -1 on errors */
static int mkfilter_network_byname(const char *name,
                                   char *buffer, size_t buflen)
{
  char safename[BUFLEN_HOSTNAME];
  /* escape attribute */
  if (myldap_escape(name, safename, sizeof(safename)))
  {
    log_log(LOG_ERR, "mkfilter_network_byname(): safename buffer too small");
    return -1;
  }
  /* build filter */
  return mysnprintf(buffer, buflen, "(&%s(%s=%s))",
                    network_filter, attmap_network_cn, safename);
}

static int mkfilter_network_byaddr(const char *addrstr,
                                   char *buffer, size_t buflen)
{
  char safeaddr[64];
  /* escape attribute */
  if (myldap_escape(addrstr, safeaddr, sizeof(safeaddr)))
  {
    log_log(LOG_ERR, "mkfilter_network_byaddr(): safeaddr buffer too small");
    return -1;
  }
  /* build filter */
  return mysnprintf(buffer, buflen, "(&%s(%s=%s))",
                    network_filter, attmap_network_ipNetworkNumber, safeaddr);
}

void network_init(void)
{
  int i;
  /* set up search bases */
  if (network_bases[0] == NULL)
    for (i = 0; i < NSS_LDAP_CONFIG_MAX_BASES; i++)
      network_bases[i] = nslcd_cfg->bases[i];
  /* set up scope */
  if (network_scope == LDAP_SCOPE_DEFAULT)
    network_scope = nslcd_cfg->scope;
  /* set up attribute list */
  network_attrs[0] = attmap_network_cn;
  network_attrs[1] = attmap_network_ipNetworkNumber;
  network_attrs[2] = NULL;
}

/* write a single network entry to the stream */
static int write_network(TFILE *fp, MYLDAP_ENTRY *entry)
{
  int32_t tmpint32, tmp2int32, tmp3int32;
  int numaddr, i;
  const char *networkname;
  const char **networknames;
  const char **addresses;
  /* get the most canonical name */
  networkname = myldap_get_rdn_value(entry, attmap_network_cn);
  /* get the other names for the network */
  networknames = myldap_get_values(entry, attmap_network_cn);
  if ((networknames == NULL) || (networknames[0] == NULL))
  {
    log_log(LOG_WARNING, "%s: %s: missing",
            myldap_get_dn(entry), attmap_network_cn);
    return 0;
  }
  /* if the networkname is not yet found, get the first entry from networknames */
  if (networkname == NULL)
    networkname = networknames[0];
  /* get the addresses */
  addresses = myldap_get_values(entry, attmap_network_ipNetworkNumber);
  if ((addresses == NULL) || (addresses[0] == NULL))
  {
    log_log(LOG_WARNING, "%s: %s: missing",
            myldap_get_dn(entry), attmap_network_ipNetworkNumber);
    return 0;
  }
  /* write the entry */
  WRITE_INT32(fp, NSLCD_RESULT_BEGIN);
  WRITE_STRING(fp, networkname);
  WRITE_STRINGLIST_EXCEPT(fp, networknames, networkname);
  for (numaddr = 0; addresses[numaddr] != NULL; numaddr++)
    /* noting */ ;
  WRITE_INT32(fp, numaddr);
  for (i = 0; i < numaddr; i++)
  {
    WRITE_ADDRESS(fp, entry, attmap_network_ipNetworkNumber, addresses[i]);
  }
  return 0;
}

NSLCD_HANDLE(
  network, byname, NSLCD_ACTION_NETWORK_BYNAME,
  char name[BUFLEN_HOSTNAME];
  char filter[BUFLEN_FILTER];
  READ_STRING(fp, name);
  log_setrequest("network=\"%s\"", name);,
  mkfilter_network_byname(name, filter, sizeof(filter)),
  write_network(fp, entry)
)

NSLCD_HANDLE(
  network, byaddr, NSLCD_ACTION_NETWORK_BYADDR,
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
  log_setrequest("network=%s", addrstr);,
  mkfilter_network_byaddr(addrstr, filter, sizeof(filter)),
  write_network(fp, entry)
)

NSLCD_HANDLE(
  network, all, NSLCD_ACTION_NETWORK_ALL,
  const char *filter;
  log_setrequest("network(all)");,
  (filter = network_filter, 0),
  write_network(fp, entry)
)
