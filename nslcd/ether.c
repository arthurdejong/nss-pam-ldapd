/*
   ether.c - ethernet address entry lookup routines
   Parts of this file were part of the nss_ldap library (as ldap-ethers.c)
   which has been forked into the nss-pam-ldapd library.

   Copyright (C) 1997-2005 Luke Howard
   Copyright (C) 2006 West Consulting
   Copyright (C) 2006-2017 Arthur de Jong

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
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif /* HAVE_STDINT_H */

#include "common.h"
#include "log.h"
#include "myldap.h"
#include "cfg.h"
#include "attmap.h"
#include "compat/ether.h"

/* ( nisSchema.2.11 NAME 'ieee802Device' SUP top AUXILIARY
 *   DESC 'A device with a MAC address; device SHOULD be
 *         used as a structural class'
 *   MAY macAddress )
 */

/* the search base for searches */
const char *ether_bases[NSS_LDAP_CONFIG_MAX_BASES] = { NULL };

/* the search scope for searches */
int ether_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *ether_filter = "(objectClass=ieee802Device)";

/* the attributes to request with searches */
const char *attmap_ether_cn         = "cn";
const char *attmap_ether_macAddress = "macAddress";

/* the attribute list to request with searches */
static const char *ether_attrs[3];

/* create a search filter for searching an ethernet address
   by name, return -1 on errors */
static int mkfilter_ether_byname(const char *name,
                                 char *buffer, size_t buflen)
{
  char safename[BUFLEN_HOSTNAME];
  /* escape attribute */
  if (myldap_escape(name, safename, sizeof(safename)))
  {
    log_log(LOG_ERR, "mkfilter_ether_byname(): safename buffer too small");
    return -1;
  }
  /* build filter */
  return mysnprintf(buffer, buflen, "(&%s(%s=%s))",
                    ether_filter, attmap_ether_cn, safename);
}

static void my_ether_ntoa(const uint8_t *addr, char *buffer, int compact)
{
  int i;
  for (i = 0; i < 6; i++)
  {
    if (i > 0)
      *buffer++ = ':';
    buffer += sprintf(buffer, compact ? "%x" : "%02x", addr[i]);
  }
  *buffer++ = '\0';
}

static int mkfilter_ether_byether(const struct ether_addr *addr,
                                  char *buffer, size_t buflen)
{
  char addrstr1[20], addrstr2[20];
  my_ether_ntoa((const uint8_t *)addr, addrstr1, 1);
  my_ether_ntoa((const uint8_t *)addr, addrstr2, 0);
  /* there should be no characters that need escaping */
  return mysnprintf(buffer, buflen, "(&%s(|(%s=%s)(%s=%s)))", ether_filter,
                    attmap_ether_macAddress, addrstr1,
                    attmap_ether_macAddress, addrstr2);
}

void ether_init(void)
{
  int i;
  /* set up search bases */
  if (ether_bases[0] == NULL)
    for (i = 0; i < NSS_LDAP_CONFIG_MAX_BASES; i++)
      ether_bases[i] = nslcd_cfg->bases[i];
  /* set up scope */
  if (ether_scope == LDAP_SCOPE_DEFAULT)
    ether_scope = nslcd_cfg->scope;
  /* set up attribute list */
  ether_attrs[0] = attmap_ether_cn;
  ether_attrs[1] = attmap_ether_macAddress;
  ether_attrs[2] = NULL;
}

/* TODO: check for errors in aton() */
#define WRITE_ETHER(fp, addr)                                               \
  ether_aton_r(addr, &tmpaddr);                                             \
  WRITE(fp, &tmpaddr, sizeof(uint8_t[6]));

static int write_ether(TFILE *fp, MYLDAP_ENTRY *entry,
                       const char *reqname, const char *reqether)
{
  int32_t tmpint32;
  struct ether_addr tmpaddr;
  const char *tmparr[2];
  const char **names, **ethers;
  int i, j;
  /* get the name of the ether entry */
  names = myldap_get_values(entry, attmap_ether_cn);
  if ((names == NULL) || (names[0] == NULL))
  {
    log_log(LOG_WARNING, "%s: %s: missing",
            myldap_get_dn(entry), attmap_ether_cn);
    return 0;
  }
  /* get the addresses */
  if (reqether != NULL)
  {
    ethers = tmparr;
    ethers[0] = reqether;
    ethers[1] = NULL;
  }
  else
  {
    ethers = myldap_get_values(entry, attmap_ether_macAddress);
    if ((ethers == NULL) || (ethers[0] == NULL))
    {
      log_log(LOG_WARNING, "%s: %s: missing",
              myldap_get_dn(entry), attmap_ether_macAddress);
      return 0;
    }
    /* TODO: move parsing of addresses up here */
  }
  /* write entries for all names and addresses */
  for (i = 0; names[i] != NULL; i++)
    if ((reqname == NULL) || (strcasecmp(reqname, names[i]) == 0))
      for (j = 0; ethers[j] != NULL; j++)
      {
        WRITE_INT32(fp, NSLCD_RESULT_BEGIN);
        WRITE_STRING(fp, names[i]);
        WRITE_ETHER(fp, ethers[j]);
      }
  return 0;
}

NSLCD_HANDLE(
  ether, byname, NSLCD_ACTION_ETHER_BYNAME,
  char name[BUFLEN_HOSTNAME];
  char filter[BUFLEN_FILTER];
  READ_STRING(fp, name);
  log_setrequest("ether=\"%s\"", name);,
  mkfilter_ether_byname(name, filter, sizeof(filter)),
  write_ether(fp, entry, name, NULL)
)

NSLCD_HANDLE(
  ether, byether, NSLCD_ACTION_ETHER_BYETHER,
  struct ether_addr addr;
  char addrstr[20];
  char filter[BUFLEN_FILTER];
  READ(fp, &addr, sizeof(uint8_t[6]));
  my_ether_ntoa((uint8_t *)&addr, addrstr, 1);
  log_setrequest("ether=%s", addrstr);,
  mkfilter_ether_byether(&addr, filter, sizeof(filter)),
  write_ether(fp, entry, NULL, addrstr)
)

NSLCD_HANDLE(
  ether, all, NSLCD_ACTION_ETHER_ALL,
  const char *filter;
  log_setrequest("ether(all)");,
  (filter = ether_filter, 0),
  write_ether(fp, entry, NULL, NULL)
)
