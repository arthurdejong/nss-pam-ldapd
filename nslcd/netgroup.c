/*
   netgroup.c - netgroup lookup routines
   Parts of this file were part of the nss_ldap library (as ldap-netgrp.c)
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
#include <stdarg.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>

#include "common.h"
#include "log.h"
#include "myldap.h"
#include "cfg.h"
#include "attmap.h"

/* ( nisSchema.2.8 NAME 'nisNetgroup' SUP top STRUCTURAL
 *   DESC 'Abstraction of a netgroup. May refer to other netgroups'
 *   MUST cn
 *   MAY ( nisNetgroupTriple $ memberNisNetgroup $ description ) )
 */

/* the search base for searches */
const char *netgroup_bases[NSS_LDAP_CONFIG_MAX_BASES] = { NULL };

/* the search scope for searches */
int netgroup_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *netgroup_filter = "(objectClass=nisNetgroup)";

/* the attributes to request with searches */
const char *attmap_netgroup_cn                = "cn";
const char *attmap_netgroup_nisNetgroupTriple = "nisNetgroupTriple";
const char *attmap_netgroup_memberNisNetgroup = "memberNisNetgroup";

/* the attribute list to request with searches */
static const char *netgroup_attrs[4];

static int mkfilter_netgroup_byname(const char *name,
                                    char *buffer, size_t buflen)
{
  char safename[BUFLEN_SAFENAME];
  /* escape attribute */
  if (myldap_escape(name, safename, sizeof(safename)))
  {
    log_log(LOG_ERR, "mkfilter_netgroup_byname(): safename buffer too small");
    return -1;
  }
  /* build filter */
  return mysnprintf(buffer, buflen, "(&%s(%s=%s))",
                    netgroup_filter, attmap_netgroup_cn, safename);
}

void netgroup_init(void)
{
  int i;
  /* set up search bases */
  if (netgroup_bases[0] == NULL)
    for (i = 0; i < NSS_LDAP_CONFIG_MAX_BASES; i++)
      netgroup_bases[i] = nslcd_cfg->bases[i];
  /* set up scope */
  if (netgroup_scope == LDAP_SCOPE_DEFAULT)
    netgroup_scope = nslcd_cfg->scope;
  /* set up attribute list */
  netgroup_attrs[0] = attmap_netgroup_cn;
  netgroup_attrs[1] = attmap_netgroup_nisNetgroupTriple;
  netgroup_attrs[2] = attmap_netgroup_memberNisNetgroup;
  netgroup_attrs[3] = NULL;
}

static int write_string_stripspace_len(TFILE *fp, const char *str, int len)
{
  int32_t tmpint32;
  int i, j;
  DEBUG_PRINT("WRITE_STRING: var=" __STRING(str) " string=\"%s\"", str);
  /* skip leading spaces */
  for (i = 0; (str[i] != '\0') && (isspace(str[i])); i++)
    /* nothing */ ;
  /* skip trailing spaces */
  for (j = len; (j > i) && (isspace(str[j - 1])); j--)
    /* nothing */ ;
  /* write length of string */
  WRITE_INT32(fp, j - i);
  /* write string itself */
  if (j > i)
  {
    WRITE(fp, str + i, j - i);
  }
  /* we're done */
  return 0;
}

#define WRITE_STRING_STRIPSPACE_LEN(fp, str, len)                           \
  if (write_string_stripspace_len(fp, str, len))                            \
    return -1;

#define WRITE_STRING_STRIPSPACE(fp, str)                                    \
  WRITE_STRING_STRIPSPACE_LEN(fp, str, strlen(str))

static int write_netgroup_triple(TFILE *fp, MYLDAP_ENTRY *entry,
                                 const char *triple)
{
  int32_t tmpint32;
  int i;
  int hostb, hoste, userb, usere, domainb, domaine;
  /* skip leading spaces */
  for (i = 0; (triple[i] != '\0') && (isspace(triple[i])); i++)
    /* nothing */ ;
  /* we should have a bracket now */
  if (triple[i] != '(')
  {
    log_log(LOG_WARNING, "%s: %s: does not begin with '('",
            myldap_get_dn(entry), attmap_netgroup_nisNetgroupTriple);
    return 0;
  }
  i++;
  hostb = i;
  /* find comma (end of host string) */
  for (; (triple[i] != '\0') && (triple[i] != ','); i++)
    /* nothing */ ;
  hoste = i;
  if (triple[i++] != ',')
  {
    log_log(LOG_WARNING, "%s: %s: missing ','",
            myldap_get_dn(entry), attmap_netgroup_nisNetgroupTriple);
    return 0;
  }
  userb = i;
  /* find comma (end of user string) */
  for (; (triple[i] != '\0') && (triple[i] != ','); i++)
    /* nothing */ ;
  usere = i;
  if (triple[i++] != ',')
  {
    log_log(LOG_WARNING, "%s: %s: missing ','",
            myldap_get_dn(entry), attmap_netgroup_nisNetgroupTriple);
    return 0;
  }
  domainb = i;
  /* find closing bracket (end of domain string) */
  for (; (triple[i] != '\0') && (triple[i] != ')'); i++)
    /* nothing */ ;
  domaine=i;
  if (triple[i++] != ')')
  {
    log_log(LOG_WARNING, "%s: %s: missing ')'",
            myldap_get_dn(entry), attmap_netgroup_nisNetgroupTriple);
    return 0;
  }
  /* skip trailing spaces */
  for (; (triple[i] != '\0') && (isspace(triple[i])); i++)
    /* nothing */ ;
  /* if anything is left in the string we have a problem */
  if (triple[i] != '\0')
  {
    log_log(LOG_WARNING, "%s: %s: contains trailing data",
            myldap_get_dn(entry), attmap_netgroup_nisNetgroupTriple);
    return 0;
  }
  /* write strings */
  WRITE_INT32(fp, NSLCD_NETGROUP_TYPE_TRIPLE);
  WRITE_STRING_STRIPSPACE_LEN(fp, triple + hostb, hoste - hostb)
  WRITE_STRING_STRIPSPACE_LEN(fp, triple + userb, usere - userb)
  WRITE_STRING_STRIPSPACE_LEN(fp, triple + domainb, domaine - domainb)
  /* we're done */
  return 0;
}

static int write_netgroup(TFILE *fp, MYLDAP_ENTRY *entry, const char *reqname)
{
  int32_t tmpint32;
  int i, j;
  const char **names;
  const char **triples;
  const char **members;
  /* get the netgroup name */
  names = myldap_get_values(entry, attmap_netgroup_cn);
  if ((names == NULL) || (names[0] == NULL))
  {
    log_log(LOG_WARNING, "%s: %s: missing",
            myldap_get_dn(entry), attmap_netgroup_cn);
    return 0;
  }
  /* get the netgroup triples and member */
  triples = myldap_get_values(entry, attmap_netgroup_nisNetgroupTriple);
  members = myldap_get_values(entry, attmap_netgroup_memberNisNetgroup);
  /* write the entries */
  for (i = 0; names[i] != NULL; i++)
    if ((reqname == NULL) || (STR_CMP(reqname, names[i]) == 0))
    {
      /* write first part of result */
      WRITE_INT32(fp, NSLCD_RESULT_BEGIN);
      WRITE_STRING(fp, names[i]);
      /* write the netgroup triples */
      if (triples != NULL)
        for (j = 0; triples[j] != NULL; j++)
          if (write_netgroup_triple(fp, entry, triples[j]))
            return -1;
      /* write netgroup members */
      if (members != NULL)
        for (j = 0; members[j] != NULL; j++)
        {
          /* write triple indicator */
          WRITE_INT32(fp, NSLCD_NETGROUP_TYPE_NETGROUP);
          /* write netgroup name */
          WRITE_STRING_STRIPSPACE(fp, members[j]);
        }
      /* write end of result marker */
      WRITE_INT32(fp, NSLCD_NETGROUP_TYPE_END);
    }
  /* we're done */
  return 0;
}

NSLCD_HANDLE(
  netgroup, byname, NSLCD_ACTION_NETGROUP_BYNAME,
  char name[BUFLEN_NAME];
  char filter[BUFLEN_FILTER];
  READ_STRING(fp, name);
  log_setrequest("netgroup=\"%s\"", name);,
  mkfilter_netgroup_byname(name, filter, sizeof(filter)),
  write_netgroup(fp, entry, name)
)

NSLCD_HANDLE(
  netgroup, all, NSLCD_ACTION_NETGROUP_ALL,
  const char *filter;
  log_setrequest("netgroup(all)");,
  (filter = netgroup_filter, 0),
  write_netgroup(fp, entry, NULL)
)
