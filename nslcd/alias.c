/*
   alias.c - alias entry lookup routines
   Parts of this file were part of the nss_ldap library (as ldap-alias.c)
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

#include "common.h"
#include "log.h"
#include "myldap.h"
#include "cfg.h"
#include "attmap.h"

/* Vendor-specific attributes and object classes.
 * (Mainly from Sun.)
 * ( 1.3.6.1.4.1.42.2.27.1.2.5 NAME 'nisMailAlias' SUP top STRUCTURAL
 *   DESC 'NIS mail alias'
 *   MUST cn
 *   MAY rfc822MailMember )
 */

/* the search base for searches */
const char *alias_bases[NSS_LDAP_CONFIG_MAX_BASES] = { NULL };

/* the search scope for searches */
int alias_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *alias_filter = "(objectClass=nisMailAlias)";

/* the attributes to request with searches */
const char *attmap_alias_cn               = "cn";
const char *attmap_alias_rfc822MailMember = "rfc822MailMember";

/* the attribute list to request with searches */
static const char *alias_attrs[3];

/* create a search filter for searching an alias by name,
   return -1 on errors */
static int mkfilter_alias_byname(const char *name,
                                 char *buffer, size_t buflen)
{
  char safename[BUFLEN_SAFENAME];
  /* escape attribute */
  if (myldap_escape(name, safename, sizeof(safename)))
  {
    log_log(LOG_ERR, "mkfilter_alias_byname(): safename buffer too small");
    return -1;
  }
  /* build filter */
  return mysnprintf(buffer, buflen, "(&%s(%s=%s))",
                    alias_filter, attmap_alias_cn, safename);
}

void alias_init(void)
{
  int i;
  /* set up search bases */
  if (alias_bases[0] == NULL)
    for (i = 0; i < NSS_LDAP_CONFIG_MAX_BASES; i++)
      alias_bases[i] = nslcd_cfg->bases[i];
  /* set up scope */
  if (alias_scope == LDAP_SCOPE_DEFAULT)
    alias_scope = nslcd_cfg->scope;
  /* set up attribute list */
  alias_attrs[0] = attmap_alias_cn;
  alias_attrs[1] = attmap_alias_rfc822MailMember;
  alias_attrs[2] = NULL;
}

static int write_alias(TFILE *fp, MYLDAP_ENTRY *entry, const char *reqalias)
{
  int32_t tmpint32, tmp2int32, tmp3int32;
  const char **names, **members;
  int i;
  /* get the name of the alias */
  names = myldap_get_values(entry, attmap_alias_cn);
  if ((names == NULL) || (names[0] == NULL))
  {
    log_log(LOG_WARNING, "%s: %s: missing",
            myldap_get_dn(entry), attmap_alias_cn);
    return 0;
  }
  /* get the members of the alias */
  members = myldap_get_values(entry, attmap_alias_rfc822MailMember);
  /* for each name, write an entry */
  for (i = 0; names[i] != NULL; i++)
  {
    if ((reqalias == NULL) || (strcasecmp(reqalias, names[i]) == 0))
    {
      WRITE_INT32(fp, NSLCD_RESULT_BEGIN);
      WRITE_STRING(fp, names[i]);
      WRITE_STRINGLIST(fp, members);
    }
  }
  return 0;
}

NSLCD_HANDLE(
  alias, byname, NSLCD_ACTION_ALIAS_BYNAME,
  char name[BUFLEN_NAME];
  char filter[BUFLEN_FILTER];
  READ_STRING(fp, name);
  log_setrequest("alias=\"%s\"", name);,
  mkfilter_alias_byname(name, filter, sizeof(filter)),
  write_alias(fp, entry, name)
)

NSLCD_HANDLE(
  alias, all, NSLCD_ACTION_ALIAS_ALL,
  const char *filter;
  log_setrequest("alias(all)");,
  (filter = alias_filter, 0),
  write_alias(fp, entry, NULL)
)
