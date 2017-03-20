/*
   group.c - group entry lookup routines
   Parts of this file were part of the nss_ldap library (as ldap-grp.c)
   which has been forked into the nss-pam-ldapd library.

   Copyright (C) 1997-2006 Luke Howard
   Copyright (C) 2006 West Consulting
   Copyright (C) 2006-2015 Arthur de Jong
   Copyright (C) 2013 Steve Hill

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
/* for gid_t */
#include <grp.h>

#include "common/set.h"
#include "common.h"
#include "log.h"
#include "myldap.h"
#include "cfg.h"
#include "attmap.h"
#include "compat/strndup.h"

/* ( nisSchema.2.2 NAME 'posixGroup' SUP top STRUCTURAL
 *   DESC 'Abstraction of a group of accounts'
 *   MUST ( cn $ gidNumber )
 *   MAY ( userPassword $ memberUid $ description ) )
 *
 * apart from the above a member attribute is also supported that
 * may contains a DN of a user
 *
 * nested groups (groups that are member of a group) are currently
 * not supported
 */

/* the search base for searches */
const char *group_bases[NSS_LDAP_CONFIG_MAX_BASES] = { NULL };

/* the search scope for searches */
int group_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *group_filter = "(objectClass=posixGroup)";

/* the attributes to request with searches */
const char *attmap_group_cn           = "cn";
const char *attmap_group_userPassword = "\"*\"";
const char *attmap_group_gidNumber    = "gidNumber";
const char *attmap_group_memberUid    = "memberUid";
const char *attmap_group_member       = "member";

/* special property for objectSid-based searches
   (these are already LDAP-escaped strings) */
static char *gidSid = NULL;

/* BUILTIN SID definitions */
static char *builtinSid = NULL;
const gid_t min_builtin_rid = 544;
const gid_t max_builtin_rid = 552;

/* default values for attributes */
static const char *default_group_userPassword = "*"; /* unmatchable */

/* the attribute list to request with searches */
static const char **group_attrs = NULL;

/* the attribute list for bymember searches (without member attributes) */
static const char **group_bymember_attrs = NULL;

/* create a search filter for searching a group entry
   by name, return -1 on errors */
static int mkfilter_group_byname(const char *name,
                                 char *buffer, size_t buflen)
{
  char safename[BUFLEN_SAFENAME];
  /* escape attribute */
  if (myldap_escape(name, safename, sizeof(safename)))
  {
    log_log(LOG_ERR, "mkfilter_group_byname(): safename buffer too small");
    return -1;
  }
  /* build filter */
  return mysnprintf(buffer, buflen, "(&%s(%s=%s))",
                    group_filter, attmap_group_cn, safename);
}

/* create a search filter for searching a group entry
   by gid, return -1 on errors */
static int mkfilter_group_bygid(gid_t gid, char *buffer, size_t buflen)
{
  gid -= nslcd_cfg->nss_gid_offset;
  /* if searching for a Windows domain SID */
  if (gidSid != NULL)
  {
    /* the given gid is a BUILTIN gid, the SID prefix is not the domain SID */
    if ((gid >= min_builtin_rid) && (gid <= max_builtin_rid))
      return mysnprintf(buffer, buflen, "(&%s(%s=%s\\%02x\\%02x\\%02x\\%02x))",
                        group_filter, attmap_group_gidNumber, builtinSid,
                        (int)(gid & 0xff), (int)((gid >> 8) & 0xff),
                        (int)((gid >> 16) & 0xff), (int)((gid >> 24) & 0xff));
    return mysnprintf(buffer, buflen, "(&%s(%s=%s\\%02x\\%02x\\%02x\\%02x))",
                      group_filter, attmap_group_gidNumber, gidSid,
                      (int)(gid & 0xff), (int)((gid >> 8) & 0xff),
                      (int)((gid >> 16) & 0xff), (int)((gid >> 24) & 0xff));
  }
  else
  {
    return mysnprintf(buffer, buflen, "(&%s(%s=%lu))",
                      group_filter, attmap_group_gidNumber, (unsigned long int)gid);
  }
}

/* create a search filter for searching a group entry
   by member uid, return -1 on errors */
static int mkfilter_group_bymember(MYLDAP_SESSION *session,
                                   const char *uid,
                                   char *buffer, size_t buflen)
{
  char dn[BUFLEN_DN];
  char safeuid[BUFLEN_SAFENAME];
  char safedn[BUFLEN_SAFEDN];
  /* escape attribute */
  if (myldap_escape(uid, safeuid, sizeof(safeuid)))
  {
    log_log(LOG_ERR, "mkfilter_group_bymember(): safeuid buffer too small");
    return -1;
  }
  /* try to translate uid to DN */
  if ((strcasecmp(attmap_group_member, "\"\"") == 0) ||
      (uid2dn(session, uid, dn, sizeof(dn)) == NULL))
    return mysnprintf(buffer, buflen, "(&%s(%s=%s))",
                      group_filter, attmap_group_memberUid, safeuid);
  /* escape DN */
  if (myldap_escape(dn, safedn, sizeof(safedn)))
  {
    log_log(LOG_ERR, "mkfilter_group_bymember(): safedn buffer too small");
    return -1;
  }
  /* also lookup using user DN */
  return mysnprintf(buffer, buflen, "(&%s(|(%s=%s)(%s=%s)))",
                    group_filter,
                    attmap_group_memberUid, safeuid,
                    attmap_group_member, safedn);
}

static int mkfilter_group_bymemberdn(const char *dn,
                                     char *buffer, size_t buflen)
{
  char safedn[BUFLEN_SAFEDN];
  /* escape DN */
  if (myldap_escape(dn, safedn, sizeof(safedn)))
  {
    log_log(LOG_ERR, "mkfilter_group_bymemberdn(): safedn buffer too small");
    return -1;
  }
  return mysnprintf(buffer, buflen,
                    "(&%s(%s=%s))",
                    group_filter,
                    attmap_group_member, safedn);
}

void group_init(void)
{
  int i;
  SET *set;
  /* set up search bases */
  if (group_bases[0] == NULL)
    for (i = 0; i < NSS_LDAP_CONFIG_MAX_BASES; i++)
      group_bases[i] = nslcd_cfg->bases[i];
  /* set up scope */
  if (group_scope == LDAP_SCOPE_DEFAULT)
    group_scope = nslcd_cfg->scope;
  /* special case when gidNumber references objectSid */
  if (strncasecmp(attmap_group_gidNumber, "objectSid:", 10) == 0)
  {
    gidSid = sid2search(attmap_group_gidNumber + 10);
    builtinSid = sid2search("S-1-5-32");
    attmap_group_gidNumber = strndup(attmap_group_gidNumber, 9);
  }
  /* set up attribute list */
  set = set_new();
  attmap_add_attributes(set, attmap_group_cn);
  attmap_add_attributes(set, attmap_group_userPassword);
  attmap_add_attributes(set, attmap_group_gidNumber);
  if (!nslcd_cfg->nss_getgrent_skipmembers)
  {
    attmap_add_attributes(set, attmap_group_memberUid);
    attmap_add_attributes(set, attmap_group_member);
  }
  group_attrs = set_tolist(set);
  if (group_attrs == NULL)
  {
    log_log(LOG_CRIT, "malloc() failed to allocate memory");
    exit(EXIT_FAILURE);
  }
  set_free(set);
  /* set up bymember attribute list */
  set = set_new();
  attmap_add_attributes(set, attmap_group_cn);
  attmap_add_attributes(set, attmap_group_userPassword);
  attmap_add_attributes(set, attmap_group_gidNumber);
  group_bymember_attrs = set_tolist(set);
  if (group_bymember_attrs == NULL)
  {
    log_log(LOG_CRIT, "malloc() failed to allocate memory");
    exit(EXIT_FAILURE);
  }
  set_free(set);
}

static int do_write_group(TFILE *fp, MYLDAP_ENTRY *entry,
                          const char **names, gid_t gids[], int numgids,
                          const char *passwd, const char **members,
                          const char *reqname)
{
  int32_t tmpint32, tmp2int32, tmp3int32;
  int i, j;
  /* write entries for all names and gids */
  for (i = 0; names[i] != NULL; i++)
  {
    if (!isvalidname(names[i]))
    {
      log_log(LOG_WARNING, "%s: %s: denied by validnames option",
              myldap_get_dn(entry), attmap_group_cn);
    }
    else if ((reqname == NULL) || (STR_CMP(reqname, names[i]) == 0))
    {
      for (j = 0; j < numgids; j++)
      {
        WRITE_INT32(fp, NSLCD_RESULT_BEGIN);
        WRITE_STRING(fp, names[i]);
        WRITE_STRING(fp, passwd);
        WRITE_INT32(fp, gids[j]);
        WRITE_STRINGLIST(fp, members);
      }
    }
  }
  return 0;
}

static void getmembers(MYLDAP_ENTRY *entry, MYLDAP_SESSION *session,
                       SET *members, SET *seen, SET *subgroups)
{
  char buf[BUFLEN_NAME];
  int i;
  const char **values;
  const char ***derefs;
  /* add the memberUid values */
  values = myldap_get_values(entry, attmap_group_memberUid);
  if (values != NULL)
    for (i = 0; values[i] != NULL; i++)
    {
      /* only add valid usernames */
      if (isvalidname(values[i]))
        set_add(members, values[i]);
    }
  /* skip rest if attmap_group_member is blank */
  if (strcasecmp(attmap_group_member, "\"\"") == 0)
    return;
  /* add deref'd entries if we have them*/
  derefs = myldap_get_deref_values(entry, attmap_group_member, attmap_passwd_uid);
  if (derefs != NULL)
  {
    /* add deref'd uid attributes */
    for (i = 0; derefs[0][i] != NULL; i++)
      set_add(members, derefs[0][i]);
    /* add non-deref'd attribute values as subgroups */
    for (i = 0; derefs[1][i] != NULL; i++)
    {
      if ((seen == NULL) || (!set_contains(seen, derefs[1][i])))
      {
        if (seen != NULL)
          set_add(seen, derefs[1][i]);
        if (subgroups != NULL)
          set_add(subgroups, derefs[1][i]);
      }
    }
    return; /* no need to parse the member attribute ourselves */
  }
  /* add the member values */
  values = myldap_get_values(entry, attmap_group_member);
  if (values != NULL)
    for (i = 0; values[i] != NULL; i++)
    {
      if ((seen == NULL) || (!set_contains(seen, values[i])))
      {
        if (seen != NULL)
          set_add(seen, values[i]);
        /* transform the DN into a uid (dn2uid() already checks validity) */
        if (dn2uid(session, values[i], buf, sizeof(buf)) != NULL)
          set_add(members, buf);
        /* wasn't a UID - try handling it as a nested group */
        else if (subgroups != NULL)
          set_add(subgroups, values[i]);
      }
    }
}

/* the maximum number of gidNumber attributes per entry */
#define MAXGIDS_PER_ENTRY 5

static int write_group(TFILE *fp, MYLDAP_ENTRY *entry, const char *reqname,
                       const gid_t *reqgid, int wantmembers,
                       MYLDAP_SESSION *session)
{
  const char **names, **gidvalues;
  const char *passwd;
  const char **members = NULL;
  SET *set, *seen=NULL, *subgroups=NULL;
  gid_t gids[MAXGIDS_PER_ENTRY];
  int numgids;
  char *tmp;
  char passbuffer[BUFLEN_PASSWORDHASH];
  MYLDAP_SEARCH *search;
  MYLDAP_ENTRY *entry2;
  int rc;
  /* get group name (cn) */
  names = myldap_get_values(entry, attmap_group_cn);
  if ((names == NULL) || (names[0] == NULL))
  {
    log_log(LOG_WARNING, "%s: %s: missing",
            myldap_get_dn(entry), attmap_group_cn);
    return 0;
  }
  /* get the group id(s) */
  if (reqgid != NULL)
  {
    gids[0] = *reqgid;
    numgids = 1;
  }
  else
  {
    gidvalues = myldap_get_values_len(entry, attmap_group_gidNumber);
    if ((gidvalues == NULL) || (gidvalues[0] == NULL))
    {
      log_log(LOG_WARNING, "%s: %s: missing",
              myldap_get_dn(entry), attmap_group_gidNumber);
      return 0;
    }
    for (numgids = 0; (numgids < MAXGIDS_PER_ENTRY) && (gidvalues[numgids] != NULL); numgids++)
    {
      if (gidSid != NULL)
        gids[numgids] = (gid_t)binsid2id(gidvalues[numgids]);
      else
      {
        errno = 0;
        gids[numgids] = strtogid(gidvalues[numgids], &tmp, 10);
        if ((*(gidvalues[numgids]) == '\0') || (*tmp != '\0'))
        {
          log_log(LOG_WARNING, "%s: %s: non-numeric",
                  myldap_get_dn(entry), attmap_group_gidNumber);
          return 0;
        }
        else if ((errno != 0) || (strchr(gidvalues[numgids], '-') != NULL))
        {
          log_log(LOG_WARNING, "%s: %s: out of range",
                  myldap_get_dn(entry), attmap_group_gidNumber);
          return 0;
        }
      }
      gids[numgids] += nslcd_cfg->nss_gid_offset;
    }
  }
  /* get group passwd (userPassword) (use only first entry) */
  passwd = get_userpassword(entry, attmap_group_userPassword,
                            passbuffer, sizeof(passbuffer));
  if (passwd == NULL)
    passwd = default_group_userPassword;
  /* get group members (memberUid&member) */
  if (wantmembers)
  {
    set = set_new();
    if (set != NULL)
    {
      if (nslcd_cfg->nss_nested_groups)
      {
        seen = set_new();
        subgroups = set_new();
      }
      /* collect the members from this group */
      getmembers(entry, session, set, seen, subgroups);
      /* add the members of any nested groups */
      if (subgroups != NULL)
      {
        while ((tmp = set_pop(subgroups)) != NULL)
        {
          search = myldap_search(session, tmp, LDAP_SCOPE_BASE, group_filter, group_attrs, NULL);
          if (search != NULL)
            while ((entry2 = myldap_get_entry(search, NULL)) != NULL)
              getmembers(entry2, session, set, seen, subgroups);
          free(tmp);
        }
      }
      members = set_tolist(set);
      set_free(set);
      if (seen != NULL)
        set_free(seen);
      if (subgroups != NULL)
        set_free(subgroups);
    }
  }
  /* write entries (split to a separate function so we can ensure the call
     to free() below in case a write fails) */
  rc = do_write_group(fp, entry, names, gids, numgids, passwd, members,
                      reqname);
  /* free and return */
  if (members != NULL)
    free(members);
  return rc;
}

NSLCD_HANDLE(
  group, byname, NSLCD_ACTION_GROUP_BYNAME,
  char name[BUFLEN_NAME];
  char filter[BUFLEN_FILTER];
  READ_STRING(fp, name);
  log_setrequest("group=\"%s\"", name);
  if (!isvalidname(name))
  {
    log_log(LOG_WARNING, "request denied by validnames option");
    return -1;
  },
  mkfilter_group_byname(name, filter, sizeof(filter)),
  write_group(fp, entry, name, NULL, 1, session)
)

NSLCD_HANDLE(
  group, bygid, NSLCD_ACTION_GROUP_BYGID,
  gid_t gid;
  char filter[BUFLEN_FILTER];
  READ_INT32(fp, gid);
  log_setrequest("group=%lu", (unsigned long int)gid);,
  mkfilter_group_bygid(gid, filter, sizeof(filter)),
  write_group(fp, entry, NULL, &gid, 1, session)
)

int nslcd_group_bymember(TFILE *fp, MYLDAP_SESSION *session)
{
  /* define common variables */
  int32_t tmpint32;
  MYLDAP_SEARCH *search;
  MYLDAP_ENTRY *entry;
  const char *dn;
  const char *base;
  int rc, i;
  char name[BUFLEN_NAME];
  char filter[BUFLEN_FILTER];
  SET *seen=NULL, *tocheck=NULL;
  /* read request parameters */
  READ_STRING(fp, name);
  log_setrequest("group/member=\"%s\"", name);
  /* validate request */
  if (!isvalidname(name))
  {
    log_log(LOG_WARNING, "request denied by validnames option");
    return -1;
  }
  if ((nslcd_cfg->nss_initgroups_ignoreusers != NULL) &&
      set_contains(nslcd_cfg->nss_initgroups_ignoreusers, name))
  {
    log_log(LOG_DEBUG, "ignored group member");
    /* just end the request, returning no results */
    WRITE_INT32(fp, NSLCD_VERSION);
    WRITE_INT32(fp, NSLCD_ACTION_GROUP_BYMEMBER);
    WRITE_INT32(fp, NSLCD_RESULT_END);
    return 0;
  }
  /* write the response header */
  WRITE_INT32(fp, NSLCD_VERSION);
  WRITE_INT32(fp, NSLCD_ACTION_GROUP_BYMEMBER);
  /* prepare the search filter */
  if (mkfilter_group_bymember(session, name, filter, sizeof(filter)))
  {
    log_log(LOG_WARNING, "nslcd_group_bymember(): filter buffer too small");
    return -1;
  }
  if ((nslcd_cfg->nss_nested_groups) && (strcasecmp(attmap_group_member, "\"\"") != 0))
  {
    seen = set_new();
    tocheck = set_new();
    if ((seen != NULL) && (tocheck == NULL))
    {
      set_free(seen);
      seen = NULL;
    }
    else if ((tocheck != NULL) && (seen == NULL))
    {
      set_free(tocheck);
      tocheck = NULL;
    }
  }
  /* perform a search for each search base */
  for (i = 0; (base = group_bases[i]) != NULL; i++)
  {
    /* do the LDAP search */
    search = myldap_search(session, base, group_scope, filter,
                           group_bymember_attrs, NULL);
    if (search == NULL)
    {
      if (seen != NULL)
      {
        set_free(seen);
        set_free(tocheck);
      }
      return -1;
    }
    /* go over results */
    while ((entry = myldap_get_entry(search, &rc)) != NULL)
    {
      if ((seen == NULL) || (!set_contains(seen, dn = myldap_get_dn(entry))))
      {
        if (seen != NULL)
        {
          set_add(seen, dn);
          set_add(tocheck, dn);
        }
        if (write_group(fp, entry, NULL, NULL, 0, session))
        {
          if (seen != NULL)
          {
            set_free(seen);
            set_free(tocheck);
          }
          return -1;
        }
      }
    }
  }
  /* write possible parent groups */
  if (tocheck != NULL)
  {
    while ((dn = set_pop(tocheck)) != NULL)
    {
      /* make filter for finding groups with our group as member */
      if (mkfilter_group_bymemberdn(dn, filter, sizeof(filter)))
      {
        log_log(LOG_WARNING, "nslcd_group_bymember(): filter buffer too small");
        free((void *)dn);
        set_free(seen);
        set_free(tocheck);
        return -1;
      }
      free((void *)dn);
      /* do the LDAP searches */
      for (i = 0; (base = group_bases[i]) != NULL; i++)
      {
        search = myldap_search(session, base, group_scope, filter, group_bymember_attrs, NULL);
        if (search != NULL)
        {
          while ((entry = myldap_get_entry(search, NULL)) != NULL)
          {
            dn = myldap_get_dn(entry);
            if (!set_contains(seen, dn))
            {
              set_add(seen, dn);
              set_add(tocheck, dn);
              if (write_group(fp, entry, NULL, NULL, 0, session))
              {
                set_free(seen);
                set_free(tocheck);
                return -1;
              }
            }
          }
        }
      }
    }
    set_free(seen);
    set_free(tocheck);
  }
  /* write the final result code */
  if (rc == LDAP_SUCCESS)
  {
    WRITE_INT32(fp, NSLCD_RESULT_END);
  }
  return 0;
}

NSLCD_HANDLE(
  group, all, NSLCD_ACTION_GROUP_ALL,
  const char *filter;
  log_setrequest("group(all)");,
  (filter = group_filter, 0),
  write_group(fp, entry, NULL, NULL, 1, session)
)
