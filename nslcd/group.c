/*
   group.c - group entry lookup routines
   This file was part of the nss_ldap library (as ldap-grp.c) which
   has been forked into the nss-ldapd library.

   Copyright (C) 1997-2006 Luke Howard
   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007 Arthur de Jong

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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <grp.h>
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
#include "common.h"
#include "log.h"
#include "cfg.h"
#include "attmap.h"
#include "ldap-schema.h"

/* FIXME: fix following problem:
          if the entry has multiple cn fields we may end up
          sending the wrong cn, we should return the requested
          cn instead, otherwise write an entry for each cn */

struct name_list
{
  char *name;
  struct name_list *next;
};

#ifdef HAVE_USERSEC_H
typedef struct ldap_initgroups_args
{
  char *grplist;
  size_t listlen;
  int depth;
  struct name_list *known_groups;
  int backlink;
}
ldap_initgroups_args_t;
#else
typedef struct ldap_initgroups_args
{
  gid_t group;
  long int *start;
  long int *size;
  gid_t **groups;
  long int limit;
  int depth;
  struct name_list *known_groups;
  int backlink;
}
ldap_initgroups_args_t;
#endif /* HAVE_USERSEC_H */

#define LDAP_NSS_MAXGR_DEPTH     16     /* maximum depth of group nesting for getgrent()/initgroups() */

#if LDAP_NSS_NGROUPS > 64
#define LDAP_NSS_BUFLEN_GROUP   (1024 + (LDAP_NSS_NGROUPS * (sizeof (char *) + LOGNAME_MAX)))
#else
#define LDAP_NSS_BUFLEN_GROUP   1024
#endif /* LDAP_NSS_NGROUPS > 64 */

#ifndef LOGNAME_MAX
#define LOGNAME_MAX 8
#endif /* LOGNAME_MAX */

#ifndef UID_NOBODY
#define UID_NOBODY      (-2)
#endif

#ifndef GID_NOBODY
#define GID_NOBODY     UID_NOBODY
#endif

static enum nss_status ng_chase(const char *dn,ldap_initgroups_args_t *lia);

static enum nss_status ng_chase_backlink(const char **membersOf,ldap_initgroups_args_t *lia);

/* the attributes to request with searches */
static const char *group_attrs[6];

/* create a search filter for searching a group entry
   by name, return -1 on errors */
static int mkfilter_group_byname(const char *name,
                                 char *buffer,size_t buflen)
{
  char buf2[1024];
  /* escape attribute */
  if(myldap_escape(name,buf2,sizeof(buf2)))
    return -1;
  /* build filter */
  return mysnprintf(buffer,buflen,
                    "(&(%s=%s)(%s=%s))",
                    attmap_objectClass,attmap_group_objectClass,
                    attmap_group_cn,buf2);
}

/* create a search filter for searching a group entry
   by gid, return -1 on errors */
static int mkfilter_group_bygid(gid_t gid,
                                char *buffer,size_t buflen)
{
  return mysnprintf(buffer,buflen,
                    "(&(%s=%s)(%s=%d))",
                    attmap_objectClass,attmap_group_objectClass,
                    attmap_group_cn,gid);
}

static char *user2dn(const char *user)
{
  /* TODO: move this to passwd.c once we are sure we would be able to lock there */
  char *userdn=NULL;
  static const char *no_attrs[]={ NULL };
  char filter[1024];
  LDAPMessage *res, *e;
  mkfilter_passwd_byname(user,filter,sizeof(filter));
  if (_nss_ldap_search_s(NULL,filter,LM_PASSWD,no_attrs,1,&res)==NSS_STATUS_SUCCESS)
  {
    e=_nss_ldap_first_entry(res);
    if (e!=NULL)
    {
      userdn=_nss_ldap_get_dn(e);
    }
    ldap_msgfree(res);
  }
  return userdn;
}

/* create a search filter for searching a group entry
   by name, return -1 on errors */
static int mkfilter_group_bymember(const char *name,
                                   char *buffer,size_t buflen)
{
  char buf2[1024];
  char *buf3;
  /* escape attribute */
  if(myldap_escape(name,buf2,sizeof(buf2)))
    return -1;
  /* DN format */
  /* TODO: look up user DN and store it in buf3 */
  buf3=buf2;
  /* build filter */
  return mysnprintf(buffer,buflen,
                    "(&(%s=%s)(|(%s=%s)(%s=%s)))",
                    attmap_objectClass,attmap_group_objectClass,
                    attmap_group_memberUid,buf2,
                    attmap_group_uniqueMember,buf3);
}

/* create a search filter for searching a group entry
   by name, return -1 on errors */
static int mkfilter_group_all(char *buffer,size_t buflen)
{
  return mysnprintf(buffer,buflen,
                    "(%s=%s)",
                    attmap_objectClass,attmap_group_objectClass);
}

static void group_attrs_init(void)
{
  group_attrs[0]=attmap_group_cn;
  group_attrs[1]=attmap_group_userPassword;
  group_attrs[2]=attmap_group_memberUid;
  group_attrs[3]=attmap_group_uniqueMember;
  group_attrs[4]=attmap_group_gidNumber;
  group_attrs[5]=NULL;
}

/*
 * Add a nested netgroup or group to the namelist
 */
static enum nss_status _nss_ldap_namelist_push(struct name_list **head,const char *name)
{
  struct name_list *nl;

  log_log(LOG_DEBUG,"==> _nss_ldap_namelist_push (%s)", name);

  nl = (struct name_list *) malloc (sizeof (*nl));
  if (nl == NULL)
    {
      log_log(LOG_DEBUG,"<== _nss_ldap_namelist_push");
      return NSS_STATUS_TRYAGAIN;
    }

  nl->name = strdup (name);
  if (nl->name == NULL)
    {
      log_log(LOG_DEBUG,"<== _nss_ldap_namelist_push");
      free (nl);
      return NSS_STATUS_TRYAGAIN;
    }

  nl->next = *head;

  *head = nl;

  log_log(LOG_DEBUG,"<== _nss_ldap_namelist_push");

  return NSS_STATUS_SUCCESS;
}

/*
 * Cleanup nested netgroup or group namelist.
 */
static void _nss_ldap_namelist_destroy(struct name_list **head)
{
  struct name_list *p, *next;

  log_log(LOG_DEBUG,"==> _nss_ldap_namelist_destroy");

  for (p = *head; p != NULL; p = next)
    {
      next = p->next;

      if (p->name != NULL)
        free (p->name);
      free (p);
    }

  *head = NULL;

  log_log(LOG_DEBUG,"<== _nss_ldap_namelist_destroy");
}

/*
 * Check whether we have already seen a netgroup or group,
 * to avoid loops in nested netgroup traversal
 */
static int _nss_ldap_namelist_find(struct name_list *head,const char *netgroup)
{
  struct name_list *p;
  int found = 0;

  log_log(LOG_DEBUG,"==> _nss_ldap_namelist_find");

  for (p = head; p != NULL; p = p->next)
    {
      if (strcasecmp (p->name, netgroup) == 0)
        {
          found++;
          break;
        }
    }

  log_log(LOG_DEBUG,"<== _nss_ldap_namelist_find");

  return found;
}

/*
 * Range retrieval logic was reimplemented from example in
 * http://msdn.microsoft.com/library/default.asp?url=/library/en-us/ldap/ldap/searching_using_range_retrieval.asp
 */

static enum nss_status
do_parse_range (const char *attributeType,
                const char *attributeDescription, int *start, int *end)
{
  enum nss_status stat = NSS_STATUS_NOTFOUND;
  char *attribute;
  size_t attributeTypeLength;
  size_t attributeDescriptionLength;
  char *p;
#ifdef HAVE_STRTOK_R
  char *st = NULL;
#endif

  *start = 0;
  *end = -1;

  if (strcasecmp (attributeType, attributeDescription) == 0)
    {
      return NSS_STATUS_SUCCESS;
    }

  attributeDescriptionLength = strlen (attributeDescription);
  attributeTypeLength = strlen (attributeType);

  if (attributeDescriptionLength < attributeTypeLength)
    {
      /* could not be a subtype */
      return NSS_STATUS_NOTFOUND;
    }

  /* XXX need to copy as strtok() is destructive */
  attribute = strdup (attributeDescription);
  if (attribute == NULL)
    {
      return NSS_STATUS_TRYAGAIN;
    }

#ifndef HAVE_STRTOK_R
  for (p = strtok (attribute, ";"); p != NULL; p = strtok (NULL, ";"))
#else
  for (p = strtok_r (attribute, ";", &st);
       p != NULL; p = strtok_r (NULL, ";", &st))
#endif /* !HAVE_STRTOK_R */
    {
      char *q;

      if (p == attribute)
        {
          if (strcasecmp (p, attributeType) != 0)
            {
              free (attribute);
              return NSS_STATUS_NOTFOUND;
            }
        }
      else if (strncasecmp (p, "range=", sizeof ("range=") - 1) == 0)
        {
          p += sizeof ("range=") - 1;

          q = strchr (p, '-');
          if (q == NULL)
            {
              free (attribute);
              return NSS_STATUS_NOTFOUND;
            }

          *q++ = '\0';

          *start = strtoul (p, (char **) NULL, 10);
          if (strcmp (q, "*") == 0)
            *end = -1;
          else
            *end = strtoul (q, (char **) NULL, 10);

          stat = NSS_STATUS_SUCCESS;
          break;
        }
    }

  free (attribute);
  return stat;
}

static enum nss_status
do_get_range_values (LDAPMessage * e,
                     const char *attributeType,
                     int *start, int *end, char ***pGroupMembers)
{
  enum nss_status stat = NSS_STATUS_NOTFOUND;
  BerElement *ber = NULL;
  char *attribute;

  *pGroupMembers = NULL;

  for (attribute = _nss_ldap_first_attribute (e, &ber);
       attribute != NULL; attribute = _nss_ldap_next_attribute (e, ber))
    {
      stat = do_parse_range (attributeType, attribute, start, end);
      if (stat == NSS_STATUS_SUCCESS)
        {
          *pGroupMembers = _nss_ldap_get_values (e, attribute);
          if (*pGroupMembers == NULL)
            {
              stat = NSS_STATUS_NOTFOUND;
            }
          else if ((*pGroupMembers)[0] == NULL)
            {
              ldap_value_free (*pGroupMembers);
              *pGroupMembers = NULL;
              stat = NSS_STATUS_NOTFOUND;
            }
        }

#ifdef HAVE_LDAP_MEMFREE
      ldap_memfree (attribute);
#endif

      if (stat == NSS_STATUS_SUCCESS)
        break;
    }

  if (ber != NULL)
    ber_free (ber, 0);

  return stat;
}

/*
 * Format an attribute with description as:
 *      attribute;range=START-END
 */
static enum nss_status
do_construct_range_attribute (const char *attribute,
                              int start,
                              int end,
                              char **buffer,
                              size_t * buflen,
                              const char **pAttributeWithRange)
{
  size_t len;
  char startbuf[32], endbuf[32];

  snprintf (startbuf, sizeof (startbuf), "%u", start);

  if (end != -1)
    snprintf (endbuf, sizeof (endbuf), "%u", end);
  else
    snprintf (endbuf, sizeof (endbuf), "*");

  len = strlen (attribute) + sizeof (";range=") - 1;
  len += strlen (startbuf) + 1 /* - */  + strlen (endbuf);
  len++;                        /* \0 */

  if (*buflen < len)
    return NSS_STATUS_TRYAGAIN;

  *pAttributeWithRange = *buffer;

  snprintf (*buffer, len, "%s;range=%s-%s", attribute, startbuf, endbuf);

  *buffer += len;
  *buflen -= len;

  return NSS_STATUS_SUCCESS;
}

/*
 * Expand group members, including nested groups
 */
static enum nss_status
do_parse_group_members (LDAPMessage * e,
                        char ***pGroupMembers,
                        size_t * pGroupMembersCount,
                        size_t * pGroupMembersBufferSize,
                        int *pGroupMembersBufferIsMalloced,
                        char **buffer, size_t * buflen,
                        int *depth,
                        struct name_list **pKnownGroups) /* traversed groups */
{
  enum nss_status stat = NSS_STATUS_SUCCESS;
  char **dnValues = NULL;
  char **uidValues = NULL;
  char **groupMembers;
  size_t groupMembersCount, i;
  char **valiter;
  const char *uniquemember_attrs[2];
  LDAPMessage *res = NULL;
  int start, end = 0;
  char *groupdn = NULL;

  uniquemember_attrs[0] = attmap_group_uniqueMember;
  uniquemember_attrs[1] = NULL;

  if (*depth > LDAP_NSS_MAXGR_DEPTH)
    {
      return NSS_STATUS_NOTFOUND;
    }

  i = *pGroupMembersCount;      /* index of next member */
  groupMembers = *pGroupMembers;

  groupdn = _nss_ldap_get_dn (e);
  if (groupdn == NULL)
    {
      stat = NSS_STATUS_NOTFOUND;
      goto out;
    }

  if (_nss_ldap_namelist_find (*pKnownGroups, groupdn))
    {
      stat = NSS_STATUS_NOTFOUND;
      goto out;
    }

  /* store group DN for nested group loop detection */
  stat = _nss_ldap_namelist_push (pKnownGroups, groupdn);
  if (stat != NSS_STATUS_SUCCESS)
    {
      goto out;
    }

  do
    {
      if (e == NULL)
        {
          stat = NSS_STATUS_NOTFOUND;
          goto out;
        }

      groupMembersCount = 0;    /* number of members in this group */

      (void) do_get_range_values (e, attmap_group_uniqueMember, &start, &end, &dnValues);
      if (dnValues != NULL)
        {
          groupMembersCount += ldap_count_values (dnValues);
        }

      uidValues = _nss_ldap_get_values (e, attmap_group_memberUid);
      if (uidValues != NULL)
        {
          groupMembersCount += ldap_count_values (uidValues);
        }

      /*
       * Check whether we need to increase the group membership buffer.
       * As an optimization the buffer is preferentially allocated off
       * the stack
       */
      if ((i + groupMembersCount) * sizeof (char *) >=
          *pGroupMembersBufferSize)
        {
          *pGroupMembersBufferSize =
            (i + groupMembersCount + 1) * sizeof (char *);
          *pGroupMembersBufferSize +=
            (LDAP_NSS_NGROUPS * sizeof (char *)) - 1;
          *pGroupMembersBufferSize -=
            (*pGroupMembersBufferSize %
             (LDAP_NSS_NGROUPS * sizeof (char *)));

          if (*pGroupMembersBufferIsMalloced == 0)
            {
              groupMembers = *pGroupMembers;
              *pGroupMembers = NULL;    /* force malloc() */
            }

          *pGroupMembers =
            (char **) realloc (*pGroupMembers, *pGroupMembersBufferSize);
          if (*pGroupMembers == NULL)
            {
              *pGroupMembersBufferIsMalloced = 0; /* don't try to free */
              stat = NSS_STATUS_TRYAGAIN;
              goto out;
            }

          if (*pGroupMembersBufferIsMalloced == 0)
            {
              memcpy (*pGroupMembers, groupMembers, i * sizeof (char *));
              groupMembers = NULL;      /* defensive programming */
              *pGroupMembersBufferIsMalloced = 1;
            }
        }

      groupMembers = *pGroupMembers;

      /* Parse distinguished name members */
      if (dnValues != NULL)
        {
          for (valiter = dnValues; *valiter != NULL; valiter++)
            {
              LDAPMessage *res;
              enum nss_status parseStat;
              int isNestedGroup = 0;
              char *uid;

              uid = strrchr (*valiter, '#');
              if (uid != NULL)
                {
                  *uid = '\0';
                }

              parseStat = _nss_ldap_dn2uid (*valiter, &groupMembers[i],
                                            buffer, buflen, &isNestedGroup,
                                            &res);
              if (parseStat == NSS_STATUS_SUCCESS)
                {
                  if (isNestedGroup == 0)
                    {
                      /* just a normal user which we have flattened */
                      i++;
                      continue;
                    }

                  (*depth)++;
                  parseStat =
                    do_parse_group_members (_nss_ldap_first_entry (res),
                                            &groupMembers, &i,
                                            pGroupMembersBufferSize,
                                            pGroupMembersBufferIsMalloced,
                                            buffer, buflen, depth,
                                            pKnownGroups);
                  (*depth)--;

                  if (parseStat == NSS_STATUS_TRYAGAIN)
                    {
                      stat = NSS_STATUS_TRYAGAIN;
                      goto out;
                    }

                  ldap_msgfree (res);
                }
              else if (parseStat == NSS_STATUS_TRYAGAIN)
                {
                  stat = NSS_STATUS_TRYAGAIN;
                  goto out;
                }
            }
        }

      /* Parse RFC 2307 (flat) members */
      if (uidValues != NULL)
        {
          for (valiter = uidValues; *valiter != NULL; valiter++)
            {
              size_t len = strlen (*valiter) + 1;
              if (*buflen < len)
                {
                  stat = NSS_STATUS_TRYAGAIN;
                  goto out;
                }
              groupMembers[i] = *buffer;
              *buffer += len;
              *buflen -= len;

              memcpy (groupMembers[i++], *valiter, len);
            }
        }

      /* Get next range for Active Directory compat */
      if (end != -1)
        {
          stat = do_construct_range_attribute (attmap_group_uniqueMember,
                                               end + 1,
                                               -1,
                                               buffer,
                                               buflen,
                                               uniquemember_attrs);
          if (stat == NSS_STATUS_SUCCESS)
            {
              if (dnValues != NULL)
                {
                  ldap_value_free (dnValues);
                  dnValues = NULL;
                }
              if (uidValues != NULL)
                {
                  ldap_value_free (uidValues);
                  uidValues = NULL;
                }
              if (res != NULL)
                {
                  ldap_msgfree (res);
                  res = NULL;
                }

              stat = _nss_ldap_read (groupdn, uniquemember_attrs, &res);
              if (stat != NSS_STATUS_SUCCESS)
                goto out;

              e = _nss_ldap_first_entry (res);
            }
        }
    }
  while (end != -1);

out:
  if (dnValues != NULL)
    ldap_value_free (dnValues);
  if (uidValues != NULL)
    ldap_value_free (uidValues);
  if (res != NULL)
    ldap_msgfree (res);
  if (groupdn != NULL)
#ifdef HAVE_LDAP_MEMFREE
    ldap_memfree (groupdn);
#else
    free (groupdn);
#endif

  *pGroupMembers = groupMembers;
  *pGroupMembersCount = i;

  return stat;
}

/*
 * "Fix" group membership list into caller provided buffer,
 * and NULL terminate.
*/
static enum nss_status
do_fix_group_members_buffer (char **mallocedGroupMembers,
                             size_t groupMembersCount,
                             char ***pGroupMembers,
                             char **buffer, size_t * buflen)
{
  size_t len;

  len = (groupMembersCount + 1) * sizeof (char *);

  if (bytesleft (*buffer, *buflen, char *) < len)
    {
      return NSS_STATUS_TRYAGAIN;
    }

  align (*buffer, *buflen, char *);
  *pGroupMembers = (char **) *buffer;
  *buffer += len;
  *buflen -= len;

  memcpy (*pGroupMembers, mallocedGroupMembers,
          groupMembersCount * sizeof (char *));
  (*pGroupMembers)[groupMembersCount] = NULL;

  return NSS_STATUS_SUCCESS;
}

static enum nss_status
_nss_ldap_parse_gr (LDAPMessage * e,
                    struct ldap_state * pvt,
                    void *result, char *buffer, size_t buflen)
{
  struct group *gr = (struct group *) result;
  char *gid;
  enum nss_status stat;
  char **groupMembers;
  size_t groupMembersCount;
  size_t groupMembersBufferSize;
  char *groupMembersBuffer[LDAP_NSS_NGROUPS];
  int groupMembersBufferIsMalloced;
  int depth;
  struct name_list *knownGroups = NULL;

  stat =
    _nss_ldap_assign_attrval (e, attmap_group_gidNumber, &gid, &buffer,
                              &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  gr->gr_gid =
    (*gid == '\0') ? (unsigned) GID_NOBODY : (gid_t) strtoul (gid,
                                                              (char **) NULL,
                                                              10);

  stat =
    _nss_ldap_getrdnvalue (e, attmap_group_cn, &gr->gr_name, &buffer,
                           &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_userpassword (e, attmap_group_userPassword,
                                   &gr->gr_passwd, &buffer, &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  if (_nss_ldap_test_config_flag (NSS_LDAP_FLAGS_RFC2307BIS))
    {
      groupMembers = groupMembersBuffer;
      groupMembersCount = 0;
      groupMembersBufferSize = sizeof (groupMembers);
      groupMembersBufferIsMalloced = 0;
      depth = 0;

      stat = do_parse_group_members (e, &groupMembers, &groupMembersCount,
                                     &groupMembersBufferSize,
                                     &groupMembersBufferIsMalloced, &buffer,
                                     &buflen, &depth, &knownGroups);
      if (stat != NSS_STATUS_SUCCESS)
        {
          if (groupMembersBufferIsMalloced)
            free (groupMembers);
          _nss_ldap_namelist_destroy (&knownGroups);
          return stat;
        }

      stat = do_fix_group_members_buffer (groupMembers, groupMembersCount,
                                          &gr->gr_mem, &buffer, &buflen);

      if (groupMembersBufferIsMalloced)
        free (groupMembers);
      _nss_ldap_namelist_destroy (&knownGroups);
    }
  else
    {
      stat =
        _nss_ldap_assign_attrvals (e, attmap_group_memberUid, NULL,
                                   &gr->gr_mem, &buffer, &buflen, NULL);
    }

  return stat;
}

/*
 * Add a group ID to a group list, and optionally the group IDs
 * of any groups to which this group belongs (RFC2307bis nested
 * group expansion is done by do_parse_initgroups_nested()).
 */
static enum nss_status
do_parse_initgroups (LDAPMessage * e,
                     struct ldap_state * pvt, void *result,
                     char *buffer, size_t buflen)
{
  char **values;
  ssize_t i;
  gid_t gid;
  ldap_initgroups_args_t *lia = (ldap_initgroups_args_t *) result;

  values = _nss_ldap_get_values (e, attmap_group_gidNumber);
  if (values == NULL)
    {
      /* invalid group; skip it */
      return NSS_STATUS_NOTFOUND;
    }

  if (values[0] == NULL)
    {
      /* invalid group; skip it */
      ldap_value_free (values);
      return NSS_STATUS_NOTFOUND;
    }

#ifdef HAVE_USERSEC_H
  i = strlen (values[0]);
  lia->grplist = realloc (lia->grplist, lia->listlen + i + 2);
  if (lia->grplist == NULL)
    {
      ldap_value_free (values);
      return NSS_STATUS_TRYAGAIN;
    }
  memcpy (lia->grplist + lia->listlen, values[0], i);
  lia->grplist[lia->listlen + i] = ',';
  lia->listlen += i + 1;
  ldap_value_free (values);
#else
  gid = strtoul (values[0], (char **) NULL, 10);
  ldap_value_free (values);

  if (gid == LONG_MAX && errno == ERANGE)
    {
      /* invalid group, skip it */
      return NSS_STATUS_NOTFOUND;
    }

  if (gid == lia->group)
    {
      /* primary group, so skip it */
      return NSS_STATUS_NOTFOUND;
    }

  if (lia->limit > 0)
    {
      if (*(lia->start) >= lia->limit)
        {
          /* can't fit any more */
          return NSS_STATUS_TRYAGAIN;
        }
    }
  if (*(lia->start) == *(lia->size))
    {
      /* Need a bigger buffer */
      *(lia->groups) = (gid_t *) realloc (*(lia->groups),
                                          2 * *(lia->size) * sizeof (gid_t));
      if (*(lia->groups) == NULL)
        {
          return NSS_STATUS_TRYAGAIN;
        }
      *(lia->size) *= 2;
    }

  /* weed out duplicates; is this really our responsibility? */
  for (i = 0; i < *(lia->start); i++)
    {
      if ((*(lia->groups))[i] == gid)
        {
          return NSS_STATUS_NOTFOUND;
        }
    }

  /* add to group list */
  (*(lia->groups))[*(lia->start)] = gid;
  (*(lia->start)) += 1;
#endif /* HAVE_USERSEC_H */

  return NSS_STATUS_NOTFOUND;
}

static enum nss_status
do_parse_initgroups_nested (LDAPMessage * e,
                            struct ldap_state * pvt, void *result,
                            char *buffer, size_t buflen)
{
  enum nss_status status;
  ldap_initgroups_args_t *lia = (ldap_initgroups_args_t *) result;
  char **values;
  char *groupdn;

  status = do_parse_initgroups (e, pvt, result, buffer, buflen);
  if (status != NSS_STATUS_NOTFOUND)
    return status;

  if (!_nss_ldap_test_config_flag (NSS_LDAP_FLAGS_RFC2307BIS))
    return NSS_STATUS_NOTFOUND;

  if (lia->backlink != 0)
    {
      /*
       * Now add the GIDs of any groups of which this group is
       * a member.
       */
      values = _nss_ldap_get_values (e, attmap_group_memberOf);
      if (values != NULL)
        {
          lia->depth++;
          status=ng_chase_backlink((const char **)values,lia);
          lia->depth--;

          ldap_value_free (values);

          return status;
        }
    }
  else
    {
      /*
       * Now add the GIDs of any groups which refer to this group
       */
      groupdn = _nss_ldap_get_dn (e);
      if (groupdn != NULL)
        {
          /* Note: there was a problem here with stat in the orriginal code */
          lia->depth++;
          status=ng_chase(groupdn,lia);
          lia->depth--;
#ifdef HAVE_LDAP_MEMFREE
          ldap_memfree(groupdn);
#else
          free(groupdn);
#endif
        }
    }

  return status;
}

static enum nss_status ng_chase(const char *dn, ldap_initgroups_args_t * lia)
{
  struct ldap_args a;
  enum nss_status stat;
  struct ent_context *ctx=NULL;
  const char *gidnumber_attrs[2];
  int erange;

  if (lia->depth>LDAP_NSS_MAXGR_DEPTH)
    return NSS_STATUS_NOTFOUND;

  if (_nss_ldap_namelist_find(lia->known_groups,dn))
    return NSS_STATUS_NOTFOUND;

  gidnumber_attrs[0]=attmap_group_gidNumber;
  gidnumber_attrs[1]=NULL;

  LA_INIT(a);
  LA_STRING(a)=dn;
  LA_TYPE(a)=LA_TYPE_STRING;

  if (_nss_ldap_ent_context_init_locked(&ctx)==NULL)
  {
    return NSS_STATUS_UNAVAIL;
  }

  stat=_nss_ldap_getent_ex(&a, &ctx, lia, NULL, 0,
                           &erange, _nss_ldap_filt_getgroupsbydn,
                           LM_GROUP, gidnumber_attrs,
                           do_parse_initgroups_nested);

  if (stat==NSS_STATUS_SUCCESS)
  {
    stat=_nss_ldap_namelist_push(&lia->known_groups,dn);
  }

  _nss_ldap_ent_context_release(ctx);
  free(ctx);

  return stat;
}

static enum nss_status ng_chase_backlink(const char ** membersOf, ldap_initgroups_args_t * lia)
{
  struct ldap_args a;
  enum nss_status stat;
  struct ent_context *ctx=NULL;
  const char *gidnumber_attrs[3];
  const char **memberP;
  const char **filteredMembersOf; /* remove already traversed groups */
  size_t memberCount, i;
  int erange;

  if (lia->depth > LDAP_NSS_MAXGR_DEPTH)
    return NSS_STATUS_NOTFOUND;

  for (memberCount = 0; membersOf[memberCount] != NULL; memberCount++)
    ;

  /* Build a list of membersOf values without any already traversed groups */
  filteredMembersOf = (const char **) malloc(sizeof(char *) * (memberCount + 1));
  if (filteredMembersOf == NULL)
    {
      return NSS_STATUS_TRYAGAIN;
    }

  memberP = filteredMembersOf;

  for (i = 0; i < memberCount; i++)
    {
      if (_nss_ldap_namelist_find (lia->known_groups, membersOf[i]))
        continue;

      *memberP = membersOf[i];
      memberP++;
    }

  *memberP = NULL;

  if (filteredMembersOf[0] == NULL)
    {
      free (filteredMembersOf);
      return NSS_STATUS_NOTFOUND;
    }

  gidnumber_attrs[0] = attmap_group_gidNumber;
  gidnumber_attrs[1] = attmap_group_memberOf;
  gidnumber_attrs[2] = NULL;

  LA_INIT (a);
  LA_STRING_LIST (a) = filteredMembersOf;
  LA_TYPE (a) = LA_TYPE_STRING_LIST_OR;

  if (_nss_ldap_ent_context_init_locked (&ctx) == NULL)
    {
      free (filteredMembersOf);
      return NSS_STATUS_UNAVAIL;
    }

  stat = _nss_ldap_getent_ex (&a, &ctx, lia, NULL, 0,
                              &erange, "(distinguishedName=%s)",
                              LM_GROUP, gidnumber_attrs,
                              do_parse_initgroups_nested);

  if (stat == NSS_STATUS_SUCCESS)
    {
      enum nss_status stat2;

      for (memberP = filteredMembersOf; *memberP != NULL; memberP++)
        {
          stat2 = _nss_ldap_namelist_push (&lia->known_groups, *memberP);
          if (stat2 != NSS_STATUS_SUCCESS)
            {
              stat = stat2;
              break;
            }
        }
    }

  free (filteredMembersOf);

  _nss_ldap_ent_context_release (ctx);
  free (ctx);

  return stat;
}

static int group_bymember(const char *user, long int *start,
                          long int *size, long int limit,
                          int *errnop)
{
  ldap_initgroups_args_t lia;
  int erange = 0;
  char *userdn=NULL;
  struct ldap_args a;
  const char *flt;
  enum nss_status stat;
  struct ent_context *ctx=NULL;
  const char *gidnumber_attrs[3];
  enum ldap_map_selector map = LM_GROUP;
  log_log(LOG_DEBUG,"==> group_bymember (user=%s)",user);
  lia.depth = 0;
  lia.known_groups = NULL;
  _nss_ldap_enter();
  /* initialize schema */
  stat=_nss_ldap_init();
  if (stat!=NSS_STATUS_SUCCESS)
  {
    log_log(LOG_DEBUG,"<== group_bymember (init failed)");
    _nss_ldap_leave();
    return -1;
  }
  if (_nss_ldap_test_config_flag(NSS_LDAP_FLAGS_RFC2307BIS))
  {
    /* lookup the user's DN. */
    userdn=user2dn(user);
  }

  if (userdn != NULL)
  {
    LA_STRING2 (a) = userdn;
    LA_TYPE (a) = LA_TYPE_STRING_AND_STRING;
    flt = _nss_ldap_filt_getgroupsbymemberanddn;
  }
  else
  {
    flt = _nss_ldap_filt_getgroupsbymember;
  }

  gidnumber_attrs[0] = attmap_group_gidNumber;
  gidnumber_attrs[1] = NULL;

  if (_nss_ldap_ent_context_init_locked(&ctx)==NULL)
  {
    log_log(LOG_DEBUG,"<== group_bymember (ent_context_init failed)");
    _nss_ldap_leave ();
    return -1;
  }

  stat=_nss_ldap_getent_ex(&a,&ctx,(void *)&lia,NULL,0,
                           errnop,
                           flt,
                           map,
                           gidnumber_attrs,
                           do_parse_initgroups_nested);

  if (userdn!=NULL)
    ldap_memfree(userdn);

  _nss_ldap_namelist_destroy(&lia.known_groups);
  _nss_ldap_ent_context_release(ctx);
  free(ctx);
  _nss_ldap_leave();

  if ((stat!=NSS_STATUS_SUCCESS)&&(stat!=NSS_STATUS_NOTFOUND))
  {
    log_log(LOG_DEBUG,"<== group_bymember (not found)");
    return -1;
  }

  log_log(LOG_DEBUG,"<== group_bymember (success)");

  return 0;
}

/* macros for expanding the NSLCD_GROUP macro */
#define NSLCD_STRING(field)     WRITE_STRING(fp,field)
#define NSLCD_TYPE(field,type)  WRITE_TYPE(fp,field,type)
#define NSLCD_STRINGLIST(field) WRITE_STRINGLIST_NULLTERM(fp,field)
#define GROUP_NAME            result.gr_name
#define GROUP_PASSWD          result.gr_passwd
#define GROUP_GID             result.gr_gid
#define GROUP_MEMBERS         result.gr_mem

int nslcd_group_byname(TFILE *fp)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  char name[256];
  char filter[1024];
  /* these are here for now until we rewrite the LDAP code */
  struct group result;
  char buffer[1024];
  int errnop;
  int retv;
  /* read request parameters */
  READ_STRING_BUF2(fp,name,sizeof(name));
  /* log call */
  log_log(LOG_DEBUG,"nslcd_group_byname(%s)",name);
  /* static buffer size check */
  if (1024<LDAP_NSS_BUFLEN_GROUP)
  {
    log_log(LOG_CRIT,"allocated buffer in nslcd_group_byname() too small");
    exit(EXIT_FAILURE);
  }
  /* do the LDAP request */
  mkfilter_group_byname(name,filter,sizeof(filter));
  group_attrs_init();
  retv=_nss_ldap_getbyname(&result,buffer,1024,&errnop,LM_GROUP,
                           NULL,filter,group_attrs,_nss_ldap_parse_gr);
  /* write the response */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_GROUP_BYNAME);
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
  {
    NSLCD_GROUP;
  }
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_group_bygid(TFILE *fp)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  gid_t gid;
  char filter[1024];
  /* these are here for now until we rewrite the LDAP code */
  struct group result;
  char buffer[1024];
  int errnop;
  int retv;
  /* read request parameters */
  READ_TYPE(fp,gid,gid_t);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_group_bygid(%d)",(int)gid);
  /* static buffer size check */
  if (1024<LDAP_NSS_BUFLEN_GROUP)
  {
    log_log(LOG_CRIT,"allocated buffer in nslcd_group_byname() too small");
    exit(EXIT_FAILURE);
  }
  /* do the LDAP request */
  mkfilter_group_bygid(gid,filter,sizeof(filter));
  group_attrs_init();
  retv=_nss_ldap_getbyname(&result,buffer,1024,&errnop,LM_GROUP,
                           NULL,filter,group_attrs,_nss_ldap_parse_gr);
  /* write the response */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_GROUP_BYGID);
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
  {
    NSLCD_GROUP;
  }
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_group_bymember(TFILE *fp)
{
  int32_t tmpint32;
  char name[256];
  /* these are here for now until we rewrite the LDAP code */
  int errnop;
  int retv;
  long int start=0,size=1024;
  long int i;
  gid_t groupsp[1024];
  /* read request parameters */
  READ_STRING_BUF2(fp,name,sizeof(name));
  /* log call */
  log_log(LOG_DEBUG,"nslcd_group_bymember(%s)",name);
  /* do the LDAP request */
  retv=NSLCD_RESULT_NOTFOUND;
  /*
  retv=group_bymember(name,&start,&size,size,&errnop);
  */
  /* Note: we write some garbadge here to ensure protocol error as this
           function currently returns incorrect data */
  /* Note: what to do with group ids that are not listed as supplemental
           groups but are the user's primary group id? */
  WRITE_INT32(fp,1234);
  start=0;
  /* TODO: fix this to actually work */
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_GROUP_BYNAME);
  if (retv==NSLCD_RESULT_SUCCESS)
  {
    /* loop over the returned gids */
    for (i=0;i<start;i++)
    {
      WRITE_INT32(fp,NSLCD_RESULT_SUCCESS);
      /* Note: we will write a fake record here for now. This is because
               we want to keep the protocol but currently the only
               client application available discards non-gid information */
      WRITE_STRING(fp,""); /* group name */
      WRITE_STRING(fp,"*"); /* group passwd */
      WRITE_TYPE(fp,groupsp[i],gid_t); /* gid */
      WRITE_INT32(fp,1); /* number of members */
      WRITE_STRING(fp,name); /* member=user requested */
    }
    WRITE_INT32(fp,NSLCD_RESULT_NOTFOUND);
  }
  else
  {
    /* some error occurred */
    WRITE_INT32(fp,retv);
  }
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_group_all(TFILE *fp)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  struct ent_context *gr_context=NULL;
  /* these are here for now until we rewrite the LDAP code */
  struct group result;
  char buffer[1024];
  int errnop;
  int retv;
  /* log call */
  log_log(LOG_DEBUG,"nslcd_group_all()");
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_GROUP_ALL);
  /* initialize context */
  if (_nss_ldap_ent_context_init(&gr_context)==NULL)
    return -1;
  /* loop over all results */
  group_attrs_init();
  while ((retv=nss2nslcd(_nss_ldap_getent(&gr_context,&result,buffer,1024,&errnop,_nss_ldap_filt_getgrent,LM_GROUP,group_attrs,_nss_ldap_parse_gr)))==NSLCD_RESULT_SUCCESS)
  {
    /* write the result */
    WRITE_INT32(fp,retv);
    NSLCD_GROUP;
  }
  /* write the final result code */
  WRITE_INT32(fp,retv);
  WRITE_FLUSH(fp);
  /* FIXME: if a previous call returns what happens to the context? */
  _nss_ldap_enter();
  _nss_ldap_ent_context_release(gr_context);
  _nss_ldap_leave();
  /* we're done */
  return 0;
}
