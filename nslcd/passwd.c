/*
   passwd.c - password entry lookup routines
   Parts of this file were part of the nss_ldap library (as ldap-pwd.c)
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
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include "common.h"
#include "log.h"
#include "myldap.h"
#include "cfg.h"
#include "attmap.h"
#include "common/dict.h"
#include "compat/strndup.h"

/* ( nisSchema.2.0 NAME 'posixAccount' SUP top AUXILIARY
 *   DESC 'Abstraction of an account with POSIX attributes'
 *   MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory )
 *   MAY ( userPassword $ loginShell $ gecos $ description ) )
 */

/* the search base for searches */
const char *passwd_bases[NSS_LDAP_CONFIG_MAX_BASES] = { NULL };

/* the search scope for searches */
int passwd_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *passwd_filter = "(objectClass=posixAccount)";

/* the attributes used in searches */
const char *attmap_passwd_uid           = "uid";
const char *attmap_passwd_userPassword  = "\"*\"";
const char *attmap_passwd_uidNumber     = "uidNumber";
const char *attmap_passwd_gidNumber     = "gidNumber";
const char *attmap_passwd_gecos         = "\"${gecos:-$cn}\"";
const char *attmap_passwd_homeDirectory = "homeDirectory";
const char *attmap_passwd_loginShell    = "loginShell";
const char *attmap_passwd_class         = "userClass";

/* special properties for objectSid-based searches
   (these are already LDAP-escaped strings) */
static char *uidSid = NULL;
static char *gidSid = NULL;

/* default values for attributes */
static const char *default_passwd_userPassword = "*"; /* unmatchable */

/* Note that the resulting password value should be one of:
   <empty> - no password set, allow login without password
   *       - often used to prevent logins
   x       - "valid" encrypted password that does not match any valid password
             often used to indicate that the password is defined elsewhere
   other   - encrypted password, usually in crypt(3) format */

/* the attribute list to request with searches */
static const char **passwd_attrs = NULL;

/* create a search filter for searching a passwd entry
   by name, return -1 on errors */
static int mkfilter_passwd_byname(const char *name,
                                  char *buffer, size_t buflen)
{
  char safename[BUFLEN_SAFENAME];
  /* escape attribute */
  if (myldap_escape(name, safename, sizeof(safename)))
  {
    log_log(LOG_ERR, "mkfilter_passwd_byname(): safename buffer too small");
    return -1;
  }
  /* build filter */
  return mysnprintf(buffer, buflen, "(&%s(%s=%s))",
                    passwd_filter, attmap_passwd_uid, safename);
}

/* create a search filter for searching a passwd entry
   by uid, return -1 on errors */
static int mkfilter_passwd_byuid(uid_t uid, char *buffer, size_t buflen)
{
  uid -= nslcd_cfg->nss_uid_offset;
  if (uidSid != NULL)
  {
    return mysnprintf(buffer, buflen, "(&%s(%s=%s\\%02x\\%02x\\%02x\\%02x))",
                      passwd_filter, attmap_passwd_uidNumber, uidSid,
                      (int)(uid & 0xff), (int)((uid >> 8) & 0xff),
                      (int)((uid >> 16) & 0xff), (int)((uid >> 24) & 0xff));
  }
  else
  {
    return mysnprintf(buffer, buflen, "(&%s(%s=%lu))",
                      passwd_filter, attmap_passwd_uidNumber, (unsigned long int)uid);
  }
}

void passwd_init(void)
{
  int i;
  SET *set;
  /* set up search bases */
  if (passwd_bases[0] == NULL)
    for (i = 0; i < NSS_LDAP_CONFIG_MAX_BASES; i++)
      passwd_bases[i] = nslcd_cfg->bases[i];
  /* set up scope */
  if (passwd_scope == LDAP_SCOPE_DEFAULT)
    passwd_scope = nslcd_cfg->scope;
  /* special case when uidNumber or gidNumber reference objectSid */
  if (strncasecmp(attmap_passwd_uidNumber, "objectSid:", 10) == 0)
  {
    uidSid = sid2search(attmap_passwd_uidNumber + 10);
    attmap_passwd_uidNumber = strndup(attmap_passwd_uidNumber, 9);
  }
  if (strncasecmp(attmap_passwd_gidNumber, "objectSid:", 10) == 0)
  {
    gidSid = sid2search(attmap_passwd_gidNumber + 10);
    attmap_passwd_gidNumber = strndup(attmap_passwd_gidNumber, 9);
  }
  /* set up attribute list */
  set = set_new();
  attmap_add_attributes(set, "objectClass"); /* for testing shadowAccount */
  attmap_add_attributes(set, attmap_passwd_uid);
  attmap_add_attributes(set, attmap_passwd_userPassword);
  attmap_add_attributes(set, attmap_passwd_uidNumber);
  attmap_add_attributes(set, attmap_passwd_gidNumber);
  attmap_add_attributes(set, attmap_passwd_gecos);
  attmap_add_attributes(set, attmap_passwd_homeDirectory);
  attmap_add_attributes(set, attmap_passwd_loginShell);
  attmap_add_attributes(set, attmap_passwd_class);
  passwd_attrs = set_tolist(set);
  if (passwd_attrs == NULL)
  {
    log_log(LOG_CRIT, "malloc() failed to allocate memory");
    exit(EXIT_FAILURE);
  }
  set_free(set);
}

/* the cache that is used in dn2uid() */
static pthread_mutex_t dn2uid_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static DICT *dn2uid_cache = NULL;
struct dn2uid_cache_entry {
  time_t timestamp;
  char *uid;
};

/* checks whether the entry has a valid uidNumber attribute
   (>= nss_min_uid) */
static int entry_has_valid_uid(MYLDAP_ENTRY *entry)
{
  int i;
  const char **values;
  char *tmp;
  uid_t uid;
  /* if min_uid is not set any entry should do */
  if (nslcd_cfg->nss_min_uid == 0)
    return 1;
  /* get all uidNumber attributes */
  values = myldap_get_values_len(entry, attmap_passwd_uidNumber);
  if ((values == NULL) || (values[0] == NULL))
  {
    log_log(LOG_WARNING, "%s: %s: missing",
            myldap_get_dn(entry), attmap_passwd_uidNumber);
    return 0;
  }
  /* check if there is a uidNumber attributes >= min_uid */
  for (i = 0; values[i] != NULL; i++)
  {
    if (uidSid != NULL)
      uid = (uid_t)binsid2id(values[i]);
    else
    {
      errno = 0;
      uid = strtouid(values[i], &tmp, 10);
      if ((*(values[i]) == '\0') || (*tmp != '\0'))
      {
        log_log(LOG_WARNING, "%s: %s: non-numeric",
                myldap_get_dn(entry), attmap_passwd_uidNumber);
        continue;
      }
      else if ((errno != 0) || (strchr(values[i], '-') != NULL))
      {
        log_log(LOG_WARNING, "%s: %s: out of range",
                myldap_get_dn(entry), attmap_passwd_uidNumber);
        continue;
      }
    }
    if (uid < nslcd_cfg->nss_min_uid)
    {
      log_log(LOG_DEBUG, "%s: %s: less than nss_min_uid",
              myldap_get_dn(entry), attmap_passwd_uidNumber);
    }
    else
      return 1;
  }
  /* nothing found */
  return 0;
}

/* Perform an LDAP lookup to translate the DN into a uid.
   This function either returns NULL or a strdup()ed string. */
char *lookup_dn2uid(MYLDAP_SESSION *session, const char *dn, int *rcp,
                    char *buf, size_t buflen)
{
  MYLDAP_SEARCH *search;
  MYLDAP_ENTRY *entry;
  static const char *attrs[3];
  int rc = LDAP_SUCCESS;
  const char **values;
  char *uid = NULL;
  if (rcp == NULL)
    rcp = &rc;
  /* we have to look up the entry */
  attrs[0] = attmap_passwd_uid;
  attrs[1] = attmap_passwd_uidNumber;
  attrs[2] = NULL;
  search = myldap_search(session, dn, LDAP_SCOPE_BASE, passwd_filter, attrs, rcp);
  if (search == NULL)
  {
    log_log(LOG_WARNING, "%s: lookup error: %s", dn, ldap_err2string(*rcp));
    return NULL;
  }
  entry = myldap_get_entry(search, rcp);
  if (entry == NULL)
  {
    if (*rcp != LDAP_SUCCESS)
      log_log(LOG_WARNING, "%s: lookup error: %s", dn, ldap_err2string(*rcp));
    return NULL;
  }
  /* check the uidNumber attribute if min_uid is set */
  if (entry_has_valid_uid(entry))
  {
    /* get uid (just use first one) */
    values = myldap_get_values(entry, attmap_passwd_uid);
    /* check the result for presence and validity */
    if ((values != NULL) && (values[0] != NULL) &&
        isvalidname(values[0]) && (strlen(values[0]) < buflen))
    {
      strcpy(buf, values[0]);
      uid = buf;
    }
  }
  /* clean up and return */
  myldap_search_close(search);
  return uid;
}

/* Translate the DN into a user name. This function tries several approaches
   at getting the user name, including looking in the DN for a uid attribute,
   looking in the cache and falling back to looking up a uid attribute in a
   LDAP query. */
char *dn2uid(MYLDAP_SESSION *session, const char *dn, char *buf, size_t buflen)
{
  struct dn2uid_cache_entry *cacheentry = NULL;
  char *uid;
  /* check for empty string */
  if ((dn == NULL) || (*dn == '\0'))
    return NULL;
  /* try to look up uid within DN string */
  if (myldap_cpy_rdn_value(dn, attmap_passwd_uid, buf, buflen) != NULL)
  {
    /* check if it is valid */
    if (!isvalidname(buf))
      return NULL;
    return buf;
  }
  /* if we don't use the cache, just lookup and return */
  if ((nslcd_cfg->cache_dn2uid_positive == 0) && (nslcd_cfg->cache_dn2uid_negative == 0))
    return lookup_dn2uid(session, dn, NULL, buf, buflen);
  /* see if we have a cached entry */
  pthread_mutex_lock(&dn2uid_cache_mutex);
  if (dn2uid_cache == NULL)
    dn2uid_cache = dict_new();
  if ((dn2uid_cache != NULL) && ((cacheentry = dict_get(dn2uid_cache, dn)) != NULL))
  {
    if ((cacheentry->uid != NULL) && (strlen(cacheentry->uid) < buflen))
    {
      /* positive hit: if the cached entry is still valid, return that */
      if ((nslcd_cfg->cache_dn2uid_positive > 0) &&
          (time(NULL) < (cacheentry->timestamp + nslcd_cfg->cache_dn2uid_positive)))
      {
        strcpy(buf, cacheentry->uid);
        pthread_mutex_unlock(&dn2uid_cache_mutex);
        return buf;
      }
    }
    else
    {
      /* negative hit: if the cached entry is still valid, return that */
      if ((nslcd_cfg->cache_dn2uid_negative > 0) &&
           (time(NULL) < (cacheentry->timestamp + nslcd_cfg->cache_dn2uid_negative)))
      {
        pthread_mutex_unlock(&dn2uid_cache_mutex);
        return NULL;
      }
    }
  }
  pthread_mutex_unlock(&dn2uid_cache_mutex);
  /* look up the uid using an LDAP query */
  uid = lookup_dn2uid(session, dn, NULL, buf, buflen);
  /* store the result in the cache */
  pthread_mutex_lock(&dn2uid_cache_mutex);
  /* try to get the entry from the cache here again because it could have
     changed in the meantime */
  cacheentry = dict_get(dn2uid_cache, dn);
  if (cacheentry == NULL)
  {
    /* allocate a new entry in the cache */
    cacheentry = (struct dn2uid_cache_entry *)malloc(sizeof(struct dn2uid_cache_entry));
    if (cacheentry != NULL)
    {
      cacheentry->uid = NULL;
      dict_put(dn2uid_cache, dn, cacheentry);
    }
  }
  /* update the cache entry */
  if (cacheentry != NULL)
  {
    cacheentry->timestamp = time(NULL);
    /* copy the uid if needed */
    if (cacheentry->uid == NULL)
      cacheentry->uid = uid != NULL ? strdup(uid) : NULL;
    else if ((uid == NULL) || (strcmp(cacheentry->uid, uid) != 0))
    {
      free(cacheentry->uid);
      cacheentry->uid = uid != NULL ? strdup(uid) : NULL;
    }
  }
  pthread_mutex_unlock(&dn2uid_cache_mutex);
  /* copy the result into the buffer */
  return uid;
}

MYLDAP_ENTRY *uid2entry(MYLDAP_SESSION *session, const char *uid, int *rcp)
{
  MYLDAP_SEARCH *search = NULL;
  MYLDAP_ENTRY *entry = NULL;
  const char *base;
  int i;
  static const char *attrs[3];
  char filter[BUFLEN_FILTER];
  /* if it isn't a valid username, just bail out now */
  if (!isvalidname(uid))
  {
    if (rcp != NULL)
      *rcp = LDAP_INVALID_SYNTAX;
    return NULL;
  }
  /* set up attributes (we don't need much) */
  attrs[0] = attmap_passwd_uid;
  attrs[1] = attmap_passwd_uidNumber;
  attrs[2] = NULL;
  /* we have to look up the entry */
  mkfilter_passwd_byname(uid, filter, sizeof(filter));
  for (i = 0; (i < NSS_LDAP_CONFIG_MAX_BASES) && ((base = passwd_bases[i]) != NULL); i++)
  {
    search = myldap_search(session, base, passwd_scope, filter, attrs, rcp);
    if (search == NULL)
    {
      if ((rcp != NULL) && (*rcp == LDAP_SUCCESS))
        *rcp = LDAP_NO_SUCH_OBJECT;
      return NULL;
    }
    entry = myldap_get_entry(search, rcp);
    if ((entry != NULL) && (entry_has_valid_uid(entry)))
      return entry;
  }
  if ((rcp != NULL) && (*rcp == LDAP_SUCCESS))
    *rcp = LDAP_NO_SUCH_OBJECT;
  return NULL;
}

char *uid2dn(MYLDAP_SESSION *session, const char *uid, char *buf, size_t buflen)
{
  MYLDAP_ENTRY *entry;
  /* look up the entry */
  entry = uid2entry(session, uid, NULL);
  if (entry == NULL)
    return NULL;
  /* get DN */
  return myldap_cpy_dn(entry, buf, buflen);
}

#ifndef NSS_FLAVOUR_GLIBC
/* only check nsswitch.conf for glibc */
#define check_nsswitch_reload()
#define shadow_uses_ldap() (1)
#endif /* NSS_FLAVOUR_GLIBC */

/* the maximum number of uidNumber attributes per entry */
#define MAXUIDS_PER_ENTRY 5

static int write_passwd(TFILE *fp, MYLDAP_ENTRY *entry, const char *requser,
                        const uid_t *requid, uid_t calleruid)
{
  int32_t tmpint32;
  const char **tmpvalues;
  char *tmp;
  const char **usernames;
  const char *passwd;
  uid_t uids[MAXUIDS_PER_ENTRY];
  int numuids;
  char gidbuf[32];
  gid_t gid;
  char gecos[1024];
  char homedir[256];
  char shell[64];
  char passbuffer[BUFLEN_PASSWORDHASH];
  char class[64];
  int i, j;
  /* get the usernames for this entry */
  usernames = myldap_get_values(entry, attmap_passwd_uid);
  if ((usernames == NULL) || (usernames[0] == NULL))
  {
    log_log(LOG_WARNING, "%s: %s: missing",
            myldap_get_dn(entry), attmap_passwd_uid);
    return 0;
  }
  /* if we are using shadow maps and this entry looks like it would return
     shadow information, make the passwd entry indicate it */
  if (myldap_has_objectclass(entry, "shadowAccount") && nsswitch_shadow_uses_ldap())
  {
    passwd = "x";
  }
  else
  {
    passwd = get_userpassword(entry, attmap_passwd_userPassword,
                              passbuffer, sizeof(passbuffer));
    if ((passwd == NULL) || (calleruid != 0))
      passwd = default_passwd_userPassword;
  }
  /* get the uids for this entry */
  if (requid != NULL)
  {
    uids[0] = *requid;
    numuids = 1;
  }
  else
  {
    tmpvalues = myldap_get_values_len(entry, attmap_passwd_uidNumber);
    if ((tmpvalues == NULL) || (tmpvalues[0] == NULL))
    {
      log_log(LOG_WARNING, "%s: %s: missing",
              myldap_get_dn(entry), attmap_passwd_uidNumber);
      return 0;
    }
    for (numuids = 0; (numuids < MAXUIDS_PER_ENTRY) && (tmpvalues[numuids] != NULL); numuids++)
    {
      if (uidSid != NULL)
        uids[numuids] = (uid_t)binsid2id(tmpvalues[numuids]);
      else
      {
        errno = 0;
        uids[numuids] = strtouid(tmpvalues[numuids], &tmp, 10);
        if ((*(tmpvalues[numuids]) == '\0') || (*tmp != '\0'))
        {
          log_log(LOG_WARNING, "%s: %s: non-numeric",
                  myldap_get_dn(entry), attmap_passwd_uidNumber);
          return 0;
        }
        else if ((errno != 0) || (strchr(tmpvalues[numuids], '-') != NULL))
        {
          log_log(LOG_WARNING, "%s: %s: out of range",
                  myldap_get_dn(entry), attmap_passwd_uidNumber);
          return 0;
        }
      }
      uids[numuids] += nslcd_cfg->nss_uid_offset;
      if (uids[numuids] < nslcd_cfg->nss_min_uid)
      {
          log_log(LOG_DEBUG, "%s: %s: less than nss_min_uid",
                  myldap_get_dn(entry), attmap_passwd_uidNumber);
      }
    }
  }
  /* get the gid for this entry */
  if (gidSid != NULL)
  {
    tmpvalues = myldap_get_values_len(entry, attmap_passwd_gidNumber);
    if ((tmpvalues == NULL) || (tmpvalues[0] == NULL))
    {
      log_log(LOG_WARNING, "%s: %s: missing",
              myldap_get_dn(entry), attmap_passwd_gidNumber);
      return 0;
    }
    gid = (gid_t)binsid2id(tmpvalues[0]);
  }
  else
  {
    attmap_get_value(entry, attmap_passwd_gidNumber, gidbuf, sizeof(gidbuf));
    if (gidbuf[0] == '\0')
    {
      log_log(LOG_WARNING, "%s: %s: missing",
              myldap_get_dn(entry), attmap_passwd_gidNumber);
      return 0;
    }
    errno = 0;
    gid = strtogid(gidbuf, &tmp, 10);
    if ((gidbuf[0] == '\0') || (*tmp != '\0'))
    {
      log_log(LOG_WARNING, "%s: %s: non-numeric",
              myldap_get_dn(entry), attmap_passwd_gidNumber);
      return 0;
    }
    else if ((errno != 0) || (strchr(gidbuf, '-') != NULL))
    {
      log_log(LOG_WARNING, "%s: %s: out of range",
              myldap_get_dn(entry), attmap_passwd_gidNumber);
      return 0;
    }
  }
  gid += nslcd_cfg->nss_gid_offset;
  /* get the gecos for this entry */
  attmap_get_value(entry, attmap_passwd_gecos, gecos, sizeof(gecos));
  /* get the home directory for this entry */
  attmap_get_value(entry, attmap_passwd_homeDirectory, homedir, sizeof(homedir));
  if (homedir[0] == '\0')
    log_log(LOG_WARNING, "%s: %s: missing",
            myldap_get_dn(entry), attmap_passwd_homeDirectory);
  /* get the shell for this entry */
  attmap_get_value(entry, attmap_passwd_loginShell, shell, sizeof(shell));
  /* get the class for this entry */
  attmap_get_value(entry, attmap_passwd_class, class, sizeof(class));
  /* write the entries */
  for (i = 0; usernames[i] != NULL; i++)
  {
    if ((requser == NULL) || (STR_CMP(requser, usernames[i]) == 0))
    {
      if (!isvalidname(usernames[i]))
      {
        log_log(LOG_WARNING, "%s: %s: denied by validnames option",
                myldap_get_dn(entry), attmap_passwd_uid);
      }
      else
      {
        for (j = 0; j < numuids; j++)
        {
          if (uids[j] >= nslcd_cfg->nss_min_uid)
          {
            WRITE_INT32(fp, NSLCD_RESULT_BEGIN);
            WRITE_STRING(fp, usernames[i]);
            WRITE_STRING(fp, passwd);
            WRITE_INT32(fp, uids[j]);
            WRITE_INT32(fp, gid);
            WRITE_STRING(fp, gecos);
            WRITE_STRING(fp, homedir);
            WRITE_STRING(fp, shell);
            WRITE_STRING(fp, class);
          }
        }
      }
    }
  }
  return 0;
}

NSLCD_HANDLE_UID(
  passwd, byname, NSLCD_ACTION_PASSWD_BYNAME,
  char name[BUFLEN_NAME];
  char filter[BUFLEN_FILTER];
  READ_STRING(fp, name);
  log_setrequest("passwd=\"%s\"", name);
  if (!isvalidname(name))
  {
    log_log(LOG_WARNING, "request denied by validnames option");
    return -1;
  }
  nsswitch_check_reload();,
  mkfilter_passwd_byname(name, filter, sizeof(filter)),
  write_passwd(fp, entry, name, NULL, calleruid)
)

NSLCD_HANDLE_UID(
  passwd, byuid, NSLCD_ACTION_PASSWD_BYUID,
  uid_t uid;
  char filter[BUFLEN_FILTER];
  READ_INT32(fp, uid);
  log_setrequest("passwd=%lu", (unsigned long int)uid);
  if (uid < nslcd_cfg->nss_min_uid)
  {
    log_log(LOG_DEBUG, "request ignored by nss_min_uid option");
    /* return an empty result */
    WRITE_INT32(fp, NSLCD_VERSION);
    WRITE_INT32(fp, NSLCD_ACTION_PASSWD_BYUID);
    WRITE_INT32(fp, NSLCD_RESULT_END);
    return 0;
  }
  nsswitch_check_reload();,
  mkfilter_passwd_byuid(uid, filter, sizeof(filter)),
  write_passwd(fp, entry, NULL, &uid, calleruid)
)

NSLCD_HANDLE_UID(
  passwd, all, NSLCD_ACTION_PASSWD_ALL,
  const char *filter;
  log_setrequest("passwd(all)");
  nsswitch_check_reload();,
  (filter = passwd_filter, 0),
  write_passwd(fp, entry, NULL, NULL, calleruid)
)
