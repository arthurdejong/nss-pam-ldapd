/*
   pam.c - pam processing routines

   Copyright (C) 2009 Howard Chu
   Copyright (C) 2009-2018 Arthur de Jong
   Copyright (C) 2015 Nokia Solutions and Networks

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
#include <unistd.h>
#include <time.h>

#include "common.h"
#include "log.h"
#include "myldap.h"
#include "cfg.h"
#include "attmap.h"
#include "common/dict.h"
#include "common/expr.h"

static void search_var_add(DICT *dict, const char *name, const char *value)
{
  size_t sz;
  char *escaped_value;
  /* allocate memory for escaped string */
  sz = ((strlen(value) + 8) * 120) / 100;
  escaped_value = (char *)malloc(sz);
  if (escaped_value == NULL)
  {
    log_log(LOG_CRIT, "search_var_add(): malloc() failed to allocate memory");
    return;
  }
  /* perform escaping of the value */
  if (myldap_escape(value, escaped_value, sz))
  {
    log_log(LOG_ERR, "search_var_add(): escaped_value buffer too small");
    free(escaped_value);
    return;
  }
  /* add to dict */
  dict_put(dict, name, escaped_value);
}

/* build a dictionary with variables that can be used in searches */
static DICT *search_vars_new(const char *dn, const char *username,
                             const char *service, const char *ruser,
                             const char *rhost, const char *tty)
{
  char hostname[BUFLEN_HOSTNAME];
  /* allocating this on the stack is OK because search_var_add()
     will allocate new memory for the value */
  const char *fqdn, *found;
  DICT *dict;
  dict = dict_new();
  if (dict == NULL)
  {
    log_log(LOG_CRIT, "search_vars_new(): dict_new() failed to allocate memory");
    return NULL;
  }
  /* NOTE: any variables added here also need to be added to
           cfg.c:check_search_variables() */
  search_var_add(dict, "username", username);
  search_var_add(dict, "service", service);
  search_var_add(dict, "ruser", ruser);
  search_var_add(dict, "rhost", rhost);
  search_var_add(dict, "tty", tty);
  if (gethostname(hostname, sizeof(hostname)) == 0)
    search_var_add(dict, "hostname", hostname);
  if ((fqdn = getfqdn()) != NULL)
  {
    search_var_add(dict, "fqdn", fqdn);
    if (((found = strchr(fqdn, '.'))) != NULL && (found[1] != '\0'))
      search_var_add(dict, "domain", found + 1);
  }
  search_var_add(dict, "dn", dn);
  search_var_add(dict, "uid", username);
  return dict;
}

static void search_vars_free(DICT *dict)
{
  int i;
  const char **keys;
  void *value;
  /* go over all keys and free all the values
     (they were allocated in search_var_add) */
  /* loop over dictionary contents */
  keys = dict_keys(dict);
  for (i = 0; keys[i] != NULL; i++)
  {
    value = dict_get(dict, keys[i]);
    if (value)
      free(value);
  }
  free(keys);
  /* after this values from the dict should obviously no longer be used */
  dict_free(dict);
}

static const char *search_var_get(const char *name, void *expander_attr)
{
  DICT *dict = (DICT *)expander_attr;
  return (const char *)dict_get(dict, name);
  /* TODO: if not set use entry to get attribute name (entry can be an
           element in the dict) */
}

/* search all search bases using the provided filter */
static int do_searches(MYLDAP_SESSION *session, const char *option,
                       const char *filter)
{
  int i;
  int rc;
  const char *base;
  static const char *attrs[2];
  MYLDAP_SEARCH *search;
  MYLDAP_ENTRY *entry;
  /* prepare the search */
  attrs[0] = "dn";
  attrs[1] = NULL;
  /* perform a search for each search base */
  log_log(LOG_DEBUG, "trying %s \"%s\"", option, filter);
  for (i = 0; (base = nslcd_cfg->bases[i]) != NULL; i++)
  {
    /* do the LDAP search */
    search = myldap_search(session, base, LDAP_SCOPE_SUBTREE, filter, attrs, &rc);
    if (search == NULL)
    {
      log_log(LOG_ERR, "%s \"%s\" failed: %s",
              option, filter, ldap_err2string(rc));
      return rc;
    }
    /* try to get an entry */
    entry = myldap_get_entry(search, &rc);
    if (entry != NULL)
    {
      log_log(LOG_DEBUG, "%s found \"%s\"", option, myldap_get_dn(entry));
      return LDAP_SUCCESS;
    }
  }
  log_log(LOG_ERR, "%s \"%s\" found no matches", option, filter);
  if (rc == LDAP_SUCCESS)
    rc = LDAP_NO_SUCH_OBJECT;
  return rc;
}

/* set up a connection and try to bind with the specified DN and password,
   returns an LDAP result code */
static int try_bind(const char *userdn, const char *password,
                    const char *username, const char *service,
                    const char *ruser, const char *rhost, const char *tty,
                    int *authzrc, char *authzmsg, size_t authzmsgsz)
{
  MYLDAP_SESSION *session;
  MYLDAP_SEARCH *search;
  MYLDAP_ENTRY *entry;
  static const char *attrs[2];
  int rc;
  const char *msg;
  DICT *dict;
  char filter[BUFLEN_FILTER];
  const char *res;
  /* set up a new connection */
  session = myldap_create_session();
  if (session == NULL)
    return LDAP_UNAVAILABLE;
  /* perform a BIND operation with user credentials */
  rc = myldap_bind(session, userdn, password, authzrc, &msg);
  if (rc == LDAP_SUCCESS)
  {
    /* perform a search to trigger the BIND operation */
    attrs[0] = "dn";
    attrs[1] = NULL;
    if (strcasecmp(nslcd_cfg->pam_authc_search, "BASE") == 0)
    {
      /* do a simple search to check userdn existence */
      search = myldap_search(session, userdn, LDAP_SCOPE_BASE,
                             "(objectClass=*)", attrs, &rc);
      if ((search == NULL) && (rc == LDAP_SUCCESS))
        rc = LDAP_LOCAL_ERROR;
      if (rc == LDAP_SUCCESS)
      {
        entry = myldap_get_entry(search, &rc);
        if ((entry == NULL) && (rc == LDAP_SUCCESS))
          rc = LDAP_NO_RESULTS_RETURNED;
      }
    }
    else if (strcasecmp(nslcd_cfg->pam_authc_search, "NONE") != 0)
    {
      /* build the search filter */
      dict = search_vars_new(userdn, username, service, ruser, rhost, tty);
      if (dict == NULL)
      {
        myldap_session_close(session);
        return LDAP_LOCAL_ERROR;
      }
      res = expr_parse(nslcd_cfg->pam_authc_search, filter, sizeof(filter),
                       search_var_get, (void *)dict);
      if (res == NULL)
      {
        search_vars_free(dict);
        myldap_session_close(session);
        log_log(LOG_ERR, "invalid pam_authc_search \"%s\"",
                nslcd_cfg->pam_authc_search);
        return LDAP_LOCAL_ERROR;
      }
      /* perform a search for each search base */
      rc = do_searches(session, "pam_authc_search", filter);
      /* free search variables */
      search_vars_free(dict);
    }
  }
  /* log any authentication, search or authorisation messages */
  if (rc != LDAP_SUCCESS)
    log_log(LOG_WARNING, "%s: %s", userdn, ldap_err2string(rc));
  if ((msg != NULL) && (msg[0] != '\0'))
  {
    mysnprintf(authzmsg, authzmsgsz - 1, "%s", msg);
    log_log(LOG_WARNING, "%s: %s", userdn, authzmsg);
  }
  /* close the session */
  myldap_session_close(session);
  /* return results */
  return rc;
}

/* ensure that both userdn and username are filled in from the entry,
   returns an LDAP result code */
static MYLDAP_ENTRY *validate_user(MYLDAP_SESSION *session,
                                   char *username, int *rcp)
{
  int rc;
  MYLDAP_ENTRY *entry = NULL;
  /* check username for validity */
  if (!isvalidname(username))
  {
    log_log(LOG_WARNING, "request denied by validnames option");
    *rcp = LDAP_NO_SUCH_OBJECT;
    return NULL;
  }
  /* get the user entry based on the username */
  entry = uid2entry(session, username, &rc);
  if (entry == NULL)
  {
    if (rc == LDAP_SUCCESS)
      rc = LDAP_NO_SUCH_OBJECT;
    log_log(LOG_DEBUG, "\"%s\": user not found: %s", username, ldap_err2string(rc));
    *rcp = rc;
  }
  return entry;
}

/* update the username value from the entry if needed */
static void update_username(MYLDAP_ENTRY *entry, char *username,
                            size_t username_len)
{
  const char **values;
  const char *value;
  /* get the "real" username */
  value = myldap_get_rdn_value(entry, attmap_passwd_uid);
  if (value == NULL)
  {
    /* get the username from the uid attribute */
    values = myldap_get_values(entry, attmap_passwd_uid);
    if ((values == NULL) || (values[0] == NULL))
    {
      log_log(LOG_WARNING, "%s: %s: missing",
              myldap_get_dn(entry), attmap_passwd_uid);
      return;
    }
    value = values[0];
  }
  /* check the username */
  if ((value == NULL) || !isvalidname(value) || strlen(value) >= username_len)
  {
    log_log(LOG_WARNING, "%s: %s: denied by validnames option",
            myldap_get_dn(entry), attmap_passwd_uid);
    return;
  }
  /* check if the username is different and update it if needed */
  if (STR_CMP(username, value) != 0)
  {
    log_log(LOG_INFO, "username changed from \"%s\" to \"%s\"",
            username, value);
    strcpy(username, value);
  }
}

static int check_shadow(MYLDAP_SESSION *session, const char *username,
                        char *authzmsg, size_t authzmsgsz,
                        int check_maxdays, int check_mindays)
{
  MYLDAP_ENTRY *entry = NULL;
  long today, lastchangedate, mindays, maxdays, warndays, inactdays, expiredate;
  unsigned long flag;
  long daysleft, inactleft;
  /* get the shadow entry */
  entry = shadow_uid2entry(session, username, NULL);
  if (entry == NULL)
    return NSLCD_PAM_SUCCESS; /* no shadow entry found, nothing to check */
  /* get today's date */
  today = (long)(time(NULL) / (60 * 60 * 24));
  /* get shadow information */
  get_shadow_properties(entry, &lastchangedate, &mindays, &maxdays, &warndays,
                        &inactdays, &expiredate, &flag);
  /* check account expiry date */
  if ((expiredate != -1) && (today >= expiredate))
  {
    daysleft = today - expiredate;
    mysnprintf(authzmsg, authzmsgsz - 1, "Account expired %ld days ago",
               daysleft);
    log_log(LOG_WARNING, "%s: %s: %s",
            myldap_get_dn(entry), attmap_shadow_shadowExpire, authzmsg);
    return NSLCD_PAM_ACCT_EXPIRED;
  }
  /* password expiration isn't interesting at this point because the user
     may not have authenticated with a password and if he did that would be
     checked in the authc phase */
  if (check_maxdays)
  {
    /* check lastchanged */
    if (lastchangedate == 0)
    {
      mysnprintf(authzmsg, authzmsgsz - 1, "Need a new password");
      log_log(LOG_WARNING, "%s: %s: %s",
              myldap_get_dn(entry), attmap_shadow_shadowLastChange, authzmsg);
      return NSLCD_PAM_NEW_AUTHTOK_REQD;
    }
    else if (today < lastchangedate)
      log_log(LOG_WARNING, "%s: %s: password changed in the future",
              myldap_get_dn(entry), attmap_shadow_shadowLastChange);
    else if (maxdays != -1)
    {
      /* check maxdays */
      daysleft = lastchangedate + maxdays - today;
      if (daysleft == 0)
        mysnprintf(authzmsg, authzmsgsz - 1, "Password will expire today");
      else if (daysleft < 0)
        mysnprintf(authzmsg, authzmsgsz - 1, "Password expired %ld days ago",
                   -daysleft);
      /* check inactdays */
      if ((daysleft <= 0) && (inactdays != -1))
      {
        inactleft = lastchangedate + maxdays + inactdays - today;
        if (inactleft == 0)
          mysnprintf(authzmsg + strlen(authzmsg), authzmsgsz - strlen(authzmsg) - 1,
                     ", account will be locked today");
        else if (inactleft > 0)
          mysnprintf(authzmsg + strlen(authzmsg), authzmsgsz - strlen(authzmsg) - 1,
                     ", account will be locked in %ld days", inactleft);
        else
        {
          mysnprintf(authzmsg + strlen(authzmsg), authzmsgsz - strlen(authzmsg) - 1,
                     ", account locked %ld days ago", -inactleft);
          log_log(LOG_WARNING, "%s: %s: %s", myldap_get_dn(entry),
                  attmap_shadow_shadowInactive, authzmsg);
          return NSLCD_PAM_AUTHTOK_EXPIRED;
        }
      }
      if (daysleft <= 0)
      {
        /* log previously built message */
        log_log(LOG_WARNING, "%s: %s: %s",
                myldap_get_dn(entry), attmap_shadow_shadowMax, authzmsg);
        return NSLCD_PAM_NEW_AUTHTOK_REQD;
      }
      /* check warndays */
      if ((warndays > 0) && (daysleft <= warndays))
      {
        mysnprintf(authzmsg, authzmsgsz - 1,
                   "Password will expire in %ld days", daysleft);
        log_log(LOG_WARNING, "%s: %s: %s",
                myldap_get_dn(entry), attmap_shadow_shadowWarning, authzmsg);
      }
    }
  }
  if (check_mindays)
  {
    daysleft = lastchangedate + mindays - today;
    if ((mindays != -1) && (daysleft > 0))
    {
      mysnprintf(authzmsg, authzmsgsz - 1,
                 "Password cannot be changed for another %ld days", daysleft);
      log_log(LOG_WARNING, "%s: %s: %s",
              myldap_get_dn(entry), attmap_shadow_shadowMin, authzmsg);
      return NSLCD_PAM_AUTHTOK_ERR;
    }
  }
  return NSLCD_PAM_SUCCESS;
}

/* check authentication credentials of the user */
int nslcd_pam_authc(TFILE *fp, MYLDAP_SESSION *session, uid_t calleruid)
{
  int32_t tmpint32;
  int rc;
  char username[BUFLEN_NAME], service[BUFLEN_NAME], ruser[BUFLEN_NAME], rhost[BUFLEN_HOSTNAME], tty[64];
  char password[BUFLEN_PASSWORD];
  const char *userdn;
  MYLDAP_ENTRY *entry;
  int authzrc = NSLCD_PAM_SUCCESS;
  char authzmsg[BUFLEN_MESSAGE];
  authzmsg[0] = '\0';
  /* read request parameters */
  READ_STRING(fp, username);
  READ_STRING(fp, service);
  READ_STRING(fp, ruser);
  READ_STRING(fp, rhost);
  READ_STRING(fp, tty);
  // READ_STRING(fp, password);
  /* log call */
  log_setrequest("authc=\"%s\"", username);
  log_log(LOG_DEBUG, "nslcd_pam_authc(\"%s\",\"%s\",\"%s\")",
          username, service, *password ? "***" : "");
  /* write the response header */
  WRITE_INT32(fp, NSLCD_VERSION);
  WRITE_INT32(fp, NSLCD_ACTION_PAM_AUTHC);
  /* if the username is blank and rootpwmoddn is configured, try to
     authenticate as administrator, otherwise validate request as usual */
  if (*username == '\0')
  {
    if (nslcd_cfg->rootpwmoddn == NULL)
    {
      log_log(LOG_NOTICE, "rootpwmoddn not configured");
      /* we break the protocol */
      memset(password, 0, sizeof(password));
      return -1;
    }
    userdn = nslcd_cfg->rootpwmoddn;
    /* if the caller is root we will allow the use of the rootpwmodpw option */
    if ((*password == '\0') && (calleruid == 0) && (nslcd_cfg->rootpwmodpw != NULL))
    {
      if (strlen(nslcd_cfg->rootpwmodpw) >= sizeof(password))
      {
        log_log(LOG_ERR, "nslcd_pam_authc(): rootpwmodpw will not fit in password");
        memset(password, 0, sizeof(password));
        return -1;
      }
      strcpy(password, nslcd_cfg->rootpwmodpw);
    }
  }
  else
  {
    /* try normal authentication, lookup the user entry */
    entry = validate_user(session, username, &rc);
    if (entry == NULL)
    {
      /* for user not found we just say no result */
      if (rc == LDAP_NO_SUCH_OBJECT)
      {
        WRITE_INT32(fp, NSLCD_RESULT_END);
      }
      memset(password, 0, sizeof(password));
      return -1;
    }
    userdn = myldap_get_dn(entry);
    update_username(entry, username, sizeof(username));
  }
  /* try authentication */
  rc = try_bind(userdn, password, username, service, ruser, rhost, tty,
                &authzrc, authzmsg, sizeof(authzmsg));
  if (rc == LDAP_SUCCESS)
    log_log(LOG_DEBUG, "bind successful");
  /* map result code */
  switch (rc)
  {
    case LDAP_SUCCESS:             rc = NSLCD_PAM_SUCCESS;  break;
    case LDAP_INVALID_CREDENTIALS: rc = NSLCD_PAM_AUTH_ERR; break;
    default:                       rc = NSLCD_PAM_AUTH_ERR;
  }
  /* perform shadow attribute checks */
  if ((*username != '\0') && (authzrc == NSLCD_PAM_SUCCESS))
    authzrc = check_shadow(session, username, authzmsg, sizeof(authzmsg), 1, 0);
  /* write response */
  WRITE_INT32(fp, NSLCD_RESULT_BEGIN);
  WRITE_INT32(fp, rc);
  WRITE_STRING(fp, username);
  WRITE_INT32(fp, authzrc);
  WRITE_STRING(fp, authzmsg);
  WRITE_INT32(fp, NSLCD_RESULT_END);
  memset(password, 0, sizeof(password));
  return 0;
}

/* perform an authorisation search, returns an LDAP status code */
static int try_authz_search(MYLDAP_SESSION *session, const char *dn,
                          const char *username, const char *service,
                          const char *ruser, const char *rhost,
                          const char *tty)
{
  DICT *dict = NULL;
  char filter[BUFLEN_FILTER];
  int rc = LDAP_SUCCESS;
  const char *res;
  int i;
  /* go over all pam_authz_search options */
  for (i = 0; (i < NSS_LDAP_CONFIG_MAX_AUTHZ_SEARCHES) && (nslcd_cfg->pam_authz_searches[i] != NULL); i++)
  {
    if (dict == NULL)
    {
      dict = search_vars_new(dn, username, service, ruser, rhost, tty);
      if (dict == NULL)
        return LDAP_LOCAL_ERROR;
    }
    /* build the search filter */
    res = expr_parse(nslcd_cfg->pam_authz_searches[i],
                     filter, sizeof(filter),
                     search_var_get, (void *)dict);
    if (res == NULL)
    {
      search_vars_free(dict);
      log_log(LOG_ERR, "invalid pam_authz_search \"%s\"",
              nslcd_cfg->pam_authz_searches[i]);
      return LDAP_LOCAL_ERROR;
    }
    /* perform the actual searches on all bases */
    rc = do_searches(session, "pam_authz_search", filter);
    if (rc != LDAP_SUCCESS)
      break;
  }
  /* we went over all pam_authz_search entries */
  if (dict != NULL)
    search_vars_free(dict);
  return rc;
}

/* check authorisation of the user */
int nslcd_pam_authz(TFILE *fp, MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  int rc;
  char username[BUFLEN_NAME], service[BUFLEN_NAME], ruser[BUFLEN_NAME], rhost[BUFLEN_HOSTNAME], tty[64];
  MYLDAP_ENTRY *entry;
  char authzmsg[BUFLEN_MESSAGE];
  authzmsg[0] = '\0';
  /* read request parameters */
  READ_STRING(fp, username);
  READ_STRING(fp, service);
  READ_STRING(fp, ruser);
  READ_STRING(fp, rhost);
  READ_STRING(fp, tty);
  /* log call */
  log_setrequest("authz=\"%s\"", username);
  log_log(LOG_DEBUG, "nslcd_pam_authz(\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")",
          username, service, ruser, rhost, tty);
  /* write the response header */
  WRITE_INT32(fp, NSLCD_VERSION);
  WRITE_INT32(fp, NSLCD_ACTION_PAM_AUTHZ);
  /* validate request */
  entry = validate_user(session, username, &rc);
  if (entry == NULL)
  {
    /* for user not found we just say no result */
    if (rc == LDAP_NO_SUCH_OBJECT)
    {
      WRITE_INT32(fp, NSLCD_RESULT_END);
    }
    return -1;
  }
  /* check authorisation search */
  rc = try_authz_search(session, myldap_get_dn(entry), username, service, ruser,
                      rhost, tty);
  if (rc != LDAP_SUCCESS)
  {
    WRITE_INT32(fp, NSLCD_RESULT_BEGIN);
    WRITE_INT32(fp, NSLCD_PAM_PERM_DENIED);
    WRITE_STRING(fp, "LDAP authorisation check failed");
    WRITE_INT32(fp, NSLCD_RESULT_END);
    return 0;
  }
  /* perform shadow attribute checks */
  rc = check_shadow(session, username, authzmsg, sizeof(authzmsg), 0, 0);
  /* write response */
  WRITE_INT32(fp, NSLCD_RESULT_BEGIN);
  WRITE_INT32(fp, rc);
  WRITE_STRING(fp, authzmsg);
  WRITE_INT32(fp, NSLCD_RESULT_END);
  return 0;
}

int nslcd_pam_sess_o(TFILE *fp, MYLDAP_SESSION UNUSED(*session))
{
  int32_t tmpint32;
  char username[BUFLEN_NAME], service[BUFLEN_NAME], ruser[BUFLEN_NAME], rhost[BUFLEN_HOSTNAME], tty[64];
  char sessionid[25];
  static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "abcdefghijklmnopqrstuvwxyz"
                                 "01234567890";
  unsigned int i;
  /* read request parameters */
  READ_STRING(fp, username);
  READ_STRING(fp, service);
  READ_STRING(fp, ruser);
  READ_STRING(fp, rhost);
  READ_STRING(fp, tty);
  /* generate pseudo-random session id */
  for (i = 0; i < (sizeof(sessionid) - 1); i++)
    sessionid[i] = alphabet[rand() % (sizeof(alphabet) - 1)];
  sessionid[i] = '\0';
  /* log call */
  log_setrequest("sess_o=\"%s\"", username);
  log_log(LOG_DEBUG, "nslcd_pam_sess_o(\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"): %s",
          username, service, tty, rhost, ruser, sessionid);
  /* write the response header */
  WRITE_INT32(fp, NSLCD_VERSION);
  WRITE_INT32(fp, NSLCD_ACTION_PAM_SESS_O);
  /* write response */
  WRITE_INT32(fp, NSLCD_RESULT_BEGIN);
  WRITE_STRING(fp, sessionid);
  WRITE_INT32(fp, NSLCD_RESULT_END);
  return 0;
}

int nslcd_pam_sess_c(TFILE *fp, MYLDAP_SESSION UNUSED(*session))
{
  int32_t tmpint32;
  char username[BUFLEN_NAME], service[BUFLEN_NAME], ruser[BUFLEN_NAME], rhost[BUFLEN_HOSTNAME], tty[64];
  char sessionid[64];
  /* read request parameters */
  READ_STRING(fp, username);
  READ_STRING(fp, service);
  READ_STRING(fp, ruser);
  READ_STRING(fp, rhost);
  READ_STRING(fp, tty);
  READ_STRING(fp, sessionid);
  /* log call */
  log_setrequest("sess_c=\"%s\"", username);
  log_log(LOG_DEBUG, "nslcd_pam_sess_c(\"%s\",\"%s\",%s)",
          username, service, sessionid);
  /* write the response header */
  WRITE_INT32(fp, NSLCD_VERSION);
  WRITE_INT32(fp, NSLCD_ACTION_PAM_SESS_C);
  /* write response */
  WRITE_INT32(fp, NSLCD_RESULT_BEGIN);
  WRITE_INT32(fp, NSLCD_RESULT_END);
  return 0;
}

extern const char *shadow_filter;

/* try to update the shadowLastChange attribute of the entry if possible */
static int update_lastchange(MYLDAP_SESSION *session, const char *userdn)
{
  MYLDAP_SEARCH *search;
  MYLDAP_ENTRY *entry;
  static const char *attrs[3];
  const char *attr;
  int rc;
  const char **values;
  LDAPMod mod, *mods[2];
  char buffer[64], *strvals[2];
  /* find the name of the attribute to use */
  if ((attmap_shadow_shadowLastChange == NULL) || (attmap_shadow_shadowLastChange[0] == '\0'))
    return LDAP_LOCAL_ERROR; /* attribute not mapped at all */
  else if (strcmp(attmap_shadow_shadowLastChange, "\"${shadowLastChange:--1}\"") == 0)
    attr = "shadowLastChange";
  else if (attmap_shadow_shadowLastChange[0] == '\"')
    return LDAP_LOCAL_ERROR; /* other expressions not supported for now */
  else
    attr = attmap_shadow_shadowLastChange;
  /* set up the attributes we need */
  attrs[0] = attmap_shadow_uid;
  attrs[1] = attr;
  attrs[2] = NULL;
  /* find the entry to see if the attribute is present */
  search = myldap_search(session, userdn, LDAP_SCOPE_BASE, shadow_filter, attrs, &rc);
  if (search == NULL)
    return rc;
  entry = myldap_get_entry(search, &rc);
  if (entry == NULL)
    return rc;
  values = myldap_get_values(entry, attr);
  if ((values == NULL) || (values[0] == NULL) || (values[0][0] == '\0'))
    return LDAP_NO_SUCH_ATTRIBUTE;
  /* build the value for the new attribute */
  if (strcasecmp(attr, "pwdLastSet") == 0)
  {
    /* for AD we use another timestamp */
    if (mysnprintf(buffer, sizeof(buffer), "%ld000000000",
                   ((long int)time(NULL) / 100L + (134774L * 864L))))
      return LDAP_LOCAL_ERROR;
  }
  else
  {
    /* time in days since Jan 1, 1970 */
    if (mysnprintf(buffer, sizeof(buffer), "%ld",
                   ((long int)(time(NULL) / (long int)(60 * 60 * 24)))))
      return LDAP_LOCAL_ERROR;
  }
  /* update the shadowLastChange attribute */
  strvals[0] = buffer;
  strvals[1] = NULL;
  mod.mod_op = LDAP_MOD_REPLACE;
  mod.mod_type = (char *)attr;
  mod.mod_values = strvals;
  mods[0] = &mod;
  mods[1] = NULL;
  rc = myldap_modify(session, userdn, mods);
  if (rc != LDAP_SUCCESS)
    log_log(LOG_WARNING, "%s: %s: modification failed: %s",
            userdn, attr, ldap_err2string(rc));
  else
    log_log(LOG_DEBUG, "%s: %s: modification succeeded", userdn, attr);
  return rc;
}

/* perform an LDAP password modification, returns an LDAP status code */
static int try_pwmod(MYLDAP_SESSION *oldsession,
                     const char *binddn, const char *userdn,
                     const char *oldpassword, const char *newpassword,
                     char *authzmsg, size_t authzmsg_len)
{
  MYLDAP_SESSION *session;
  char buffer[BUFLEN_MESSAGE];
  int rc;
  /* set up a new connection */
  session = myldap_create_session();
  if (session == NULL)
    return LDAP_UNAVAILABLE;
  /* perform a BIND operation */
  rc = myldap_bind(session, binddn, oldpassword, NULL, NULL);
  if (rc == LDAP_SUCCESS)
  {
    /* if doing password modification as admin, don't pass old password along */
    if ((nslcd_cfg->rootpwmoddn != NULL) &&
        (strcmp(binddn, nslcd_cfg->rootpwmoddn) == 0))
      oldpassword = NULL;
    /* perform password modification */
    rc = myldap_passwd(session, userdn, oldpassword, newpassword);
    if (rc == LDAP_SUCCESS)
    {
      /* try to update the shadowLastChange attribute */
      if (update_lastchange(session, userdn) != LDAP_SUCCESS)
        /* retry with the normal session */
        (void)update_lastchange(oldsession, userdn);
    }
    else
    {
      /* get a diagnostic or error message */
      if ((myldap_error_message(session, rc, buffer, sizeof(buffer)) == LDAP_SUCCESS) &&
          (buffer[0] != '\0'))
        mysnprintf(authzmsg, authzmsg_len - 1, "password change failed: %s",
                   buffer);
    }
  }
  /* close the session */
  myldap_session_close(session);
  /* return */
  return rc;
}

int nslcd_pam_pwmod(TFILE *fp, MYLDAP_SESSION *session, uid_t calleruid)
{
  int32_t tmpint32;
  int rc;
  char username[BUFLEN_NAME], service[BUFLEN_NAME], ruser[BUFLEN_NAME], rhost[BUFLEN_HOSTNAME], tty[64];
  int asroot;
  char oldpassword[BUFLEN_PASSWORD];
  char newpassword[BUFLEN_PASSWORD];
  const char *binddn = NULL; /* the user performing the modification */
  MYLDAP_ENTRY *entry;
  char authzmsg[BUFLEN_MESSAGE];
  authzmsg[0] = '\0';
  /* read request parameters */
  READ_STRING(fp, username);
  READ_STRING(fp, service);
  READ_STRING(fp, ruser);
  READ_STRING(fp, rhost);
  READ_STRING(fp, tty);
  READ_INT32(fp, asroot);
  READ_STRING(fp, oldpassword);
  READ_STRING(fp, newpassword);
  /* log call */
  log_setrequest("pwmod=\"%s\"", username);
  log_log(LOG_DEBUG, "nslcd_pam_pwmod(\"%s\",%s,\"%s\",\"%s\",\"%s\")",
          username, asroot ? "asroot" : "asuser", service,
          *oldpassword ? "***" : "", *newpassword ? "***" : "");
  /* write the response header */
  WRITE_INT32(fp, NSLCD_VERSION);
  WRITE_INT32(fp, NSLCD_ACTION_PAM_PWMOD);
  /* validate request */
  entry = validate_user(session, username, &rc);
  if (entry == NULL)
  {
    /* for user not found we just say no result */
    if (rc == LDAP_NO_SUCH_OBJECT)
    {
      WRITE_INT32(fp, NSLCD_RESULT_END);
    }
    memset(oldpassword, 0, sizeof(oldpassword));
    memset(newpassword, 0, sizeof(newpassword));
    return -1;
  }
  /* check if pam_password_prohibit_message is set */
  if (nslcd_cfg->pam_password_prohibit_message != NULL)
  {
    log_log(LOG_NOTICE, "password change prohibited");
    WRITE_INT32(fp, NSLCD_RESULT_BEGIN);
    WRITE_INT32(fp, NSLCD_PAM_PERM_DENIED);
    WRITE_STRING(fp, nslcd_cfg->pam_password_prohibit_message);
    WRITE_INT32(fp, NSLCD_RESULT_END);
    memset(oldpassword, 0, sizeof(oldpassword));
    memset(newpassword, 0, sizeof(newpassword));
    return 0;
  }
  /* check if the the user passed the rootpwmoddn */
  if (asroot)
  {
    binddn = nslcd_cfg->rootpwmoddn;
    /* check if rootpwmodpw should be used */
    if ((*oldpassword == '\0') && (calleruid == 0) &&
        (nslcd_cfg->rootpwmodpw != NULL))
    {
      if (strlen(nslcd_cfg->rootpwmodpw) >= sizeof(oldpassword))
      {
        log_log(LOG_ERR, "nslcd_pam_pwmod(): rootpwmodpw will not fit in oldpassword");
        memset(oldpassword, 0, sizeof(oldpassword));
        memset(newpassword, 0, sizeof(newpassword));
        return -1;
      }
      strcpy(oldpassword, nslcd_cfg->rootpwmodpw);
    }
  }
  else
  {
    binddn = myldap_get_dn(entry);
    /* check whether shadow properties allow password change */
    rc = check_shadow(session, username, authzmsg, sizeof(authzmsg), 0, 1);
    if (rc != NSLCD_PAM_SUCCESS)
    {
      WRITE_INT32(fp, NSLCD_RESULT_BEGIN);
      WRITE_INT32(fp, rc);
      WRITE_STRING(fp, authzmsg);
      WRITE_INT32(fp, NSLCD_RESULT_END);
      memset(oldpassword, 0, sizeof(oldpassword));
      memset(newpassword, 0, sizeof(newpassword));
      return 0;
    }
  }
  /* perform password modification */
  rc = try_pwmod(session, binddn, myldap_get_dn(entry), oldpassword, newpassword,
                 authzmsg, sizeof(authzmsg));
  if (rc != LDAP_SUCCESS)
  {
    if (authzmsg[0] == '\0')
      mysnprintf(authzmsg, sizeof(authzmsg) - 1, "password change failed: %s",
                 ldap_err2string(rc));
    WRITE_INT32(fp, NSLCD_RESULT_BEGIN);
    WRITE_INT32(fp, NSLCD_PAM_PERM_DENIED);
    WRITE_STRING(fp, authzmsg);
    WRITE_INT32(fp, NSLCD_RESULT_END);
    memset(oldpassword, 0, sizeof(oldpassword));
    memset(newpassword, 0, sizeof(newpassword));
    return 0;
  }
  /* write response */
  log_log(LOG_NOTICE, "password changed for %s", myldap_get_dn(entry));
  WRITE_INT32(fp, NSLCD_RESULT_BEGIN);
  WRITE_INT32(fp, NSLCD_PAM_SUCCESS);
  WRITE_STRING(fp, "");
  WRITE_INT32(fp, NSLCD_RESULT_END);
  memset(oldpassword, 0, sizeof(oldpassword));
  memset(newpassword, 0, sizeof(newpassword));
  return 0;
}
