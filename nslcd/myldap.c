/*
   myldap.c - simple interface to do LDAP requests
   Parts of this file were part of the nss_ldap library (as ldap-nss.c)
   which has been forked into the nss-pam-ldapd library.

   Copyright (C) 1997-2006 Luke Howard
   Copyright (C) 2006-2007 West Consulting
   Copyright (C) 2006-2020 Arthur de Jong

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

/*
   This library expects to use an LDAP library to provide the real
   functionality and only provides a convenient wrapper.
   Some pointers for more information on the LDAP API:
     http://tools.ietf.org/id/draft-ietf-ldapext-ldap-c-api-05.txt
     http://www.mozilla.org/directory/csdk-docs/function.htm
     http://publib.boulder.ibm.com/infocenter/iseries/v5r3/topic/apis/dirserv1.htm
     http://www.openldap.org/software/man.cgi?query=ldap
*/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <lber.h>
#include <ldap.h>
#ifdef HAVE_LDAP_SSL_H
#include <ldap_ssl.h>
#endif
#ifdef HAVE_GSSLDAP_H
#include <gssldap.h>
#endif
#ifdef HAVE_GSSSASL_H
#include <gsssasl.h>
#endif
#ifdef HAVE_SASL_SASL_H
#include <sasl/sasl.h>
#endif
#ifdef HAVE_SASL_H
#include <sasl.h>
#endif
#include <ctype.h>
#include <pthread.h>
#include <stdarg.h>

#include "myldap.h"
#include "common.h"
#include "log.h"
#include "cfg.h"
#include "common/set.h"
#include "compat/ldap_compat.h"
#include "attmap.h"

/* the maximum number of searches per session */
#define MAX_SEARCHES_IN_SESSION 4

/* the maximum number of dn's to log to the debug log for each search */
#define MAX_DEBUG_LOG_DNS 10

/* a fake scope that is used to not perform an actual search but only
   simulate the handling of the search (used for authentication) */
#define MYLDAP_SCOPE_BINDONLY 0x1972  /* magic number: should never be a real scope */

/* This refers to a current LDAP session that contains the connection
   information. */
struct ldap_session {
  /* the connection */
  LDAP *ld;
  /* timestamp of last activity */
  time_t lastactivity;
  /* index into uris: currently connected LDAP uri */
  int current_uri;
  /* a list of searches registered with this session */
  struct myldap_search *searches[MAX_SEARCHES_IN_SESSION];
  /* the username to bind with */
  char binddn[BUFLEN_DN];
  /* the password to bind with if any */
  char bindpw[BUFLEN_PASSWORD];
  /* the authentication result (NSLCD_PAM_* code) */
  int policy_response;
  /* the authentication message */
  char policy_message[BUFLEN_MESSAGE];
};

/* A search description set as returned by myldap_search(). */
struct myldap_search {
  /* reference to the session */
  MYLDAP_SESSION *session;
  /* indicator that the search is still valid */
  int valid;
  /* the parameters describing the search */
  const char *base;
  int scope;
  const char *filter;
  char **attrs;
  /* a pointer to the current result entry, used for
     freeing resource allocated with that entry */
  MYLDAP_ENTRY *entry;
  /* LDAP message id for the search, -1 indicates absence of an active search */
  int msgid;
  /* the last result that was returned by ldap_result() */
  LDAPMessage *msg;
  /* cookie for paged searches */
  struct berval *cookie;
  /* to indicate that we can retry the search from myldap_get_entry() */
  int may_retry_search;
  /* the number of results returned so far */
  int count;
};

/* The maximum number of calls to myldap_get_values() that may be
   done per returned entry. */
#define MAX_ATTRIBUTES_PER_ENTRY 16

/* The maximum number of buffers (used for ranged attribute values and
   values returned by bervalues_to_values()) that may be stored per entry. */
#define MAX_BUFFERS_PER_ENTRY 8

/* A single entry from the LDAP database as returned by
   myldap_get_entry(). */
struct myldap_entry {
  /* reference to the search to be used to get parameters
     (e.g. LDAP connection) for other calls */
  MYLDAP_SEARCH *search;
  /* the DN */
  const char *dn;
  /* a cached version of the exploded rdn */
  char **exploded_rdn;
  /* a cache of attribute to value list */
  char **attributevalues[MAX_ATTRIBUTES_PER_ENTRY];
  /* a reference to buffers so we can free() them later on */
  char **buffers[MAX_BUFFERS_PER_ENTRY];
};

/* Flag to record first search operation */
int first_search = 1;

static void myldap_err(int pri, LDAP *ld, int rc, const char *format, ...)
{
  char message[BUFLEN_MESSAGE];
  char *msg_ldap = NULL;
  char *msg_diag = NULL;
  char *msg_errno = NULL;
  va_list ap;
  /* make the message */
  va_start(ap, format);
  vsnprintf(message, sizeof(message), format, ap);
  message[sizeof(message) - 1] = '\0';
  va_end(ap);
  /* get the various error message */
  if (rc != LDAP_SUCCESS)
  {
    msg_ldap = ldap_err2string(rc);
    /* get the diagnostic information */
#ifdef LDAP_OPT_DIAGNOSTIC_MESSAGE
    if (ld != NULL)
      ldap_get_option(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, &msg_diag);
#endif /* LDAP_OPT_DIAGNOSTIC_MESSAGE */
  }
  if (errno != 0)
    msg_errno = strerror(errno);
  /* log the message */
  log_log(pri, "%s%s%s%s%s%s%s", message,
          (msg_ldap == NULL) ? "" : ": ", (msg_ldap == NULL) ? "" : msg_ldap,
          (msg_diag == NULL) ? "" : ": ", (msg_diag == NULL) ? "" : msg_diag,
          (msg_errno == NULL) ? "" : ": ", (msg_errno == NULL) ? "" : msg_errno);
  /* free diagnostic message */
  if (msg_diag != NULL)
    ldap_memfree(msg_diag);
}

static MYLDAP_ENTRY *myldap_entry_new(MYLDAP_SEARCH *search)
{
  MYLDAP_ENTRY *entry;
  int i;
  /* Note: as an alternative we could embed the myldap_entry into the
     myldap_search struct to save on malloc() and free() calls. */
  /* allocate new entry */
  entry = (MYLDAP_ENTRY *)malloc(sizeof(struct myldap_entry));
  if (entry == NULL)
  {
    log_log(LOG_CRIT, "myldap_entry_new(): malloc() failed to allocate memory");
    exit(EXIT_FAILURE);
  }
  /* fill in fields */
  entry->search = search;
  entry->dn = NULL;
  entry->exploded_rdn = NULL;
  for (i = 0; i < MAX_ATTRIBUTES_PER_ENTRY; i++)
    entry->attributevalues[i] = NULL;
  for (i = 0; i < MAX_BUFFERS_PER_ENTRY; i++)
    entry->buffers[i] = NULL;
  /* return the fresh entry */
  return entry;
}

static void myldap_entry_free(MYLDAP_ENTRY *entry)
{
  int i;
  /* free the DN */
  if (entry->dn != NULL)
    ldap_memfree((char *)entry->dn);
  /* free the exploded RDN */
  if (entry->exploded_rdn != NULL)
    ldap_value_free(entry->exploded_rdn);
  /* free all attribute values */
  for (i = 0; i < MAX_ATTRIBUTES_PER_ENTRY; i++)
    if (entry->attributevalues[i] != NULL)
      ldap_value_free(entry->attributevalues[i]);
  /* free all buffers */
  for (i = 0; i < MAX_BUFFERS_PER_ENTRY; i++)
    if (entry->buffers[i] != NULL)
      free(entry->buffers[i]);
  /* we don't need the result anymore, ditch it. */
  ldap_msgfree(entry->search->msg);
  entry->search->msg = NULL;
  /* free the actual memory for the struct */
  free(entry);
}

static MYLDAP_SEARCH *myldap_search_new(MYLDAP_SESSION *session,
                                        const char *base, int scope,
                                        const char *filter,
                                        const char **attrs)
{
  char *buffer;
  MYLDAP_SEARCH *search;
  int i;
  size_t sz;
  /* figure out size for new memory block to allocate
     this has the advantage that we can free the whole lot with one call */
  sz = sizeof(struct myldap_search);
  sz += strlen(base) + 1 + strlen(filter) + 1;
  for (i = 0; attrs[i] != NULL; i++)
    sz += strlen(attrs[i]) + 1;
  sz += (i + 1) * sizeof(char *);
  /* allocate new results memory region */
  buffer = (char *)malloc(sz);
  if (buffer == NULL)
  {
    log_log(LOG_CRIT, "myldap_search_new(): malloc() failed to allocate memory");
    exit(EXIT_FAILURE);
  }
  /* initialize struct */
  search = (MYLDAP_SEARCH *)(void *)(buffer);
  buffer += sizeof(struct myldap_search);
  /* save pointer to session */
  search->session = session;
  /* flag as valid search */
  search->valid = 1;
  /* initialize array of attributes */
  search->attrs = (char **)(void *)buffer;
  buffer += (i + 1) * sizeof(char *);
  /* copy base */
  strcpy(buffer, base);
  search->base = buffer;
  buffer += strlen(base) + 1;
  /* just plainly store scope */
  search->scope = scope;
  /* copy filter */
  strcpy(buffer, filter);
  search->filter = buffer;
  buffer += strlen(filter) + 1;
  /* copy attributes themselves */
  for (i = 0; attrs[i] != NULL; i++)
  {
    strcpy(buffer, attrs[i]);
    search->attrs[i] = buffer;
    buffer += strlen(attrs[i]) + 1;
  }
  search->attrs[i] = NULL;
  /* initialize context */
  search->cookie = NULL;
  search->msg = NULL;
  search->msgid = -1;
  search->may_retry_search = 1;
  /* clear result entry */
  search->entry = NULL;
  search->count = 0;
  /* return the new search struct */
  return search;
}

static MYLDAP_SESSION *myldap_session_new(void)
{
  MYLDAP_SESSION *session;
  int i;
  /* allocate memory for the session storage */
  session = (struct ldap_session *)malloc(sizeof(struct ldap_session));
  if (session == NULL)
  {
    log_log(LOG_CRIT, "myldap_session_new(): malloc() failed to allocate memory");
    exit(EXIT_FAILURE);
  }
  /* initialize the session */
  session->ld = NULL;
  session->lastactivity = 0;
  session->current_uri = 0;
  for (i = 0; i < MAX_SEARCHES_IN_SESSION; i++)
    session->searches[i] = NULL;
  session->binddn[0] = '\0';
  memset(session->bindpw, 0, sizeof(session->bindpw));
  session->bindpw[0] = '\0';
  session->policy_response = NSLCD_PAM_SUCCESS;
  session->policy_message[0] = '\0';
  /* return the new session */
  return session;
}

PURE static inline int is_valid_entry(MYLDAP_ENTRY *entry)
{
 return (entry != NULL) && (entry->search != NULL) &&
        (entry->search->session != NULL) && (entry->search->session->ld != NULL) &&
        (entry->search->msg != NULL);
}

#ifdef HAVE_SASL_INTERACT_T
/* this is registered with ldap_sasl_interactive_bind_s() in do_bind() */
static int do_sasl_interact(LDAP UNUSED(*ld), unsigned UNUSED(flags),
                            void *defaults, void *_interact)
{
  struct ldap_config *cfg = defaults;
  sasl_interact_t *interact = _interact;
  while (interact->id != SASL_CB_LIST_END)
  {
    switch (interact->id)
    {
      case SASL_CB_GETREALM:
        if (cfg->sasl_realm)
        {
          log_log(LOG_DEBUG, "do_sasl_interact(): returning sasl_realm \"%s\"",
                  cfg->sasl_realm);
          interact->result = cfg->sasl_realm;
          interact->len = strlen(cfg->sasl_realm);
        }
        else
          log_log(LOG_DEBUG, "do_sasl_interact(): were asked for sasl_realm but we don't have any");
        break;
      case SASL_CB_AUTHNAME:
        if (cfg->sasl_authcid)
        {
          log_log(LOG_DEBUG, "do_sasl_interact(): returning sasl_authcid \"%s\"",
                  cfg->sasl_authcid);
          interact->result = cfg->sasl_authcid;
          interact->len = strlen(cfg->sasl_authcid);
        }
        else
          log_log(LOG_DEBUG, "do_sasl_interact(): were asked for sasl_authcid but we don't have any");
        break;
      case SASL_CB_USER:
        if (cfg->sasl_authzid)
        {
          log_log(LOG_DEBUG, "do_sasl_interact(): returning sasl_authzid \"%s\"",
                  cfg->sasl_authzid);
          interact->result = cfg->sasl_authzid;
          interact->len = strlen(cfg->sasl_authzid);
        }
        else
          log_log(LOG_DEBUG, "do_sasl_interact(): were asked for sasl_authzid but we don't have any");
        break;
      case SASL_CB_PASS:
        if (cfg->bindpw)
        {
          log_log(LOG_DEBUG, "do_sasl_interact(): returning bindpw \"***\"");
          interact->result = cfg->bindpw;
          interact->len = strlen(cfg->bindpw);
        }
        else
          log_log(LOG_DEBUG, "do_sasl_interact(): were asked for bindpw but we don't have any");
        break;
      default:
        /* just ignore */
        break;
    }
    interact++;
  }
  return LDAP_SUCCESS;
}
#endif /* HAVE_SASL_INTERACT_T */

#define LDAP_SET_OPTION(ld, option, invalue)                                \
  rc = ldap_set_option(ld, option, invalue);                                \
  if (rc != LDAP_SUCCESS)                                                   \
  {                                                                         \
    myldap_err(LOG_ERR, ld, rc, "ldap_set_option(" #option ") failed");     \
    return rc;                                                              \
  }

#if defined(HAVE_LDAP_SASL_BIND) && defined(LDAP_SASL_SIMPLE)
static void print_ppolicy_expiry(MYLDAP_SESSION *session, unsigned int sec)
{
  unsigned int days = 0;
  unsigned int hours = 0;
  unsigned int minutes = 0;
  /* return this warning so PAM can present it to the user */
  if (strlen(session->policy_message) != 0)
    return;
  if (sec > 24 * 3600)
  {
    days = sec / (24 * 3600);
    sec -= days * 24 * 3600;
  }
  if (sec > 3600)
  {
    hours = sec / 3600;
    sec -= (hours * 3600);
  }
  if (sec > 60)
  {
    minutes = sec / 60;
    sec -= minutes * 60;
  }
  if (days > 1)
    mysnprintf(session->policy_message, sizeof(session->policy_message),
               "Password will expire in %u days", days);
  else if (days > 0)
    mysnprintf(session->policy_message, sizeof(session->policy_message),
               "Password will expire in %u hours", hours + 24);
  else if (hours > 1)
  {
    if (minutes > 1)
      mysnprintf(session->policy_message, sizeof(session->policy_message),
                 "Password will expire in %u hours and %u minutes",
                 hours, minutes);
    else
      mysnprintf(session->policy_message, sizeof(session->policy_message),
                 "Password will expire in %u hours", hours);
  }
  else if (hours > 0)
    mysnprintf(session->policy_message, sizeof(session->policy_message),
               "Password will expire in %u minutes", minutes + 60);
  else if (minutes > 1)
  {
    if (sec > 1)
      mysnprintf(session->policy_message, sizeof(session->policy_message),
                 "Password will expire in %u minutes and %u seconds",
                 minutes, sec);
    else
      mysnprintf(session->policy_message, sizeof(session->policy_message),
                 "Password will expire in %u minutes", minutes);
  }
  else
    mysnprintf(session->policy_message, sizeof(session->policy_message),
               "Password will expire in %u seconds", sec);
}

static void handle_ppolicy_controls(MYLDAP_SESSION *session, LDAP *ld, LDAPControl **ctrls)
{
  int i;
  int rc;
  /* clear policy response information in session */
  session->policy_response = NSLCD_PAM_SUCCESS;
  strncpy(session->policy_message, "", sizeof(session->policy_message));
  for (i = 0; ctrls[i] != NULL; i++)
  {
    if (strcmp(ctrls[i]->ldctl_oid, LDAP_CONTROL_PWEXPIRED) == 0)
    {
      /* check for expired control: force the user to change their password */
      log_log(LOG_DEBUG, "got LDAP_CONTROL_PWEXPIRED (password expired, user should change)");
      if (session->policy_response == NSLCD_PAM_SUCCESS)
        session->policy_response = NSLCD_PAM_NEW_AUTHTOK_REQD;
    }
    else if (strcmp(ctrls[i]->ldctl_oid, LDAP_CONTROL_PWEXPIRING) == 0)
    {
      /* check for password expiration warning control: the password is about
         to expire (returns the number of seconds remaining until the password
         expires) */
      char seconds[32];
      long int sec;
      mysnprintf(seconds, sizeof(seconds), "%.*s", (int)ctrls[i]->ldctl_value.bv_len,
                 ctrls[i]->ldctl_value.bv_val);
      sec = atol(seconds);
      log_log(LOG_DEBUG, "got LDAP_CONTROL_PWEXPIRING (password will expire in %ld seconds)",
              sec);
      print_ppolicy_expiry(session, (unsigned int)sec);
    }
    else if (strcmp(ctrls[i]->ldctl_oid, LDAP_CONTROL_PASSWORDPOLICYRESPONSE) == 0)
    {
      /* check for password policy control */
      int expire = 0, grace = 0;
      LDAPPasswordPolicyError error = -1;
      rc = ldap_parse_passwordpolicy_control(ld, ctrls[i], &expire, &grace, &error);
      if (rc != LDAP_SUCCESS)
        myldap_err(LOG_WARNING, ld, rc, "ldap_parse_passwordpolicy_control() failed (ignored)");
      else
      {
        /* log returned control information */
        log_log(LOG_DEBUG, "got LDAP_CONTROL_PASSWORDPOLICYRESPONSE (%s)",
                ldap_passwordpolicy_err2txt(error));
        if (expire >= 0)
          log_log(LOG_DEBUG, "got LDAP_CONTROL_PASSWORDPOLICYRESPONSE (password will expire in %d seconds)",
                  expire);
        if (grace >= 0)
          log_log(LOG_DEBUG, "got LDAP_CONTROL_PASSWORDPOLICYRESPONSE (%d grace logins left)",
                  grace);
        /* return this information to PAM */
        if ((error == PP_passwordExpired) &&
            ((session->policy_response == NSLCD_PAM_SUCCESS) ||
             (session->policy_response == NSLCD_PAM_NEW_AUTHTOK_REQD)))
        {
          /* this means that the password has expired and must be reset */
          session->policy_response = NSLCD_PAM_NEW_AUTHTOK_REQD;
          mysnprintf(session->policy_message, sizeof(session->policy_message),
                     "%s", ldap_passwordpolicy_err2txt(error));
        }
        else if ((error == PP_accountLocked) &&
                 ((session->policy_response == NSLCD_PAM_SUCCESS) ||
                  (session->policy_response == NSLCD_PAM_NEW_AUTHTOK_REQD)))
        {
          /* this means that the account is locked and the user cannot log
             in (the bind probably failed already) */
          session->policy_response = NSLCD_PAM_ACCT_EXPIRED;
          mysnprintf(session->policy_message, sizeof(session->policy_message),
                     "%s", ldap_passwordpolicy_err2txt(error));
        }
        else if ((error == PP_changeAfterReset) &&
                 (session->policy_response == NSLCD_PAM_SUCCESS))
        {
          /* this indicates that the password must be changed before the
             user is allowed to perform any other operation */
          session->policy_response = NSLCD_PAM_NEW_AUTHTOK_REQD;
          mysnprintf(session->policy_message, sizeof(session->policy_message),
                     "%s", ldap_passwordpolicy_err2txt(error));
        }
        else if ((error != PP_noError) &&
                 ((session->policy_response == NSLCD_PAM_SUCCESS) ||
                  (session->policy_response == NSLCD_PAM_NEW_AUTHTOK_REQD)))
        {
          /* any other error is assumed to mean that the operation failed */
          session->policy_response = NSLCD_PAM_PERM_DENIED;
          mysnprintf(session->policy_message, sizeof(session->policy_message),
                     "%s", ldap_passwordpolicy_err2txt(error));
        }
        /* both expire and grace should just be warnings to the user */
        if ((expire >= 0) && (strlen(session->policy_message) == 0))
        {
          /* if no other error has happened, this indicates that the password
             will soon expire (number of seconds) */
          print_ppolicy_expiry(session, (unsigned int)expire);
        }
        else if ((grace >= 0) && (strlen(session->policy_message) == 0))
        {
          /* this indicates the number of grace logins that are left before
             no further login attempts will be allowed */
          mysnprintf(session->policy_message, sizeof(session->policy_message),
                     "Password expired, %d grace logins left", grace);
        }
      }
    }
    /* ignore any other controls */
  }
}

static int do_ppolicy_bind(MYLDAP_SESSION *session, LDAP *ld, const char *uri)
{
  int rc, parserc;
  struct berval cred;
  LDAPControl passwd_policy_req;
  LDAPControl *requestctrls[2];
  LDAPControl **responsectrls;
  int msgid;
  struct timeval timeout;
  LDAPMessage *result;
  /* build policy request if pam_authc_ppolicy is set */
  if (nslcd_cfg->pam_authc_ppolicy)
  {
    passwd_policy_req.ldctl_oid = LDAP_CONTROL_PASSWORDPOLICYREQUEST;
    passwd_policy_req.ldctl_value.bv_val = NULL; /* none */
    passwd_policy_req.ldctl_value.bv_len = 0;
    passwd_policy_req.ldctl_iscritical = 0; /* not critical */
    requestctrls[0] = &passwd_policy_req;
  }
  else
    requestctrls[0] = NULL;
  requestctrls[1] = NULL;
  /* build password berval */
  cred.bv_val = (char *)session->bindpw;
  cred.bv_len = strlen(session->bindpw);
  /* do a SASL simple bind with the binddn and bindpw */
  log_log(LOG_DEBUG, "ldap_sasl_bind(\"%s\",%s) (uri=\"%s\") (ppolicy=%s)",
          session->binddn, (session->bindpw[0] != '\0') ? "\"***\"" : "\"\"",
          uri, (requestctrls[0] == NULL) ? "no" : "yes");
  rc = ldap_sasl_bind(ld, session->binddn, LDAP_SASL_SIMPLE, &cred, requestctrls, NULL, &msgid);
  if (rc != LDAP_SUCCESS)
    return rc;
  if (msgid == -1)
  {
    myldap_err(LOG_WARNING, ld, rc,"ldap_sasl_bind() failed (msgid=-1, uri=%s)", uri);
    return LDAP_OPERATIONS_ERROR;
  }
  /* get the result from the bind operation */
  timeout.tv_sec = nslcd_cfg->bind_timelimit;
  timeout.tv_usec = 0;
  result = NULL;
  rc = ldap_result(ld, msgid, LDAP_MSG_ALL, &timeout, &result);
  if (rc == -1) /* some error */
  {
    if (ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &rc) != LDAP_SUCCESS)
      rc = LDAP_UNAVAILABLE;
    myldap_err(LOG_ERR, ld, rc, "ldap_result() failed");
    if (result != NULL)
      ldap_msgfree(result);
    return LDAP_LOCAL_ERROR;
  }
  if (rc == 0) /* the timeout expired */
  {
    log_log(LOG_ERR, "ldap_result() timed out");
    if (result != NULL)
      ldap_msgfree(result);
    return LDAP_TIMEOUT;
  }
  /* parse the result from the bind operation (frees result, gets controls) */
  responsectrls = NULL;
  parserc = ldap_parse_result(ld, result, &rc, NULL, NULL, NULL, &responsectrls, 1);
  if (parserc != LDAP_SUCCESS)
  {
    myldap_err(LOG_ERR, ld, parserc, "ldap_parse_result() failed");
    if (responsectrls != NULL)
      ldap_controls_free(responsectrls);
    return parserc;
  }
  /* handle any returned controls */
  if (responsectrls != NULL)
  {
    if (nslcd_cfg->pam_authc_ppolicy)
      handle_ppolicy_controls(session, ld, responsectrls);
    ldap_controls_free(responsectrls);
  }
  /* return the result of the BIND operation */
  if (rc != LDAP_SUCCESS)
  {
    myldap_err(LOG_DEBUG, ld, rc, "ldap_parse_result() result");
    return rc;
  }
  return LDAP_SUCCESS;
}
#endif /* no SASL, so no ppolicy */

/* This function performs the authentication phase of opening a connection.
   The binddn and bindpw parameters may be used to override the authentication
   mechanism defined in the configuration.  This returns an LDAP result
   code. */
static int do_bind(MYLDAP_SESSION *session, LDAP *ld, const char *uri)
{
  int rc;
#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S
#ifndef HAVE_SASL_INTERACT_T
  struct berval cred;
#endif /* not HAVE_SASL_INTERACT_T */
#endif /* HAVE_LDAP_SASL_INTERACTIVE_BIND_S */
#ifdef LDAP_OPT_X_TLS
  /* check if StartTLS is requested */
  if (nslcd_cfg->ssl == SSL_START_TLS)
  {
    log_log(LOG_DEBUG, "ldap_start_tls_s()");
    errno = 0;
    rc = ldap_start_tls_s(ld, NULL, NULL);
    if (rc != LDAP_SUCCESS)
    {
      myldap_err(LOG_WARNING, ld, rc, "ldap_start_tls_s() failed (uri=%s)",
                 uri);
      return rc;
    }
  }
#endif /* LDAP_OPT_X_TLS */
  /* check if the binddn and bindpw are overwritten in the session */
  if (session->binddn[0] != '\0')
  {
#if defined(HAVE_LDAP_SASL_BIND) && defined(LDAP_SASL_SIMPLE)
    return do_ppolicy_bind(session, ld, uri);
#else /* no SASL, so no ppolicy */
    /* do a simple bind */
    log_log(LOG_DEBUG, "ldap_simple_bind_s(\"%s\",%s) (uri=\"%s\")",
            session->binddn,
            (session->bindpw[0] != '\0') ? "\"***\"" : "\"\"",
            uri);
    return ldap_simple_bind_s(ld, session->binddn, session->bindpw);
#endif
  }
  /* perform SASL bind if requested and available on platform */
#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S
  /* TODO: store this information in the session */
  if (nslcd_cfg->sasl_mech != NULL)
  {
    /* do a SASL bind */
    if (nslcd_cfg->sasl_secprops != NULL)
    {
      log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_X_SASL_SECPROPS,\"%s\")",
              nslcd_cfg->sasl_secprops);
      LDAP_SET_OPTION(ld, LDAP_OPT_X_SASL_SECPROPS, (void *)nslcd_cfg->sasl_secprops);
    }
#ifdef HAVE_SASL_INTERACT_T
    if (nslcd_cfg->binddn != NULL)
      log_log(LOG_DEBUG, "ldap_sasl_interactive_bind_s(\"%s\",\"%s\") (uri=\"%s\")",
              nslcd_cfg->binddn, nslcd_cfg->sasl_mech, uri);
    else
      log_log(LOG_DEBUG, "ldap_sasl_interactive_bind_s(NULL,\"%s\") (uri=\"%s\")",
              nslcd_cfg->sasl_mech, uri);
    return ldap_sasl_interactive_bind_s(ld, nslcd_cfg->binddn,
                                        nslcd_cfg->sasl_mech, NULL, NULL,
                                        LDAP_SASL_QUIET, do_sasl_interact,
                                        (void *)nslcd_cfg);
#else /* HAVE_SASL_INTERACT_T */
    if (nslcd_cfg->bindpw != NULL)
    {
      cred.bv_val = nslcd_cfg->bindpw;
      cred.bv_len = strlen(nslcd_cfg->bindpw);
    }
    else
    {
      cred.bv_val = "";
      cred.bv_len = 0;
    }
    if (nslcd_cfg->binddn != NULL)
      log_log(LOG_DEBUG, "ldap_sasl_bind_s(\"%s\",\"%s\",%s) (uri=\"%s\")",
              nslcd_cfg->binddn, nslcd_cfg->sasl_mech,
              nslcd_cfg->bindpw ? "\"***\"" : "NULL", uri);
    else
      log_log(LOG_DEBUG, "ldap_sasl_bind_s(NULL,\"%s\",%s) (uri=\"%s\")",
              nslcd_cfg->sasl_mech,
              nslcd_cfg->bindpw ? "\"***\"" : "NULL", uri);
    return ldap_sasl_bind_s(ld, nslcd_cfg->binddn,
                            nslcd_cfg->sasl_mech, &cred, NULL, NULL, NULL);
#endif /* not HAVE_SASL_INTERACT_T */
  }
#endif /* HAVE_LDAP_SASL_INTERACTIVE_BIND_S */
  /* do a simple bind */
  if (nslcd_cfg->binddn)
    log_log(LOG_DEBUG, "ldap_simple_bind_s(\"%s\",%s) (uri=\"%s\")",
            nslcd_cfg->binddn, nslcd_cfg->bindpw ? "\"***\"" : "NULL",
            uri);
  else
    log_log(LOG_DEBUG, "ldap_simple_bind_s(NULL,%s) (uri=\"%s\")",
            nslcd_cfg->bindpw ? "\"***\"" : "NULL", uri);
  return ldap_simple_bind_s(ld, nslcd_cfg->binddn, nslcd_cfg->bindpw);
}

#ifdef HAVE_LDAP_SET_REBIND_PROC
/* This function is called by the LDAP library when chasing referrals.
   It is configured with the ldap_set_rebind_proc() below. */
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
static int do_rebind(LDAP *ld, LDAP_CONST char *url,
                     ber_tag_t UNUSED(request),
                     ber_int_t UNUSED(msgid), void *arg)
{
  MYLDAP_SESSION *session = (MYLDAP_SESSION *)arg;
  log_log(LOG_DEBUG, "rebinding to %s", url);
  return do_bind(session, ld, url);
}
#else /* not recent OpenLDAP */
static int do_rebind(LDAP *ld, char **dnp, char **passwdp, int *authmethodp,
                     int freeit, void *arg)
{
  MYLDAP_SESSION *session = (MYLDAP_SESSION *)arg;
  if (freeit)
  {
    free(*dnp);
    memset(*passwdp, 0, strlen(*passwdp));
    free(*passwdp);
  }
  else
  {
    log_log(LOG_DEBUG, "rebinding");
    *dnp = strdup(session->binddn);
    *passwdp = strdup(session->bindpw);
    *authmethodp = LDAP_AUTH_SIMPLE;
    if ((*dnp == NULL) || (*passwdp == NULL))
    {
      if (*dnp != NULL)
        free(*dnp);
      log_log(LOG_CRIT, "do_rebind(): strdup() failed to allocate memory");
      return LDAP_NO_MEMORY;
    }
  }
  return LDAP_SUCCESS;
}
#endif /* not recent OpenLDAP */
#endif /* HAVE_LDAP_SET_REBIND_PROC */

/* set a recieve and send timeout on a socket */
static int set_socket_timeout(LDAP *ld, time_t sec, suseconds_t usec)
{
  struct timeval tv;
  int rc = LDAP_SUCCESS;
  int sd;
  log_log(LOG_DEBUG, "set_socket_timeout(%lu,%lu)",
          (unsigned long)sec, (unsigned long)usec);
  /* get the socket */
  if ((rc = ldap_get_option(ld, LDAP_OPT_DESC, &sd)) != LDAP_SUCCESS)
  {
    myldap_err(LOG_ERR, ld, rc, "ldap_get_option(LDAP_OPT_DESC) failed");
    return rc;
  }
  /* ignore invalid (probably closed) file descriptors */
  if (sd <= 0)
    return LDAP_SUCCESS;
  /* set timeouts */
  memset(&tv, 0, sizeof(tv));
  tv.tv_sec = sec;
  tv.tv_usec = usec;
  if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (void *)&tv, sizeof(tv)))
  {
    log_log(LOG_ERR, "setsockopt(%d,SO_RCVTIMEO) failed: %s",
            sd, strerror(errno));
    rc = LDAP_LOCAL_ERROR;
  }
  if (setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, (void *)&tv, sizeof(tv)))
  {
    log_log(LOG_ERR, "setsockopt(%d,SO_RCVTIMEO) failed: %s",
            sd, strerror(errno));
    rc = LDAP_LOCAL_ERROR;
  }
  return rc;
}

#ifdef LDAP_OPT_CONNECT_CB
/* This function is called by the LDAP library once a connection was made to the server. We
   set a timeout on the socket here, to catch network timeouts during the ssl
   handshake phase. It is configured with LDAP_OPT_CONNECT_CB. */
static int connect_cb(LDAP *ld, Sockbuf UNUSED(*sb),
                      LDAPURLDesc UNUSED(*srv), struct sockaddr UNUSED(*addr),
                      struct ldap_conncb UNUSED(*ctx))
{
  /* set timeout options on socket to avoid hang in some cases (a little
     more than the normal timeout so this should only be triggered in cases
     where the library behaves incorrectly) */
  if (nslcd_cfg->timelimit)
    set_socket_timeout(ld, nslcd_cfg->timelimit, 500000);
  return LDAP_SUCCESS;
}

/* We have an empty disconnect callback because LDAP_OPT_CONNECT_CB expects
   both functions to be available. */
static void disconnect_cb(LDAP UNUSED(*ld), Sockbuf UNUSED(*sb),
                          struct ldap_conncb UNUSED(*ctx))
{
}
#endif /* LDAP_OPT_CONNECT_CB */

/* This function sets a number of properties on the connection, based
   what is configured in the configfile. This function returns an
   LDAP status code. */
static int do_set_options(MYLDAP_SESSION *session)
{
  int rc;
  struct timeval tv;
#ifdef LDAP_OPT_CONNECT_CB
  /* make this static because OpenLDAP doesn't make its own copy */
  static struct ldap_conncb cb;
#endif /* LDAP_OPT_CONNECT_CB */
#ifdef LDAP_OPT_X_TLS
  int i;
#endif /* LDAP_OPT_X_TLS */
#ifdef HAVE_LDAP_SET_REBIND_PROC
  /* the rebind function that is called when chasing referrals, see
     http://publib.boulder.ibm.com/infocenter/iseries/v5r3/topic/apis/ldap_set_rebind_proc.htm
     http://www.openldap.org/software/man.cgi?query=ldap_set_rebind_proc&manpath=OpenLDAP+2.4-Release */
  /* TODO: probably only set this if we should chase referrals */
  log_log(LOG_DEBUG, "ldap_set_rebind_proc()");
#ifndef LDAP_SET_REBIND_PROC_RETURNS_VOID /* it returns int */
  rc = ldap_set_rebind_proc(session->ld, do_rebind, session);
  if (rc != LDAP_SUCCESS)
  {
    myldap_err(LOG_ERR, session->ld, rc, "ldap_set_rebind_proc() failed");
    return rc;
  }
#else /* ldap_set_rebind_proc() returns void */
  ldap_set_rebind_proc(session->ld, do_rebind, session);
#endif
#endif /* HAVE_LDAP_SET_REBIND_PROC */
  /* set the protocol version to use */
  log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_PROTOCOL_VERSION,%d)",
          nslcd_cfg->ldap_version);
  LDAP_SET_OPTION(session->ld, LDAP_OPT_PROTOCOL_VERSION,
                  &nslcd_cfg->ldap_version);
  /* set some other options */
  log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_DEREF,%d)",
          nslcd_cfg->deref);
  LDAP_SET_OPTION(session->ld, LDAP_OPT_DEREF, &nslcd_cfg->deref);
  log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_TIMELIMIT,%d)",
          nslcd_cfg->timelimit);
  LDAP_SET_OPTION(session->ld, LDAP_OPT_TIMELIMIT, &nslcd_cfg->timelimit);
  tv.tv_sec = nslcd_cfg->bind_timelimit;
  tv.tv_usec = 0;
#ifdef LDAP_OPT_TIMEOUT
  log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_TIMEOUT,%d)",
          nslcd_cfg->bind_timelimit);
  LDAP_SET_OPTION(session->ld, LDAP_OPT_TIMEOUT, &tv);
#endif /* LDAP_OPT_TIMEOUT */
#ifdef LDAP_OPT_NETWORK_TIMEOUT
  log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_NETWORK_TIMEOUT,%d)",
          nslcd_cfg->bind_timelimit);
  LDAP_SET_OPTION(session->ld, LDAP_OPT_NETWORK_TIMEOUT, &tv);
#endif /* LDAP_OPT_NETWORK_TIMEOUT */
#ifdef LDAP_X_OPT_CONNECT_TIMEOUT
  log_log(LOG_DEBUG, "ldap_set_option(LDAP_X_OPT_CONNECT_TIMEOUT,%d)",
          nslcd_cfg->bind_timelimit);
  LDAP_SET_OPTION(session->ld, LDAP_X_OPT_CONNECT_TIMEOUT, &tv);
#endif /* LDAP_X_OPT_CONNECT_TIMEOUT */
  log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_REFERRALS,%s)",
          nslcd_cfg->referrals ? "LDAP_OPT_ON" : "LDAP_OPT_OFF");
  LDAP_SET_OPTION(session->ld, LDAP_OPT_REFERRALS,
                  nslcd_cfg->referrals ? LDAP_OPT_ON : LDAP_OPT_OFF);
  log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_RESTART,LDAP_OPT_ON)");
  LDAP_SET_OPTION(session->ld, LDAP_OPT_RESTART, LDAP_OPT_ON);
#ifdef LDAP_OPT_CONNECT_CB
  /* register a connection callback */
  cb.lc_add = connect_cb;
  cb.lc_del = disconnect_cb;
  cb.lc_arg = NULL;
  LDAP_SET_OPTION(session->ld, LDAP_OPT_CONNECT_CB, (void *)&cb);
#endif /* LDAP_OPT_CONNECT_CB */
#ifdef LDAP_OPT_X_TLS
  /* if SSL is desired, then enable it */
  if ((nslcd_cfg->ssl == SSL_LDAPS) ||
      (strncasecmp(nslcd_cfg->uris[session->current_uri].uri, "ldaps://", 8) == 0))
  {
    /* use tls */
    i = LDAP_OPT_X_TLS_HARD;
    log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_X_TLS,LDAP_OPT_X_TLS_HARD)");
    LDAP_SET_OPTION(session->ld, LDAP_OPT_X_TLS, &i);
  }
#endif /* LDAP_OPT_X_TLS */
#ifdef LDAP_OPT_X_SASL_NOCANON
  if (nslcd_cfg->sasl_canonicalize >= 0)
  {
    log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_X_SASL_NOCANON,%s)",
            nslcd_cfg->sasl_canonicalize ? "LDAP_OPT_OFF" : "LDAP_OPT_ON");
    LDAP_SET_OPTION(session->ld, LDAP_OPT_X_SASL_NOCANON,
                    nslcd_cfg->sasl_canonicalize ? LDAP_OPT_OFF : LDAP_OPT_ON);
  }
#endif /* LDAP_OPT_X_SASL_NOCANON */
  /* if nothing above failed, everything should be fine */
  return LDAP_SUCCESS;
}

/* close the connection to the server and invalidate any running searches */
static void do_close(MYLDAP_SESSION *session)
{
  int i;
  int rc;
  time_t sec;
  /* if we had reachability problems with the server close the connection */
  if (session->ld != NULL)
  {
    /* set timeout options on socket to avoid hang in some cases
       (we set a short timeout because we don't care too much about properly
       shutting down the connection) */
    if (nslcd_cfg->timelimit)
    {
      sec = nslcd_cfg->timelimit / 2;
      if (!sec)
        sec = 1;
      set_socket_timeout(session->ld, sec, 0);
    }
    /* go over the other searches and partially close them */
    for (i = 0; i < MAX_SEARCHES_IN_SESSION; i++)
    {
      if (session->searches[i] != NULL)
      {
        /* free any messages (because later ld is no longer valid) */
        if (session->searches[i]->msg != NULL)
        {
          ldap_msgfree(session->searches[i]->msg);
          session->searches[i]->msg = NULL;
        }
        /* abandon the search if there were more results to fetch */
        if (session->searches[i]->msgid != -1)
        {
          log_log(LOG_DEBUG, "ldap_abandon()");
          if (ldap_abandon(session->searches[i]->session->ld, session->searches[i]->msgid))
          {
            if (ldap_get_option(session->ld, LDAP_OPT_ERROR_NUMBER, &rc) != LDAP_SUCCESS)
              rc = LDAP_OTHER;
            myldap_err(LOG_WARNING, session->ld, rc,
                       "ldap_abandon() failed to abandon search");
          }
          session->searches[i]->msgid = -1;
        }
        /* flag the search as invalid */
        session->searches[i]->valid = 0;
      }
    }
    /* close the connection to the server */
    log_log(LOG_DEBUG, "ldap_unbind()");
    rc = ldap_unbind(session->ld);
    session->ld = NULL;
    if (rc != LDAP_SUCCESS)
      myldap_err(LOG_WARNING, session->ld, rc, "ldap_unbind() failed");
  }
}

void myldap_session_check(MYLDAP_SESSION *session)
{
  int i;
  time_t current_time;
  int sd;
  int rc;
  struct sockaddr sa;
  socklen_t salen = sizeof(sa);
  /* check parameters */
  if (session == NULL)
  {
    log_log(LOG_ERR, "myldap_session_check(): invalid parameter passed");
    errno = EINVAL;
    return;
  }
  if (session->ld != NULL)
  {
    rc = ldap_get_option(session->ld, LDAP_OPT_DESC, &sd);
    if (rc != LDAP_SUCCESS)
    {
      myldap_err(LOG_WARNING, session->ld, rc,
                 "ldap_get_option(LDAP_OPT_DESC) failed (ignored)");
    }
    else
    {
      /* check if the connection was closed by the peer */
      if (getpeername(sd, &sa, &salen) == -1)
      {
        if (errno == ENOTCONN)
        {
          log_log(LOG_DEBUG, "myldap_session_check(): connection reset by peer");
          do_close(session);
          return;
        }
      }
    }
    /* check if we should time out the connection */
    if (nslcd_cfg->idle_timelimit > 0)
    {
      /* if we have any running searches, don't time out */
      for (i = 0; i < MAX_SEARCHES_IN_SESSION; i++)
        if ((session->searches[i] != NULL) && (session->searches[i]->valid))
          return;
      /* consider timeout (there are no running searches) */
      time(&current_time);
      if ((session->lastactivity + nslcd_cfg->idle_timelimit) < current_time)
      {
        log_log(LOG_DEBUG, "myldap_session_check(): idle_timelimit reached");
        do_close(session);
        /* try to use the first URI from the list again */
        session->current_uri = 0;
      }
    }
  }
}

/* This opens connection to an LDAP server, sets all connection options
   and binds to the server. This returns an LDAP status code. */
static int do_open(MYLDAP_SESSION *session)
{
  int rc;
  /* if the connection is still there (ie. ldap_unbind() wasn't
     called) then we can return the cached connection */
  if (session->ld != NULL)
    return LDAP_SUCCESS;
  /* we should build a new session now */
  session->ld = NULL;
  session->lastactivity = 0;
  /* open the connection */
  log_log(LOG_DEBUG, "ldap_initialize(%s)",
          nslcd_cfg->uris[session->current_uri].uri);
  errno = 0;
  rc = ldap_initialize(&(session->ld), nslcd_cfg->uris[session->current_uri].uri);
  if (rc != LDAP_SUCCESS)
  {
    myldap_err(LOG_WARNING, session->ld, rc, "ldap_initialize(%s) failed",
               nslcd_cfg->uris[session->current_uri].uri);
    if (session->ld != NULL)
      do_close(session);
    return rc;
  }
  else if (session->ld == NULL)
  {
    log_log(LOG_WARNING, "ldap_initialize() returned NULL");
    return LDAP_LOCAL_ERROR;
  }
  /* set the options for the connection */
  rc = do_set_options(session);
  if (rc != LDAP_SUCCESS)
  {
    do_close(session);
    return rc;
  }
  /* bind to the server */
  errno = 0;
  rc = do_bind(session, session->ld, nslcd_cfg->uris[session->current_uri].uri);
  if (rc != LDAP_SUCCESS)
  {
    /* log actual LDAP error code */
    myldap_err((session->binddn[0] == '\0') ? LOG_WARNING : LOG_DEBUG,
               session->ld, rc, "failed to bind to LDAP server %s",
               nslcd_cfg->uris[session->current_uri].uri);
    do_close(session);
    return rc;
  }
  /* update last activity and finish off state */
  time(&(session->lastactivity));
  return LDAP_SUCCESS;
}

/* Perform a simple bind operation and return the ppolicy results. */
int myldap_bind(MYLDAP_SESSION *session, const char *dn, const char *password,
                int *response, const char **message)
{
  MYLDAP_SEARCH *search;
  static const char *attrs[2];
  int rc;
  /* error out when buffers are too small */
  if (strlen(dn) >= sizeof(session->binddn))
  {
    log_log(LOG_ERR, "myldap_bind(): binddn buffer too small (%lu required)",
            (unsigned long) strlen(dn));
    return LDAP_LOCAL_ERROR;
  }
  if (strlen(password) >= sizeof(session->bindpw))
  {
    log_log(LOG_ERR, "myldap_bind(): bindpw buffer too small (%lu required)",
            (unsigned long) strlen(password));
    return LDAP_LOCAL_ERROR;
  }
  /* copy dn and password into session */
  strncpy(session->binddn, dn, sizeof(session->binddn));
  session->binddn[sizeof(session->binddn) - 1] = '\0';
  strncpy(session->bindpw, password, sizeof(session->bindpw));
  session->bindpw[sizeof(session->bindpw) - 1] = '\0';
  /* construct a fake search to trigger the BIND operation */
  attrs[0] = "dn";
  attrs[1] = NULL;
  search = myldap_search(session, session->binddn, MYLDAP_SCOPE_BINDONLY,
                         "(objectClass=*)", attrs, &rc);
  if (search != NULL)
    myldap_search_close(search);
  /* return ppolicy results */
  if (response != NULL)
    *response = session->policy_response;
  if (message != NULL)
    *message = session->policy_message;
  return rc;
}

/* perform a search operation, the connection is assumed to be open */
static int do_try_search(MYLDAP_SEARCH *search)
{
  int ctrlidx = 0;
  int rc;
  LDAPControl *serverctrls[3];
#ifdef HAVE_LDAP_CREATE_DEREF_CONTROL
  int i;
  struct LDAPDerefSpec ds[2];
  char *deref_attrs[2];
#endif /* HAVE_LDAP_CREATE_DEREF_CONTROL */
  int msgid;
  /* if we're using paging, build a page control */
  if ((nslcd_cfg->pagesize > 0) && (search->scope != LDAP_SCOPE_BASE))
  {
    rc = ldap_create_page_control(search->session->ld, nslcd_cfg->pagesize,
                                  search->cookie, 0, &serverctrls[ctrlidx]);
    if (rc == LDAP_SUCCESS)
      ctrlidx++;
    else
    {
      myldap_err(LOG_WARNING, search->session->ld, rc,
                 "ldap_create_page_control() failed");
      serverctrls[ctrlidx] = NULL;
      /* if we were paging, failure building the second control is fatal */
      if (search->cookie != NULL)
        return rc;
    }
  }
#ifdef HAVE_LDAP_CREATE_DEREF_CONTROL
  /* if doing group searches, add deref control to search request
     (this is currently a bit of a hack and hard-coded for group searches
     which are detected by requesting the attmap_group_member member
     attribute) */
  for (i = 0; search->attrs[i] != NULL; i++)
    if (strcasecmp(search->attrs[i], attmap_group_member) == 0)
    {
      /* attributes from dereff'd entries */
      deref_attrs[0] = (void *)attmap_passwd_uid;
      deref_attrs[1] = NULL;
      /* build deref control */
      ds[0].derefAttr = (void *)attmap_group_member;
      ds[0].attributes = deref_attrs;
      ds[1].derefAttr = NULL;
      ds[1].attributes = NULL;
      rc = ldap_create_deref_control(search->session->ld, ds, 0, &serverctrls[ctrlidx]);
      if (rc == LDAP_SUCCESS)
        ctrlidx++;
      else
      {
        myldap_err(LOG_WARNING, search->session->ld, rc,
                   "ldap_create_deref_control() failed");
        serverctrls[ctrlidx] = NULL;
      }
    }
#endif /* HAVE_LDAP_CREATE_DEREF_CONTROL */
  /* NULL terminate control list */
  serverctrls[ctrlidx] = NULL;
  /* clear error flag (perhaps control setting failed) */
  if (ctrlidx > 0)
  {
    rc = LDAP_SUCCESS;
    if (ldap_set_option(search->session->ld, LDAP_OPT_ERROR_NUMBER, &rc) != LDAP_SUCCESS)
      log_log(LOG_WARNING, "failed to clear the error flag");
  }
  /* perform the search */
  rc = ldap_search_ext(search->session->ld, search->base, search->scope,
                       search->filter, (char **)(search->attrs),
                       0, serverctrls[0] == NULL ? NULL : serverctrls,
                       NULL, NULL, LDAP_NO_LIMIT, &msgid);
  /* free the controls if we had them */
  for (ctrlidx = 0; serverctrls[ctrlidx] != NULL; ctrlidx++)
    ldap_control_free(serverctrls[ctrlidx]);
  /* handle errors */
  if (rc != LDAP_SUCCESS)
  {
    myldap_err(LOG_WARNING, search->session->ld, rc, "ldap_search_ext() failed");
    return rc;
  }
  /* update the last activity on the connection */
  time(&(search->session->lastactivity));
  /* save msgid */
  search->msgid = msgid;
  /* return the new search */
  return LDAP_SUCCESS;
}

MYLDAP_SESSION *myldap_create_session(void)
{
  return myldap_session_new();
}

void myldap_session_cleanup(MYLDAP_SESSION *session)
{
  int i;
  /* check parameter */
  if (session == NULL)
  {
    log_log(LOG_ERR, "myldap_session_cleanup(): invalid session passed");
    return;
  }
  /* go over all searches in the session and close them */
  for (i = 0; i < MAX_SEARCHES_IN_SESSION; i++)
  {
    if (session->searches[i] != NULL)
    {
      myldap_search_close(session->searches[i]);
      session->searches[i] = NULL;
    }
  }
}

void myldap_session_close(MYLDAP_SESSION *session)
{
  /* check parameter */
  if (session == NULL)
  {
    log_log(LOG_ERR, "myldap_session_cleanup(): invalid session passed");
    return;
  }
  /* close pending searches */
  myldap_session_cleanup(session);
  /* close any open connections */
  do_close(session);
  /* free allocated memory */
  memset(session->bindpw, 0, sizeof(session->bindpw));
  free(session);
}

/* mutex for updating the times in the uri */
pthread_mutex_t uris_mutex = PTHREAD_MUTEX_INITIALIZER;

static int do_retry_search(MYLDAP_SEARCH *search)
{
  int sleeptime = 0;
  int start_uri;
  time_t endtime;
  time_t nexttry;
  time_t t;
  int rc = LDAP_UNAVAILABLE;
  struct myldap_uri *current_uri;
  int dotry[NSS_LDAP_CONFIG_MAX_URIS];
  int do_invalidate = 0;
  /* clear time stamps */
  for (start_uri = 0; start_uri < NSS_LDAP_CONFIG_MAX_URIS; start_uri++)
    dotry[start_uri] = 1;
  /* keep trying until we time out */
  endtime = time(NULL) + nslcd_cfg->reconnect_retrytime;
  while (1)
  {
    nexttry = endtime;
    /* try each configured URL once */
    pthread_mutex_lock(&uris_mutex);
    start_uri = search->session->current_uri;
    do
    {
      current_uri = &(nslcd_cfg->uris[search->session->current_uri]);
      /* only try this URI if we should */
      if (!dotry[search->session->current_uri])
      { /* skip this URI */ }
      else if ((current_uri->lastfail > (current_uri->firstfail + nslcd_cfg->reconnect_retrytime)) &&
               ((t = time(NULL)) < (current_uri->lastfail + nslcd_cfg->reconnect_retrytime)))
      {
        /* we are in a hard fail state and have retried not long ago */
        log_log(LOG_DEBUG, "not retrying server %s which failed just %d second(s) ago and has been failing for %d seconds",
                current_uri->uri, (int)(t - current_uri->lastfail),
                (int)(t - current_uri->firstfail));
        dotry[search->session->current_uri] = 0;
      }
      else
      {
        /* try to start the search */
        pthread_mutex_unlock(&uris_mutex);
        /* ensure that we have an open connection and start a search */
        rc = do_open(search->session);
        /* perform the actual search, unless we were only binding */
        if ((rc == LDAP_SUCCESS) && (search->scope != MYLDAP_SCOPE_BINDONLY))
          rc = do_try_search(search);
        /* if we are authenticating a user and get an error regarding failed
           password we should error out instead of trying all servers */
        if ((search->session->binddn[0] != '\0') && (rc == LDAP_INVALID_CREDENTIALS))
        {
          do_close(search->session);
          return rc;
        }
        if (rc == LDAP_SUCCESS)
        {
          pthread_mutex_lock(&uris_mutex);
          /* check if we are coming back from an error */
          if ((current_uri->lastfail > 0) || (search->session->current_uri != start_uri))
          {
            log_log(LOG_INFO, "connected to LDAP server %s", current_uri->uri);
            do_invalidate = 1;
          }
          if (first_search)
          {
            do_invalidate = 1;
            first_search = 0;
          }
          /* update ok time */
          current_uri->firstfail = 0;
          current_uri->lastfail = 0;
          pthread_mutex_unlock(&uris_mutex);
          /* flag the search as valid */
          search->valid = 1;
          /* signal external invalidation of configured caches */
          if (do_invalidate)
            invalidator_do(LM_NONE);
          return LDAP_SUCCESS;
        }
        /* close the current connection */
        do_close(search->session);
        /* update time of failure and figure out when we should retry */
        pthread_mutex_lock(&uris_mutex);
        t = time(NULL);
        /* update timestamps unless we are doing an authentication search */
        if (search->session->binddn[0] == '\0')
        {
          if (current_uri->firstfail == 0)
            current_uri->firstfail = t;
          current_uri->lastfail = t;
        }
        /* if it is one of these, retrying this URI is not going to help */
        if ((rc == LDAP_INVALID_CREDENTIALS) || (rc == LDAP_INSUFFICIENT_ACCESS) ||
            (rc == LDAP_AUTH_METHOD_NOT_SUPPORTED))
          dotry[search->session->current_uri] = 0;
        /* check when we should try this URI again */
        else if (t <= (current_uri->firstfail + nslcd_cfg->reconnect_retrytime))
        {
          t += nslcd_cfg->reconnect_sleeptime;
          if (t < nexttry)
            nexttry = t;
        }
      }
      /* try the next URI (with wrap-around) */
      search->session->current_uri++;
      if (nslcd_cfg->uris[search->session->current_uri].uri == NULL)
        search->session->current_uri = 0;
    }
    while (search->session->current_uri != start_uri);
    pthread_mutex_unlock(&uris_mutex);
    /* see if it is any use sleeping */
    if (nexttry >= endtime)
    {
      if (search->session->binddn[0] == '\0')
        myldap_err(LOG_ERR, search->session->ld, rc, "no available LDAP server found");
      return rc;
    }
    /* sleep between tries */
    sleeptime = nexttry - time(NULL);
    if (sleeptime > 0)
    {
      log_log(LOG_WARNING, "no available LDAP server found, sleeping %d seconds",
              sleeptime);
      (void)sleep(sleeptime);
    }
  }
}

/* force quick retries of all failing LDAP servers */
void myldap_immediate_reconnect(void)
{
  int i;
  time_t t;
  t = time(NULL) - nslcd_cfg->reconnect_retrytime;
  pthread_mutex_lock(&uris_mutex);
  for (i = 0; i < (NSS_LDAP_CONFIG_MAX_URIS + 1); i++)
  {
    /* only adjust failing connections that are in a hard fail state */
    if ((nslcd_cfg->uris[i].lastfail > t) &&
        (nslcd_cfg->uris[i].lastfail > (nslcd_cfg->uris[i].firstfail + nslcd_cfg->reconnect_retrytime)))
    {
      /* move lastfail back to ensure quick retry */
      log_log(LOG_DEBUG, "moving lastfail of %s %d second(s) back to force retry",
              nslcd_cfg->uris[i].uri, (int)(nslcd_cfg->uris[i].lastfail - t));
      nslcd_cfg->uris[i].lastfail = t;
    }
  }
  pthread_mutex_unlock(&uris_mutex);
}

MYLDAP_SEARCH *myldap_search(MYLDAP_SESSION *session,
                             const char *base, int scope, const char *filter,
                             const char **attrs, int *rcp)
{
  MYLDAP_SEARCH *search;
  int i;
  int rc;
  /* check parameters */
  if ((session == NULL) || (base == NULL) || (filter == NULL) || (attrs == NULL))
  {
    log_log(LOG_ERR, "myldap_search(): invalid parameter passed");
    errno = EINVAL;
    if (rcp != NULL)
      *rcp = LDAP_OPERATIONS_ERROR;
    return NULL;
  }
  /* log the call */
  log_log(LOG_DEBUG, "myldap_search(base=\"%s\", filter=\"%s\")",
          base, filter);
  /* check if the idle time for the connection has expired */
  myldap_session_check(session);
  /* allocate a new search entry */
  search = myldap_search_new(session, base, scope, filter, attrs);
  /* find a place in the session where we can register our search */
  for (i = 0; (i < MAX_SEARCHES_IN_SESSION) && (session->searches[i] != NULL); i++)
    /* nothing */ ;
  if (i >= MAX_SEARCHES_IN_SESSION)
  {
    log_log(LOG_ERR, "myldap_search(): too many searches registered with session (max %d)",
            MAX_SEARCHES_IN_SESSION);
    myldap_search_close(search);
    if (rcp != NULL)
      *rcp = LDAP_OPERATIONS_ERROR;
    return NULL;
  }
  /* register search with the session so we can free it later on */
  session->searches[i] = search;
  /* do the search with retries to all configured servers */
  rc = do_retry_search(search);
  if (rc != LDAP_SUCCESS)
  {
    myldap_search_close(search);
    if (rcp != NULL)
      *rcp = rc;
    return NULL;
  }
  if (rcp != NULL)
    *rcp = LDAP_SUCCESS;
  return search;
}

void myldap_search_close(MYLDAP_SEARCH *search)
{
  int i;
  if (search == NULL)
    return;
  /* free any messages */
  if (search->msg != NULL)
  {
    ldap_msgfree(search->msg);
    search->msg = NULL;
  }
  /* abandon the search if there were more results to fetch */
  if ((search->session->ld != NULL) && (search->msgid != -1))
  {
    ldap_abandon(search->session->ld, search->msgid);
    search->msgid = -1;
  }
  /* find the reference to this search in the session */
  for (i = 0; i < MAX_SEARCHES_IN_SESSION; i++)
  {
    if (search->session->searches[i] == search)
      search->session->searches[i] = NULL;
  }
  /* free any search entries */
  if (search->entry != NULL)
    myldap_entry_free(search->entry);
  /* clean up cookie */
  if (search->cookie != NULL)
    ber_bvfree(search->cookie);
  /* free read messages */
  if (search->msg != NULL)
    ldap_msgfree(search->msg);
  /* free the storage we allocated */
  free(search);
}

MYLDAP_ENTRY *myldap_get_entry(MYLDAP_SEARCH *search, int *rcp)
{
  int rc;
  int parserc;
  struct timeval tv, *tvp;
  LDAPControl **resultcontrols;
  ber_int_t count;
  /* check parameters */
  if ((search == NULL) || (search->session == NULL) || (search->session->ld == NULL))
  {
    log_log(LOG_ERR, "myldap_get_entry(): invalid search passed");
    errno = EINVAL;
    if (rcp != NULL)
      *rcp = LDAP_OPERATIONS_ERROR;
    return NULL;
  }
  /* check if the connection wasn't closed in another search */
  if (!search->valid)
  {
    log_log(LOG_WARNING, "myldap_get_entry(): connection was closed");
    /* retry the search */
    if (search->may_retry_search)
    {
      log_log(LOG_DEBUG, "myldap_get_entry(): retry search");
      search->may_retry_search = 0;
      if (do_retry_search(search) == LDAP_SUCCESS)
        return myldap_get_entry(search, rcp);
    }
    myldap_search_close(search);
    if (rcp != NULL)
      *rcp = LDAP_SERVER_DOWN;
    return NULL;
  }
  /* set up a timelimit value for operations */
  if (nslcd_cfg->timelimit == LDAP_NO_LIMIT)
    tvp = NULL;
  else
  {
    tv.tv_sec = nslcd_cfg->timelimit;
    tv.tv_usec = 0;
    tvp = &tv;
  }
  /* if we have an existing result entry, free it */
  if (search->entry != NULL)
  {
    myldap_entry_free(search->entry);
    search->entry = NULL;
  }
  /* try to parse results until we have a final error or ok */
  while (1)
  {
    /* free the previous message if there was any */
    if (search->msg != NULL)
    {
      ldap_msgfree(search->msg);
      search->msg = NULL;
    }
    /* get the next result */
    rc = ldap_result(search->session->ld, search->msgid, LDAP_MSG_ONE, tvp,
                     &(search->msg));
    /* handle result */
    switch (rc)
    {
      case LDAP_RES_SEARCH_ENTRY:
        /* we have a normal search entry, update timestamp and return result */
        time(&(search->session->lastactivity));
        search->entry = myldap_entry_new(search);
        if (rcp != NULL)
          *rcp = LDAP_SUCCESS;
        /* log the first couple of dns in the result (but not all, to
           prevent swamping the log) */
        if (search->count < MAX_DEBUG_LOG_DNS)
          log_log(LOG_DEBUG, "ldap_result(): %s", myldap_get_dn(search->entry));
        search->count++;
        search->may_retry_search = 0;
        return search->entry;
      case LDAP_RES_SEARCH_RESULT:
        /* we have a search result, parse it */
        resultcontrols = NULL;
        if (search->cookie != NULL)
        {
          ber_bvfree(search->cookie);
          search->cookie = NULL;
        }
        /* NB: this frees search->msg */
        parserc = ldap_parse_result(search->session->ld, search->msg, &rc,
                                    NULL, NULL, NULL, &resultcontrols, 1);
        search->msg = NULL;
        /* check for errors during parsing */
        if ((parserc != LDAP_SUCCESS) && (parserc != LDAP_MORE_RESULTS_TO_RETURN))
        {
          if (resultcontrols != NULL)
            ldap_controls_free(resultcontrols);
          myldap_err(LOG_ERR, search->session->ld, parserc, "ldap_parse_result() failed");
          myldap_search_close(search);
          if (rcp != NULL)
            *rcp = parserc;
          return NULL;
        }
        /* check for errors in message */
        if ((rc != LDAP_SUCCESS) && (rc != LDAP_MORE_RESULTS_TO_RETURN))
        {
          if (resultcontrols != NULL)
            ldap_controls_free(resultcontrols);
          myldap_err(LOG_ERR, search->session->ld, rc, "ldap_result() failed");
          /* close connection on connection problems */
          if ((rc == LDAP_UNAVAILABLE) || (rc == LDAP_SERVER_DOWN))
            do_close(search->session);
          myldap_search_close(search);
          if (rcp != NULL)
            *rcp = rc;
          return NULL;
        }
        /* handle result controls */
        if (resultcontrols != NULL)
        {
          /* see if there are any more pages to come */
          rc = ldap_parse_page_control(search->session->ld, resultcontrols,
                                       &count, &(search->cookie));
          if (rc != LDAP_SUCCESS)
          {
            if (rc != LDAP_CONTROL_NOT_FOUND)
              myldap_err(LOG_WARNING, search->session->ld, rc, "ldap_parse_page_control() failed");
            /* clear error flag */
            rc = LDAP_SUCCESS;
            if (ldap_set_option(search->session->ld, LDAP_OPT_ERROR_NUMBER,
                                &rc) != LDAP_SUCCESS)
              log_log(LOG_WARNING, "failed to clear the error flag");
          }
          /* TODO: handle the above return code?? */
          ldap_controls_free(resultcontrols);
        }
        search->msgid = -1;
        /* check if there are more pages to come */
        if ((search->cookie == NULL) || (search->cookie->bv_len == 0))
        {
          if (search->count > MAX_DEBUG_LOG_DNS)
            log_log(LOG_DEBUG, "ldap_result(): ... %d more results",
                    search->count - MAX_DEBUG_LOG_DNS);
          log_log(LOG_DEBUG, "ldap_result(): end of results (%d total)",
                  search->count);
          /* we are at the end of the search, no more results */
          myldap_search_close(search);
          if (rcp != NULL)
            *rcp = LDAP_SUCCESS;
          return NULL;
        }
        /* try the next page */
        rc = do_try_search(search);
        if (rc != LDAP_SUCCESS)
        {
          /* close connection on connection problems */
          if ((rc == LDAP_UNAVAILABLE) || (rc == LDAP_SERVER_DOWN))
            do_close(search->session);
          myldap_search_close(search);
          if (rcp != NULL)
            *rcp = rc;
          return NULL;
        }
        /* we continue with another pass */
        break;
      case LDAP_RES_SEARCH_REFERENCE:
        break; /* just ignore search references */
      default:
        /* we have some error condition, find out which */
        switch (rc)
        {
          case -1:
            /* try to get error code */
            if (ldap_get_option(search->session->ld, LDAP_OPT_ERROR_NUMBER,
                                &rc) != LDAP_SUCCESS)
              rc = LDAP_UNAVAILABLE;
            myldap_err(LOG_ERR, search->session->ld, rc, "ldap_result() failed");
            break;
          case 0:
            /* the timeout expired */
            log_log(LOG_ERR, "ldap_result() timed out");
            rc = LDAP_TIMELIMIT_EXCEEDED;
            break;
          default:
            /* unknown code */
            log_log(LOG_WARNING, "ldap_result() returned unexpected result type");
            rc = LDAP_PROTOCOL_ERROR;
        }
        /* close connection on some connection problems */
        if ((rc == LDAP_UNAVAILABLE) || (rc == LDAP_SERVER_DOWN) ||
            (rc == LDAP_SUCCESS) || (rc == LDAP_TIMELIMIT_EXCEEDED) ||
            (rc == LDAP_OPERATIONS_ERROR) || (rc == LDAP_PROTOCOL_ERROR) ||
            (rc == LDAP_BUSY) || (rc == LDAP_UNWILLING_TO_PERFORM) ||
            (rc == LDAP_TIMEOUT) || (rc == LDAP_CONNECT_ERROR) ||
            (rc == LDAP_NOT_SUPPORTED))
        {
          do_close(search->session);
          /* retry once if no data has been received yet */
          if (search->may_retry_search)
          {
            log_log(LOG_DEBUG, "myldap_get_entry(): retry search");
            search->may_retry_search = 0;
            if (do_retry_search(search) == LDAP_SUCCESS)
              return myldap_get_entry(search, rcp);
          }
        }
        /* close search */
        myldap_search_close(search);
        if (rcp != NULL)
          *rcp = rc;
        return NULL;
    }
  }
}

/* Get the DN from the entry. This function only returns NULL (and sets
   errno) if an incorrect entry is passed. If the DN value cannot be
   retrieved "unknown" is returned instead. */
const char *myldap_get_dn(MYLDAP_ENTRY *entry)
{
  int rc;
  /* check parameters */
  if (!is_valid_entry(entry))
  {
    log_log(LOG_ERR, "myldap_get_dn(): invalid result entry passed");
    errno = EINVAL;
    return "unknown";
  }
  /* if we don't have it yet, retrieve it */
  if ((entry->dn == NULL) && (entry->search->valid))
  {
    entry->dn = ldap_get_dn(entry->search->session->ld, entry->search->msg);
    if (entry->dn == NULL)
    {
      if (ldap_get_option(entry->search->session->ld, LDAP_OPT_ERROR_NUMBER,
                          &rc) != LDAP_SUCCESS)
        rc = LDAP_UNAVAILABLE;
      myldap_err(LOG_WARNING, entry->search->session->ld, rc, "ldap_get_dn() returned NULL");
      /* close connection on connection problems */
      if ((rc == LDAP_UNAVAILABLE) || (rc == LDAP_SERVER_DOWN))
        do_close(entry->search->session);
    }
  }
  /* if we still don't have it, return unknown */
  if (entry->dn == NULL)
    return "unknown";
  /* return it */
  return entry->dn;
}

char *myldap_cpy_dn(MYLDAP_ENTRY *entry, char *buf, size_t buflen)
{
  const char *dn;
  /* get the dn */
  dn = myldap_get_dn(entry);
  /* copy into buffer */
  if (strlen(dn) < buflen)
    strcpy(buf, dn);
  else
    buf = NULL;
  return buf;
}

/* Perform ranged retrieval of attributes.
   http://msdn.microsoft.com/en-us/library/aa367017(vs.85).aspx
   http://www.tkk.fi/cc/docs/kerberos/draft-kashi-incremental-00.txt */
static char **myldap_get_ranged_values(MYLDAP_ENTRY *entry, const char *attr)
{
  char **values;
  char *attn;
  const char *attrs[2];
  BerElement *ber;
  int i;
  int startat = 0, nxt = 0;
  char attbuf[80];
  const char *dn = myldap_get_dn(entry);
  MYLDAP_SESSION *session = entry->search->session;
  MYLDAP_SEARCH *search = NULL;
  SET *set = NULL;
  /* build the attribute name to find */
  if (mysnprintf(attbuf, sizeof(attbuf), "%s;range=0-*", attr))
  {
    log_log(LOG_ERR, "myldap_get_ranged_values(): attbuf buffer too small (%lu required)",
            (unsigned long) strlen(attr) + 10);
    return NULL;
  }
  /* keep doing lookups untul we can't get any more results */
  while (1)
  {
    /* go over all attributes to find the ranged attribute */
    ber = NULL;
    attn = ldap_first_attribute(entry->search->session->ld, entry->search->msg, &ber);
    values = NULL;
    while (attn != NULL)
    {
      if (strncasecmp(attn, attbuf, strlen(attbuf) - 1) == 0)
      {
        log_log(LOG_DEBUG, "found ranged results %s", attn);
        nxt = atoi(attn + strlen(attbuf) - 1) + 1;
        values = ldap_get_values(entry->search->session->ld, entry->search->msg, attn);
        ldap_memfree(attn);
        break;
      }
      /* free old attribute name and get next one */
      ldap_memfree(attn);
      attn = ldap_next_attribute(entry->search->session->ld, entry->search->msg, ber);
    }
    ber_free(ber, 0);
    /* see if we found any values */
    if ((values == NULL) || (*values == NULL))
      break;
    /* allocate memory */
    if (set == NULL)
    {
      set = set_new();
      if (set == NULL)
      {
        ldap_value_free(values);
        log_log(LOG_CRIT, "myldap_get_ranged_values(): set_new() failed to allocate memory");
        return NULL;
      }
    }
    /* add to the set */
    for (i = 0; values[i] != NULL; i++)
      set_add(set, values[i]);
    /* free results */
    ldap_value_free(values);
    /* check if we should start a new search */
    if (nxt <= startat)
      break;
    startat = nxt;
    /* build attributes for a new search */
    if (mysnprintf(attbuf, sizeof(attbuf), "%s;range=%d-*", attr, startat))
    {
      log_log(LOG_ERR, "myldap_get_ranged_values(): attbuf buffer too small");
      break;
    }
    attrs[0] = attbuf;
    attrs[1] = NULL;
    /* close the previous search, if any */
    if (search != NULL)
      myldap_search_close(search);
    /* start the new search */
    search = myldap_search(session, dn, LDAP_SCOPE_BASE, "(objectClass=*)", attrs, NULL);
    if (search == NULL)
      break;
    entry = myldap_get_entry(search, NULL);
    if (entry == NULL)
      break;
  }
  /* close any started searches */
  if (search != NULL)
    myldap_search_close(search);
  /* return the contents of the set as a list */
  if (set == NULL)
    return NULL;
  values = (char **)set_tolist(set);
  set_free(set);
  if (values == NULL)
    log_log(LOG_CRIT, "myldap_get_ranged_values(): malloc() failed to allocate memory");
  return values;
}

/* Simple wrapper around ldap_get_values(). */
const char **myldap_get_values(MYLDAP_ENTRY *entry, const char *attr)
{
  char **values;
  int rc;
  int i;
  /* check parameters */
  if (!is_valid_entry(entry))
  {
    log_log(LOG_ERR, "myldap_get_values(): invalid result entry passed");
    errno = EINVAL;
    return NULL;
  }
  else if (attr == NULL)
  {
    log_log(LOG_ERR, "myldap_get_values(): invalid attribute name passed");
    errno = EINVAL;
    return NULL;
  }
  if (!entry->search->valid)
    return NULL; /* search has been stopped */
  /* get from LDAP */
  values = ldap_get_values(entry->search->session->ld, entry->search->msg, attr);
  if (values == NULL)
  {
    if (ldap_get_option(entry->search->session->ld, LDAP_OPT_ERROR_NUMBER, &rc) != LDAP_SUCCESS)
      rc = LDAP_UNAVAILABLE;
    /* ignore decoding errors as they are just non-existing attribute values */
    if (rc == LDAP_DECODING_ERROR)
    {
      rc = LDAP_SUCCESS;
      if (ldap_set_option(entry->search->session->ld, LDAP_OPT_ERROR_NUMBER, &rc) != LDAP_SUCCESS)
        log_log(LOG_WARNING, "failed to clear the error flag");
    }
    else if (rc == LDAP_SUCCESS)
    {
      /* we have a success code but no values, let's try to get ranged
         values */
      values = myldap_get_ranged_values(entry, attr);
      if (values == NULL)
        return NULL;
      /* store values entry so we can free it later on */
      for (i = 0; i < MAX_BUFFERS_PER_ENTRY; i++)
        if (entry->buffers[i] == NULL)
        {
          entry->buffers[i] = values;
          return (const char **)entry->buffers[i];
        }
      /* we found no room to store the values */
      log_log(LOG_ERR, "ldap_get_values() couldn't store results, increase MAX_BUFFERS_PER_ENTRY");
      free(values);
      return NULL;
    }
    else
      myldap_err(LOG_WARNING, entry->search->session->ld, rc,
                 "ldap_get_values() of attribute \"%s\" on entry \"%s\" returned NULL",
                 attr, myldap_get_dn(entry));
    return NULL;
  }
  /* store values entry so we can free it later on */
  for (i = 0; i < MAX_ATTRIBUTES_PER_ENTRY; i++)
    if (entry->attributevalues[i] == NULL)
    {
      entry->attributevalues[i] = values;
      return (const char **)values;
    }
  /* we found no room to store the entry */
  log_log(LOG_ERR, "ldap_get_values() couldn't store results, increase MAX_ATTRIBUTES_PER_ENTRY");
  ldap_value_free(values);
  return NULL;
}

/* Convert the bervalues to a simple list of strings that can be freed
   with one call to free(). */
static const char **bervalues_to_values(struct berval **bvalues)
{
  int num_values;
  int i;
  size_t sz;
  char *buf;
  char **values;
  /* figure out how much memory to allocate */
  num_values = ldap_count_values_len(bvalues);
  sz = (num_values + 1) * sizeof(char *);
  for (i = 0; i < num_values; i++)
    sz += bvalues[i]->bv_len + 1;
  /* allocate the needed memory */
  values = (char **)malloc(sz);
  if (values == NULL)
  {
    log_log(LOG_CRIT, "bervalues_to_values(): malloc() failed to allocate memory");
    return NULL;
  }
  buf = (char *)values;
  buf += (num_values + 1) * sizeof(char *);
  /* copy from bvalues */
  for (i = 0; i < num_values; i++)
  {
    values[i] = buf;
    memcpy(values[i], bvalues[i]->bv_val, bvalues[i]->bv_len);
    values[i][bvalues[i]->bv_len] = '\0';
    buf += bvalues[i]->bv_len + 1;
  }
  values[i] = NULL;
  return (const char **)values;
}

/* Simple wrapper around ldap_get_values(). */
const char **myldap_get_values_len(MYLDAP_ENTRY *entry, const char *attr)
{
  const char **values;
  struct berval **bvalues;
  int rc;
  int i;
  /* check parameters */
  if (!is_valid_entry(entry))
  {
    log_log(LOG_ERR, "myldap_get_values_len(): invalid result entry passed");
    errno = EINVAL;
    return NULL;
  }
  else if (attr == NULL)
  {
    log_log(LOG_ERR, "myldap_get_values_len(): invalid attribute name passed");
    errno = EINVAL;
    return NULL;
  }
  if (!entry->search->valid)
    return NULL; /* search has been stopped */
  /* get from LDAP */
  bvalues = ldap_get_values_len(entry->search->session->ld, entry->search->msg, attr);
  if (bvalues == NULL)
  {
    if (ldap_get_option(entry->search->session->ld, LDAP_OPT_ERROR_NUMBER, &rc) != LDAP_SUCCESS)
      rc = LDAP_UNAVAILABLE;
    /* ignore decoding errors as they are just non-existing attribute values */
    if (rc == LDAP_DECODING_ERROR)
    {
      rc = LDAP_SUCCESS;
      if (ldap_set_option(entry->search->session->ld, LDAP_OPT_ERROR_NUMBER, &rc) != LDAP_SUCCESS)
        log_log(LOG_WARNING, "failed to clear the error flag");
      return NULL;
    }
    else if (rc == LDAP_SUCCESS)
    {
      /* we have a success code but no values, let's try to get ranged
         values */
      values = (const char **)myldap_get_ranged_values(entry, attr);
    }
    else
    {
      myldap_err(LOG_WARNING, entry->search->session->ld, rc,
                 "myldap_get_values_len() of attribute \"%s\" on entry \"%s\" returned NULL",
                 attr, myldap_get_dn(entry));
      return NULL;
    }
  }
  else
  {
    values = bervalues_to_values(bvalues);
    ldap_value_free_len(bvalues);
  }
  /* check if we got allocated memory */
  if (values == NULL)
    return NULL;
  /* store values entry so we can free it later on */
  for (i = 0; i < MAX_BUFFERS_PER_ENTRY; i++)
    if (entry->buffers[i] == NULL)
    {
      entry->buffers[i] = (char **)values;
      return values;
    }
  /* we found no room to store the values */
  log_log(LOG_ERR, "myldap_get_values_len() couldn't store results, increase MAX_BUFFERS_PER_ENTRY");
  free(values);
  return NULL;
}

/* Go over the entries in exploded_rdn and see if any start with
   the requested attribute. Return a reference to the value part of
   the DN (does not modify exploded_rdn). */
static const char *find_rdn_value(char **exploded_rdn, const char *attr)
{
  int i, j;
  int l;
  if (exploded_rdn == NULL)
    return NULL;
  /* go over all RDNs */
  l = strlen(attr);
  for (i = 0; exploded_rdn[i] != NULL; i++)
  {
    /* check that RDN starts with attr */
    if (strncasecmp(exploded_rdn[i], attr, l) != 0)
      continue;
    j = l;
    /* skip spaces */
    while (isspace(exploded_rdn[i][j]))
      j++;
    /* ensure that we found an equals sign now */
    if (exploded_rdn[i][j] != '=')
      continue;
    j++;
    /* skip more spaces */
    while (isspace(exploded_rdn[i][j]))
      j++;
    /* ensure that we're not at the end of the string */
    if (exploded_rdn[i][j] == '\0')
      continue;
    /* we found our value */
    return exploded_rdn[i] + j;
  }
  /* fail */
  return NULL;
}

/* explode the first part of DN into parts
   (e.g. "cn=Test", "uid=test")
   The returned value should be freed with ldap_value_free(). */
static char **get_exploded_rdn(const char *dn)
{
  char **exploded_dn;
  char **exploded_rdn;
  /* check if we have a DN */
  if ((dn == NULL) || (strcasecmp(dn, "unknown") == 0))
    return NULL;
  /* explode dn into { "uid=test", "ou=people", ..., NULL } */
  exploded_dn = ldap_explode_dn(dn, LDAP_DN_FORMAT_LDAPV3);
  if ((exploded_dn == NULL) || (exploded_dn[0] == NULL))
  {
    log_log(LOG_WARNING, "ldap_explode_dn(%s) returned NULL: %s",
            dn, strerror(errno));
    return NULL;
  }
  /* explode rdn (first part of exploded_dn),
     e.g. "cn=Test User+uid=testusr" into
     { "cn=Test User", "uid=testusr", NULL } */
  errno = 0;
  exploded_rdn = ldap_explode_rdn(exploded_dn[0], LDAP_DN_FORMAT_LDAPV3);
  if ((exploded_rdn == NULL) || (exploded_rdn[0] == NULL))
  {
    log_log(LOG_WARNING, "ldap_explode_rdn(%s) returned NULL: %s",
            exploded_dn[0], strerror(errno));
    if (exploded_rdn != NULL)
      ldap_value_free(exploded_rdn);
    ldap_value_free(exploded_dn);
    return NULL;
  }
  ldap_value_free(exploded_dn);
  return exploded_rdn;
}

const char *myldap_get_rdn_value(MYLDAP_ENTRY *entry, const char *attr)
{
  /* check parameters */
  if (!is_valid_entry(entry))
  {
    log_log(LOG_ERR, "myldap_get_rdn_value(): invalid result entry passed");
    errno = EINVAL;
    return NULL;
  }
  else if (attr == NULL)
  {
    log_log(LOG_ERR, "myldap_get_rdn_value(): invalid attribute name passed");
    errno = EINVAL;
    return NULL;
  }
  /* check if entry contains exploded_rdn */
  if (entry->exploded_rdn == NULL)
  {
    entry->exploded_rdn = get_exploded_rdn(myldap_get_dn(entry));
    if (entry->exploded_rdn == NULL)
      return NULL;
  }
  /* find rnd value */
  return find_rdn_value(entry->exploded_rdn, attr);
}

const char *myldap_cpy_rdn_value(const char *dn, const char *attr,
                                 char *buf, size_t buflen)
{
  char **exploded_rdn;
  const char *value;
  /* explode dn into { "cn=Test", "uid=test", NULL } */
  exploded_rdn = get_exploded_rdn(dn);
  if (exploded_rdn == NULL)
    return NULL;
  /* see if we have a match */
  value = find_rdn_value(exploded_rdn, attr);
  /* if we have something store it in the buffer */
  if ((value != NULL) && (strlen(value) < buflen))
    strcpy(buf, value);
  else
    value = NULL;
  /* free allocated stuff */
  ldap_value_free(exploded_rdn);
  /* check if we have something to return */
  return (value != NULL) ? buf : NULL;
}

int myldap_has_objectclass(MYLDAP_ENTRY *entry, const char *objectclass)
{
  const char **values;
  int i;
  if ((!is_valid_entry(entry)) || (objectclass == NULL))
  {
    log_log(LOG_ERR, "myldap_has_objectclass(): invalid argument passed");
    errno = EINVAL;
    return 0;
  }
  values = myldap_get_values(entry, "objectClass");
  if (values == NULL)
    return 0;
  for (i = 0; values[i] != NULL; i++)
  {
    if (strcasecmp(values[i], objectclass) == 0)
      return -1;
  }
  return 0;
}

#ifdef HAVE_LDAP_PARSE_DEREF_CONTROL
const char ***myldap_get_deref_values(MYLDAP_ENTRY *entry,
                const char *derefattr, const char *getattr)
{
  LDAPControl **entryctrls;
  LDAPDerefRes *deref, *d;
  LDAPDerefVal *a;
  int i, pass;
  int rc;
  int found;
  int counts[2];
  size_t sizes[2], size;
  char *buffer = NULL;
  char ***results = NULL;
  rc = ldap_get_entry_controls(entry->search->session->ld, entry->search->msg,
                                &entryctrls);
  if (rc != LDAP_SUCCESS)
  {
    myldap_err(LOG_WARNING, entry->search->session->ld, rc,
               "ldap_get_entry_controls() failed");
    return NULL;
  }
  if (entryctrls == NULL)
    return NULL;
  /* see if we can find a deref control */
  rc = ldap_parse_deref_control(entry->search->session->ld, entryctrls,
                                &deref);
  if ((rc != LDAP_SUCCESS) || (deref == NULL))
  {
    if ((rc != LDAP_SUCCESS) && (rc != LDAP_CONTROL_NOT_FOUND))
      myldap_err(LOG_WARNING, entry->search->session->ld, rc,
                 "ldap_parse_deref_control() failed");
    /* clear error flag */
    rc = LDAP_SUCCESS;
    if (ldap_set_option(entry->search->session->ld, LDAP_OPT_ERROR_NUMBER,
                        &rc) != LDAP_SUCCESS)
      log_log(LOG_WARNING, "failed to clear the error flag");
    ldap_controls_free(entryctrls);
    return NULL;
  }
  /* two passes: one to calculate size, one to store data */
  for (pass=0; pass < 2; pass++)
  {
    /* reset counters and size */
    for (i = 0; i < 2; i++)
    {
      counts[i] = 0;
      sizes[i] = 0;
    }
    /* go over all deref'd attributes and find the one we're looking for */
    for (d = deref; d != NULL; d = d->next)
      if ((d->derefAttr != NULL) && (d->derefVal.bv_val != NULL) &&
          (strcasecmp(derefattr, d->derefAttr) == 0))
      {
        /* we should have one d per original attribute value */
        found = 0;
        /* go over deref'd attribute values to find the ones we're looking for */
        for (a = d->attrVals; a != NULL; a = a->next)
          if ((a->type != NULL) && (a->vals != NULL) &&
              (strcasecmp(getattr, a->type) == 0))
            for (i=0; a->vals[i].bv_val != NULL; i++)
            {
              found = 1;
              if (results == NULL)
              {
                log_log(LOG_DEBUG, "deref %s %s=%s -> %s=%s",
                        myldap_get_dn(entry),  d->derefAttr, d->derefVal.bv_val,
                        a->type, a->vals[i].bv_val);
                counts[0]++;
                sizes[0] += strlen(a->vals[i].bv_val) + 1;
              }
              else
              {
                strcpy(buffer, a->vals[i].bv_val);
                results[0][counts[0]++] = buffer;
                buffer += strlen(buffer) + 1;
              }
            }
        if (!found)
        {
          if (results == NULL)
          {
            log_log(LOG_DEBUG, "no %s deref %s %s=%s", getattr,
                    myldap_get_dn(entry),  d->derefAttr, d->derefVal.bv_val);
            counts[1]++;
            sizes[1] += strlen(d->derefVal.bv_val) + 1;
          }
          else
          {
            strcpy(buffer, d->derefVal.bv_val);
            results[1][counts[1]++] = buffer;
            buffer += strlen(buffer) + 1;
          }
        }
      }
    /* allocate memory after first pass */
    if (results == NULL)
    {
      size = sizeof(char **) * 3;
      for (i = 0; i < 2; i++)
        size += sizeof(char *) * (counts[i] + 1);
      for (i = 0; i < 2; i++)
        size += sizeof(char) * sizes[i];
      buffer = (char *)malloc(size);
      if (buffer == NULL)
      {
        log_log(LOG_CRIT, "myldap_get_deref_values(): malloc() failed to allocate memory");
        return NULL;
      }
      /* allocate the list of lists */
      results = (void *)buffer;
      buffer += sizeof(char **) * 3;
      /* allocate the lists */
      for (i = 0; i < 2; i++)
      {
        results[i] = (char **)buffer;
        buffer += sizeof(char *) * (counts[i] + 1);
      }
      results[i] = NULL;
    }
  }
  /* NULL terminate the lists */
  results[0][counts[0]] = NULL;
  results[1][counts[1]] = NULL;
  /* free control data */
  ldap_derefresponse_free(deref);
  ldap_controls_free(entryctrls);
  /* store results so we can free it later on */
  for (i = 0; i < MAX_BUFFERS_PER_ENTRY; i++)
    if (entry->buffers[i] == NULL)
    {
      entry->buffers[i] = (void *)results;
      return (const char ***)results;
    }
  /* we found no room to store the values */
  log_log(LOG_ERR, "myldap_get_deref_values() couldn't store results, "
          "increase MAX_BUFFERS_PER_ENTRY");
  free(results);
  return NULL;
}
#else /* not HAVE_LDAP_PARSE_DEREF_CONTROL */
const char ***myldap_get_deref_values(MYLDAP_ENTRY UNUSED(*entry),
                const char UNUSED(*derefattr), const char UNUSED(*getattr))
{
  return NULL;
}
#endif /* not HAVE_LDAP_PARSE_DEREF_CONTROL */

int myldap_escape(const char *src, char *buffer, size_t buflen)
{
  size_t pos = 0;
  /* go over all characters in source string */
  for (; *src != '\0'; src++)
  {
    /* check if char will fit */
    if ((pos + 4) >= buflen)
      return -1;
    /* do escaping for some characters */
    switch (*src)
    {
      case '*':
        strcpy(buffer + pos, "\\2a");
        pos += 3;
        break;
      case '(':
        strcpy(buffer + pos, "\\28");
        pos += 3;
        break;
      case ')':
        strcpy(buffer + pos, "\\29");
        pos += 3;
        break;
      case '\\':
        strcpy(buffer + pos, "\\5c");
        pos += 3;
        break;
      default:
        /* just copy character */
        buffer[pos++] = *src;
        break;
    }
  }
  /* terminate destination string */
  buffer[pos] = '\0';
  return 0;
}

int myldap_set_debuglevel(int level)
{
  int i;
  int rc;
  /* turn on debugging */
  if (level > 1)
  {
#ifdef LBER_OPT_LOG_PRINT_FILE
    log_log(LOG_DEBUG, "ber_set_option(LBER_OPT_LOG_PRINT_FILE)");
    rc = ber_set_option(NULL, LBER_OPT_LOG_PRINT_FILE, stderr);
    if (rc != LDAP_SUCCESS)
    {
      myldap_err(LOG_ERR, NULL, rc, "ber_set_option(LBER_OPT_LOG_PRINT_FILE) failed");
      return rc;
    }
#endif /* LBER_OPT_LOG_PRINT_FILE */
#ifdef LBER_OPT_DEBUG_LEVEL
    if (level > 2)
    {
      i = -1;
      log_log(LOG_DEBUG, "ber_set_option(LBER_OPT_DEBUG_LEVEL,-1)");
      rc = ber_set_option(NULL, LBER_OPT_DEBUG_LEVEL, &i);
      if (rc != LDAP_SUCCESS)
      {
        myldap_err(LOG_ERR, NULL, rc, "ber_set_option(LBER_OPT_DEBUG_LEVEL) failed");
        return rc;
      }
    }
#endif /* LBER_OPT_DEBUG_LEVEL */
#ifdef LDAP_OPT_DEBUG_LEVEL
    i = -1;
    log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_DEBUG_LEVEL,-1)");
    rc = ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &i);
    if (rc != LDAP_SUCCESS)
    {
      myldap_err(LOG_ERR, NULL, rc, "ldap_set_option(LDAP_OPT_DEBUG_LEVEL) failed");
      return rc;
    }
#endif /* LDAP_OPT_DEBUG_LEVEL */
  }
  return LDAP_SUCCESS;
}

int myldap_passwd(MYLDAP_SESSION *session,
                  const char *userdn, const char *oldpassword,
                  const char *newpasswd)
{
  int rc;
  struct berval ber_userdn, ber_oldpassword, ber_newpassword, ber_retpassword;
  /* check parameters */
  if ((session == NULL) || (userdn == NULL) || (newpasswd == NULL))
  {
    log_log(LOG_ERR, "myldap_passwd(): invalid parameter passed");
    errno = EINVAL;
    return LDAP_OTHER;
  }
  /* log the call */
  log_log(LOG_DEBUG, "myldap_passwd(userdn=\"%s\",oldpasswd=%s,newpasswd=\"***\")",
          userdn, oldpassword ? "\"***\"" : "NULL");
  /* translate to ber stuff */
  ber_userdn.bv_val = (char *)userdn;
  ber_userdn.bv_len = strlen(userdn);
  ber_newpassword.bv_val = (char *)newpasswd;
  ber_newpassword.bv_len = strlen(newpasswd);
  ber_retpassword.bv_val = NULL;
  ber_retpassword.bv_len = 0;
  /* perform request */
  log_log(LOG_DEBUG, "myldap_passwd(): try ldap_passwd_s() without old password");
  rc = ldap_passwd_s(session->ld, &ber_userdn, NULL, &ber_newpassword,
                     &ber_retpassword, NULL, NULL);
  if (rc != LDAP_SUCCESS)
    myldap_err(LOG_ERR, session->ld, rc, "ldap_passwd_s() without old password failed");
  /* free returned data if needed */
  if (ber_retpassword.bv_val != NULL)
    ldap_memfree(ber_retpassword.bv_val);
  if ((rc != LDAP_SUCCESS) && (oldpassword != NULL))
  {
    /* retry with old password */
    log_log(LOG_DEBUG, "myldap_passwd(): try ldap_passwd_s() with old password");
    ber_oldpassword.bv_val = (char *)oldpassword;
    ber_oldpassword.bv_len = strlen(oldpassword);
    /* perform request */
    rc = ldap_passwd_s(session->ld, &ber_userdn, &ber_oldpassword,
                       &ber_newpassword, &ber_retpassword, NULL, NULL);
    if (rc != LDAP_SUCCESS)
      myldap_err(LOG_ERR, session->ld, rc, "ldap_passwd_s() with old password failed");
    /* free returned data if needed */
    if (ber_retpassword.bv_val != NULL)
      ldap_memfree(ber_retpassword.bv_val);
  }
  return rc;
}

int myldap_modify(MYLDAP_SESSION *session, const char *dn, LDAPMod * mods[])
{
  if ((session == NULL) || (dn == NULL))
  {
    log_log(LOG_ERR, "myldap_passwd(): invalid parameter passed");
    errno = EINVAL;
    return LDAP_OTHER;
  }
  return ldap_modify_ext_s(session->ld, dn, mods, NULL, NULL);
}

int myldap_error_message(MYLDAP_SESSION *session, int rc,
                         char *buffer, size_t buflen)
{
  char *msg_diag = NULL;
  if ((session == NULL) || (buffer == NULL) || (buflen <= 0))
  {
    log_log(LOG_ERR, "myldap_error_message(): invalid parameter passed");
    errno = EINVAL;
    return LDAP_OTHER;
  }
  /* clear buffer */
  buffer[0] = '\0';
#ifdef LDAP_OPT_DIAGNOSTIC_MESSAGE
  if (session->ld != NULL)
    ldap_get_option(session->ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, &msg_diag);
#endif /* LDAP_OPT_DIAGNOSTIC_MESSAGE */
  /* return msg_diag or generic error message */
  mysnprintf(buffer, buflen - 1, "%s",
             ((msg_diag != NULL) && (msg_diag[0]!='\0')) ?
             msg_diag : ldap_err2string(rc));
  /* free diagnostic message */
  if (msg_diag != NULL)
    ldap_memfree(msg_diag);
  return LDAP_SUCCESS;
}
