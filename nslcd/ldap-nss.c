/*
   ldap-nss.c - main file for NSS interface
   This file was part of the nss_ldap library which has been
   forked into the nss-ldapd library.

   Copyright (C) 1997-2006 Luke Howard
   Copyright (C) 2006, 2007 West Consulting
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

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <stdio.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <errno.h>
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#include <netinet/in.h>
#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif
#ifdef HAVE_LDAP_SSL_H
#include <ldap_ssl.h>
#endif
#ifdef HAVE_GSSLDAP_H
#include <gssldap.h>
#endif
#ifdef HAVE_GSSSASL_H
#include <gsssasl.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#if defined(HAVE_THREAD_H)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif
/* Try to handle systems with both SASL libraries installed */
#if defined(HAVE_SASL_SASL_H) && defined(HAVE_SASL_AUXPROP_REQUEST)
#include <sasl/sasl.h>
#elif defined(HAVE_SASL_H)
#include <sasl.h>
#endif
#ifdef HAVE_GSSAPI_H
#include <gssapi.h>
#elif defined(HAVE_GSSAPI_GSSAPI_KRB5_H)
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#endif

#include "ldap-nss.h"
#include "util.h"
#include "dnsconfig.h"
#include "pagectrl.h"
#include "common.h"
#include "log.h"

/* how many messages to retrieve results for */
#ifndef LDAP_MSG_ONE
#define LDAP_MSG_ONE            0x00
#endif
#ifndef LDAP_MSG_ALL
#define LDAP_MSG_ALL            0x01
#endif
#ifndef LDAP_MSG_RECEIVED
#define LDAP_MSG_RECEIVED       0x02
#endif

#ifdef HAVE_LDAP_LD_FREE
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
extern int ldap_ld_free (LDAP * ld, int close, LDAPControl **,
                         LDAPControl **);
#else
extern int ldap_ld_free (LDAP * ld, int close);
#endif /* OPENLDAP 2.x */
#endif /* HAVE_LDAP_LD_FREE */

NSS_LDAP_DEFINE_LOCK (__lock);

/*
 * LS_INIT only used for enumeration contexts
 */
#define LS_INIT(state)  do { state.ls_type = LS_TYPE_INDEX; state.ls_retry = 0; state.ls_info.ls_index = -1; } while (0)

/*
 * the configuration is read by the first call to do_open().
 * Pointers to elements of the list are passed around but should not
 * be freed.
 */
static char __configbuf[NSS_LDAP_CONFIG_BUFSIZ];
static struct ldap_config *__config = NULL;

#ifdef HAVE_SIGACTION
static struct sigaction __stored_handler;
static int __sigaction_retval = -1;
#else
static void (*__sigpipe_handler) (int) = SIG_DFL;
#endif /* HAVE_SIGACTION */

/*
 * Global LDAP session.
 */
static struct ldap_session __session = { NULL, NULL, 0, LS_UNINITIALIZED };

#ifdef LBER_OPT_LOG_PRINT_FILE
static FILE *__debugfile;
#endif /* LBER_OPT_LOG_PRINT_FILE */

#ifdef HAVE_LDAPSSL_CLIENT_INIT
static int __ssl_initialized = 0;
#endif /* HAVE_LDAPSSL_CLIENT_INIT */

/*
 * Close the global session, sending an unbind.
 */
static void do_close (void);

/*
 * Disable keepalive on a LDAP connection's socket.
 */
static void do_set_sockopts (void);

/*
 * TLS routines: set global SSL session options.
 */
#if defined(HAVE_LDAP_START_TLS_S) || defined(HAVE_LDAP_START_TLS) || (defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS))
static int do_ssl_options (struct ldap_config * cfg);
static int do_start_tls (struct ldap_session * session);
#endif

/*
 * Function to be braced by reconnect harness. Used so we
 * can apply the reconnect code to both asynchronous and
 * synchronous searches.
 */
typedef int (*search_func_t) (const char *, int, const char *,
                              const char **, int, void *);

static enum nss_status
do_map_error (int rc)
{
  enum nss_status stat;

  switch (rc)
    {
    case LDAP_SUCCESS:
    case LDAP_SIZELIMIT_EXCEEDED:
    case LDAP_TIMELIMIT_EXCEEDED:
      stat = NSS_STATUS_SUCCESS;
      break;
    case LDAP_NO_SUCH_ATTRIBUTE:
    case LDAP_UNDEFINED_TYPE:
    case LDAP_INAPPROPRIATE_MATCHING:
    case LDAP_CONSTRAINT_VIOLATION:
    case LDAP_TYPE_OR_VALUE_EXISTS:
    case LDAP_INVALID_SYNTAX:
    case LDAP_NO_SUCH_OBJECT:
    case LDAP_ALIAS_PROBLEM:
    case LDAP_INVALID_DN_SYNTAX:
    case LDAP_IS_LEAF:
    case LDAP_ALIAS_DEREF_PROBLEM:
    case LDAP_FILTER_ERROR:
      stat = NSS_STATUS_NOTFOUND;
      break;
    case LDAP_SERVER_DOWN:
    case LDAP_TIMEOUT:
    case LDAP_UNAVAILABLE:
    case LDAP_BUSY:
#ifdef LDAP_CONNECT_ERROR
    case LDAP_CONNECT_ERROR:
#endif /* LDAP_CONNECT_ERROR */
    case LDAP_LOCAL_ERROR:
    case LDAP_INVALID_CREDENTIALS:
    default:
      stat = NSS_STATUS_UNAVAIL;
      break;
    }
  return stat;
}

#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) ||defined (HAVE_SASL_SASL_H))
static int
do_sasl_interact (LDAP * ld, unsigned flags, void *defaults, void *_interact)
{
  char *authzid = (char *) defaults;
  sasl_interact_t *interact = (sasl_interact_t *) _interact;

  while (interact->id != SASL_CB_LIST_END)
    {
      if (interact->id == SASL_CB_USER)
        {
          if (authzid != NULL)
            {
              interact->result = authzid;
              interact->len = strlen (authzid);
            }
          else if (interact->defresult != NULL)
            {
              interact->result = interact->defresult;
              interact->len = strlen (interact->defresult);
            }
          else
            {
              interact->result = "";
              interact->len = 0;
            }
#if SASL_VERSION_MAJOR < 2
          interact->result = strdup (interact->result);
          if (interact->result == NULL)
            {
              return LDAP_NO_MEMORY;
            }
#endif /* SASL_VERSION_MAJOR < 2 */
        }
      else
        {
          return LDAP_PARAM_ERROR;
        }
      interact++;
    }
  return LDAP_SUCCESS;
}
#endif

static int
do_bind (LDAP * ld, int timelimit, const char *dn, const char *pw,
         int with_sasl)
{
  int rc;
  int msgid;
  struct timeval tv;
  LDAPMessage *result;

  log_log(LOG_DEBUG,"==> do_bind");

  /*
   * set timelimit in ld for select() call in ldap_pvt_connect()
   * function implemented in libldap2's os-ip.c
   */
  tv.tv_sec = timelimit;
  tv.tv_usec = 0;

#if (defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))) || defined(HAVE_LDAP_GSS_BIND)
  if (!with_sasl)
    {
#endif
      msgid = ldap_simple_bind (ld, dn, pw);

      if (msgid < 0)
        {
          if (ldap_get_option (ld, LDAP_OPT_ERROR_NUMBER, &rc) !=
              LDAP_SUCCESS)
            {
              rc = LDAP_UNAVAILABLE;
            }
          /* Notify if we failed. */
          syslog (LOG_AUTHPRIV | LOG_ERR, "nss_ldap: could not connect to any LDAP server as %s - %s",
                          dn, ldap_err2string (rc));
          log_log(LOG_DEBUG,"<== do_bind");

          return rc;
        }

      rc = ldap_result (ld, msgid, 0, &tv, &result);
      if (rc > 0)
        {
          log_log(LOG_DEBUG,"<== do_bind");
          return ldap_result2error (ld, result, 1);
        }

      /* took too long */
      if (rc == 0)
        {
          ldap_abandon (ld, msgid);
        }
#if (defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))) || defined(HAVE_LDAP_GSS_BIND)
    }
  else
    {
#ifdef HAVE_LDAP_GSS_BIND
      return ldap_gss_bind (ld, dn, pw, GSSSASL_NO_SECURITY_LAYER,
                            LDAP_SASL_GSSAPI);
#else
#ifdef CONFIGURE_KRB5_CCNAME
#ifndef CONFIGURE_KRB5_CCNAME_GSSAPI
      char tmpbuf[256];
      static char envbuf[256];
#endif
      char *ccname;
      const char *oldccname = NULL;
      int retval;
#endif /* CONFIGURE_KRB5_CCNAME */

      if (__config->ldc_sasl_secprops != NULL)
        {
          rc =
            ldap_set_option (ld, LDAP_OPT_X_SASL_SECPROPS,
                             (void *) __config->ldc_sasl_secprops);
          if (rc != LDAP_SUCCESS)
            {
              log_log(LOG_DEBUG,"do_bind: unable to set SASL security properties");
              return rc;
            }
        }

#ifdef CONFIGURE_KRB5_CCNAME
      /* Set default Kerberos ticket cache for SASL-GSSAPI */
      /* There are probably race conditions here XXX */
      if (__config->ldc_krb5_ccname != NULL)
        {
          ccname = __config->ldc_krb5_ccname;
#ifdef CONFIGURE_KRB5_CCNAME_ENV
          oldccname = getenv ("KRB5CCNAME");
          if (oldccname != NULL)
            {
              strncpy (tmpbuf, oldccname, sizeof (tmpbuf));
              tmpbuf[sizeof (tmpbuf) - 1] = '\0';
            }
          else
            {
              tmpbuf[0] = '\0';
            }
          oldccname = tmpbuf;
          snprintf (envbuf, sizeof (envbuf), "KRB5CCNAME=%s", ccname);
          putenv (envbuf);
#elif defined(CONFIGURE_KRB5_CCNAME_GSSAPI)
          if (gss_krb5_ccache_name (&retval, ccname, &oldccname) !=
              GSS_S_COMPLETE)
            {
              log_log(LOG_DEBUG,"do_bind: unable to set default credential cache");
              return -1;
            }
#endif
        }
#endif /* CONFIGURE_KRB5_CCNAME */

      rc = ldap_sasl_interactive_bind_s (ld, dn, "GSSAPI", NULL, NULL,
                                         LDAP_SASL_QUIET,
                                         do_sasl_interact, (void *) pw);

#ifdef CONFIGURE_KRB5_CCNAME
      /* Restore default Kerberos ticket cache. */
      if (oldccname != NULL)
        {
#ifdef CONFIGURE_KRB5_CCNAME_ENV
          snprintf (envbuf, sizeof (envbuf), "KRB5CCNAME=%s", oldccname);
          putenv (envbuf);
#elif defined(CONFIGURE_KRB5_CCNAME_GSSAPI)
          if (gss_krb5_ccache_name (&retval, oldccname, NULL) !=
              GSS_S_COMPLETE)
            {
              log_log(LOG_DEBUG,"do_bind: unable to restore default credential cache");
              return -1;
            }
#endif
        }
#endif /* CONFIGURE_KRB5_CCNAME */

      return rc;
#endif /* HAVE_LDAP_GSS_BIND */
    }
#endif

  log_log(LOG_DEBUG,"<== do_bind");

  return -1;
}

/*
 * Rebind functions.
 */

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
#if LDAP_SET_REBIND_PROC_ARGS == 3
static int
do_rebind (LDAP * ld, LDAP_CONST char *url, ber_tag_t request,
           ber_int_t msgid, void *arg)
#else
static int
do_rebind (LDAP * ld, LDAP_CONST char *url, int request, ber_int_t msgid)
#endif
{
  char *who, *cred;
  int timelimit;
  int with_sasl = 0;

  if (geteuid () == 0 && __session.ls_config->ldc_rootbinddn)
    {
      who = __session.ls_config->ldc_rootbinddn;
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
      with_sasl = __session.ls_config->ldc_rootusesasl;
      if (with_sasl)
        {
          cred = __session.ls_config->ldc_rootsaslid;
        }
      else
        {
#endif
          cred = __session.ls_config->ldc_rootbindpw;
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
        }
#endif
    }
  else
    {
      who = __session.ls_config->ldc_binddn;
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
      with_sasl = __session.ls_config->ldc_usesasl;
      if (with_sasl)
        {
          cred = __session.ls_config->ldc_saslid;
        }
      else
        {
#endif
          cred = __session.ls_config->ldc_bindpw;
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
        }
#endif
    }

  timelimit = __session.ls_config->ldc_bind_timelimit;

#ifdef HAVE_LDAP_START_TLS_S
  if (__session.ls_config->ldc_ssl_on == SSL_START_TLS)
    {
      int version;

      if (ldap_get_option
          (__session.ls_conn, LDAP_OPT_PROTOCOL_VERSION,
           &version) == LDAP_OPT_SUCCESS)
        {
          if (version < LDAP_VERSION3)
            {
              version = LDAP_VERSION3;
              ldap_set_option (__session.ls_conn, LDAP_OPT_PROTOCOL_VERSION,
                               &version);
            }
        }

      if (do_start_tls (&__session) == LDAP_SUCCESS)
        {
          log_log(LOG_DEBUG,"TLS startup succeeded");
        }
      else
        {
          log_log(LOG_DEBUG,"TLS startup failed");
          return NSS_STATUS_UNAVAIL;
        }
    }
#endif /* HAVE_LDAP_START_TLS_S */

  return do_bind (ld, timelimit, who, cred, with_sasl);
}
#else
#if LDAP_SET_REBIND_PROC_ARGS == 3
static int
do_rebind (LDAP * ld, char **whop, char **credp, int *methodp,
           int freeit, void *arg)
#elif LDAP_SET_REBIND_PROC_ARGS == 2
static int
do_rebind (LDAP * ld, char **whop, char **credp, int *methodp, int freeit)
#endif
{
  if (freeit)
    {
      if (*whop != NULL)
        free (*whop);
      if (*credp != NULL)
        free (*credp);
    }

  *whop = *credp = NULL;
  if (geteuid () == 0 && __session.ls_config->ldc_rootbinddn)
    {
      *whop = strdup (__session.ls_config->ldc_rootbinddn);
      if (__session.ls_config->ldc_rootbindpw != NULL)
        *credp = strdup (__session.ls_config->ldc_rootbindpw);
    }
  else
    {
      if (__session.ls_config->ldc_binddn != NULL)
        *whop = strdup (__session.ls_config->ldc_binddn);
      if (__session.ls_config->ldc_bindpw != NULL)
        *credp = strdup (__session.ls_config->ldc_bindpw);
    }

  *methodp = LDAP_AUTH_SIMPLE;

  return LDAP_SUCCESS;
}
#endif

static void
_nss_ldap_block_sigpipe (void)
{
#ifdef HAVE_SIGACTION
  struct sigaction new_handler;

  memset (&new_handler, 0, sizeof (new_handler));
#if 0
  /* XXX need to test for sa_sigaction, not on all platforms */
  new_handler.sa_sigaction = NULL;
#endif
  new_handler.sa_handler = SIG_IGN;
  sigemptyset (&new_handler.sa_mask);
  new_handler.sa_flags = 0;
#endif /* HAVE_SIGACTION */

  /*
   * Patch for Debian Bug 130006:
   * ignore SIGPIPE for all LDAP operations.
   *
   * The following bug was reintroduced in nss_ldap-213 and is fixed here:
   * http://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=84344
   *
   * See:
   * http://www.gnu.org/software/libc/manual/html_node/Signal-and-Sigaction.html
   * for more details.
   */
#ifdef HAVE_SIGACTION
  __sigaction_retval = sigaction (SIGPIPE, &new_handler, &__stored_handler);
#elif defined(HAVE_SIGSET)
  __sigpipe_handler = sigset (SIGPIPE, SIG_IGN);
#else
  __sigpipe_handler = signal (SIGPIPE, SIG_IGN);
#endif /* HAVE_SIGSET */
}

static void
_nss_ldap_unblock_sigpipe (void)
{
#ifdef HAVE_SIGACTION
  if (__sigaction_retval == 0)
    (void) sigaction (SIGPIPE, &__stored_handler, NULL);
#else
  if (__sigpipe_handler != SIG_ERR && __sigpipe_handler != SIG_IGN)
    {
#ifdef HAVE_SIGSET
      (void) sigset (SIGPIPE, __sigpipe_handler);
#else
      (void) signal (SIGPIPE, __sigpipe_handler);
#endif /* HAVE_SIGSET */
    }
#endif /* HAVE_SIGACTION */
}

/*
 * Acquires global lock, blocks SIGPIPE.
 */
void
_nss_ldap_enter (void)
{
  log_log(LOG_DEBUG,"==> _nss_ldap_enter");

  NSS_LDAP_LOCK (__lock);
  _nss_ldap_block_sigpipe();

  log_log(LOG_DEBUG,"<== _nss_ldap_enter");
}

/*
 * Releases global mutex, releases SIGPIPE.
 */
void
_nss_ldap_leave (void)
{
  log_log(LOG_DEBUG,"==> _nss_ldap_leave");

  _nss_ldap_unblock_sigpipe();
  NSS_LDAP_UNLOCK (__lock);

  log_log(LOG_DEBUG,"<== _nss_ldap_leave");
}

static void
do_set_sockopts (void)
{
/*
 * Netscape SSL-enabled LDAP library does not
 * return the real socket.
 */
#ifndef HAVE_LDAPSSL_CLIENT_INIT
  int sd = -1;

  log_log(LOG_DEBUG,"==> do_set_sockopts");
  if (ldap_get_option (__session.ls_conn, LDAP_OPT_DESC, &sd) == 0)
    {
      int off = 0;
      socklen_t socknamelen = sizeof (struct sockaddr_storage);
      socklen_t peernamelen = sizeof (struct sockaddr_storage);

      (void) setsockopt (sd, SOL_SOCKET, SO_KEEPALIVE, (void *) &off,
                         sizeof (off));
      (void) fcntl (sd, F_SETFD, FD_CLOEXEC);
    }
  log_log(LOG_DEBUG,"<== do_set_sockopts");
#endif /* HAVE_LDAPSSL_CLIENT_INIT */

  return;
}

/*
 * Closes connection to the LDAP server.
 * This assumes that we have exclusive access to __session.ls_conn,
 * either by some other function having acquired a lock, or by
 * using a thread safe libldap.
 */
static void
do_close (void)
{
#if defined(DEBUG) || defined(DEBUG_SOCKETS)
  int sd = -1;
#endif

  log_log(LOG_DEBUG,"==> do_close");

  if (__session.ls_conn != NULL)
    {
#if defined(DEBUG) || defined(DEBUG_SOCKETS)
#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_DESC)
      ldap_get_option (__session.ls_conn, LDAP_OPT_DESC, &sd);
#else
      sd = __session.ls_conn->ld_sb.sb_sd;
#endif /* LDAP_OPT_DESC */
      syslog (LOG_AUTHPRIV | LOG_INFO, "nss_ldap: closing connection %p fd %d",
              (void *)__session.ls_conn, sd);
#endif /* DEBUG */

      ldap_unbind (__session.ls_conn);
      __session.ls_conn = NULL;
      __session.ls_state = LS_UNINITIALIZED;
    }

  log_log(LOG_DEBUG,"<== do_close");
}

static enum nss_status
do_init_session (LDAP ** ld, const char *uri, int defport)
{
  int rc;
  int ldaps;
  char uribuf[1024];
  char *p;
  enum nss_status stat;

  ldaps = (strncasecmp (uri, "ldaps://", sizeof ("ldaps://") - 1) == 0);
  p = strchr (uri, ':');
  /* we should be looking for the second instance to find the port number */
  if (p != NULL)
    {
      p = strchr (p, ':');
    }

#ifdef HAVE_LDAP_INITIALIZE
  if (p == NULL &&
      ((ldaps && defport != LDAPS_PORT) || (!ldaps && defport != LDAP_PORT)))
    {
      /* No port specified in URI and non-default port specified */
      snprintf (uribuf, sizeof (uribuf), "%s:%d", uri, defport);
      uri = uribuf;
    }

  rc = ldap_initialize (ld, uri);
#else
  if (strncasecmp (uri, "ldap://", sizeof ("ldap://") - 1) != 0)
    {
      return NSS_STATUS_UNAVAIL;
    }

  uri += sizeof ("ldap://") - 1;
  p = strchr (uri, ':');

  if (p != NULL)
    {
      size_t urilen = (p - uri);

      if (urilen >= sizeof (uribuf))
        {
          return NSS_STATUS_UNAVAIL;
        }

      memcpy (uribuf, uri, urilen);
      uribuf[urilen] = '\0';

      defport = atoi (p + 1);
      uri = uribuf;
    }

#ifdef HAVE_LDAP_INIT
  *ld = ldap_init (uri, defport);
#else
  *ld = ldap_open (uri, defport);
#endif

  rc = (*ld == NULL) ? LDAP_SERVER_DOWN : LDAP_SUCCESS;

#endif /* HAVE_LDAP_INITIALIZE */

  stat = do_map_error (rc);
  if (stat == NSS_STATUS_SUCCESS && *ld == NULL)
    {
      stat = NSS_STATUS_UNAVAIL;
    }
  return stat;
}

static enum nss_status
do_init (void)
{
  struct ldap_config *cfg;
  enum nss_status stat;

  log_log(LOG_DEBUG,"==> do_init");

  if (_nss_ldap_validateconfig (__config) != NSS_STATUS_SUCCESS)
    {
      do_close ();
      __config = NULL;
      __session.ls_current_uri = 0;
    }

  if (__session.ls_state == LS_CONNECTED_TO_DSA)
    {
      time_t current_time;

      /*
       * Otherwise we can hand back this process' global
       * LDAP session.
       *
       * Patch from Steven Barrus <sbarrus@eng.utah.edu> to
       * close the session after an idle timeout.
       */

      assert (__session.ls_conn != NULL);
      assert (__session.ls_config != NULL);

      if (__session.ls_config->ldc_idle_timelimit)
        {
          time (&current_time);
          if ((__session.ls_timestamp +
               __session.ls_config->ldc_idle_timelimit) < current_time)
            {
              log_log(LOG_DEBUG,"idle_timelimit reached");
              do_close ();
            }
        }

      /*
       * If the connection is still there (ie. do_close() wasn't
       * called) then we can return the cached connection.
       */
      if (__session.ls_state == LS_CONNECTED_TO_DSA)
        {
          log_log(LOG_DEBUG,"<== do_init (cached session)");
          return NSS_STATUS_SUCCESS;
        }
    }

  __session.ls_conn = NULL;
  __session.ls_timestamp = 0;
  __session.ls_state = LS_UNINITIALIZED;

  /* Initialize schema and LDAP handle (but do not connect) */
  if (__config == NULL)
    {
      char *configbufp = __configbuf;
      size_t configbuflen = sizeof (__configbuf);

      stat = _nss_ldap_readconfig (&__config, &configbufp, &configbuflen);
      if (stat == NSS_STATUS_NOTFOUND)
        {
          /* Config was read but no host information specified; try DNS */
          stat = _nss_ldap_mergeconfigfromdns (__config, &configbufp, &configbuflen);
        }

      if (stat != NSS_STATUS_SUCCESS)
        {
          log_log(LOG_DEBUG,"<== do_init (failed to read config)");
          return NSS_STATUS_UNAVAIL;
        }
    }

  cfg = __config;

  _nss_ldap_init_attributes (cfg->ldc_attrtab);
  _nss_ldap_init_filters ();

#ifdef HAVE_LDAP_SET_OPTION
  if (cfg->ldc_debug)
    {
#ifdef LBER_OPT_LOG_PRINT_FILE
      if (cfg->ldc_logdir && !__debugfile)
        {
          char namebuf[PATH_MAX];

          snprintf (namebuf, sizeof (namebuf), "%s/ldap.%d", cfg->ldc_logdir,
                    (int) getpid ());
          __debugfile = fopen (namebuf, "a");

          if (__debugfile != NULL)
            {
              ber_set_option (NULL, LBER_OPT_LOG_PRINT_FILE, __debugfile);
            }
        }
#endif /* LBER_OPT_LOG_PRINT_FILE */
#ifdef LBER_OPT_DEBUG_LEVEL
      if (cfg->ldc_debug)
        {
          ber_set_option (NULL, LBER_OPT_DEBUG_LEVEL, &cfg->ldc_debug);
          ldap_set_option (NULL, LDAP_OPT_DEBUG_LEVEL, &cfg->ldc_debug);
        }
#endif /* LBER_OPT_DEBUG_LEVEL */
    }
#endif /* HAVE_LDAP_SET_OPTION */

#ifdef HAVE_LDAPSSL_CLIENT_INIT
  /*
   * Initialize the SSL library.
   */
  if (cfg->ldc_ssl_on == SSL_LDAPS)
    {
      int rc = 0;
      if (__ssl_initialized == 0
          && (rc = ldapssl_client_init (cfg->ldc_sslpath, NULL)) != LDAP_SUCCESS)
        {
          log_log(LOG_DEBUG,"<== do_init (ldapssl_client_init failed with rc = %d)", rc);
          return NSS_STATUS_UNAVAIL;
        }
      __ssl_initialized = 1;
    }
#endif /* SSL */

  __session.ls_conn = NULL;

  assert (__session.ls_current_uri <= NSS_LDAP_CONFIG_URI_MAX);
  assert (cfg->ldc_uris[__session.ls_current_uri] != NULL);

  stat = do_init_session (&__session.ls_conn,
                          cfg->ldc_uris[__session.ls_current_uri],
                          cfg->ldc_port);
  if (stat != NSS_STATUS_SUCCESS)
    {
      log_log(LOG_DEBUG,"<== do_init (failed to initialize LDAP session)");
      return stat;
    }

  __session.ls_config = cfg;
  __session.ls_state = LS_INITIALIZED;

  log_log(LOG_DEBUG,"<== do_init (initialized session)");

  return NSS_STATUS_SUCCESS;
}

/*
 * A simple alias around do_init().
 */
enum nss_status
_nss_ldap_init (void)
{
  return do_init ();
}

/*
 * A simple alias around do_close().
 */
void
_nss_ldap_close (void)
{
  do_close ();
}

#if defined(HAVE_LDAP_START_TLS_S) || defined(HAVE_LDAP_START_TLS)
static int
do_start_tls (struct ldap_session * session)
{
  int rc;
#ifdef HAVE_LDAP_START_TLS
  int msgid;
  struct timeval tv, *timeout;
  LDAPMessage *res = NULL;

  log_log(LOG_DEBUG,"==> do_start_tls");

  rc = ldap_start_tls (session->ls_conn, NULL, NULL, &msgid);
  if (rc != LDAP_SUCCESS)
    {
      log_log(LOG_DEBUG,"<== do_start_tls (ldap_start_tls failed: %s)", ldap_err2string (rc));
      return rc;
    }

  if (session->ls_config->ldc_bind_timelimit == LDAP_NO_LIMIT)
    {
      timeout = NULL;
    }
  else
    {
      tv.tv_sec = session->ls_config->ldc_bind_timelimit;
      tv.tv_usec = 0;
      timeout = &tv;
    }

  rc = ldap_result (session->ls_conn, msgid, 1, timeout, &res);
  if (rc == -1)
    {
#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_ERROR_NUMBER)
      if (ldap_get_option (session->ls_conn, LDAP_OPT_ERROR_NUMBER, &rc) != LDAP_SUCCESS)
        {
          rc = LDAP_UNAVAILABLE;
        }
#else
      rc = ld->ld_errno;
#endif /* LDAP_OPT_ERROR_NUMBER */

      log_log(LOG_DEBUG,"<== do_start_tls (ldap_start_tls failed: %s)", ldap_err2string (rc));
      return rc;
    }

  rc = ldap_result2error (session->ls_conn, res, 1);
  if (rc != LDAP_SUCCESS)
    {
      log_log(LOG_DEBUG,"<== do_start_tls (ldap_result2error failed: %s)", ldap_err2string (rc));
      return rc;
    }

  rc = ldap_install_tls (session->ls_conn);
#else
  rc = ldap_start_tls_s (session->ls_conn, NULL, NULL);
#endif /* HAVE_LDAP_START_TLS */

  if (rc != LDAP_SUCCESS)
    {
      log_log(LOG_DEBUG,"<== do_start_tls (start TLS failed: %s)", ldap_err2string(rc));
      return rc;
    }

  return LDAP_SUCCESS;
}
#endif

/*
 * Opens connection to an LDAP server - should only be called from search
 * API. Other API that just needs access to configuration and schema should
 * call do_init().
 *
 * As with do_close(), this assumes ownership of sess.
 * It also wants to own __config: is there a potential deadlock here? XXX
 */
static enum nss_status
do_open (void)
{
  struct ldap_config *cfg;
  int usesasl;
  char *bindarg;
  enum nss_status stat;
#ifdef LDAP_OPT_NETWORK_TIMEOUT
  struct timeval tv;
#endif
#ifdef LDAP_X_OPT_CONNECT_TIMEOUT
  int timeout;
#endif
  int rc;

  log_log(LOG_DEBUG,"==> do_open");

  /* Moved the head part of do_open() into do_init() */
  stat = do_init ();
  if (stat != NSS_STATUS_SUCCESS)
    {
      log_log(LOG_DEBUG,"<== do_open (session initialization failed)");
      return stat;
    }

  assert (__session.ls_conn != NULL);
  assert (__session.ls_config != NULL);
  assert (__session.ls_state != LS_UNINITIALIZED);

  if (__session.ls_state == LS_CONNECTED_TO_DSA)
    {
      log_log(LOG_DEBUG,"<== do_open (cached session)");
      return NSS_STATUS_SUCCESS;
    }

  cfg = __session.ls_config;

#if LDAP_SET_REBIND_PROC_ARGS == 3
  ldap_set_rebind_proc (__session.ls_conn, do_rebind, NULL);
#elif LDAP_SET_REBIND_PROC_ARGS == 2
  ldap_set_rebind_proc (__session.ls_conn, do_rebind);
#endif

  ldap_set_option (__session.ls_conn, LDAP_OPT_PROTOCOL_VERSION,
                   &cfg->ldc_version);

  ldap_set_option (__session.ls_conn, LDAP_OPT_DEREF, &cfg->ldc_deref);

  ldap_set_option (__session.ls_conn, LDAP_OPT_TIMELIMIT,
                   &cfg->ldc_timelimit);

#ifdef LDAP_X_OPT_CONNECT_TIMEOUT
  /*
   * This is a new option in the Netscape SDK which sets
   * the TCP connect timeout. For want of a better value,
   * we use the bind_timelimit to control this.
   */
  timeout = cfg->ldc_bind_timelimit * 1000;
  ldap_set_option (__session.ls_conn, LDAP_X_OPT_CONNECT_TIMEOUT, &timeout);
#endif /* LDAP_X_OPT_CONNECT_TIMEOUT */

#ifdef LDAP_OPT_NETWORK_TIMEOUT
  tv.tv_sec = cfg->ldc_bind_timelimit;
  tv.tv_usec = 0;
  ldap_set_option (__session.ls_conn, LDAP_OPT_NETWORK_TIMEOUT, &tv);
#endif /* LDAP_OPT_NETWORK_TIMEOUT */

#ifdef LDAP_OPT_REFERRALS
  ldap_set_option (__session.ls_conn, LDAP_OPT_REFERRALS,
                   cfg->ldc_referrals ? LDAP_OPT_ON : LDAP_OPT_OFF);
#endif /* LDAP_OPT_REFERRALS */

#ifdef LDAP_OPT_RESTART
  ldap_set_option (__session.ls_conn, LDAP_OPT_RESTART,
                   cfg->ldc_restart ? LDAP_OPT_ON : LDAP_OPT_OFF);
#endif /* LDAP_OPT_RESTART */

#if defined(HAVE_LDAP_START_TLS_S) || defined(HAVE_LDAP_START_TLS)
  if (cfg->ldc_ssl_on == SSL_START_TLS)
    {
      int version;

      if (ldap_get_option
          (__session.ls_conn, LDAP_OPT_PROTOCOL_VERSION,
           &version) == LDAP_OPT_SUCCESS)
        {
          if (version < LDAP_VERSION3)
            {
              version = LDAP_VERSION3;
              ldap_set_option (__session.ls_conn, LDAP_OPT_PROTOCOL_VERSION,
                               &version);
            }
        }

      /* set up SSL context */
      if (do_ssl_options (cfg) != LDAP_SUCCESS)
        {
          do_close ();
          log_log(LOG_DEBUG,"<== do_open (SSL setup failed)");
          return NSS_STATUS_UNAVAIL;
        }

      stat = do_map_error (do_start_tls (&__session));
      if (stat == NSS_STATUS_SUCCESS)
        {
          log_log(LOG_DEBUG,":== do_open (TLS startup succeeded)");
        }
      else
        {
          do_close ();
          log_log(LOG_DEBUG,"<== do_open (TLS startup failed)");
          return stat;
        }
    }
  else
#endif /* HAVE_LDAP_START_TLS_S || HAVE_LDAP_START_TLS */

    /*
     * If SSL is desired, then enable it.
     */
  if (cfg->ldc_ssl_on == SSL_LDAPS)
    {
#if defined(LDAP_OPT_X_TLS)
      int tls = LDAP_OPT_X_TLS_HARD;
      if (ldap_set_option (__session.ls_conn, LDAP_OPT_X_TLS, &tls) !=
          LDAP_SUCCESS)
        {
          do_close ();
          log_log(LOG_DEBUG,"<== do_open (TLS setup failed)");
          return NSS_STATUS_UNAVAIL;
        }

      /* set up SSL context */
      if (do_ssl_options (cfg) != LDAP_SUCCESS)
        {
          do_close ();
          log_log(LOG_DEBUG,"<== do_open (SSL setup failed)");
          return NSS_STATUS_UNAVAIL;
        }

#elif defined(HAVE_LDAPSSL_CLIENT_INIT)
      if (ldapssl_install_routines (__session.ls_conn) != LDAP_SUCCESS)
        {
          do_close ();
          log_log(LOG_DEBUG,"<== do_open (SSL setup failed)");
          return NSS_STATUS_UNAVAIL;
        }
/* not in Solaris 9? */
#ifndef LDAP_OPT_SSL
#define LDAP_OPT_SSL 0x0A
#endif
      if (ldap_set_option (__session.ls_conn, LDAP_OPT_SSL, LDAP_OPT_ON) !=
          LDAP_SUCCESS)
        {
          do_close ();
          log_log(LOG_DEBUG,"<== do_open (SSL setup failed)");
          return NSS_STATUS_UNAVAIL;
        }
#endif
    }

  /*
   * If we're running as root, let us bind as a special
   * user, so we can fake shadow passwords.
   * Thanks to Doug Nazar <nazard@dragoninc.on.ca> for this
   * patch.
   */
  if (geteuid() == 0 && cfg->ldc_rootbinddn != NULL)
    {
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
      usesasl = cfg->ldc_rootusesasl;
      bindarg =
        cfg->ldc_rootusesasl ? cfg->ldc_rootsaslid : cfg->ldc_rootbindpw;
#else
      usesasl = 0;
      bindarg = cfg->ldc_rootbindpw;
#endif

      rc = do_bind (__session.ls_conn,
                    cfg->ldc_bind_timelimit,
                    cfg->ldc_rootbinddn, bindarg, usesasl);
    }
  else
    {
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
      usesasl = cfg->ldc_usesasl;
      bindarg = cfg->ldc_usesasl ? cfg->ldc_saslid : cfg->ldc_bindpw;
#else
      usesasl = 0;
      bindarg = cfg->ldc_bindpw;
#endif

      rc = do_bind (__session.ls_conn,
                    cfg->ldc_bind_timelimit,
                    cfg->ldc_binddn,
                    cfg->ldc_bindpw, usesasl);
    }

  if (rc != LDAP_SUCCESS)
    {
      /* log actual LDAP error code */
      syslog (LOG_AUTHPRIV | LOG_INFO,
              "nss_ldap: failed to bind to LDAP server %s: %s",
              cfg->ldc_uris[__session.ls_current_uri],
              ldap_err2string (rc));
      stat = do_map_error (rc);
      do_close ();
      log_log(LOG_DEBUG,"<== do_open (failed to bind to DSA");
    }
  else
    {
      do_set_sockopts ();
      time (&__session.ls_timestamp);
      __session.ls_state = LS_CONNECTED_TO_DSA;
      stat = NSS_STATUS_SUCCESS;
      log_log(LOG_DEBUG,"<== do_open (session connected to DSA)");
    }

  return stat;
}

#if defined HAVE_LDAP_START_TLS_S || (defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS))
static int
do_ssl_options (struct ldap_config * cfg)
{
  int rc;

  log_log(LOG_DEBUG,"==> do_ssl_options");

#ifdef LDAP_OPT_X_TLS_RANDOM_FILE
  if (cfg->ldc_tls_randfile != NULL)
    {
      /* rand file */
      rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_RANDOM_FILE,
                            cfg->ldc_tls_randfile);
      if (rc != LDAP_SUCCESS)
        {
          log_log(LOG_DEBUG,"<== do_ssl_options: Setting of LDAP_OPT_X_TLS_RANDOM_FILE failed");
          return LDAP_OPERATIONS_ERROR;
        }
    }
#endif /* LDAP_OPT_X_TLS_RANDOM_FILE */

  if (cfg->ldc_tls_cacertfile != NULL)
    {
      /* ca cert file */
      rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTFILE,
                            cfg->ldc_tls_cacertfile);
      if (rc != LDAP_SUCCESS)
        {
          log_log(LOG_DEBUG,"<== do_ssl_options: Setting of LDAP_OPT_X_TLS_CACERTFILE failed");
          return LDAP_OPERATIONS_ERROR;
        }
    }

  if (cfg->ldc_tls_cacertdir != NULL)
    {
      /* ca cert directory */
      rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTDIR,
                            cfg->ldc_tls_cacertdir);
      if (rc != LDAP_SUCCESS)
        {
          log_log(LOG_DEBUG,"<== do_ssl_options: Setting of LDAP_OPT_X_TLS_CACERTDIR failed");
          return LDAP_OPERATIONS_ERROR;
        }
    }

  /* require cert? */
  if (cfg->ldc_tls_checkpeer > -1)
    {
      rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_REQUIRE_CERT,
                            &cfg->ldc_tls_checkpeer);
      if (rc != LDAP_SUCCESS)
        {
          log_log(LOG_DEBUG,"<== do_ssl_options: Setting of LDAP_OPT_X_TLS_REQUIRE_CERT failed");
          return LDAP_OPERATIONS_ERROR;
        }
    }

  if (cfg->ldc_tls_ciphers != NULL)
    {
      /* set cipher suite, certificate and private key: */
      rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CIPHER_SUITE,
                            cfg->ldc_tls_ciphers);
      if (rc != LDAP_SUCCESS)
        {
          log_log(LOG_DEBUG,"<== do_ssl_options: Setting of LDAP_OPT_X_TLS_CIPHER_SUITE failed");
          return LDAP_OPERATIONS_ERROR;
        }
    }

  if (cfg->ldc_tls_cert != NULL)
    {
      rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CERTFILE, cfg->ldc_tls_cert);
      if (rc != LDAP_SUCCESS)
        {
          log_log(LOG_DEBUG,"<== do_ssl_options: Setting of LDAP_OPT_X_TLS_CERTFILE failed");
          return LDAP_OPERATIONS_ERROR;
        }
    }

  if (cfg->ldc_tls_key != NULL)
    {
      rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_KEYFILE, cfg->ldc_tls_key);
      if (rc != LDAP_SUCCESS)
        {
          log_log(LOG_DEBUG,"<== do_ssl_options: Setting of LDAP_OPT_X_TLS_KEYFILE failed");
          return LDAP_OPERATIONS_ERROR;
        }
    }

  log_log(LOG_DEBUG,"<== do_ssl_options");

  return LDAP_SUCCESS;
}
#endif

/*
 * This function initializes an enumeration context, acquiring
 * the global mutex.
 *
 * It could be done from the default constructor, under Solaris, but we
 * delay it until the setXXent() function is called.
 */
struct ent_context *
_nss_ldap_ent_context_init (struct ent_context ** pctx)
{
  struct ent_context *ctx;

  _nss_ldap_enter ();

  ctx = _nss_ldap_ent_context_init_locked (pctx);

  _nss_ldap_leave ();

  return ctx;
}

/*
 * Wrapper around ldap_result() to skip over search references
 * and deal transparently with the last entry.
 */
static enum nss_status
do_result (struct ent_context * ctx, int all)
{
  int rc = LDAP_UNAVAILABLE;
  enum nss_status stat = NSS_STATUS_TRYAGAIN;
  struct timeval tv, *tvp;

  log_log(LOG_DEBUG,"==> do_result");

  if (__session.ls_config->ldc_timelimit == LDAP_NO_LIMIT)
    {
      tvp = NULL;
    }
  else
    {
      tv.tv_sec = __session.ls_config->ldc_timelimit;
      tv.tv_usec = 0;
      tvp = &tv;
    }

  do
    {
      if (ctx->ec_res != NULL)
        {
          ldap_msgfree (ctx->ec_res);
          ctx->ec_res = NULL;
        }

      rc =
        ldap_result (__session.ls_conn, ctx->ec_msgid, all, tvp,
                     &ctx->ec_res);
      switch (rc)
        {
        case -1:
        case 0:
          if (ldap_get_option
              (__session.ls_conn, LDAP_OPT_ERROR_NUMBER, &rc) != LDAP_SUCCESS)
            {
              rc = LDAP_UNAVAILABLE;
            }
          syslog (LOG_AUTHPRIV | LOG_ERR, "nss_ldap: could not get LDAP result - %s",
                  ldap_err2string (rc));
          stat = NSS_STATUS_UNAVAIL;
          break;
        case LDAP_RES_SEARCH_ENTRY:
          stat = NSS_STATUS_SUCCESS;
          break;
        case LDAP_RES_SEARCH_RESULT:
          if (all == LDAP_MSG_ALL)
            {
              /* we asked for the result chain, we got it. */
              stat = NSS_STATUS_SUCCESS;
            }
          else
            {
#ifdef LDAP_MORE_RESULTS_TO_RETURN
              int parserc;
              /* NB: this frees ctx->ec_res */
              LDAPControl **resultControls = NULL;

              ctx->ec_cookie = NULL;

              parserc =
                ldap_parse_result (__session.ls_conn, ctx->ec_res, &rc, NULL,
                                   NULL, NULL, &resultControls, 1);
              if (parserc != LDAP_SUCCESS
                  && parserc != LDAP_MORE_RESULTS_TO_RETURN)
                {
                  stat = NSS_STATUS_UNAVAIL;
                  ldap_abandon (__session.ls_conn, ctx->ec_msgid);
                  syslog (LOG_AUTHPRIV | LOG_ERR,
                          "nss_ldap: could not get LDAP result - %s",
                          ldap_err2string (rc));
                }
              else if (resultControls != NULL)
                {
                  /* See if there are any more pages to come */
                  parserc = ldap_parse_page_control (__session.ls_conn,
                                                     resultControls, NULL,
                                                     &(ctx->ec_cookie));
                  ldap_controls_free (resultControls);
                  stat = NSS_STATUS_NOTFOUND;
                }
              else
                {
                  stat = NSS_STATUS_NOTFOUND;
                }
#else
              stat = NSS_STATUS_NOTFOUND;
#endif /* LDAP_MORE_RESULTS_TO_RETURN */
              ctx->ec_res = NULL;
              ctx->ec_msgid = -1;
            }
          break;
        default:
          stat = NSS_STATUS_UNAVAIL;
          break;
        }
    }
#ifdef LDAP_RES_SEARCH_REFERENCE
  while (rc == LDAP_RES_SEARCH_REFERENCE);
#else
  while (0);
#endif /* LDAP_RES_SEARCH_REFERENCE */

  if (stat == NSS_STATUS_SUCCESS)
    time (&__session.ls_timestamp);

  log_log(LOG_DEBUG,"<== do_result");

  return stat;
}

/*
 * This function initializes an enumeration context.
 *
 * It could be done from the default constructor, under Solaris, but we
 * delay it until the setXXent() function is called.
 */
struct ent_context *
_nss_ldap_ent_context_init_locked(struct ent_context **pctx)
{
  struct ent_context *ctx;

  log_log(LOG_DEBUG,"==> _nss_ldap_ent_context_init_locked");

  ctx = *pctx;

  if (ctx == NULL)
  {
    ctx=(struct ent_context *)malloc(sizeof(struct ent_context));
    if (ctx == NULL)
    {
      log_log(LOG_DEBUG,"<== _nss_ldap_ent_context_init_locked");
      return NULL;
    }
    *pctx = ctx;
  }
  else
    {
      if (ctx->ec_res != NULL)
        {
          ldap_msgfree (ctx->ec_res);
        }
      if (ctx->ec_cookie != NULL)
        {
          ber_bvfree (ctx->ec_cookie);
        }
      if (ctx->ec_msgid > -1 && do_result (ctx, LDAP_MSG_ONE) == NSS_STATUS_SUCCESS)
        {
          ldap_abandon (__session.ls_conn, ctx->ec_msgid);
        }
    }

  ctx->ec_cookie = NULL;
  ctx->ec_res = NULL;
  ctx->ec_msgid = -1;
  ctx->ec_sd = NULL;

  LS_INIT (ctx->ec_state);

  log_log(LOG_DEBUG,"<== _nss_ldap_ent_context_init_locked");

  return ctx;
}

/*
 * Clears a given context; we require the caller
 * to acquire the lock.
 */
void
_nss_ldap_ent_context_release (struct ent_context * ctx)
{
  log_log(LOG_DEBUG,"==> _nss_ldap_ent_context_release");

  if (ctx == NULL)
    {
      log_log(LOG_DEBUG,"<== _nss_ldap_ent_context_release");
      return;
    }

  if (ctx->ec_res != NULL)
    {
      ldap_msgfree (ctx->ec_res);
      ctx->ec_res = NULL;
    }

  /*
   * Abandon the search if there were more results to fetch.
   */
  if (ctx->ec_msgid > -1 && do_result (ctx, LDAP_MSG_ONE) == NSS_STATUS_SUCCESS)
    {
      ldap_abandon (__session.ls_conn, ctx->ec_msgid);
      ctx->ec_msgid = -1;
    }

  if (ctx->ec_cookie != NULL)
    {
      ber_bvfree (ctx->ec_cookie);
      ctx->ec_cookie = NULL;
    }

  ctx->ec_sd = NULL;

  LS_INIT (ctx->ec_state);

  if (_nss_ldap_test_config_flag (NSS_LDAP_FLAGS_CONNECT_POLICY_ONESHOT))
    {
      do_close ();
    }

  log_log(LOG_DEBUG,"<== _nss_ldap_ent_context_release");

  return;
}

/*
 * AND or OR a set of filters.
 */
static enum nss_status
do_aggregate_filter (const char **values,
                     enum ldap_args_types type,
                     const char *filterprot, char *bufptr, size_t buflen)
{
  const char **valueP;

  assert (buflen > sizeof ("(|)"));

  bufptr[0] = '(';
  bufptr[1] = (type == LA_TYPE_STRING_LIST_AND) ? '&' : '|';

  bufptr += 2;
  buflen -= 2;

  for (valueP = values; *valueP != NULL; valueP++)
    {
      size_t len;
      char filter[LDAP_FILT_MAXSIZ], escapedBuf[LDAP_FILT_MAXSIZ];

      if (_nss_ldap_escape_string (*valueP, escapedBuf, sizeof (escapedBuf)))
        return NSS_STATUS_TRYAGAIN;

      snprintf (filter, sizeof (filter), filterprot, escapedBuf);
      len = strlen (filter);

      if (buflen < len + 1 /* ')' */ )
        return NSS_STATUS_TRYAGAIN;

      memcpy (bufptr, filter, len);
      bufptr[len] = '\0';
      bufptr += len;
      buflen -= len;
    }

  if (buflen < 2)
    return NSS_STATUS_TRYAGAIN;

  *bufptr++ = ')';
  *bufptr++ = '\0';

  buflen -= 2;

  return NSS_STATUS_SUCCESS;
}

/*
 * Do the necessary formatting to create a string filter.
 */
static enum nss_status
do_filter (const struct ldap_args *args, const char *filterprot,
           struct ldap_service_search_descriptor *sd, char *userBuf,
           size_t userBufSiz, char **dynamicUserBuf, const char **retFilter)
{
  char buf1[LDAP_FILT_MAXSIZ], buf2[LDAP_FILT_MAXSIZ];
  char *filterBufP, filterBuf[LDAP_FILT_MAXSIZ];
  size_t filterSiz;
  enum nss_status stat = NSS_STATUS_SUCCESS;

  log_log(LOG_DEBUG,"==> do_filter");

  *dynamicUserBuf = NULL;

  if (args != NULL && args->la_type != LA_TYPE_NONE)
    {
      /* choose what to use for temporary storage */

      if (sd != NULL && sd->lsd_filter != NULL)
        {
          filterBufP = filterBuf;
          filterSiz = sizeof (filterBuf);
        }
      else
        {
          filterBufP = userBuf;
          filterSiz = userBufSiz;
        }

      switch (args->la_type)
        {
        case LA_TYPE_STRING:
          if (_nss_ldap_escape_string(args->la_arg1.la_string,buf1,sizeof(buf1)))
          {
            stat=NSS_STATUS_TRYAGAIN;
            break;
          }
          snprintf (filterBufP, filterSiz, filterprot, buf1);
          break;
        case LA_TYPE_NUMBER:
          snprintf (filterBufP, filterSiz, filterprot,
                    args->la_arg1.la_number);
          break;
        case LA_TYPE_STRING_AND_STRING:
          if (_nss_ldap_escape_string(args->la_arg1.la_string,buf1,sizeof(buf1)))
          {
            stat=NSS_STATUS_TRYAGAIN;
            break;
          }
          if (_nss_ldap_escape_string(args->la_arg2.la_string,buf2,sizeof(buf2)))
          {
            stat=NSS_STATUS_TRYAGAIN;
            break;
          }
          snprintf (filterBufP, filterSiz, filterprot, buf1, buf2);
          break;
        case LA_TYPE_NUMBER_AND_STRING:
          if (_nss_ldap_escape_string(args->la_arg2.la_string,buf1,sizeof(buf1)))
          {
            stat=NSS_STATUS_TRYAGAIN;
            break;
          }
          snprintf (filterBufP, filterSiz, filterprot,
                    args->la_arg1.la_number, buf1);
          break;
        case LA_TYPE_STRING_LIST_OR:
        case LA_TYPE_STRING_LIST_AND:
          do
            {
              stat = do_aggregate_filter (args->la_arg1.la_string_list,
                                          args->la_type,
                                          filterprot, filterBufP, filterSiz);
              if (stat == NSS_STATUS_TRYAGAIN)
                {
                  filterBufP = *dynamicUserBuf = realloc (*dynamicUserBuf,
                                                          2 * filterSiz);
                  if (filterBufP == NULL)
                    return NSS_STATUS_UNAVAIL;
                  filterSiz *= 2;
                }
            }
          while (stat == NSS_STATUS_TRYAGAIN);
          break;
        default:
          return NSS_STATUS_UNAVAIL;
          break;
        }

      if (stat != NSS_STATUS_SUCCESS)
        return stat;

      /*
       * This code really needs to be cleaned up.
       */
      if (sd != NULL && sd->lsd_filter != NULL)
        {
          size_t filterBufPLen = strlen (filterBufP);

          /* remove trailing bracket */
          if (filterBufP[filterBufPLen - 1] == ')')
            filterBufP[filterBufPLen - 1] = '\0';

          if (*dynamicUserBuf != NULL)
            {
              char *oldDynamicUserBuf = *dynamicUserBuf;
              size_t dynamicUserBufSiz;

              dynamicUserBufSiz = filterBufPLen + strlen (sd->lsd_filter) +
                sizeof ("())");
              *dynamicUserBuf = malloc (dynamicUserBufSiz);
              if (*dynamicUserBuf == NULL)
                {
                  free (oldDynamicUserBuf);
                  return NSS_STATUS_UNAVAIL;
                }

              snprintf (*dynamicUserBuf, dynamicUserBufSiz, "%s(%s))",
                        filterBufP, sd->lsd_filter);
              free (oldDynamicUserBuf);
            }
          else
            {
              snprintf (userBuf, userBufSiz, "%s(%s))",
                        filterBufP, sd->lsd_filter);
            }
        }

      if (*dynamicUserBuf != NULL)
        *retFilter = *dynamicUserBuf;
      else
        *retFilter = userBuf;
    }
  else
    {
      /* no arguments, probably an enumeration filter */
      if (sd != NULL && sd->lsd_filter != NULL)
        {
          snprintf (userBuf, userBufSiz, "(&%s(%s))",
                    filterprot, sd->lsd_filter);
          *retFilter = userBuf;
        }
      else
        {
          *retFilter = filterprot;
        }
    }

  log_log(LOG_DEBUG,":== do_filter: %s", *retFilter);

  log_log(LOG_DEBUG,"<== do_filter");

  return NSS_STATUS_SUCCESS;
}

/*
 * Function to call either do_search() or do_search_s() with
 * reconnection logic.
 */
static enum nss_status
do_with_reconnect (const char *base, int scope,
                   const char *filter, const char **attrs, int sizelimit,
                   void *private, search_func_t search_func)
{
  int rc = LDAP_UNAVAILABLE, tries = 0, backoff = 0;
  int hard = 1, start_uri = 0, log = 0;
  enum nss_status stat = NSS_STATUS_UNAVAIL;
  int maxtries;

  log_log(LOG_DEBUG,"==> do_with_reconnect");

  /* caller must successfully call do_init() first */
  assert (__session.ls_config != NULL);

  maxtries = __session.ls_config->ldc_reconnect_maxconntries +
             __session.ls_config->ldc_reconnect_tries;

  while (stat == NSS_STATUS_UNAVAIL && hard && tries < maxtries)
    {
      if (tries >= __session.ls_config->ldc_reconnect_maxconntries)
        {
          if (backoff == 0)
            backoff = __session.ls_config->ldc_reconnect_sleeptime;
          else if (backoff < __session.ls_config->ldc_reconnect_maxsleeptime)
            backoff *= 2;

          syslog (LOG_AUTHPRIV | LOG_INFO,
                  "nss_ldap: reconnecting to LDAP server (sleeping %d seconds)...",
                  backoff);
          (void) sleep (backoff);
        }
      else if (tries > 1)
        {
          /* Don't sleep, reconnect immediately. */
          syslog (LOG_AUTHPRIV | LOG_INFO, "nss_ldap: reconnecting to LDAP server...");
        }

      /* For each "try", attempt to connect to all specified URIs */
      start_uri = __session.ls_current_uri;
      do
        {
          stat = do_open ();
          if (stat == NSS_STATUS_SUCCESS)
            {
              stat = do_map_error (search_func (base, scope, filter,
                                                attrs, sizelimit, private));
            }
          if (stat != NSS_STATUS_UNAVAIL)
            break;

          log++;

          /* test in case config file could not be read */
          if (__session.ls_config != NULL)
            {
              assert (__session.ls_config->
                      ldc_uris[__session.ls_current_uri] != NULL);

              __session.ls_current_uri++;

              if (__session.ls_config->ldc_uris[__session.ls_current_uri] ==
                  NULL)
                __session.ls_current_uri = 0;
            }
        }
      while (__session.ls_current_uri != start_uri);

      if (stat == NSS_STATUS_UNAVAIL)
        {
          do_close ();

          /*
           * If a soft reconnect policy is specified, then do not
           * try to reconnect to the LDAP server if it is down.
           */
          if (__session.ls_config->ldc_reconnect_pol == LP_RECONNECT_SOFT)
            hard = 0;

          /*
           * If the file /lib/init/rw/libnss-ldap.bind_policy_soft exists,
           * then ignore the actual bind_policy definition and use the
           * soft semantics.  This file should only exist during early
           * boot and late shutdown, points at which the networking or
           * the LDAP server itself are likely to be unavailable anyway.
           */
          if (access("/lib/init/rw/libnss-ldap.bind_policy_soft",R_OK) == 0)
              hard = 0;

          ++tries;
        }
    }

  switch (stat)
    {
    case NSS_STATUS_UNAVAIL:
      syslog (LOG_AUTHPRIV | LOG_ERR, "nss_ldap: could not search LDAP server - %s",
              ldap_err2string (rc));
      break;
    case NSS_STATUS_TRYAGAIN:
      syslog (LOG_AUTHPRIV | LOG_ERR,
              "nss_ldap: could not %s %sconnect to LDAP server - %s",
              hard ? "hard" : "soft", tries ? "re" : "",
              ldap_err2string (rc));
      stat = NSS_STATUS_UNAVAIL;
      break;
    case NSS_STATUS_SUCCESS:
      if (log)
        {
          char *uri = __session.ls_config->ldc_uris[__session.ls_current_uri];

          if (uri == NULL)
            uri = "(null)";

          if (tries)
            syslog (LOG_AUTHPRIV | LOG_INFO,
              "nss_ldap: reconnected to LDAP server %s after %d attempt%s",
              uri, tries, (tries == 1) ? "" : "s");
          else
            syslog (LOG_AUTHPRIV | LOG_INFO, "nss_ldap: reconnected to LDAP server %s", uri);
        }
      time (&__session.ls_timestamp);
      break;
    default:
      break;
    }

  log_log(LOG_DEBUG,"<== do_with_reconnect");
  return stat;
}

/*
 * Synchronous search function. Don't call this directly;
 * always wrap calls to this with do_with_reconnect(), or,
 * better still, use _nss_ldap_search_s().
 */
static int
do_search_s (const char *base, int scope,
             const char *filter, const char **attrs, int sizelimit,
             LDAPMessage ** res)
{
  int rc;
  struct timeval tv, *tvp;

  log_log(LOG_DEBUG,"==> do_search_s");

  ldap_set_option (__session.ls_conn, LDAP_OPT_SIZELIMIT,
                   (void *) &sizelimit);

  if (__session.ls_config->ldc_timelimit == LDAP_NO_LIMIT)
    {
      tvp = NULL;
    }
  else
    {
      tv.tv_sec = __session.ls_config->ldc_timelimit;
      tv.tv_usec = 0;
      tvp = &tv;
    }

  rc = ldap_search_st (__session.ls_conn, base, scope, filter,
                       (char **) attrs, 0, tvp, res);

  log_log(LOG_DEBUG,"<== do_search_s");

  return rc;
}

/*
 * Asynchronous search function. Don't call this directly;
 * always wrap calls to this with do_with_reconnect(), or,
 * better still, use _nss_ldap_search().
 */
static int
do_search (const char *base, int scope,
           const char *filter, const char **attrs, int sizelimit, int *msgid)
{
  int rc;
  LDAPControl *serverCtrls[2];
  LDAPControl **pServerCtrls;

  log_log(LOG_DEBUG,"==> do_search");

#ifdef HAVE_LDAP_SEARCH_EXT
  if (_nss_ldap_test_config_flag (NSS_LDAP_FLAGS_PAGED_RESULTS))
    {
      rc = ldap_create_page_control (__session.ls_conn,
                                     __session.ls_config->ldc_pagesize,
                                     NULL, 0, &serverCtrls[0]);
      if (rc != LDAP_SUCCESS)
        return rc;

      serverCtrls[1] = NULL;
      pServerCtrls = serverCtrls;
    }
  else
    {
      pServerCtrls = NULL;
    }

  rc = ldap_search_ext (__session.ls_conn, base, scope, filter,
                        (char **) attrs, 0, pServerCtrls, NULL,
                        LDAP_NO_LIMIT, sizelimit, msgid);

  if (pServerCtrls != NULL)
    {
      ldap_control_free (serverCtrls[0]);
      serverCtrls[0] = NULL;
    }

#else
  ldap_set_option (__session.ls_conn, LDAP_OPT_SIZELIMIT,
                   (void *) &sizelimit);

  *msgid = ldap_search (__session.ls_conn, base, scope, filter,
                        (char **) attrs, 0);
  if (*msgid < 0)
    {
      if (ldap_get_option
          (__session.ls_conn, LDAP_OPT_ERROR_NUMBER, &rc) != LDAP_SUCCESS)
        {
          rc = LDAP_UNAVAILABLE;
        }
    }
  else
    {
      rc = LDAP_SUCCESS;
    }
#endif /* HAVE_LDAP_SEARCH_EXT */

  log_log(LOG_DEBUG,"<== do_search");

  return rc;
}

static void
do_map_errno (enum nss_status status, int *errnop)
{
  switch (status)
    {
    case NSS_STATUS_TRYAGAIN:
      *errnop = ERANGE;
      break;
    case NSS_STATUS_NOTFOUND:
      *errnop = ENOENT;
      break;
    case NSS_STATUS_SUCCESS:
    default:
      *errnop = 0;
    }
}

/*
 * Tries parser function "parser" on entries, calling do_result()
 * to retrieve them from the LDAP server until one parses
 * correctly or there is an exceptional condition.
 */
static enum nss_status
do_parse (struct ent_context * ctx, void *result, char
          *buffer, size_t buflen, int *errnop, parser_t parser)
{
  enum nss_status parseStat = NSS_STATUS_NOTFOUND;

  log_log(LOG_DEBUG,"==> do_parse");

  /*
   * if ec_state.ls_info.ls_index is non-zero, then we don't collect another
   * entry off the LDAP chain, and instead refeed the existing result to
   * the parser. Once the parser has finished with it, it will return
   * NSS_STATUS_NOTFOUND and reset the index to -1, at which point we'll retrieve
   * another entry.
   */
  do
    {
      enum nss_status resultStat = NSS_STATUS_SUCCESS;

      if (ctx->ec_state.ls_retry == 0 &&
          (ctx->ec_state.ls_type == LS_TYPE_KEY
           || ctx->ec_state.ls_info.ls_index == -1))
        {
          resultStat = do_result (ctx, LDAP_MSG_ONE);
        }

      if (resultStat != NSS_STATUS_SUCCESS)
        {
          /* Could not get a result; bail */
          parseStat = resultStat;
          break;
        }

      /*
       * We have an entry; now, try to parse it.
       *
       * If we do not parse the entry because of a schema
       * violation, the parser should return NSS_STATUS_NOTFOUND.
       * We'll keep on trying subsequent entries until we
       * find one which is parseable, or exhaust avialable
       * entries, whichever is first.
       */
      parseStat = parser (ctx->ec_res, &ctx->ec_state, result,
                          buffer, buflen);

      /* hold onto the state if we're out of memory XXX */
      ctx->ec_state.ls_retry = (parseStat == NSS_STATUS_TRYAGAIN && buffer != NULL ? 1 : 0);

      /* free entry is we're moving on */
      if (ctx->ec_state.ls_retry == 0 &&
          (ctx->ec_state.ls_type == LS_TYPE_KEY
           || ctx->ec_state.ls_info.ls_index == -1))
        {
          /* we don't need the result anymore, ditch it. */
          ldap_msgfree (ctx->ec_res);
          ctx->ec_res = NULL;
        }
    }
  while (parseStat == NSS_STATUS_NOTFOUND);

  do_map_errno (parseStat, errnop);

  log_log(LOG_DEBUG,"<== do_parse");

  return parseStat;
}

/*
 * Parse, fetching reuslts from chain instead of server.
 */
static enum nss_status
do_parse_s (struct ent_context * ctx, void *result, char
            *buffer, size_t buflen, int *errnop, parser_t parser)
{
  enum nss_status parseStat = NSS_STATUS_NOTFOUND;
  LDAPMessage *e = NULL;

  log_log(LOG_DEBUG,"==> do_parse_s");

  /*
   * if ec_state.ls_info.ls_index is non-zero, then we don't collect another
   * entry off the LDAP chain, and instead refeed the existing result to
   * the parser. Once the parser has finished with it, it will return
   * NSS_STATUS_NOTFOUND and reset the index to -1, at which point we'll retrieve
   * another entry.
   */
  do
    {
      if (ctx->ec_state.ls_retry == 0 &&
          (ctx->ec_state.ls_type == LS_TYPE_KEY
           || ctx->ec_state.ls_info.ls_index == -1))
        {
          if (e == NULL)
            e = ldap_first_entry (__session.ls_conn, ctx->ec_res);
          else
            e = ldap_next_entry (__session.ls_conn, e);
        }

      if (e == NULL)
        {
          /* Could not get a result; bail */
          parseStat = NSS_STATUS_NOTFOUND;
          break;
        }

      /*
       * We have an entry; now, try to parse it.
       *
       * If we do not parse the entry because of a schema
       * violation, the parser should return NSS_STATUS_NOTFOUND.
       * We'll keep on trying subsequent entries until we
       * find one which is parseable, or exhaust avialable
       * entries, whichever is first.
       */
      parseStat = parser (e, &ctx->ec_state, result, buffer, buflen);

      /* hold onto the state if we're out of memory XXX */
      ctx->ec_state.ls_retry = (parseStat == NSS_STATUS_TRYAGAIN && buffer != NULL ? 1 : 0);
    }
  while (parseStat == NSS_STATUS_NOTFOUND);

  do_map_errno (parseStat, errnop);

  log_log(LOG_DEBUG,"<== do_parse_s");

  return parseStat;
}

/*
 * Read an entry from the directory, a la X.500. This is used
 * for functions that need to retrieve attributes from a DN,
 * such as the RFC2307bis group expansion function.
 */
enum nss_status
_nss_ldap_read (const char *dn, const char **attributes, LDAPMessage ** res)
{
  return do_with_reconnect (dn, LDAP_SCOPE_BASE, "(objectclass=*)",
                            attributes, 1, /* sizelimit */ res,
                            (search_func_t) do_search_s);
}

/*
 * Simple wrapper around ldap_get_values(). Requires that
 * session is already established.
 */
char **
_nss_ldap_get_values (LDAPMessage * e, const char *attr)
{
  if (__session.ls_state != LS_CONNECTED_TO_DSA)
    {
      return NULL;
    }
  assert (__session.ls_conn != NULL);

  return ldap_get_values (__session.ls_conn, e, (char *) attr);
}

/*
 * Simple wrapper around ldap_get_dn(). Requires that
 * session is already established.
 */
char *
_nss_ldap_get_dn (LDAPMessage * e)
{
  if (__session.ls_state != LS_CONNECTED_TO_DSA)
    {
      return NULL;
    }
  assert (__session.ls_conn != NULL);

  return ldap_get_dn (__session.ls_conn, e);
}

/*
 * Simple wrapper around ldap_first_entry(). Requires that
 * session is already established.
 */
LDAPMessage *
_nss_ldap_first_entry (LDAPMessage * res)
{
  if (__session.ls_state != LS_CONNECTED_TO_DSA)
    {
      return NULL;
    }
  assert (__session.ls_conn != NULL);

  return ldap_first_entry (__session.ls_conn, res);
}

/*
 * Simple wrapper around ldap_next_entry(). Requires that
 * session is already established.
 */
LDAPMessage *
_nss_ldap_next_entry (LDAPMessage * res)
{
  if (__session.ls_state != LS_CONNECTED_TO_DSA)
    {
      return NULL;
    }
  assert (__session.ls_conn != NULL);

  return ldap_next_entry (__session.ls_conn, res);
}

char *
_nss_ldap_first_attribute (LDAPMessage * entry, BerElement ** berptr)
{
  if (__session.ls_state != LS_CONNECTED_TO_DSA)
    {
      return NULL;
    }
  assert (__session.ls_conn != NULL);

  return ldap_first_attribute (__session.ls_conn, entry, berptr);
}

char *
_nss_ldap_next_attribute (LDAPMessage * entry, BerElement * ber)
{
  if (__session.ls_state != LS_CONNECTED_TO_DSA)
    {
      return NULL;
    }
  assert (__session.ls_conn != NULL);

  return ldap_next_attribute (__session.ls_conn, entry, ber);
}

/*
 * The generic synchronous lookup cover function.
 * Assumes caller holds lock.
 */
enum nss_status _nss_ldap_search_s(
        const struct ldap_args *args,
        const char *filterprot,enum ldap_map_selector sel,
        const char **user_attrs,int sizelimit,LDAPMessage **res)
{
  char sdBase[LDAP_FILT_MAXSIZ];
  const char *base=NULL;
  char filterBuf[LDAP_FILT_MAXSIZ],*dynamicFilterBuf=NULL;
  const char **attrs,*filter;
  int scope;
  enum nss_status stat;
  struct ldap_service_search_descriptor *sd=NULL;
  log_log(LOG_DEBUG,"==> _nss_ldap_search_s");
  /* initilize session */
  if ((stat=do_init())!=NSS_STATUS_SUCCESS)
  {
    log_log(LOG_DEBUG,"<== _nss_ldap_search_s");
    return stat;
  }
  /* Set some reasonable defaults. */
  base=__session.ls_config->ldc_base;
  scope=__session.ls_config->ldc_scope;
  attrs=NULL;
  /* if args includes a base, use that */
  if (args!=NULL&&args->la_base!=NULL)
  {
    sel=LM_NONE;
    base=args->la_base;
  }
  if (sel<LM_NONE)
  {
    /* get search descriptor */
    sd=__session.ls_config->ldc_sds[sel];
next:
    if (sd!=NULL)
    {
      if (sd->lsd_base[strlen(sd->lsd_base)-1]==',')
      {
        /* is relative */
        snprintf(sdBase,sizeof(sdBase),"%s%s", sd->lsd_base,__session.ls_config->ldc_base);
        base=sdBase;
      }
      else
      {
        base=sd->lsd_base;
      }
      if (sd->lsd_scope!=-1)
      {
        scope=sd->lsd_scope;
      }
    }
    attrs=__session.ls_config->ldc_attrtab[sel];
  }
  /* this may allocate dynamicFilterBuf */
  stat=do_filter(args,filterprot,sd,filterBuf,sizeof(filterBuf),&dynamicFilterBuf,&filter);
  if (stat!=NSS_STATUS_SUCCESS)
    return stat;
  stat=do_with_reconnect(
          base,scope,filter,(user_attrs!=NULL)?user_attrs:attrs,
          sizelimit,res,(search_func_t)do_search_s);
  if (dynamicFilterBuf!=NULL)
  {
    free(dynamicFilterBuf);
    dynamicFilterBuf=NULL;
  }
  /* If no entry was returned, try the next search descriptor. */
  if (sd != NULL && sd->lsd_next != NULL)
  {
    if (stat==NSS_STATUS_NOTFOUND ||
        (stat==NSS_STATUS_SUCCESS &&
         ldap_first_entry(__session.ls_conn,*res)==NULL))
    {
      sd=sd->lsd_next;
      goto next;
    }
  }
  return stat;
}

/*
 * The generic lookup cover function (asynchronous).
 * Assumes caller holds lock.
 */
static enum nss_status
_nss_ldap_search (const struct ldap_args * args,
                  const char *filterprot, enum ldap_map_selector sel,
                  const char **user_attrs, int sizelimit, int *msgid,
                  struct ldap_service_search_descriptor ** csd)
{
  char sdBase[LDAP_FILT_MAXSIZ];
  const char *base = NULL;
  char filterBuf[LDAP_FILT_MAXSIZ], *dynamicFilterBuf = NULL;
  const char **attrs, *filter;
  int scope;
  enum nss_status stat;
  struct ldap_service_search_descriptor *sd = NULL;

  log_log(LOG_DEBUG,"==> _nss_ldap_search");

  *msgid = -1;

  stat = do_init ();
  if (stat != NSS_STATUS_SUCCESS)
    {
      log_log(LOG_DEBUG,"<== _nss_ldap_search");
      return stat;
    }

  /* Set some reasonable defaults. */
  base = __session.ls_config->ldc_base;
  scope = __session.ls_config->ldc_scope;
  attrs = NULL;

  if (args != NULL && args->la_base != NULL)
    {
      sel = LM_NONE;
      base = args->la_base;
    }

  if (sel < LM_NONE || *csd != NULL)
    {
      /*
       * If we were chasing multiple descriptors and there are none left,
       * just quit with NSS_STATUS_NOTFOUND.
       */
      if (*csd != NULL)
        {
          sd = (*csd)->lsd_next;
          if (sd == NULL)
            return NSS_STATUS_NOTFOUND;
        }
      else
        {
          sd = __session.ls_config->ldc_sds[sel];
        }

      *csd = sd;

      if (sd != NULL)
        {
          size_t len = strlen (sd->lsd_base);
          if (sd->lsd_base[len - 1] == ',')
            {
              /* is relative */
              snprintf (sdBase, sizeof (sdBase), "%s%s", sd->lsd_base,
                        __session.ls_config->ldc_base);
              base = sdBase;
            }
          else
            {
              base = sd->lsd_base;
            }

          if (sd->lsd_scope != -1)
            {
              scope = sd->lsd_scope;
            }
        }
      attrs = __session.ls_config->ldc_attrtab[sel];
    }

  stat =
    do_filter (args, filterprot, sd, filterBuf, sizeof (filterBuf),
               &dynamicFilterBuf, &filter);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat = do_with_reconnect (base, scope, filter,
                            (user_attrs != NULL) ? user_attrs : attrs,
                            sizelimit, msgid, (search_func_t) do_search);

  if (dynamicFilterBuf != NULL)
    free (dynamicFilterBuf);

  log_log(LOG_DEBUG,"<== _nss_ldap_search");

  return stat;
}

#ifdef HAVE_LDAP_SEARCH_EXT
static enum nss_status
do_next_page (const struct ldap_args * args,
              const char *filterprot, enum ldap_map_selector sel, int
              sizelimit, int *msgid, struct berval *pCookie)
{
  char sdBase[LDAP_FILT_MAXSIZ];
  const char *base = NULL;
  char filterBuf[LDAP_FILT_MAXSIZ], *dynamicFilterBuf = NULL;
  const char **attrs, *filter;
  int scope;
  enum nss_status stat;
  struct ldap_service_search_descriptor *sd = NULL;
  LDAPControl *serverctrls[2] = {
    NULL, NULL
  };

  /* Set some reasonable defaults. */
  base = __session.ls_config->ldc_base;
  scope = __session.ls_config->ldc_scope;
  attrs = NULL;

  if (args != NULL && args->la_base != NULL)
    {
      sel = LM_NONE;
      base = args->la_base;
    }

  if (sel < LM_NONE)
    {
      sd = __session.ls_config->ldc_sds[sel];
      if (sd != NULL)
        {
          size_t len = strlen (sd->lsd_base);
          if (sd->lsd_base[len - 1] == ',')
            {
              snprintf (sdBase, sizeof (sdBase), "%s%s", sd->lsd_base,
                        __session.ls_config->ldc_base);
              base = sdBase;
            }
          else
            {
              base = sd->lsd_base;
            }

          if (sd->lsd_scope != -1)
            {
              scope = sd->lsd_scope;
            }
        }
      attrs = __session.ls_config->ldc_attrtab[sel];
    }

  stat =
    do_filter (args, filterprot, sd, filterBuf, sizeof (filterBuf),
               &dynamicFilterBuf, &filter);
  if (stat != NSS_STATUS_SUCCESS)
    {
      return stat;
    }

  stat =
    ldap_create_page_control (__session.ls_conn,
                              __session.ls_config->ldc_pagesize,
                              pCookie, 0, &serverctrls[0]);
  if (stat != LDAP_SUCCESS)
    {
      if (dynamicFilterBuf != NULL)
        free (dynamicFilterBuf);
      return NSS_STATUS_UNAVAIL;
    }

  stat =
    ldap_search_ext (__session.ls_conn, base,
                     __session.ls_config->ldc_scope,
                     filter,
                     (char **) attrs, 0, serverctrls, NULL, LDAP_NO_LIMIT,
                     sizelimit, msgid);

  ldap_control_free (serverctrls[0]);
  if (dynamicFilterBuf != NULL)
    free (dynamicFilterBuf);

  return (*msgid < 0) ? NSS_STATUS_UNAVAIL : NSS_STATUS_SUCCESS;
}
#endif /* HAVE_LDAP_SEARCH_EXT */

/*
 * General entry point for enumeration routines.
 * This should really use the asynchronous LDAP search API to avoid
 * pulling down all the entries at once, particularly if the
 * enumeration is not completed.
 * Locks mutex.
 */
enum nss_status
_nss_ldap_getent (struct ent_context ** ctx,
                  void *result, char *buffer, size_t buflen,
                  int *errnop, const char *filterprot,
                  enum ldap_map_selector sel, parser_t parser)
{
  enum nss_status status;

  /*
   * we need to lock here as the context may not be thread-specific
   * data (under glibc, for example). Maybe we should make the lock part
   * of the context.
   */

  _nss_ldap_enter ();
  status = _nss_ldap_getent_ex (NULL, ctx, result,
                                buffer, buflen,
                                errnop, filterprot, sel, NULL, parser);
  _nss_ldap_leave ();

  return status;
}

/*
 * Internal entry point for enumeration routines.
 * Caller holds global mutex
 */
enum nss_status
_nss_ldap_getent_ex (struct ldap_args * args,
                     struct ent_context ** ctx, void *result,
                     char *buffer, size_t buflen, int *errnop,
                     const char *filterprot,
                     enum ldap_map_selector sel,
                     const char **user_attrs, parser_t parser)
{
  enum nss_status stat = NSS_STATUS_SUCCESS;

  log_log(LOG_DEBUG,"==> _nss_ldap_getent_ex");

  if (*ctx == NULL || (*ctx)->ec_msgid < 0)
    {
      /*
       * implicitly call setent() if this is the first time
       * or there is no active search
       */
      if (_nss_ldap_ent_context_init_locked (ctx) == NULL)
        {
          log_log(LOG_DEBUG,"<== _nss_ldap_getent_ex");
          return NSS_STATUS_UNAVAIL;
        }
    }

next:
  /*
   * If ctx->ec_msgid < 0, then we haven't searched yet. Let's do it!
   */
  if ((*ctx)->ec_msgid < 0)
    {
      int msgid;

      stat = _nss_ldap_search (args, filterprot, sel, user_attrs,
                               LDAP_NO_LIMIT, &msgid, &(*ctx)->ec_sd);
      if (stat != NSS_STATUS_SUCCESS)
        {
          log_log(LOG_DEBUG,"<== _nss_ldap_getent_ex");
          return stat;
        }

      (*ctx)->ec_msgid = msgid;
    }

  stat = do_parse (*ctx, result, buffer, buflen, errnop, parser);

#ifdef HAVE_LDAP_SEARCH_EXT
  if (stat == NSS_STATUS_NOTFOUND)
    {
      /* Is there another page of results? */
      if ((*ctx)->ec_cookie != NULL && (*ctx)->ec_cookie->bv_len != 0)
        {
          int msgid;

          stat =
            do_next_page (NULL, filterprot, sel, LDAP_NO_LIMIT, &msgid,
                          (*ctx)->ec_cookie);
          if (stat != NSS_STATUS_SUCCESS)
            {
              log_log(LOG_DEBUG,"<== _nss_ldap_getent_ex");
              return stat;
            }
          (*ctx)->ec_msgid = msgid;
          stat = do_parse (*ctx, result, buffer, buflen, errnop, parser);
        }
    }
#endif /* HAVE_LDAP_SEARCH_EXT */

  if (stat == NSS_STATUS_NOTFOUND && (*ctx)->ec_sd != NULL)
    {
      (*ctx)->ec_msgid = -1;
      goto next;
    }

  log_log(LOG_DEBUG,"<== _nss_ldap_getent_ex");

  return stat;
}

/*
 * General match function.
 * Locks mutex.
 */
enum nss_status
_nss_ldap_getbyname (struct ldap_args * args,
                     void *result, char *buffer, size_t buflen, int
                     *errnop, const char *filterprot,
                     enum ldap_map_selector sel, parser_t parser)
{
  enum nss_status stat = NSS_STATUS_NOTFOUND;
  struct ent_context ctx;

  _nss_ldap_enter ();

  log_log(LOG_DEBUG,"==> _nss_ldap_getbyname");

  ctx.ec_msgid = -1;
  ctx.ec_cookie = NULL;

  stat = _nss_ldap_search_s (args, filterprot, sel, NULL, 1, &ctx.ec_res);
  if (stat != NSS_STATUS_SUCCESS)
    {
      _nss_ldap_leave ();
      log_log(LOG_DEBUG,"<== _nss_ldap_getbyname");
      return stat;
    }

  /*
   * we pass this along for the benefit of the services parser,
   * which uses it to figure out which protocol we really wanted.
   * we only pass the second argument along, as that's what we need
   * in services.
   */
  LS_INIT (ctx.ec_state);
  ctx.ec_state.ls_type = LS_TYPE_KEY;
  ctx.ec_state.ls_info.ls_key = args->la_arg2.la_string;

  stat = do_parse_s (&ctx, result, buffer, buflen, errnop, parser);

  _nss_ldap_ent_context_release (&ctx);

  log_log(LOG_DEBUG,"<== _nss_ldap_getbyname");

  /* moved unlock here to avoid race condition bug #49 */
  _nss_ldap_leave ();

  return stat;
}

static int NEW_do_parse_s(struct ent_context *ctx,FILE *fp,NEWparser_t parser)
{
  int parseStat=NSLCD_RESULT_NOTFOUND;
  LDAPMessage *e=NULL;
  /*
   * if ec_state.ls_info.ls_index is non-zero, then we don't collect another
   * entry off the LDAP chain, and instead refeed the existing result to
   * the parser. Once the parser has finished with it, it will return
   * NSS_STATUS_NOTFOUND and reset the index to -1, at which point we'll retrieve
   * another entry.
   */
  do
  {
    if (ctx->ec_state.ls_retry == 0 &&
        (ctx->ec_state.ls_type == LS_TYPE_KEY
         || ctx->ec_state.ls_info.ls_index == -1))
    {
      if (e == NULL)
        e = ldap_first_entry (__session.ls_conn, ctx->ec_res);
      else
        e = ldap_next_entry (__session.ls_conn, e);
    }
    if (e == NULL)
    {
      /* Could not get a result; bail */
      parseStat=NSLCD_RESULT_NOTFOUND;
      break;
    }
    /*
     * We have an entry; now, try to parse it.
     *
     * If we do not parse the entry because of a schema
     * violation, the parser should return NSS_STATUS_NOTFOUND.
     * We'll keep on trying subsequent entries until we
     * find one which is parseable, or exhaust avialable
     * entries, whichever is first.
     */
    parseStat=parser(e,&ctx->ec_state,fp);
    /* hold onto the state if we're out of memory XXX */
    ctx->ec_state.ls_retry=0;
  }
  while (parseStat==NSLCD_RESULT_NOTFOUND);
  return parseStat;
}


int _nss_ldap_searchbyname(
        struct ldap_args *args,const char *filterprot,
        enum ldap_map_selector sel,FILE *fp,NEWparser_t parser)
{
  int stat;
  struct ent_context ctx;
  int32_t tmpint32;

  _nss_ldap_enter();

  ctx.ec_msgid=-1;
  ctx.ec_cookie=NULL;

  stat=nss2nslcd(_nss_ldap_search_s(args,filterprot,sel,NULL,1,&ctx.ec_res));
  /* write the result code */
  WRITE_INT32(fp,stat);
  /* bail on nothing found */
  if (stat!=NSLCD_RESULT_SUCCESS)
  {
    _nss_ldap_leave();
    return 1;
  }
  /*
   * we pass this along for the benefit of the services parser,
   * which uses it to figure out which protocol we really wanted.
   * we only pass the second argument along, as that's what we need
   * in services.
   */
  LS_INIT(ctx.ec_state);
  ctx.ec_state.ls_type=LS_TYPE_KEY;
  ctx.ec_state.ls_info.ls_key=args->la_arg2.la_string;
  /* call the parser for the result */
  stat=NEW_do_parse_s(&ctx,fp,parser);

  _nss_ldap_ent_context_release(&ctx);

  /* moved unlock here to avoid race condition bug #49 */
  _nss_ldap_leave();

  return stat;
}

/*
 * These functions are called from within the parser, where it is assumed
 * to be safe to use the connection and the respective message.
 */

/*
 * Assign all values, bar omitvalue (if not NULL), to *valptr.
 */
enum nss_status
_nss_ldap_assign_attrvals (LDAPMessage * e,
                           const char *attr, const char *omitvalue,
                           char ***valptr, char **pbuffer, size_t *
                           pbuflen, size_t * pvalcount)
{
  char **vals;
  char **valiter;
  int valcount;
  char **p = NULL;

  register int buflen = *pbuflen;
  register char *buffer = *pbuffer;

  if (pvalcount != NULL)
    {
      *pvalcount = 0;
    }

  if (__session.ls_conn == NULL)
    {
      return NSS_STATUS_UNAVAIL;
    }

  vals = ldap_get_values (__session.ls_conn, e, (char *) attr);

  valcount = (vals == NULL) ? 0 : ldap_count_values (vals);
  if (bytesleft (buffer, buflen, char *) < (valcount + 1) * sizeof (char *))
    {
      ldap_value_free (vals);
      return NSS_STATUS_TRYAGAIN;
    }

  align (buffer, buflen, char *);
  p = *valptr = (char **) buffer;

  buffer += (valcount + 1) * sizeof (char *);
  buflen -= (valcount + 1) * sizeof (char *);

  if (valcount == 0)
    {
      *p = NULL;
      *pbuffer = buffer;
      *pbuflen = buflen;
      return NSS_STATUS_SUCCESS;
    }

  valiter = vals;

  while (*valiter != NULL)
    {
      int vallen;
      char *elt = NULL;

      if (omitvalue != NULL && strcmp (*valiter, omitvalue) == 0)
        {
          valcount--;
        }
      else
        {
          vallen = strlen (*valiter);
          if (buflen < (size_t) (vallen + 1))
            {
              ldap_value_free (vals);
              return NSS_STATUS_TRYAGAIN;
            }

          /* copy this value into the next block of buffer space */
          elt = buffer;
          buffer += vallen + 1;
          buflen -= vallen + 1;

          strncpy (elt, *valiter, vallen);
          elt[vallen] = '\0';
          *p = elt;
          p++;
        }
      valiter++;
    }

  *p = NULL;
  *pbuffer = buffer;
  *pbuflen = buflen;

  if (pvalcount != NULL)
    {
      *pvalcount = valcount;
    }

  ldap_value_free (vals);
  return NSS_STATUS_SUCCESS;
}

int _nss_ldap_write_attrvals(FILE *fp,LDAPMessage *e,const char *attr)
{
  char **vals;
  int valcount;
  int i;
  int32_t tmpint32;
  /* log */
  log_log(LOG_DEBUG,"_nss_ldap_write_attrvals(%s)",attr);
  /* check if we have a connection */
  if (__session.ls_conn==NULL)
    return NSLCD_RESULT_UNAVAIL;
  /* get the values and the number of values */
  vals=ldap_get_values(__session.ls_conn,e,(char *)attr);
  valcount=(vals==NULL)?0:ldap_count_values(vals);
  /* write number of entries */
  WRITE_INT32(fp,valcount);
  /* write the entries themselves */
  for (i=0;i<valcount;i++)
  {
    WRITE_STRING(fp,vals[i]);
  }
  if (vals!=NULL)
    ldap_value_free(vals);
  return NSLCD_RESULT_SUCCESS;
}

/* Assign a single value to *valptr. */
enum nss_status
_nss_ldap_assign_attrval (LDAPMessage * e,
                          const char *attr, char **valptr, char **buffer,
                          size_t * buflen)
{
  char **vals;
  int vallen;
  const char *ovr, *def;

  ovr = OV (attr);
  if (ovr != NULL)
    {
      vallen = strlen (ovr);
      if (*buflen < (size_t) (vallen + 1))
        {
          return NSS_STATUS_TRYAGAIN;
        }

      *valptr = *buffer;

      strncpy (*valptr, ovr, vallen);
      (*valptr)[vallen] = '\0';

      *buffer += vallen + 1;
      *buflen -= vallen + 1;

      return NSS_STATUS_SUCCESS;
    }

  if (__session.ls_conn == NULL)
    {
      return NSS_STATUS_UNAVAIL;
    }

  vals = ldap_get_values (__session.ls_conn, e, (char *) attr);
  if (vals == NULL)
    {
      def = DF (attr);
      if (def != NULL)
        {
          vallen = strlen (def);
          if (*buflen < (size_t) (vallen + 1))
            {
              return NSS_STATUS_TRYAGAIN;
            }

          *valptr = *buffer;

          strncpy (*valptr, def, vallen);
          (*valptr)[vallen] = '\0';

          *buffer += vallen + 1;
          *buflen -= vallen + 1;

          return NSS_STATUS_SUCCESS;
        }
      else
        {
          return NSS_STATUS_NOTFOUND;
        }
    }

  vallen = strlen (*vals);
  if (*buflen < (size_t) (vallen + 1))
    {
      ldap_value_free (vals);
      return NSS_STATUS_TRYAGAIN;
    }

  *valptr = *buffer;

  strncpy (*valptr, *vals, vallen);
  (*valptr)[vallen] = '\0';

  *buffer += vallen + 1;
  *buflen -= vallen + 1;

  ldap_value_free (vals);

  return NSS_STATUS_SUCCESS;
}

const char *
_nss_ldap_locate_userpassword (char **vals)
{
  const char *token = NULL;
  size_t token_length = 0;
  char **valiter;
  const char *pwd = NULL;

  if (__config != NULL)
    {
      switch (__config->ldc_password_type)
        {
        case LU_RFC2307_USERPASSWORD:
          token = "{CRYPT}";
          token_length = sizeof ("{CRYPT}") - 1;
          break;
        case LU_RFC3112_AUTHPASSWORD:
          token = "CRYPT$";
          token_length = sizeof ("CRYPT$") - 1;
          break;
        case LU_OTHER_PASSWORD:
          break;
        }
    }

  if (vals != NULL)
    {
      for (valiter = vals; *valiter != NULL; valiter++)
        {
          if (token_length == 0 ||
              strncasecmp (*valiter, token, token_length) == 0)
            {
              pwd = *valiter;
              break;
            }
        }
    }

  if (pwd == NULL)
    pwd = "*";
  else
    pwd += token_length;

  return pwd;
}

/*
 * Assign a single value to *valptr, after examining userPassword for
 * a syntactically suitable value.
 */
enum nss_status
_nss_ldap_assign_userpassword (LDAPMessage * e,
                               const char *attr, char **valptr,
                               char **buffer, size_t * buflen)
{
  char **vals;
  const char *pwd;
  int vallen;

  log_log(LOG_DEBUG,"==> _nss_ldap_assign_userpassword");

  if (__session.ls_conn == NULL)
    {
      return NSS_STATUS_UNAVAIL;
    }

  vals=ldap_get_values(__session.ls_conn,e,(char *)attr);
  pwd=_nss_ldap_locate_userpassword(vals);

  vallen=strlen(pwd);

  if (*buflen < (size_t) (vallen + 1))
    {
      if (vals != NULL)
        {
          ldap_value_free (vals);
        }
      log_log(LOG_DEBUG,"<== _nss_ldap_assign_userpassword");
      return NSS_STATUS_TRYAGAIN;
    }

  *valptr = *buffer;

  strncpy (*valptr, pwd, vallen);
  (*valptr)[vallen] = '\0';

  *buffer += vallen + 1;
  *buflen -= vallen + 1;

  if (vals != NULL)
    {
      ldap_value_free (vals);
    }

  log_log(LOG_DEBUG,"<== _nss_ldap_assign_userpassword");

  return NSS_STATUS_SUCCESS;
}

int has_objectclass(LDAPMessage *entry,const char *objectclass)
{
  char **vals;
  int i;
  LDAP *ld;
  ld=__session.ls_conn;
  if (ld==NULL)
    return 0;
  vals=ldap_get_values(ld,entry,AT(objectClass));
  if (vals==NULL)
    return 0;
  for (i=0;vals[i]!=NULL;i++)
  {
    if (strcasecmp(vals[i],objectclass)==0)
    {
      ldap_value_free(vals);
      return -1;
    }
  }
  ldap_value_free(vals);
  return 0;
}

#ifdef HAVE_SHADOW_H
int
_nss_ldap_shadow_date (const char *val)
{
  int date;

  if (__config->ldc_shadow_type == LS_AD_SHADOW)
    {
      date = atoll (val) / 864000000000LL - 134774LL;
      date = (date > 99999) ? 99999 : date;
    }
  else
    {
      date = atol (val);
    }

  return date;
}

void
_nss_ldap_shadow_handle_flag (struct spwd *sp)
{
  if (__config->ldc_shadow_type == LS_AD_SHADOW)
    {
      if (sp->sp_flag & UF_DONT_EXPIRE_PASSWD)
        sp->sp_max = 99999;
      sp->sp_flag = 0;
    }
}
#endif /* HAVE_SHADOW_H */

const char *
_nss_ldap_map_at (enum ldap_map_selector sel, const char *attribute)
{
  const char *mapped = NULL;
  enum nss_status stat;

  stat = _nss_ldap_map_get (__config, sel, MAP_ATTRIBUTE, attribute, &mapped);

  return (stat == NSS_STATUS_SUCCESS) ? mapped : attribute;
}

const char *
_nss_ldap_unmap_at (enum ldap_map_selector sel, const char *attribute)
{
  const char *mapped = NULL;
  enum nss_status stat;

  stat = _nss_ldap_map_get (__config, sel, MAP_ATTRIBUTE_REVERSE, attribute, &mapped);

  return (stat == NSS_STATUS_SUCCESS) ? mapped : attribute;
}

const char *
_nss_ldap_map_oc (enum ldap_map_selector sel, const char *objectclass)
{
  const char *mapped = NULL;
  enum nss_status stat;

  stat = _nss_ldap_map_get (__config, sel, MAP_OBJECTCLASS, objectclass, &mapped);

  return (stat == NSS_STATUS_SUCCESS) ? mapped : objectclass;
}

const char *
_nss_ldap_unmap_oc (enum ldap_map_selector sel, const char *objectclass)
{
  const char *mapped = NULL;
  enum nss_status stat;

  stat = _nss_ldap_map_get (__config, sel, MAP_OBJECTCLASS_REVERSE, objectclass, &mapped);

  return (stat == NSS_STATUS_SUCCESS) ? mapped : objectclass;
}

const char *
_nss_ldap_map_ov (const char *attribute)
{
  const char *value = NULL;

  _nss_ldap_map_get (__config, LM_NONE, MAP_OVERRIDE, attribute, &value);

  return value;
}

const char *
_nss_ldap_map_df (const char *attribute)
{
  const char *value = NULL;

  _nss_ldap_map_get (__config, LM_NONE, MAP_DEFAULT, attribute, &value);

  return value;
}

enum nss_status
_nss_ldap_map_put (struct ldap_config * config,
                   enum ldap_map_selector sel,
                   enum ldap_map_type type,
                   const char *from,
                   const char *to)
{
  struct ldap_datum key, val;
  void **map;
  enum nss_status stat;

  switch (type)
    {
    case MAP_ATTRIBUTE:
      /* special handling for attribute mapping */ if (strcmp
                                                       (from,
                                                        "userPassword") == 0)
        {
          if (strcasecmp (to, "userPassword") == 0)
            config->ldc_password_type = LU_RFC2307_USERPASSWORD;
          else if (strcasecmp (to, "authPassword") == 0)
            config->ldc_password_type = LU_RFC3112_AUTHPASSWORD;
          else
            config->ldc_password_type = LU_OTHER_PASSWORD;
        }
      else if (strcmp (from, "shadowLastChange") == 0)
        {
          if (strcasecmp (to, "shadowLastChange") == 0)
            config->ldc_shadow_type = LS_RFC2307_SHADOW;
          else if (strcasecmp (to, "pwdLastSet") == 0)
            config->ldc_shadow_type = LS_AD_SHADOW;
          else
            config->ldc_shadow_type = LS_OTHER_SHADOW;
        }
      break;
    case MAP_OBJECTCLASS:
    case MAP_OVERRIDE:
    case MAP_DEFAULT:
      break;
    default:
      return NSS_STATUS_NOTFOUND;
      break;
    }

  assert (sel <= LM_NONE);
  map = &config->ldc_maps[sel][type];
  assert (*map != NULL);

  NSS_LDAP_DATUM_ZERO (&key);
  key.data = (void *) from;
  key.size = strlen (from) + 1;

  NSS_LDAP_DATUM_ZERO (&val);
  val.data = (void *) to;
  val.size = strlen (to) + 1;

  stat = _nss_ldap_db_put (*map, NSS_LDAP_DB_NORMALIZE_CASE, &key, &val);
  if (stat == NSS_STATUS_SUCCESS &&
      (type == MAP_ATTRIBUTE || type == MAP_OBJECTCLASS))
    {
      type = (type == MAP_ATTRIBUTE) ? MAP_ATTRIBUTE_REVERSE : MAP_OBJECTCLASS_REVERSE;
      map = &config->ldc_maps[sel][type];

      stat = _nss_ldap_db_put (*map, NSS_LDAP_DB_NORMALIZE_CASE, &val, &key);
    }

  return stat;
}

enum nss_status
_nss_ldap_map_get (struct ldap_config * config,
                   enum ldap_map_selector sel,
                   enum ldap_map_type type,
                   const char *from, const char **to)
{
  struct ldap_datum key, val;
  void *map;
  enum nss_status stat;

  if (config == NULL || sel > LM_NONE || type > MAP_MAX)
    {
      return NSS_STATUS_NOTFOUND;
    }

  map = config->ldc_maps[sel][type];
  assert (map != NULL);

  NSS_LDAP_DATUM_ZERO (&key);
  key.data = from;
  key.size = strlen (from) + 1;

  NSS_LDAP_DATUM_ZERO (&val);

  stat = _nss_ldap_db_get (map, NSS_LDAP_DB_NORMALIZE_CASE, &key, &val);
  if (stat == NSS_STATUS_NOTFOUND && sel != LM_NONE)
    {
      map = config->ldc_maps[LM_NONE][type];
      assert (map != NULL);
      stat = _nss_ldap_db_get (map, NSS_LDAP_DB_NORMALIZE_CASE, &key, &val);
    }

  if (stat == NSS_STATUS_SUCCESS)
    *to = (char *) val.data;
  else
    *to = NULL;

  return stat;
}

/*
 * Proxy bind support for AIX. Very simple, but should do
 * the job.
 */

struct ldap_proxy_bind_args
{
  char *binddn;
  const char *bindpw;
};


#if LDAP_SET_REBIND_PROC_ARGS < 3
static struct ldap_proxy_bind_args __proxy_args = { NULL, NULL };
#endif

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
#if LDAP_SET_REBIND_PROC_ARGS == 3
static int
do_proxy_rebind (LDAP * ld, LDAP_CONST char *url, ber_tag_t request,
                 ber_int_t msgid, void *arg)
#else
static int
do_proxy_rebind (LDAP * ld, LDAP_CONST char *url, int request,
                 ber_int_t msgid)
#endif
{
  int timelimit;
#if LDAP_SET_REBIND_PROC_ARGS == 3
  struct ldap_proxy_bind_args *who = (struct ldap_proxy_bind_args *) arg;
#else
  struct ldap_proxy_bind_args *who = &__proxy_args;
#endif

  timelimit = __session.ls_config->ldc_bind_timelimit;

  return do_bind (ld, timelimit, who->binddn, who->bindpw, 0);
}
#else
#if LDAP_SET_REBIND_PROC_ARGS == 3
static int
do_proxy_rebind (LDAP * ld, char **whop, char **credp, int *methodp,
                 int freeit, void *arg)
#elif LDAP_SET_REBIND_PROC_ARGS == 2
static int
do_proxy_rebind (LDAP * ld, char **whop, char **credp, int *methodp,
                 int freeit)
#endif
{
#if LDAP_SET_REBIND_PROC_ARGS == 3
  struct ldap_proxy_bind_args *who = (struct ldap_proxy_bind_args *) arg;
#else
  struct ldap_proxy_bind_args *who = &__proxy_args;
#endif
  if (freeit)
    {
      if (*whop != NULL)
        free (*whop);
      if (*credp != NULL)
        free (*credp);
    }

  *whop = who->binddn ? strdup (who->binddn) : NULL;
  *credp = who->bindpw ? strdup (who->bindpw) : NULL;

  *methodp = LDAP_AUTH_SIMPLE;

  return LDAP_SUCCESS;
}
#endif

enum nss_status
_nss_ldap_proxy_bind (const char *user, const char *password)
{
  struct ldap_args args;
  LDAPMessage *res, *e;
  enum nss_status stat;
  int rc;
#if LDAP_SET_REBIND_PROC_ARGS == 3
  struct ldap_proxy_bind_args proxy_args_buf;
  struct ldap_proxy_bind_args *proxy_args = &proxy_args_buf;
#else
  struct ldap_proxy_bind_args *proxy_args = &__proxy_args;
#endif

  log_log(LOG_DEBUG,"==> _nss_ldap_proxy_bind");

  LA_INIT (args);
  LA_TYPE (args) = LA_TYPE_STRING;
  LA_STRING (args) = user;

  /*
   * Binding with an empty password will always work, so don't let
   * the user in if they try that.
   */
  if (password == NULL || password[0] == '\0')
    {
      log_log(LOG_DEBUG,"<== _nss_ldap_proxy_bind (empty password not permitted)");
      /* XXX overload */
      return NSS_STATUS_TRYAGAIN;
    }

  _nss_ldap_enter ();

  stat = _nss_ldap_search_s (&args, _nss_ldap_filt_getpwnam,
                             LM_PASSWD, NULL, 1, &res);
  if (stat == NSS_STATUS_SUCCESS)
    {
      e = _nss_ldap_first_entry (res);
      if (e != NULL)
        {
          proxy_args->binddn = _nss_ldap_get_dn (e);
          proxy_args->bindpw = password;

          if (proxy_args->binddn != NULL)
            {
              /* Use our special rebind procedure. */
#if LDAP_SET_REBIND_PROC_ARGS == 3
              ldap_set_rebind_proc (__session.ls_conn, do_proxy_rebind, NULL);
#elif LDAP_SET_REBIND_PROC_ARGS == 2
              ldap_set_rebind_proc (__session.ls_conn, do_proxy_rebind);
#endif

              log_log(LOG_DEBUG,":== _nss_ldap_proxy_bind: %s", proxy_args->binddn);

              rc = do_bind (__session.ls_conn,
                            __session.ls_config->ldc_bind_timelimit,
                            proxy_args->binddn, proxy_args->bindpw, 0);
              switch (rc)
                {
                case LDAP_INVALID_CREDENTIALS:
                  /* XXX overload */
                  stat = NSS_STATUS_TRYAGAIN;
                  break;
                case LDAP_NO_SUCH_OBJECT:
                  stat = NSS_STATUS_NOTFOUND;
                  break;
                case LDAP_SUCCESS:
                  stat = NSS_STATUS_SUCCESS;
                  break;
                default:
                  stat = NSS_STATUS_UNAVAIL;
                  break;
                }
              /*
               * Close the connection, don't want to continue
               * being bound as this user or using this rebind proc.
               */
              do_close ();
              ldap_memfree (proxy_args->binddn);
            }
          else
            {
              stat = NSS_STATUS_NOTFOUND;
            }
          proxy_args->binddn = NULL;
          proxy_args->bindpw = NULL;
        }
      else
        {
          stat = NSS_STATUS_NOTFOUND;
        }
      ldap_msgfree (res);
    }

  _nss_ldap_leave ();

  log_log(LOG_DEBUG,"<== _nss_ldap_proxy_bind");

  return stat;
}

const char **
_nss_ldap_get_attributes (enum ldap_map_selector sel)
{
  const char **attrs = NULL;

  log_log(LOG_DEBUG,"==> _nss_ldap_get_attributes");

  if (sel < LM_NONE)
    {
      if (do_init () != NSS_STATUS_SUCCESS)
        {
          log_log(LOG_DEBUG,"<== _nss_ldap_get_attributes (init failed)");
          return NULL;
        }

      attrs = __session.ls_config->ldc_attrtab[sel];
    }

  log_log(LOG_DEBUG,"<== _nss_ldap_get_attributes");

  return attrs;
}

int
_nss_ldap_test_config_flag (unsigned int flag)
{
  if (__config != NULL && (__config->ldc_flags & flag) != 0)
    return 1;

  return 0;
}

int
_nss_ldap_test_initgroups_ignoreuser (const char *user)
{
  char **p;

  if (__config == NULL)
    return 0;

  if (__config->ldc_initgroups_ignoreusers == NULL)
    return 0;

  for (p = __config->ldc_initgroups_ignoreusers; *p != NULL; p++)
    {
      if (strcmp (*p, user) == 0)
        return 1;
    }

  return 0;
}
