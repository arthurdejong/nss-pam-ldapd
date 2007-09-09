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
#include "pagectrl.h"
#include "common.h"
#include "log.h"
#include "cfg.h"
#include "attmap.h"
#include "compat/ldap.h"

NSS_LDAP_DEFINE_LOCK (__lock);

/*
 * LS_INIT only used for enumeration contexts
 */
#define LS_INIT(state)  do { state.ls_type = LS_TYPE_INDEX; state.ls_retry = 0; state.ls_info.ls_index = -1; } while (0)

enum ldap_session_state
{
  LS_UNINITIALIZED = -1,
  LS_INITIALIZED,
  LS_CONNECTED_TO_DSA
};

/*
 * convenient wrapper around pointer into global config list, and a
 * connection to an LDAP server.
 */
struct ldap_session
{
  /* the connection */
  LDAP *ls_conn;
  /* timestamp of last activity */
  time_t ls_timestamp;
  /* has session been connected? */
  enum ldap_session_state ls_state;
  /* index into ldc_uris: currently connected DSA */
  int ls_current_uri;
};

/*
 * Global LDAP session.
 */
static struct ldap_session __session = { NULL, 0, LS_UNINITIALIZED, 0 };

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
do_sasl_interact (LDAP *ld, unsigned flags, void *defaults, void *_interact)
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
          log_log(LOG_ERR,"could not connect to any LDAP server as %s - %s",
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

      if (nslcd_cfg->ldc_sasl_secprops!=NULL)
        {
          rc =
            ldap_set_option (ld, LDAP_OPT_X_SASL_SECPROPS,
                             (void *)nslcd_cfg->ldc_sasl_secprops);
          if (rc != LDAP_SUCCESS)
            {
              log_log(LOG_DEBUG,"do_bind: unable to set SASL security properties");
              return rc;
            }
        }

#ifdef CONFIGURE_KRB5_CCNAME
      /* Set default Kerberos ticket cache for SASL-GSSAPI */
      /* There are probably race conditions here XXX */
      if (nslcd_cfg->ldc_krb5_ccname != NULL)
        {
          ccname = nslcd_cfg->ldc_krb5_ccname;
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

#if defined(HAVE_LDAP_START_TLS_S) || defined(HAVE_LDAP_START_TLS)
static int do_start_tls (struct ldap_session * session)
{
  int rc;
#ifdef HAVE_LDAP_START_TLS
  int msgid;
  struct timeval tv,*timeout;
  LDAPMessage *res=NULL;

  log_log(LOG_DEBUG,"==> do_start_tls");

  rc=ldap_start_tls(session->ls_conn, NULL, NULL, &msgid);
  if (rc != LDAP_SUCCESS)
  {
    log_log(LOG_DEBUG,"<== do_start_tls (ldap_start_tls failed: %s)",ldap_err2string(rc));
    return rc;
  }

  if (session->ls_config->ldc_bind_timelimit==LDAP_NO_LIMIT)
  {
    timeout=NULL;
  }
  else
  {
    tv.tv_sec=session->ls_config->ldc_bind_timelimit;
    tv.tv_usec=0;
    timeout=&tv;
  }

  rc=ldap_result(session->ls_conn,msgid,1,timeout,&res);
  if (rc==-1)
  {
#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_ERROR_NUMBER)
    if (ldap_get_option(session->ls_conn,LDAP_OPT_ERROR_NUMBER,&rc)!=LDAP_SUCCESS)
    {
      rc=LDAP_UNAVAILABLE;
    }
#else
    rc=ld->ld_errno;
#endif /* LDAP_OPT_ERROR_NUMBER */
    log_log(LOG_DEBUG,"<== do_start_tls (ldap_start_tls failed: %s)",ldap_err2string (rc));
    return rc;
  }

  rc=ldap_result2error(session->ls_conn,res,1);
  if (rc!=LDAP_SUCCESS)
  {
    log_log(LOG_DEBUG,"<== do_start_tls (ldap_result2error failed: %s)",ldap_err2string (rc));
    return rc;
  }

  rc=ldap_install_tls(session->ls_conn);
#else
  rc=ldap_start_tls_s(session->ls_conn,NULL,NULL);
#endif /* HAVE_LDAP_START_TLS */

  if (rc != LDAP_SUCCESS)
  {
    log_log(LOG_DEBUG,"<== do_start_tls (start TLS failed: %s)",ldap_err2string(rc));
    return rc;
  }

  return LDAP_SUCCESS;
}
#endif

/*
 * Rebind functions.
 */

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
#if LDAP_SET_REBIND_PROC_ARGS == 3
static int
do_rebind (LDAP *ld, LDAP_CONST char *url, ber_tag_t request,
           ber_int_t msgid, void *arg)
#else
static int
do_rebind (LDAP * ld, LDAP_CONST char *url, int request, ber_int_t msgid)
#endif
{
  char *who, *cred;
  int timelimit;
  int with_sasl = 0;

  if (geteuid () == 0 && nslcd_cfg->ldc_rootbinddn)
    {
      who = nslcd_cfg->ldc_rootbinddn;
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
      with_sasl = nslcd_cfg->ldc_rootusesasl;
      if (with_sasl)
        {
          cred = nslcd_cfg->ldc_rootsaslid;
        }
      else
        {
#endif
          cred = nslcd_cfg->ldc_rootbindpw;
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
        }
#endif
    }
  else
    {
      who = nslcd_cfg->ldc_binddn;
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
      with_sasl = nslcd_cfg->ldc_usesasl;
      if (with_sasl)
        {
          cred = nslcd_cfg->ldc_saslid;
        }
      else
        {
#endif
          cred = nslcd_cfg->ldc_bindpw;
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
        }
#endif
    }

  timelimit = nslcd_cfg->ldc_bind_timelimit;

#ifdef HAVE_LDAP_START_TLS_S
  if (nslcd_cfg->ldc_ssl_on == SSL_START_TLS)
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
  if (geteuid () == 0 && nslcd_cfg->ldc_rootbinddn)
    {
      *whop = strdup (nslcd_cfg->ldc_rootbinddn);
      if (nslcd_cfg->ldc_rootbindpw != NULL)
        *credp = strdup (nslcd_cfg->ldc_rootbindpw);
    }
  else
    {
      if (nslcd_cfg->ldc_binddn != NULL)
        *whop = strdup (nslcd_cfg->ldc_binddn);
      if (nslcd_cfg->ldc_bindpw != NULL)
        *credp = strdup (nslcd_cfg->ldc_bindpw);
    }

  *methodp = LDAP_AUTH_SIMPLE;

  return LDAP_SUCCESS;
}
#endif

/*
 * Acquires global lock.
 */
void
_nss_ldap_enter (void)
{
  log_log(LOG_DEBUG,"==> _nss_ldap_enter");
  NSS_LDAP_LOCK (__lock);
  log_log(LOG_DEBUG,"<== _nss_ldap_enter");
}

/*
 * Releases global mutex.
 */
void
_nss_ldap_leave (void)
{
  log_log(LOG_DEBUG,"==> _nss_ldap_leave");
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
      log_log(LOG_INFO,"closing connection %p fd %d",
              (void *)__session.ls_conn, sd);
#endif /* DEBUG */

      ldap_unbind (__session.ls_conn);
      __session.ls_conn = NULL;
      __session.ls_state = LS_UNINITIALIZED;
    }

  log_log(LOG_DEBUG,"<== do_close");
}

static enum nss_status do_init_session(LDAP **ld,const char *uri)
{
  enum nss_status stat;
  stat=do_map_error(ldap_initialize(ld,uri));
  if ((stat==NSS_STATUS_SUCCESS)&&(*ld==NULL))
    return NSS_STATUS_UNAVAIL;
  return stat;
}

enum nss_status _nss_ldap_init(void)
{
  enum nss_status stat;

  log_log(LOG_DEBUG,"==> _nss_ldap_init");

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
      assert (nslcd_cfg != NULL);

      if (nslcd_cfg->ldc_idle_timelimit)
        {
          time (&current_time);
          if ((__session.ls_timestamp +
               nslcd_cfg->ldc_idle_timelimit) < current_time)
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
          log_log(LOG_DEBUG,"<== _nss_ldap_init (cached session)");
          return NSS_STATUS_SUCCESS;
        }
    }

  __session.ls_conn = NULL;
  __session.ls_timestamp = 0;
  __session.ls_state = LS_UNINITIALIZED;

#ifdef HAVE_LDAP_SET_OPTION
  if (nslcd_cfg->ldc_debug)
  {
    ber_set_option(NULL,LBER_OPT_DEBUG_LEVEL,&nslcd_cfg->ldc_debug);
    ldap_set_option(NULL,LDAP_OPT_DEBUG_LEVEL,&nslcd_cfg->ldc_debug);
  }
#endif /* HAVE_LDAP_SET_OPTION */

#ifdef HAVE_LDAPSSL_CLIENT_INIT
  /*
   * Initialize the SSL library.
   */
  if (nslcd_cfg->ldc_ssl_on == SSL_LDAPS)
    {
      int rc = 0;
      if (__ssl_initialized == 0
          && (rc = ldapssl_client_init (nslcd_cfg->ldc_sslpath, NULL)) != LDAP_SUCCESS)
        {
          log_log(LOG_DEBUG,"<== _nss_ldap_init (ldapssl_client_init failed with rc = %d)", rc);
          return NSS_STATUS_UNAVAIL;
        }
      __ssl_initialized = 1;
    }
#endif /* SSL */

  __session.ls_conn = NULL;

  assert (__session.ls_current_uri <= NSS_LDAP_CONFIG_URI_MAX);
  assert (nslcd_cfg->ldc_uris[__session.ls_current_uri] != NULL);

  stat = do_init_session (&__session.ls_conn,
                          nslcd_cfg->ldc_uris[__session.ls_current_uri]);
  if (stat!=NSS_STATUS_SUCCESS)
  {
    log_log(LOG_DEBUG,"<== _nss_ldap_init (failed to initialize LDAP session)");
    return stat;
  }

  __session.ls_state=LS_INITIALIZED;

  log_log(LOG_DEBUG,"<== _nss_ldap_init (initialized session)");

  return NSS_STATUS_SUCCESS;
}

#if defined HAVE_LDAP_START_TLS_S || (defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS))
static int do_ssl_options(void)
{
  log_log(LOG_DEBUG,"==> do_ssl_options");
#ifdef LDAP_OPT_X_TLS_RANDOM_FILE
  if (nslcd_cfg->ldc_tls_randfile!=NULL)
  {
    /* rand file */
    if (ldap_set_option(NULL,LDAP_OPT_X_TLS_RANDOM_FILE,
                        nslcd_cfg->ldc_tls_randfile)!=LDAP_SUCCESS)
    {
      log_log(LOG_DEBUG,"<== do_ssl_options: Setting of LDAP_OPT_X_TLS_RANDOM_FILE failed");
      return LDAP_OPERATIONS_ERROR;
    }
  }
#endif /* LDAP_OPT_X_TLS_RANDOM_FILE */
  if (nslcd_cfg->ldc_tls_cacertfile!=NULL)
  {
    /* ca cert file */
    if (ldap_set_option(NULL,LDAP_OPT_X_TLS_CACERTFILE,
                        nslcd_cfg->ldc_tls_cacertfile)!=LDAP_SUCCESS)
    {
      log_log(LOG_DEBUG,"<== do_ssl_options: Setting of LDAP_OPT_X_TLS_CACERTFILE failed");
      return LDAP_OPERATIONS_ERROR;
    }
  }
  if (nslcd_cfg->ldc_tls_cacertdir!=NULL)
  {
    /* ca cert directory */
    if (ldap_set_option(NULL,LDAP_OPT_X_TLS_CACERTDIR,
                        nslcd_cfg->ldc_tls_cacertdir)!=LDAP_SUCCESS)
    {
      log_log(LOG_DEBUG,"<== do_ssl_options: Setting of LDAP_OPT_X_TLS_CACERTDIR failed");
      return LDAP_OPERATIONS_ERROR;
    }
  }
  /* require cert? */
  if (nslcd_cfg->ldc_tls_checkpeer > -1)
  {
    if (ldap_set_option(NULL,LDAP_OPT_X_TLS_REQUIRE_CERT,
                          &nslcd_cfg->ldc_tls_checkpeer)!=LDAP_SUCCESS)
    {
      log_log(LOG_DEBUG,"<== do_ssl_options: Setting of LDAP_OPT_X_TLS_REQUIRE_CERT failed");
      return LDAP_OPERATIONS_ERROR;
    }
  }

  if (nslcd_cfg->ldc_tls_ciphers != NULL)
  {
    /* set cipher suite, certificate and private key: */
    if (ldap_set_option(NULL,LDAP_OPT_X_TLS_CIPHER_SUITE,
                          nslcd_cfg->ldc_tls_ciphers)!=LDAP_SUCCESS)
      {
        log_log(LOG_DEBUG,"<== do_ssl_options: Setting of LDAP_OPT_X_TLS_CIPHER_SUITE failed");
        return LDAP_OPERATIONS_ERROR;
      }
  }

  if (nslcd_cfg->ldc_tls_cert != NULL)
  {
    if (ldap_set_option(NULL,LDAP_OPT_X_TLS_CERTFILE,
                        nslcd_cfg->ldc_tls_cert)!=LDAP_SUCCESS)
      {
        log_log(LOG_DEBUG,"<== do_ssl_options: Setting of LDAP_OPT_X_TLS_CERTFILE failed");
        return LDAP_OPERATIONS_ERROR;
      }
  }
  if (nslcd_cfg->ldc_tls_key != NULL)
  {
    if (ldap_set_option(NULL,LDAP_OPT_X_TLS_KEYFILE,
                        nslcd_cfg->ldc_tls_key)!=LDAP_SUCCESS)
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
 * Opens connection to an LDAP server - should only be called from search
 * API. Other API that just needs access to configuration and schema should
 * call _nss_ldap_init().
 *
 * As with do_close(), this assumes ownership of sess.
 * It also wants to own __config: is there a potential deadlock here? XXX
 */
static enum nss_status
do_open (void)
{
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

  /* Moved the head part of do_open() into _nss_ldap_init() */
  stat = _nss_ldap_init();
  if (stat != NSS_STATUS_SUCCESS)
    {
      log_log(LOG_DEBUG,"<== do_open (session initialization failed)");
      return stat;
    }

  assert (__session.ls_conn != NULL);
  assert (nslcd_cfg != NULL);
  assert (__session.ls_state != LS_UNINITIALIZED);

  if (__session.ls_state == LS_CONNECTED_TO_DSA)
    {
      log_log(LOG_DEBUG,"<== do_open (cached session)");
      return NSS_STATUS_SUCCESS;
    }

#if LDAP_SET_REBIND_PROC_ARGS == 3
  ldap_set_rebind_proc (__session.ls_conn, do_rebind, NULL);
#elif LDAP_SET_REBIND_PROC_ARGS == 2
  ldap_set_rebind_proc (__session.ls_conn, do_rebind);
#endif

  ldap_set_option (__session.ls_conn, LDAP_OPT_PROTOCOL_VERSION,
                   &nslcd_cfg->ldc_version);

  ldap_set_option (__session.ls_conn, LDAP_OPT_DEREF, &nslcd_cfg->ldc_deref);

  ldap_set_option (__session.ls_conn, LDAP_OPT_TIMELIMIT,
                   &nslcd_cfg->ldc_timelimit);

#ifdef LDAP_X_OPT_CONNECT_TIMEOUT
  /*
   * This is a new option in the Netscape SDK which sets
   * the TCP connect timeout. For want of a better value,
   * we use the bind_timelimit to control this.
   */
  timeout = nslcd_cfg->ldc_bind_timelimit * 1000;
  ldap_set_option (__session.ls_conn, LDAP_X_OPT_CONNECT_TIMEOUT, &timeout);
#endif /* LDAP_X_OPT_CONNECT_TIMEOUT */

#ifdef LDAP_OPT_NETWORK_TIMEOUT
  tv.tv_sec = nslcd_cfg->ldc_bind_timelimit;
  tv.tv_usec = 0;
  ldap_set_option (__session.ls_conn, LDAP_OPT_NETWORK_TIMEOUT, &tv);
#endif /* LDAP_OPT_NETWORK_TIMEOUT */

#ifdef LDAP_OPT_REFERRALS
  ldap_set_option (__session.ls_conn, LDAP_OPT_REFERRALS,
                   nslcd_cfg->ldc_referrals ? LDAP_OPT_ON : LDAP_OPT_OFF);
#endif /* LDAP_OPT_REFERRALS */

#ifdef LDAP_OPT_RESTART
  ldap_set_option (__session.ls_conn, LDAP_OPT_RESTART,
                   nslcd_cfg->ldc_restart ? LDAP_OPT_ON : LDAP_OPT_OFF);
#endif /* LDAP_OPT_RESTART */

#if defined(HAVE_LDAP_START_TLS_S) || defined(HAVE_LDAP_START_TLS)
  if (nslcd_cfg->ldc_ssl_on == SSL_START_TLS)
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
      if (do_ssl_options()!=LDAP_SUCCESS)
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
  if (nslcd_cfg->ldc_ssl_on == SSL_LDAPS)
    {
#if defined(LDAP_OPT_X_TLS)
      int tls = LDAP_OPT_X_TLS_HARD;
      if (ldap_set_option(__session.ls_conn, LDAP_OPT_X_TLS, &tls) !=
          LDAP_SUCCESS)
        {
          do_close ();
          log_log(LOG_DEBUG,"<== do_open (TLS setup failed)");
          return NSS_STATUS_UNAVAIL;
        }

      /* set up SSL context */
      if (do_ssl_options()!=LDAP_SUCCESS)
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
  if (geteuid() == 0 && nslcd_cfg->ldc_rootbinddn != NULL)
    {
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
      usesasl = nslcd_cfg->ldc_rootusesasl;
      bindarg = nslcd_cfg->ldc_rootusesasl ? nslcd_cfg->ldc_rootsaslid : nslcd_cfg->ldc_rootbindpw;
#else
      usesasl = 0;
      bindarg = nslcd_cfg->ldc_rootbindpw;
#endif

      rc = do_bind (__session.ls_conn,
                    nslcd_cfg->ldc_bind_timelimit,
                    nslcd_cfg->ldc_rootbinddn, bindarg, usesasl);
    }
  else
    {
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
      usesasl = nslcd_cfg->ldc_usesasl;
      bindarg = nslcd_cfg->ldc_usesasl ? nslcd_cfg->ldc_saslid : nslcd_cfg->ldc_bindpw;
#else
      usesasl = 0;
      bindarg = nslcd_cfg->ldc_bindpw;
#endif

      rc = do_bind (__session.ls_conn,
                    nslcd_cfg->ldc_bind_timelimit,
                    nslcd_cfg->ldc_binddn,
                    nslcd_cfg->ldc_bindpw, usesasl);
    }

  if (rc != LDAP_SUCCESS)
    {
      /* log actual LDAP error code */
      log_log(LOG_INFO,
              "failed to bind to LDAP server %s: %s",
              nslcd_cfg->ldc_uris[__session.ls_current_uri],
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

/*
 * Wrapper around ldap_result() to skip over search references
 * and deal transparently with the last entry.
 */
static enum nss_status
do_result (struct ent_context *context, int all)
{
  int rc = LDAP_UNAVAILABLE;
  enum nss_status stat = NSS_STATUS_TRYAGAIN;
  struct timeval tv, *tvp;

  log_log(LOG_DEBUG,"==> do_result");

  if (nslcd_cfg->ldc_timelimit == LDAP_NO_LIMIT)
    {
      tvp = NULL;
    }
  else
    {
      tv.tv_sec = nslcd_cfg->ldc_timelimit;
      tv.tv_usec = 0;
      tvp = &tv;
    }

  do
    {
      if (context->ec_res!=NULL)
      {
        ldap_msgfree(context->ec_res);
        context->ec_res=NULL;
      }

      rc =
        ldap_result (__session.ls_conn, context->ec_msgid, all, tvp,
                     &(context->ec_res));
      switch (rc)
        {
        case -1:
        case 0:
          if (ldap_get_option
              (__session.ls_conn, LDAP_OPT_ERROR_NUMBER, &rc) != LDAP_SUCCESS)
            {
              rc = LDAP_UNAVAILABLE;
            }
          log_log(LOG_ERR,"could not get LDAP result - %s",
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
              /* NB: this frees context->ec_res */
              LDAPControl **resultControls = NULL;

              context->ec_cookie = NULL;

              parserc =
                ldap_parse_result (__session.ls_conn, context->ec_res, &rc, NULL,
                                   NULL, NULL, &resultControls, 1);
              if (parserc != LDAP_SUCCESS
                  && parserc != LDAP_MORE_RESULTS_TO_RETURN)
                {
                  stat = NSS_STATUS_UNAVAIL;
                  ldap_abandon (__session.ls_conn, context->ec_msgid);
                  log_log(LOG_ERR,"could not get LDAP result - %s",
                          ldap_err2string (rc));
                }
              else if (resultControls != NULL)
                {
                  /* See if there are any more pages to come */
                  parserc = ldap_parse_page_control (__session.ls_conn,
                                                     resultControls, NULL,
                                                     &(context->ec_cookie));
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
              context->ec_res = NULL;
              context->ec_msgid = -1;
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
 * This function initializes an enumeration context, acquiring
 * the global mutex.
 *
 * It could be done from the default constructor, under Solaris, but we
 * delay it until the setXXent() function is called.
 */
void _nss_ldap_ent_context_init(struct ent_context *context)
{
  _nss_ldap_enter();
  _nss_ldap_ent_context_init_locked(context);
  _nss_ldap_leave();
}

/*
 * This function initializes an enumeration context.
 *
 * It could be done from the default constructor, under Solaris, but we
 * delay it until the setXXent() function is called.
 */
void _nss_ldap_ent_context_init_locked(struct ent_context *context)
{
  /* TODO: find out why we need to have aquired a lock for this */
  context->ec_cookie=NULL;
  context->ec_res=NULL;
  context->ec_msgid=-1;
  LS_INIT(context->ec_state);
}

/*
 * Clears a given context; we require the caller
 * to acquire the lock.
 */
void _nss_ldap_ent_context_cleanup(struct ent_context *context)
{
  if (context==NULL)
    return;
  /* free read messages */
  if (context->ec_res!=NULL)
  {
    ldap_msgfree(context->ec_res);
    context->ec_res=NULL;
  }
  /* abandon the search if there were more results to fetch */
  if ((context->ec_msgid>-1)&&(do_result(context,LDAP_MSG_ONE)==NSS_STATUS_SUCCESS))
  {
    ldap_abandon(__session.ls_conn,context->ec_msgid);
    context->ec_msgid=-1;
  }
  /* clean up cookie */
  if (context->ec_cookie!=NULL)
  {
    ber_bvfree(context->ec_cookie);
    context->ec_cookie=NULL;
  }
  LS_INIT(context->ec_state);
  if (_nss_ldap_test_config_flag(NSS_LDAP_FLAGS_CONNECT_POLICY_ONESHOT))
    do_close ();
}

/*
 * Synchronous search function. Don't call this directly;
 * always wrap calls to this with do_with_reconnect(), or,
 * better still, use _nss_ldap_search_locked().
 */
static int do_search_s(const char *base,int scope,const char *filter,
                       const char **attrs,int sizelimit,LDAPMessage **res)
{
  int rc;
  struct timeval tv, *tvp;

  log_log(LOG_DEBUG,"==> do_search_s");

  ldap_set_option (__session.ls_conn, LDAP_OPT_SIZELIMIT,
                   (void *) &sizelimit);

  if (nslcd_cfg->ldc_timelimit == LDAP_NO_LIMIT)
    {
      tvp = NULL;
    }
  else
    {
      tv.tv_sec = nslcd_cfg->ldc_timelimit;
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
static int do_search(const char *base,int scope,const char *filter,
                     const char **attrs,int sizelimit,int *msgid)
{
  int rc;
  LDAPControl *serverCtrls[2];
  LDAPControl **pServerCtrls;

  log_log(LOG_DEBUG,"==> do_search");

#ifdef HAVE_LDAP_SEARCH_EXT
  if (nslcd_cfg->ldc_pagesize>0)
    {
      rc = ldap_create_page_control (__session.ls_conn,
                                     nslcd_cfg->ldc_pagesize,
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

/*
 * Function to call either do_search() or do_search_s() with
 * reconnection logic (depending on wheter res or msgid is not NULL).
 */
static enum nss_status
do_with_reconnect(const char *base,int scope,const char *filter,
                  const char **attrs,int sizelimit,
                  LDAPMessage **res,int *msgid)
{
  int rc=LDAP_UNAVAILABLE, tries=0, backoff=0;
  int hard=1, start_uri=0, log=0;
  enum nss_status stat=NSS_STATUS_UNAVAIL;
  int maxtries;
  log_log(LOG_DEBUG,"==> do_with_reconnect (base=\"%s\", scope=%d, filter=\"%s\")",base,scope,filter);
  /* get the maximum number of tries */
  maxtries=nslcd_cfg->ldc_reconnect_tries;
  /* keep trying until we have success or a hard failure */
  while ((stat==NSS_STATUS_UNAVAIL)&&(hard)&&(tries<maxtries))
  {
    /* sleep between tries */
    if (tries>0)
    {
      if (backoff==0)
        backoff=nslcd_cfg->ldc_reconnect_sleeptime;
      else if (backoff<nslcd_cfg->ldc_reconnect_maxsleeptime)
        backoff*=2;
      log_log(LOG_INFO,"reconnecting to LDAP server (sleeping %d seconds)...",backoff);
      (void)sleep(backoff);
    }
    /* for each "try", attempt to connect to all specified URIs */
    start_uri=__session.ls_current_uri;
    do
    {
      /* open a connection and do the search */
      stat=do_open();
      if (stat==NSS_STATUS_SUCCESS)
      {
        if (res!=NULL)
          stat=do_map_error(do_search_s(base,scope,filter,attrs,sizelimit,res));
        else
          stat=do_map_error(do_search(base,scope,filter,attrs,sizelimit,msgid));
      }
      /* if we got any feedback from the server, don't try other ones */
      if (stat!=NSS_STATUS_UNAVAIL)
        break;
      log++;
      /* the currently configured uri should exist */
      assert(nslcd_cfg->ldc_uris[__session.ls_current_uri]!=NULL);
      /* try the next URI (with wrap-around) */
      __session.ls_current_uri++;
      if (nslcd_cfg->ldc_uris[__session.ls_current_uri]==NULL)
        __session.ls_current_uri = 0;
    }
    while (__session.ls_current_uri != start_uri);
    /* if we had reachability problems with the server close the connection */
    /* TODO: we should probably close in the loop above */
    if (stat==NSS_STATUS_UNAVAIL)
    {
      do_close ();
      /* If a soft reconnect policy is specified, then do not
       * try to reconnect to the LDAP server if it is down.
       */
      if (nslcd_cfg->ldc_reconnect_pol == LP_RECONNECT_SOFT)
        hard = 0;
      ++tries;
    }
  }

  switch (stat)
  {
    case NSS_STATUS_UNAVAIL:
      log_log(LOG_ERR,"could not search LDAP server - %s",ldap_err2string(rc));
      break;
    case NSS_STATUS_TRYAGAIN:
      log_log(LOG_ERR,"could not %s %sconnect to LDAP server - %s",
              hard?"hard":"soft", tries?"re":"",
              ldap_err2string(rc));
      stat=NSS_STATUS_UNAVAIL;
      break;
    case NSS_STATUS_SUCCESS:
      if (log)
      {
        char *uri=nslcd_cfg->ldc_uris[__session.ls_current_uri];
        if (uri==NULL)
          uri = "(null)";
        if (tries)
          log_log(LOG_INFO,"reconnected to LDAP server %s after %d attempt%s",
            uri, tries, (tries == 1) ? "" : "s");
        else
          log_log(LOG_INFO,"reconnected to LDAP server %s", uri);
      }
      /* update the last activity on the connection */
      time(&__session.ls_timestamp);
      break;
    default:
      break;
  }
  log_log(LOG_DEBUG,"<== do_with_reconnect");
  return stat;
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
do_parse (struct ent_context *context, void *result, char
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

      if ((context->ec_state.ls_retry==0) &&
          ( (context->ec_state.ls_type==LS_TYPE_KEY) ||
            (context->ec_state.ls_info.ls_index==-1) ))
        {
          resultStat=do_result(context,LDAP_MSG_ONE);
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
      parseStat=parser(context->ec_res,&(context->ec_state),result,buffer,buflen);

      /* hold onto the state if we're out of memory XXX */
      context->ec_state.ls_retry = (parseStat == NSS_STATUS_TRYAGAIN && buffer != NULL ? 1 : 0);

      /* free entry is we're moving on */
      if ((context->ec_state.ls_retry==0) &&
          ( (context->ec_state.ls_type==LS_TYPE_KEY) ||
            (context->ec_state.ls_info.ls_index==-1) ))
        {
          /* we don't need the result anymore, ditch it. */
          ldap_msgfree(context->ec_res);
          context->ec_res=NULL;
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
do_parse_s (struct ent_context *context, void *result, char
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
      if ((context->ec_state.ls_retry==0) &&
          ( (context->ec_state.ls_type==LS_TYPE_KEY) ||
            (context->ec_state.ls_info.ls_index==-1) ))
        {
          if (e == NULL)
            e = ldap_first_entry (__session.ls_conn, context->ec_res);
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
      parseStat=parser(e,&(context->ec_state),result,buffer,buflen);

      /* hold onto the state if we're out of memory XXX */
      context->ec_state.ls_retry=(parseStat==NSS_STATUS_TRYAGAIN)&&(buffer!=NULL);
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
                            attributes, 1 /* sizelimit */, res,
                            NULL);
}

/*
 * Simple wrapper around ldap_get_values(). Requires that
 * session is already established.
 */
char **_nss_ldap_get_values(LDAPMessage *e,const char *attr)
{
  if (__session.ls_state!=LS_CONNECTED_TO_DSA)
  {
    return NULL;
  }
  assert(__session.ls_conn!=NULL);
  return ldap_get_values(__session.ls_conn,e,attr);
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
enum nss_status _nss_ldap_search_locked(
        const char *base,int scope,const char *filter,
        const char **attrs,int sizelimit,LDAPMessage **res)
{
  enum nss_status stat;
  log_log(LOG_DEBUG,"==> _nss_ldap_search_locked (base=\"%s\", filter=\"%s\")",base,filter);
  /* initilize session */
  if ((stat=_nss_ldap_init())!=NSS_STATUS_SUCCESS)
  {
    log_log(LOG_DEBUG,"<== _nss_ldap_search_locked");
    return stat;
  }
  stat=do_with_reconnect(
          base,scope,filter,attrs,
          sizelimit,res,NULL);
  return stat;
}

/*
 * The generic lookup cover function (asynchronous).
 * Assumes caller holds lock.
 */
static enum nss_status
_nss_ldap_search(const char *base,int scope,const char *filter,const char **attrs,
                 int sizelimit, int *msgid)
{
  enum nss_status stat;
  log_log(LOG_DEBUG,"==> _nss_ldap_search");
  *msgid=-1;
  /* initialize connection if needed */
  stat=_nss_ldap_init();
  if (stat!=NSS_STATUS_SUCCESS)
  {
    log_log(LOG_DEBUG,"<== _nss_ldap_search");
    return stat;
  }
  /* perform the search */
  stat=do_with_reconnect(base,scope,filter,attrs,
                         sizelimit,NULL,msgid);
  log_log(LOG_DEBUG,"<== _nss_ldap_search");
  return stat;
}

static enum nss_status
do_next_page (const char *base,int scope,const char *filter,const char **attrs,
              int sizelimit, int *msgid,
              struct berval *pCookie)
{
  enum nss_status stat;
  LDAPControl *serverctrls[2]={ NULL, NULL };
  stat=ldap_create_page_control(__session.ls_conn,
                                nslcd_cfg->ldc_pagesize,
                                pCookie,0,&serverctrls[0]);
  if (stat != LDAP_SUCCESS)
    return NSS_STATUS_UNAVAIL;
  stat=ldap_search_ext(__session.ls_conn,
                       base,scope,filter,
                       (char **)attrs,0,serverctrls,NULL,LDAP_NO_LIMIT,
                       sizelimit,msgid);
  ldap_control_free(serverctrls[0]);
  return (*msgid<0)?NSS_STATUS_UNAVAIL:NSS_STATUS_SUCCESS;
}

/* translates a nslcd return code (as defined in nslcd.h) to
   a nss code (as defined in nss.h) */
/* FIXME: this is a temporary hack, get rid of it */
static int nss2nslcd(enum nss_status code)
{
  switch (code)
  {
    case NSS_STATUS_UNAVAIL:  return NSLCD_RESULT_UNAVAIL;
    case NSS_STATUS_NOTFOUND: return NSLCD_RESULT_NOTFOUND;
    case NSS_STATUS_SUCCESS:  return NSLCD_RESULT_SUCCESS;
/*    case NSS_STATUS_TRYAGAIN: return NSLCD_RS_SMALLBUF; */
    default:                  return NSLCD_RESULT_UNAVAIL;
  }
}

/*
 * General entry point for enumeration routines.
 * This should really use the asynchronous LDAP search API to avoid
 * pulling down all the entries at once, particularly if the
 * enumeration is not completed.
 * Locks mutex.
 */
int
_nss_ldap_getent(struct ent_context *context,
                 void *result,char *buffer,size_t buflen,int *errnop,
                 const char *base,int scope,const char *filter,
                 const char **attrs, parser_t parser)
{
  int status;
  /*
   * we need to lock here as the context may not be thread-specific
   * data (under glibc, for example). Maybe we should make the lock part
   * of the context.
   */
  _nss_ldap_enter();
  status=nss2nslcd(_nss_ldap_getent_locked(context,result,
                             buffer,buflen,errnop,
                             base,scope,filter,attrs,parser));
  _nss_ldap_leave();
  return status;
}

/*
 * Internal entry point for enumeration routines.
 * Caller holds global mutex
 */
enum nss_status
_nss_ldap_getent_locked(struct ent_context *context,
                    void *result,char *buffer,size_t buflen,int *errnop,
                    const char *base,int scope,const char *filter,const char **attrs,
                    parser_t parser)
{
  enum nss_status stat=NSS_STATUS_SUCCESS;
  int msgid;
  log_log(LOG_DEBUG,"==> _nss_ldap_getent_locked (base=\"%s\", filter=\"%s\")",base,filter);
  /* if context->ec_msgid < 0, then we haven't searched yet */
  if (context->ec_msgid<0)
  {
    /* set up a new search */
    stat=_nss_ldap_search(base,scope,filter,attrs,LDAP_NO_LIMIT,&msgid);
    if (stat != NSS_STATUS_SUCCESS)
    {
      log_log(LOG_DEBUG,"<== _nss_ldap_getent_locked");
      return stat;
    }
    context->ec_msgid=msgid;
  }

  /* parse a result */
  stat=do_parse(context,result,buffer,buflen,errnop,parser);

  if (stat==NSS_STATUS_NOTFOUND)
  {
    /* Is there another page of results? */
    if ((context->ec_cookie!=NULL)&&(context->ec_cookie->bv_len!=0))
    {
      stat=do_next_page(base,scope,filter,attrs,LDAP_NO_LIMIT,&msgid,context->ec_cookie);
      if (stat!=NSS_STATUS_SUCCESS)
      {
        log_log(LOG_DEBUG,"<== _nss_ldap_getent_locked");
        return stat;
      }
      context->ec_msgid=msgid;
      /* retry parsing a result */
      stat=do_parse(context,result,buffer,buflen,errnop,parser);
    }
  }
  log_log(LOG_DEBUG,"<== _nss_ldap_getent_locked");
  return stat;
}

/*
 * General match function.
 * Locks mutex.
 */
int _nss_ldap_getbyname(void *result, char *buffer, size_t buflen,int *errnop,
                        const char *base,int scope,const char *filter,const char **attrs,
                        parser_t parser)
{

  enum nss_status stat = NSS_STATUS_NOTFOUND;
  struct ent_context context;

  _nss_ldap_enter();

  log_log(LOG_DEBUG,"==> _nss_ldap_getbyname (base=\"%s\", filter=\"%s\"",base,filter);

  _nss_ldap_ent_context_init_locked(&context);

  stat=_nss_ldap_search_locked(base,scope,filter,attrs,1,&context.ec_res);
  if (stat!=NSS_STATUS_SUCCESS)
  {
    _nss_ldap_leave ();
    log_log(LOG_DEBUG,"<== _nss_ldap_getbyname");
    return nss2nslcd(stat);
  }

  /*
   * we pass this along for the benefit of the services parser,
   * which uses it to figure out which protocol we really wanted.
   * we only pass the second argument along, as that's what we need
   * in services.
   */
  LS_INIT(context.ec_state);
  context.ec_state.ls_type=LS_TYPE_KEY;
  context.ec_state.ls_info.ls_key=NULL /*was: args->la_arg2.la_string*/;

  stat=do_parse_s(&context,result,buffer,buflen,errnop,parser);

  _nss_ldap_ent_context_cleanup(&context);

  log_log(LOG_DEBUG,"<== _nss_ldap_getbyname");

  /* moved unlock here to avoid race condition bug #49 */
  _nss_ldap_leave();

  return nss2nslcd(stat);
}

static int NEW_do_parse_s(struct ent_context *context,TFILE *fp,NEWparser_t parser)
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
    if ((context->ec_state.ls_retry==0) &&
        ( (context->ec_state.ls_type==LS_TYPE_KEY) ||
          (context->ec_state.ls_info.ls_index==-1) ))
    {
      if (e == NULL)
        e = ldap_first_entry (__session.ls_conn,context->ec_res);
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
    parseStat=parser(e,&context->ec_state,fp);
    /* hold onto the state if we're out of memory XXX */
    context->ec_state.ls_retry=0;
  }
  while (parseStat==NSLCD_RESULT_NOTFOUND);
  return parseStat;
}


int _nss_ldap_searchbyname(
        const char *base,int scope,const char *filter,const char **attrs,
        TFILE *fp,NEWparser_t parser)
{
  int stat;
  struct ent_context context;
  int32_t tmpint32;

  _nss_ldap_enter();

  _nss_ldap_ent_context_init_locked(&context);

  stat=nss2nslcd(_nss_ldap_search_locked(base,scope,filter,attrs,1,&context.ec_res));
  /* write the result code */
  WRITE_INT32(fp,stat);
  /* bail on nothing found */
  if (stat!=NSLCD_RESULT_SUCCESS)
  {
    _nss_ldap_leave();
    return 1;
  }
  /* call the parser for the result */
  stat=NEW_do_parse_s(&context,fp,parser);

  _nss_ldap_ent_context_cleanup(&context);

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

  vals=ldap_get_values(__session.ls_conn,e,attr);

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

int _nss_ldap_write_attrvals(TFILE *fp,LDAPMessage *e,const char *attr)
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
  vals=ldap_get_values(__session.ls_conn,e,attr);
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

  if (__session.ls_conn == NULL)
    {
      return NSS_STATUS_UNAVAIL;
    }

  vals=ldap_get_values(__session.ls_conn,e,attr);
  if (vals == NULL)
    {
      return NSS_STATUS_NOTFOUND;
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

static const char *_nss_ldap_locate_userpassword (char **vals)
{
  const char *token = NULL;
  size_t token_length = 0;
  char **valiter;
  const char *pwd = NULL;

  if (nslcd_cfg != NULL)
    {
      switch (nslcd_cfg->ldc_password_type)
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

  vals=ldap_get_values(__session.ls_conn,e,attr);
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
  vals=ldap_get_values(ld,entry,"objectClass");
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
