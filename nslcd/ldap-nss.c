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
#include "pagectrl.h"
#include "common.h"
#include "log.h"
#include "cfg.h"
#include "attmap.h"
#include "compat/ldap.h"

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

MYLDAP_SESSION *myldap_create_session(void)
{
  MYLDAP_SESSION *session;
  /* allocate memory for the session storage */
  session=(struct ldap_session *)malloc(sizeof(struct ldap_session));
  if (session==NULL)
  {
    log_log(LOG_CRIT,"malloc() failed to allocate memory");
    exit(EXIT_FAILURE);
  }
  /* initialize the session */
  session->ls_conn=NULL;
  session->ls_timestamp=0;
  session->ls_state=LS_UNINITIALIZED;
  session->ls_current_uri=0;
  /* return the new session */
  return session;
}

static enum nss_status do_map_error(int rc)
{
  switch (rc)
  {
    case LDAP_SUCCESS:
    case LDAP_SIZELIMIT_EXCEEDED:
    case LDAP_TIMELIMIT_EXCEEDED:
      return NSS_STATUS_SUCCESS;
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
      return NSS_STATUS_NOTFOUND;
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
      return NSS_STATUS_UNAVAIL;
  }
}

static int do_sasl_interact(LDAP UNUSED(*ld),unsigned UNUSED(flags),void *defaults,void *_interact)
{
  char *authzid=(char *)defaults;
  sasl_interact_t *interact=(sasl_interact_t *)_interact;
  while (interact->id!=SASL_CB_LIST_END)
  {
    if (interact->id!=SASL_CB_USER)
      return LDAP_PARAM_ERROR;
    if (authzid!=NULL)
    {
      interact->result=authzid;
      interact->len=strlen(authzid);
    }
    else if (interact->defresult!=NULL)
    {
      interact->result=interact->defresult;
      interact->len=strlen(interact->defresult);
    }
    else
    {
      interact->result="";
      interact->len=0;
    }
    interact++;
  }
  return LDAP_SUCCESS;
}

static int do_bind(LDAP *ld,int timelimit,const char *dn,const char *pw,int with_sasl)
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

  if (!with_sasl)
  {
    msgid=ldap_simple_bind(ld,dn,pw);
    if (msgid<0)
    {
      if (ldap_get_option(ld,LDAP_OPT_ERROR_NUMBER,&rc)!=LDAP_SUCCESS)
        rc=LDAP_UNAVAILABLE;
      /* Notify if we failed. */
      log_log(LOG_ERR,"could not connect to any LDAP server as %s - %s",
                      dn, ldap_err2string(rc));
      log_log(LOG_DEBUG,"<== do_bind");
      return rc;
    }

    rc=ldap_result(ld,msgid,0,&tv,&result);
    if (rc>0)
    {
      log_log(LOG_DEBUG,"<== do_bind");
      return ldap_result2error(ld,result,1);
    }

    /* took too long */
    if (rc==0)
      ldap_abandon(ld,msgid);
  }
  else
  {
    if (nslcd_cfg->ldc_sasl_secprops!=NULL)
    {
      rc=ldap_set_option(ld,LDAP_OPT_X_SASL_SECPROPS,(void *)nslcd_cfg->ldc_sasl_secprops);
      if (rc!=LDAP_SUCCESS)
      {
        log_log(LOG_DEBUG,"do_bind: unable to set SASL security properties");
        return rc;
      }
    }
    rc=ldap_sasl_interactive_bind_s(ld, dn, "GSSAPI", NULL, NULL,
                                       LDAP_SASL_QUIET,
                                       do_sasl_interact,(void *) pw);
    return rc;
  }

  log_log(LOG_DEBUG,"<== do_bind");
  return -1;
}

/*
 * This function is called by the LDAP library when chasing referrals.
 * It is configured with the ldap_set_rebind_proc() below.
 */
static int do_rebind(LDAP *ld,LDAP_CONST char UNUSED(*url),
                     ber_tag_t UNUSED(request),
                     ber_int_t UNUSED(msgid),void UNUSED(*arg))
{
  char *who, *cred;
  int with_sasl=0;

  if ((geteuid()==0)&&(nslcd_cfg->ldc_rootbinddn))
  {
    who=nslcd_cfg->ldc_rootbinddn;
    with_sasl=nslcd_cfg->ldc_rootusesasl;
    if (with_sasl)
      cred=nslcd_cfg->ldc_rootsaslid;
    else
      cred=nslcd_cfg->ldc_rootbindpw;
  }
  else
  {
    who=nslcd_cfg->ldc_binddn;
    with_sasl = nslcd_cfg->ldc_usesasl;
    if (with_sasl)
      cred = nslcd_cfg->ldc_saslid;
    else
      cred = nslcd_cfg->ldc_bindpw;
  }

  return do_bind(ld,nslcd_cfg->ldc_bind_timelimit,who,cred,with_sasl);
}

/*
 * Disable keepalive on a LDAP connection's socket.
 */
static void do_set_sockopts(MYLDAP_SESSION *session)
{
  /* Netscape SSL-enabled LDAP library does not return the real socket */
  int sd=-1;
  log_log(LOG_DEBUG,"==> do_set_sockopts");
  if (ldap_get_option(session->ls_conn,LDAP_OPT_DESC,&sd)==0)
  {
    int off=0;
    /* ignore errors */
    (void)setsockopt(sd,SOL_SOCKET,SO_KEEPALIVE,(void *)&off,sizeof(off));
    (void)fcntl(sd,F_SETFD,FD_CLOEXEC);
  }
  log_log(LOG_DEBUG,"<== do_set_sockopts");
  return;
}

/*
 * Close the global session, sending an unbind.
 * Closes connection to the LDAP server.
 */
static void do_close(MYLDAP_SESSION *session)
{
  log_log(LOG_DEBUG,"==> do_close");
  if (session->ls_conn!=NULL)
  {
    ldap_unbind(session->ls_conn);
    session->ls_conn=NULL;
    session->ls_state=LS_UNINITIALIZED;
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

/* set up the session state, ensure that we have an LDAP connection */
enum nss_status _nss_ldap_init(MYLDAP_SESSION *session)
{
  enum nss_status stat;
  time_t current_time;
  log_log(LOG_DEBUG,"==> _nss_ldap_init");
  /* check if the idle time for the connection has expired */
  if ((session->ls_state==LS_CONNECTED_TO_DSA)&&nslcd_cfg->ldc_idle_timelimit)
  {
    time(&current_time);
    if ((session->ls_timestamp+nslcd_cfg->ldc_idle_timelimit)<current_time)
    {
      log_log(LOG_DEBUG,"idle_timelimit reached");
      do_close(session);
    }
  }
  /* if the connection is still there (ie. do_close() wasn't
     called) then we can return the cached connection */
  if (session->ls_state==LS_CONNECTED_TO_DSA)
  {
    log_log(LOG_DEBUG,"<== _nss_ldap_init(cached session)");
    return NSS_STATUS_SUCCESS;
  }
  /* we should build a new session now */
  session->ls_conn=NULL;
  session->ls_timestamp=0;
  session->ls_state=LS_UNINITIALIZED;
  /* turn on debugging */
  if (nslcd_cfg->ldc_debug)
  {
    ber_set_option(NULL,LBER_OPT_DEBUG_LEVEL,&nslcd_cfg->ldc_debug);
    ldap_set_option(NULL,LDAP_OPT_DEBUG_LEVEL,&nslcd_cfg->ldc_debug);
  }
  /* open the connection */
  stat=do_init_session(&(session->ls_conn),nslcd_cfg->ldc_uris[session->ls_current_uri]);
  if (stat!=NSS_STATUS_SUCCESS)
  {
    log_log(LOG_DEBUG,"<== _nss_ldap_init(failed to initialize LDAP session)");
    return stat;
  }
  /* flag the session as initialized */
  session->ls_state=LS_INITIALIZED;
  log_log(LOG_DEBUG,"<== _nss_ldap_init(initialized session)");
  return NSS_STATUS_SUCCESS;
}

static int do_ssl_options(void)
{
  /* TODO: save return value of ldap_set_option() and include it in the error message */
  /* rand file */
  if (nslcd_cfg->ldc_tls_randfile!=NULL)
  {
    if (ldap_set_option(NULL,LDAP_OPT_X_TLS_RANDOM_FILE,
                        nslcd_cfg->ldc_tls_randfile)!=LDAP_SUCCESS)
    {
      log_log(LOG_ERR,"setting of LDAP_OPT_X_TLS_RANDOM_FILE failed");
      return LDAP_OPERATIONS_ERROR;
    }
  }
  /* ca cert file */
  if (nslcd_cfg->ldc_tls_cacertfile!=NULL)
  {
    if (ldap_set_option(NULL,LDAP_OPT_X_TLS_CACERTFILE,
                        nslcd_cfg->ldc_tls_cacertfile)!=LDAP_SUCCESS)
    {
      log_log(LOG_ERR,"setting of LDAP_OPT_X_TLS_CACERTFILE failed");
      return LDAP_OPERATIONS_ERROR;
    }
  }
  /* ca cert directory */
  if (nslcd_cfg->ldc_tls_cacertdir!=NULL)
  {
    if (ldap_set_option(NULL,LDAP_OPT_X_TLS_CACERTDIR,
                        nslcd_cfg->ldc_tls_cacertdir)!=LDAP_SUCCESS)
    {
      log_log(LOG_ERR,"setting of LDAP_OPT_X_TLS_CACERTDIR failed");
      return LDAP_OPERATIONS_ERROR;
    }
  }
  /* require cert? */
  if (nslcd_cfg->ldc_tls_checkpeer > -1)
  {
    if (ldap_set_option(NULL,LDAP_OPT_X_TLS_REQUIRE_CERT,
                          &nslcd_cfg->ldc_tls_checkpeer)!=LDAP_SUCCESS)
    {
      log_log(LOG_ERR,"setting of LDAP_OPT_X_TLS_REQUIRE_CERT failed");
      return LDAP_OPERATIONS_ERROR;
    }
  }
  /* set cipher suite, certificate and private key: */
  if (nslcd_cfg->ldc_tls_ciphers != NULL)
  {
    if (ldap_set_option(NULL,LDAP_OPT_X_TLS_CIPHER_SUITE,
                          nslcd_cfg->ldc_tls_ciphers)!=LDAP_SUCCESS)
    {
      log_log(LOG_ERR,"setting of LDAP_OPT_X_TLS_CIPHER_SUITE failed");
      return LDAP_OPERATIONS_ERROR;
    }
  }

  if (nslcd_cfg->ldc_tls_cert != NULL)
  {
    if (ldap_set_option(NULL,LDAP_OPT_X_TLS_CERTFILE,
                        nslcd_cfg->ldc_tls_cert)!=LDAP_SUCCESS)
    {
      log_log(LOG_ERR,"setting of LDAP_OPT_X_TLS_CERTFILE failed");
      return LDAP_OPERATIONS_ERROR;
    }
  }
  if (nslcd_cfg->ldc_tls_key != NULL)
  {
    if (ldap_set_option(NULL,LDAP_OPT_X_TLS_KEYFILE,
                        nslcd_cfg->ldc_tls_key)!=LDAP_SUCCESS)
    {
      log_log(LOG_ERR,"setting of LDAP_OPT_X_TLS_KEYFILE failed");
      return LDAP_OPERATIONS_ERROR;
    }
  }
  return LDAP_SUCCESS;
}

/*
 * Opens connection to an LDAP server - should only be called from search
 * API. Other API that just needs access to configuration and schema should
 * call _nss_ldap_init().
 */
static enum nss_status do_open(MYLDAP_SESSION *session)
{
  int usesasl;
  char *bindarg;
  enum nss_status stat;
  struct timeval tv;
  int rc;
  log_log(LOG_DEBUG,"==> do_open");
  /* moved the head part of do_open() into _nss_ldap_init() */
  stat = _nss_ldap_init(session);
  if (stat!=NSS_STATUS_SUCCESS)
  {
    log_log(LOG_DEBUG,"<== do_open(session initialization failed)");
    return stat;
  }
  assert(session->ls_conn!=NULL);
  assert(nslcd_cfg!=NULL);
  assert(session->ls_state!=LS_UNINITIALIZED);
  if (session->ls_state==LS_CONNECTED_TO_DSA)
  {
    log_log(LOG_DEBUG,"<== do_open(cached session)");
    return NSS_STATUS_SUCCESS;
  }
  /* the rebind function that is called when chasing referrals */
  /* http://publib.boulder.ibm.com/infocenter/iseries/v5r3/topic/apis/ldap_set_rebind_proc.htm */
  ldap_set_rebind_proc(session->ls_conn,do_rebind,NULL);
  /* set the protocol version to use */
  ldap_set_option(session->ls_conn,LDAP_OPT_PROTOCOL_VERSION,&nslcd_cfg->ldc_version);
  ldap_set_option(session->ls_conn,LDAP_OPT_DEREF,&nslcd_cfg->ldc_deref);
  ldap_set_option(session->ls_conn,LDAP_OPT_TIMELIMIT,&nslcd_cfg->ldc_timelimit);
  tv.tv_sec=nslcd_cfg->ldc_bind_timelimit;
  tv.tv_usec=0;
  ldap_set_option(session->ls_conn,LDAP_OPT_NETWORK_TIMEOUT,&tv);
  ldap_set_option(session->ls_conn,LDAP_OPT_REFERRALS,nslcd_cfg->ldc_referrals?LDAP_OPT_ON:LDAP_OPT_OFF);
  ldap_set_option(session->ls_conn,LDAP_OPT_RESTART,nslcd_cfg->ldc_restart?LDAP_OPT_ON:LDAP_OPT_OFF);
  /* if SSL is desired, then enable it */
  if (nslcd_cfg->ldc_ssl_on==SSL_LDAPS)
  {
    int tls=LDAP_OPT_X_TLS_HARD;
    if (ldap_set_option(session->ls_conn,LDAP_OPT_X_TLS,&tls)!=LDAP_SUCCESS)
    {
      do_close(session);
      log_log(LOG_DEBUG,"<== do_open(TLS setup failed)");
      return NSS_STATUS_UNAVAIL;
    }
    /* set up SSL context */
    if (do_ssl_options()!=LDAP_SUCCESS)
    {
      do_close(session);
      log_log(LOG_DEBUG,"<== do_open(SSL setup failed)");
      return NSS_STATUS_UNAVAIL;
    }
  }
  /*
   * If we're running as root, let us bind as a special
   * user, so we can fake shadow passwords.
   * Thanks to Doug Nazar <nazard@dragoninc.on.ca> for this
   * patch.
   */
  if (geteuid()==0&&nslcd_cfg->ldc_rootbinddn!=NULL)
  {
    usesasl=nslcd_cfg->ldc_rootusesasl;
    bindarg=nslcd_cfg->ldc_rootusesasl?nslcd_cfg->ldc_rootsaslid:nslcd_cfg->ldc_rootbindpw;
    rc=do_bind(session->ls_conn,nslcd_cfg->ldc_bind_timelimit,nslcd_cfg->ldc_rootbinddn,bindarg,usesasl);
  }
  else
  {
    usesasl=nslcd_cfg->ldc_usesasl;
    bindarg=nslcd_cfg->ldc_usesasl?nslcd_cfg->ldc_saslid:nslcd_cfg->ldc_bindpw;
    rc=do_bind(session->ls_conn,nslcd_cfg->ldc_bind_timelimit,nslcd_cfg->ldc_binddn,nslcd_cfg->ldc_bindpw,usesasl);
  }
  if (rc!=LDAP_SUCCESS)
  {
    /* log actual LDAP error code */
    log_log(LOG_WARNING,"failed to bind to LDAP server %s: %s",
            nslcd_cfg->ldc_uris[session->ls_current_uri],ldap_err2string(rc));
    stat=do_map_error(rc);
    do_close(session);
    log_log(LOG_DEBUG,"<== do_open(failed to bind to DSA");
  }
  else
  {
    do_set_sockopts(session);
    time(&(session->ls_timestamp));
    session->ls_state=LS_CONNECTED_TO_DSA;
    stat=NSS_STATUS_SUCCESS;
    log_log(LOG_DEBUG,"<== do_open(session connected to DSA)");
  }
  return stat;
}

/*
 * Wrapper around ldap_result() to skip over search references
 * and deal transparently with the last entry.
 */
static enum nss_status do_result_async(struct ent_context *context)
{
  int rc = LDAP_UNAVAILABLE;
  enum nss_status stat = NSS_STATUS_TRYAGAIN;
  struct timeval tv, *tvp;
  int parserc;
  LDAPControl **resultControls;

  log_log(LOG_DEBUG,"==> do_result_async");

  if (nslcd_cfg->ldc_timelimit==LDAP_NO_LIMIT)
    tvp=NULL;
  else
  {
    tv.tv_sec=nslcd_cfg->ldc_timelimit;
    tv.tv_usec=0;
    tvp=&tv;
  }

  do
  {
    if (context->ec_res!=NULL)
    {
      ldap_msgfree(context->ec_res);
      context->ec_res=NULL;
    }

    rc=ldap_result(context->session->ls_conn,context->ec_msgid,LDAP_MSG_ONE,tvp,&(context->ec_res));
    switch (rc)
    {
      case -1:
      case 0:
        if (ldap_get_option(context->session->ls_conn,LDAP_OPT_ERROR_NUMBER,&rc)!=LDAP_SUCCESS)
          rc=LDAP_UNAVAILABLE;
        log_log(LOG_ERR,"could not get LDAP result: %s",ldap_err2string(rc));
        stat=NSS_STATUS_UNAVAIL;
        break;
      case LDAP_RES_SEARCH_ENTRY:
        stat=NSS_STATUS_SUCCESS;
        break;
      case LDAP_RES_SEARCH_RESULT:
        /* NB: this frees context->ec_res */
        resultControls=NULL;
        context->ec_cookie=NULL;
        parserc=ldap_parse_result(context->session->ls_conn,context->ec_res,&rc,NULL,
                                  NULL,NULL,&resultControls,1);
        if ((parserc!=LDAP_SUCCESS)&&(parserc!=LDAP_MORE_RESULTS_TO_RETURN))
        {
          stat = NSS_STATUS_UNAVAIL;
          ldap_abandon(context->session->ls_conn, context->ec_msgid);
          log_log(LOG_ERR,"could not get LDAP result: %s",ldap_err2string(rc));
        }
        else if (resultControls!=NULL)
        {
          /* See if there are any more pages to come */
          parserc=ldap_parse_page_control(context->session->ls_conn,
                                          resultControls,NULL,
                                          &(context->ec_cookie));
          /* TODO: handle the above return code?? */
          ldap_controls_free(resultControls);
          stat=NSS_STATUS_NOTFOUND;
        }
        else
          stat=NSS_STATUS_NOTFOUND;
        context->ec_res=NULL;
        context->ec_msgid=-1;
        break;
      default:
        stat = NSS_STATUS_UNAVAIL;
        break;
    }
  }
  while (rc==LDAP_RES_SEARCH_REFERENCE);

  /* update timestamp on success */
  if (stat==NSS_STATUS_SUCCESS)
    time(&(context->session->ls_timestamp));

  log_log(LOG_DEBUG,"<== do_result_async");

  return stat;
}

/*
 * This function initializes an enumeration context.
 *
 * It could be done from the default constructor, under Solaris, but we
 * delay it until the setXXent() function is called.
 */
void _nss_ldap_ent_context_init(struct ent_context *context,MYLDAP_SESSION *session)
{
  context->session=session;
  context->ec_cookie=NULL;
  context->ec_res=NULL;
  context->ec_msgid=-1;
  LS_INIT(context->ec_state);
}

/*
 * Clears a given context.
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
  if ((context->ec_msgid>-1)&&(do_result_async(context)==NSS_STATUS_SUCCESS))
  {
    ldap_abandon(context->session->ls_conn,context->ec_msgid);
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
    do_close(context->session);
}

/*
 * Synchronous search function. Don't call this directly;
 * always wrap calls to this with do_with_reconnect(), or,
 * better still, use _nss_ldap_search().
 */
static int do_search_sync(
        MYLDAP_SESSION *session,const char *base,int scope,
        const char *filter,const char **attrs,int sizelimit,
        LDAPMessage **res)
{
  int rc;
  struct timeval tv, *tvp;
  ldap_set_option(session->ls_conn,LDAP_OPT_SIZELIMIT,(void *)&sizelimit);
  if (nslcd_cfg->ldc_timelimit==LDAP_NO_LIMIT)
    tvp=NULL;
  else
  {
    tv.tv_sec=nslcd_cfg->ldc_timelimit;
    tv.tv_usec=0;
    tvp=&tv;
  }
  rc=ldap_search_st(session->ls_conn,base,scope,filter,(char **)attrs,0,tvp,res);
  return rc;
}

/*
 * Asynchronous search function. Don't call this directly;
 * always wrap calls to this with do_with_reconnect(), or,
 * better still, use _nss_ldap_search().
 */
static int do_search_async(
        MYLDAP_SESSION *session,const char *base,int scope,
        const char *filter,const char **attrs,int sizelimit,int *msgid)
{
  int rc;
  LDAPControl *serverCtrls[2];
  LDAPControl **pServerCtrls;
  if (nslcd_cfg->ldc_pagesize>0)
  {
    rc=ldap_create_page_control(session->ls_conn,nslcd_cfg->ldc_pagesize,
                                NULL,0,&serverCtrls[0]);
    if (rc!=LDAP_SUCCESS)
      return rc;
    serverCtrls[1]=NULL;
    pServerCtrls=serverCtrls;
  }
  else
    pServerCtrls=NULL;
  rc=ldap_search_ext(session->ls_conn,base,scope,filter,(char **) attrs,
                     0,pServerCtrls,NULL,LDAP_NO_LIMIT,sizelimit,msgid);
  if (pServerCtrls!=NULL)
  {
    ldap_control_free(serverCtrls[0]);
    serverCtrls[0]=NULL;
  }
  return rc;
}

/*
 * Function to call either do_search_async() or do_search_sync() with
 * reconnection logic (depending on wheter res or msgid is not NULL).
 */
static enum nss_status do_with_reconnect(
        MYLDAP_SESSION *session,const char *base,int scope,
        const char *filter,const char **attrs,int sizelimit,
        LDAPMessage **res,int *msgid)
{
  int rc=LDAP_UNAVAILABLE, tries=0, backoff=0;
  int hard=1, start_uri=0, log=0;
  enum nss_status stat=NSS_STATUS_UNAVAIL;
  int maxtries;
  log_log(LOG_DEBUG,"do_with_reconnect(base=\"%s\", scope=%d, filter=\"%s\")",base,scope,filter);
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
    start_uri=session->ls_current_uri;
    do
    {
      /* open a connection and do the search */
      stat=do_open(session);
      if (stat==NSS_STATUS_SUCCESS)
      {
        if (res!=NULL)
          stat=do_map_error(do_search_sync(session,base,scope,filter,attrs,sizelimit,res));
        else
          stat=do_map_error(do_search_async(session,base,scope,filter,attrs,sizelimit,msgid));
      }
      /* if we got any feedback from the server, don't try other ones */
      if (stat!=NSS_STATUS_UNAVAIL)
        break;
      log++;
      /* the currently configured uri should exist */
      assert(nslcd_cfg->ldc_uris[session->ls_current_uri]!=NULL);
      /* try the next URI (with wrap-around) */
      session->ls_current_uri++;
      if (nslcd_cfg->ldc_uris[session->ls_current_uri]==NULL)
        session->ls_current_uri = 0;
    }
    while (session->ls_current_uri != start_uri);
    /* if we had reachability problems with the server close the connection */
    /* TODO: we should probably close in the loop above */
    if (stat==NSS_STATUS_UNAVAIL)
    {
      do_close(session);
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
        char *uri=nslcd_cfg->ldc_uris[session->ls_current_uri];
        if (uri==NULL)
          uri = "(null)";
        if (tries)
          log_log(LOG_INFO,"reconnected to LDAP server %s after %d attempt%s",
            uri, tries,(tries == 1) ? "" : "s");
        else
          log_log(LOG_INFO,"reconnected to LDAP server %s", uri);
      }
      /* update the last activity on the connection */
      time(&session->ls_timestamp);
      break;
    default:
      break;
  }
  return stat;
}

static void do_map_errno(enum nss_status status, int *errnop)
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
 * Tries parser function "parser" on entries, calling do_result_async()
 * to retrieve them from the LDAP server until one parses
 * correctly or there is an exceptional condition.
 */
static enum nss_status do_parse_async(
        struct ent_context *context,void *result,
        char *buffer,size_t buflen,int *errnop,parser_t parser)
{
  enum nss_status parseStat=NSS_STATUS_NOTFOUND;
  log_log(LOG_DEBUG,"==> do_parse_async");
  /*
   * if ec_state.ls_info.ls_index is non-zero, then we don't collect another
   * entry off the LDAP chain, and instead refeed the existing result to
   * the parser. Once the parser has finished with it, it will return
   * NSS_STATUS_NOTFOUND and reset the index to -1, at which point we'll retrieve
   * another entry.
   */
  do
  {
    enum nss_status resultStat=NSS_STATUS_SUCCESS;

    if ((context->ec_state.ls_retry==0) &&
        ( (context->ec_state.ls_type==LS_TYPE_KEY) ||
          (context->ec_state.ls_info.ls_index==-1) ))
    {
      resultStat=do_result_async(context);
    }

    if (resultStat!=NSS_STATUS_SUCCESS)
    {
      /* Could not get a result; bail */
      parseStat=resultStat;
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
    parseStat=parser(context->session,context->ec_res,&(context->ec_state),result,buffer,buflen);

    /* hold onto the state if we're out of memory XXX */
    context->ec_state.ls_retry=(parseStat==NSS_STATUS_TRYAGAIN && buffer!=NULL?1:0);

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
  while (parseStat==NSS_STATUS_NOTFOUND);

  do_map_errno(parseStat,errnop);

  log_log(LOG_DEBUG,"<== do_parse_async");

  return parseStat;
}

/*
 * Parse, fetching reuslts from chain instead of server.
 */
static enum nss_status do_parse_sync(
        struct ent_context *context,void *result,
        char *buffer,size_t buflen,int *errnop,parser_t parser)
{
  enum nss_status parseStat=NSS_STATUS_NOTFOUND;
  LDAPMessage *e=NULL;

  log_log(LOG_DEBUG,"==> do_parse_sync");

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
      if (e==NULL)
        e=ldap_first_entry(context->session->ls_conn,context->ec_res);
      else
        e=ldap_next_entry(context->session->ls_conn,e);
    }

    if (e==NULL)
    {
      /* Could not get a result; bail */
      parseStat=NSS_STATUS_NOTFOUND;
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
    parseStat=parser(context->session,e,&(context->ec_state),result,buffer,buflen);

    /* hold onto the state if we're out of memory XXX */
    context->ec_state.ls_retry=(parseStat==NSS_STATUS_TRYAGAIN)&&(buffer!=NULL);
  }
  while (parseStat==NSS_STATUS_NOTFOUND);

  do_map_errno(parseStat,errnop);

  log_log(LOG_DEBUG,"<== do_parse_sync");

  return parseStat;
}

/*
 * Read an entry from the directory, a la X.500. This is used
 * for functions that need to retrieve attributes from a DN,
 * such as the RFC2307bis group expansion function.
 */
enum nss_status _nss_ldap_read_sync(
        MYLDAP_SESSION *session,const char *dn,const char **attributes,
        LDAPMessage ** res)
{
  /* synchronous search */
  return do_with_reconnect(session,dn,LDAP_SCOPE_BASE,"(objectclass=*)",
                           attributes,1 /* sizelimit */,res,NULL);
}

/*
 * Simple wrapper around ldap_get_values(). Requires that
 * session is already established.
 */
char **_nss_ldap_get_values(MYLDAP_SESSION *session,LDAPMessage *e,
                            const char *attr)
{
  if (session->ls_state!=LS_CONNECTED_TO_DSA)
    return NULL;
  assert(session->ls_conn!=NULL);
  return ldap_get_values(session->ls_conn,e,attr);
}

/*
 * Simple wrapper around ldap_get_dn(). Requires that
 * session is already established.
 */
char *_nss_ldap_get_dn(MYLDAP_SESSION *session,LDAPMessage *e)
{
  if (session->ls_state!=LS_CONNECTED_TO_DSA)
    return NULL;
  assert(session->ls_conn!=NULL);
  return ldap_get_dn(session->ls_conn,e);
}

/*
 * Simple wrapper around ldap_first_entry(). Requires that
 * session is already established.
 */
LDAPMessage *_nss_ldap_first_entry(MYLDAP_SESSION *session,LDAPMessage *res)
{
  if (session->ls_state!=LS_CONNECTED_TO_DSA)
    return NULL;
  assert(session->ls_conn!=NULL);
  return ldap_first_entry(session->ls_conn,res);
}

char *_nss_ldap_first_attribute(MYLDAP_SESSION *session,LDAPMessage *entry,BerElement **berptr)
{
  if (session->ls_state!=LS_CONNECTED_TO_DSA)
    return NULL;
  assert(session->ls_conn!=NULL);
  return ldap_first_attribute(session->ls_conn,entry,berptr);
}

char *_nss_ldap_next_attribute(MYLDAP_SESSION *session,LDAPMessage *entry,BerElement *ber)
{
  if (session->ls_state!=LS_CONNECTED_TO_DSA)
    return NULL;
  assert(session->ls_conn!=NULL);
  return ldap_next_attribute(session->ls_conn,entry,ber);
}

/*
 * The generic synchronous lookup cover function.
 */
enum nss_status _nss_ldap_search_sync(
        MYLDAP_SESSION *session,const char *base,int scope,
        const char *filter,const char **attrs,int sizelimit,
        LDAPMessage **res)
{
  enum nss_status stat;
  log_log(LOG_DEBUG,"_nss_ldap_search_sync(base=\"%s\", filter=\"%s\")",base,filter);
  /* initilize session */
  if ((stat=_nss_ldap_init(session))!=NSS_STATUS_SUCCESS)
  {
    log_log(LOG_DEBUG,"_nss_ldap_init() failed");
    return stat;
  }
  /* synchronous search */
  stat=do_with_reconnect(session,base,scope,filter,attrs,sizelimit,res,NULL);
  return stat;
}

/*
 * The generic lookup cover function (asynchronous).
 */
static enum nss_status _nss_ldap_search_async(
        MYLDAP_SESSION *session,const char *base,int scope,
        const char *filter,const char **attrs,int sizelimit,int *msgid)
{
  enum nss_status stat;
  log_log(LOG_DEBUG,"_nss_ldap_search_async(base=\"%s\", filter=\"%s\")",base,filter);
  *msgid=-1;
  /* initialize session */
  if ((stat=_nss_ldap_init(session))!=NSS_STATUS_SUCCESS)
  {
    log_log(LOG_DEBUG,"_nss_ldap_init() failed");
    return stat;
  }
  /* asynchronous search */
  stat=do_with_reconnect(session,base,scope,filter,attrs,sizelimit,NULL,msgid);
  log_log(LOG_DEBUG,"<== _nss_ldap_search");
  return stat;
}

static enum nss_status do_next_page(
        MYLDAP_SESSION *session,const char *base,int scope,
        const char *filter,const char **attrs,int sizelimit, int *msgid,
        struct berval *pCookie)
{
  enum nss_status stat;
  LDAPControl *serverctrls[2]={ NULL, NULL };
  stat=ldap_create_page_control(session->ls_conn,
                                nslcd_cfg->ldc_pagesize,
                                pCookie,0,&serverctrls[0]);
  if (stat != LDAP_SUCCESS)
    return NSS_STATUS_UNAVAIL;
  stat=ldap_search_ext(session->ls_conn,
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
 * Internal entry point for enumeration routines.
 * This should really use the asynchronous LDAP search API to avoid
 * pulling down all the entries at once, particularly if the
 * enumeration is not completed.
 */
int _nss_ldap_getent(
        struct ent_context *context,void *result,char *buffer,size_t buflen,int *errnop,
        const char *base,int scope,const char *filter,const char **attrs,
        parser_t parser)
{
  enum nss_status stat=NSS_STATUS_SUCCESS;
  int msgid;
  log_log(LOG_DEBUG,"_nss_ldap_getent(base=\"%s\", filter=\"%s\")",base,filter);
  /* if context->ec_msgid < 0, then we haven't searched yet */
  if (context->ec_msgid<0)
  {
    /* set up a new search */
    stat=_nss_ldap_search_async(context->session,base,scope,filter,attrs,LDAP_NO_LIMIT,&msgid);
    if (stat != NSS_STATUS_SUCCESS)
      return nss2nslcd(stat);
    context->ec_msgid=msgid;
  }
  /* try to parse results until we have a final error or ok */
  while (1)
  {
    /* parse a result */
    stat=do_parse_async(context,result,buffer,buflen,errnop,parser);
    /* if this had no more results, try the next page */
    if ((stat==NSS_STATUS_NOTFOUND)&&(context->ec_cookie!=NULL)&&(context->ec_cookie->bv_len!=0))
    {
      stat=do_next_page(context->session,base,scope,filter,attrs,LDAP_NO_LIMIT,&msgid,context->ec_cookie);
      if (stat!=NSS_STATUS_SUCCESS)
        return nss2nslcd(stat);
      context->ec_msgid=msgid;
    }
    else
      return nss2nslcd(stat);
  }
}

/*
 * General match function.
 */
int _nss_ldap_getbyname(MYLDAP_SESSION *session,void *result, char *buffer, size_t buflen,int *errnop,
                        const char *base,int scope,const char *filter,const char **attrs,
                        parser_t parser)
{

  enum nss_status stat = NSS_STATUS_NOTFOUND;
  struct ent_context context;

  log_log(LOG_DEBUG,"_nss_ldap_getbyname(base=\"%s\", filter=\"%s\"",base,filter);

  _nss_ldap_ent_context_init(&context,session);

  stat=_nss_ldap_search_sync(context.session,base,scope,filter,attrs,1,&context.ec_res);
  if (stat!=NSS_STATUS_SUCCESS)
    return nss2nslcd(stat);

  /*
   * we pass this along for the benefit of the services parser,
   * which uses it to figure out which protocol we really wanted.
   * we only pass the second argument along, as that's what we need
   * in services.
   */
  LS_INIT(context.ec_state);
  context.ec_state.ls_type=LS_TYPE_KEY;
  context.ec_state.ls_info.ls_key=NULL /*was: args->la_arg2.la_string*/;

  stat=do_parse_sync(&context,result,buffer,buflen,errnop,parser);

  _nss_ldap_ent_context_cleanup(&context);

  return nss2nslcd(stat);
}

/*
 * These functions are called from within the parser, where it is assumed
 * to be safe to use the connection and the respective message.
 */

/*
 * Assign all values, bar omitvalue (if not NULL), to *valptr.
 */
enum nss_status _nss_ldap_assign_attrvals(
        MYLDAP_SESSION *session,
        LDAPMessage *e,const char *attr,const char *omitvalue,
        char ***valptr,char **pbuffer,size_t *pbuflen,size_t *pvalcount)
{
  char **vals;
  char **valiter;
  size_t valcount;
  char **p=NULL;

  size_t buflen=*pbuflen;
  char *buffer=*pbuffer;

  if (pvalcount!=NULL)
    *pvalcount=0;

  if (session->ls_conn==NULL)
    return NSS_STATUS_UNAVAIL;

  vals=_nss_ldap_get_values(session,e,attr);

  valcount=(vals==NULL)?0:ldap_count_values(vals);
  if (bytesleft(buffer,buflen,char *)<(valcount+1)*sizeof(char *))
  {
    ldap_value_free(vals);
    return NSS_STATUS_TRYAGAIN;
  }

  align(buffer,buflen,char *);
  p=*valptr=(char **)buffer;

  buffer+=(valcount+1)*sizeof(char *);
  buflen-=(valcount+1)*sizeof(char *);

  if (valcount==0)
  {
    *p = NULL;
    *pbuffer=buffer;
    *pbuflen=buflen;
    return NSS_STATUS_SUCCESS;
  }

  valiter=vals;

  while (*valiter!=NULL)
  {
    size_t vallen;
    char *elt = NULL;

    if ((omitvalue!=NULL)&&(strcmp(*valiter,omitvalue)==0))
      valcount--;
    else
    {
      vallen=strlen(*valiter);
      if (buflen<(vallen+1))
      {
        ldap_value_free(vals);
        return NSS_STATUS_TRYAGAIN;
      }

      /* copy this value into the next block of buffer space */
      elt=buffer;
      buffer+=vallen+1;
      buflen-=vallen+1;

      strncpy(elt,*valiter,vallen);
      elt[vallen]='\0';
      *p=elt;
      p++;
    }
    valiter++;
  }

  *p=NULL;
  *pbuffer=buffer;
  *pbuflen=buflen;

  if (pvalcount!=NULL)
    *pvalcount=valcount;

  ldap_value_free(vals);
  return NSS_STATUS_SUCCESS;
}

/* Assign a single value to *valptr. */
enum nss_status _nss_ldap_assign_attrval(
        MYLDAP_SESSION *session,LDAPMessage *e,const char *attr,char **valptr,
        char **buffer,size_t *buflen)
{
  char **vals;
  int vallen;
  if (session->ls_conn==NULL)
    return NSS_STATUS_UNAVAIL;
  vals=_nss_ldap_get_values(session,e,attr);
  if (vals==NULL)
    return NSS_STATUS_NOTFOUND;
  vallen=strlen(*vals);
  if (*buflen<(size_t)(vallen+1))
  {
    ldap_value_free(vals);
    return NSS_STATUS_TRYAGAIN;
  }
  *valptr=*buffer;
  strncpy(*valptr,*vals,vallen);
  (*valptr)[vallen]='\0';
  *buffer+=vallen + 1;
  *buflen-=vallen + 1;
  ldap_value_free(vals);
  return NSS_STATUS_SUCCESS;
}

static const char *_nss_ldap_locate_userpassword(char **vals)
{
  const char *token=NULL;
  size_t token_length=0;
  char **valiter;
  const char *pwd=NULL;

  if (nslcd_cfg!=NULL)
  {
    switch (nslcd_cfg->ldc_password_type)
    {
      case LU_RFC2307_USERPASSWORD:
        token = "{CRYPT}";
        token_length = sizeof("{CRYPT}") - 1;
        break;
      case LU_RFC3112_AUTHPASSWORD:
        token = "CRYPT$";
        token_length = sizeof("CRYPT$") - 1;
        break;
      case LU_OTHER_PASSWORD:
        break;
    }
  }

  if (vals!=NULL)
  {
    for (valiter=vals;*valiter!=NULL;valiter++)
    {
      if (token_length==0 ||
          strncasecmp(*valiter,token,token_length)==0)
      {
        pwd=*valiter;
        break;
      }
    }
  }

  if (pwd==NULL)
    pwd="*";
  else
    pwd+=token_length;

  return pwd;
}

/*
 * Assign a single value to *valptr, after examining userPassword for
 * a syntactically suitable value.
 */
enum nss_status _nss_ldap_assign_userpassword(
        MYLDAP_SESSION *session,
        LDAPMessage *e,const char *attr,char **valptr,
        char **buffer,size_t *buflen)
{
  char **vals;
  const char *pwd;
  int vallen;
  log_log(LOG_DEBUG,"==> _nss_ldap_assign_userpassword");
  if (session->ls_conn==NULL)
    return NSS_STATUS_UNAVAIL;
  vals=_nss_ldap_get_values(session,e,attr);
  pwd=_nss_ldap_locate_userpassword(vals);
  vallen=strlen(pwd);
  if (*buflen<(size_t)(vallen+1))
  {
    if (vals!=NULL)
      ldap_value_free(vals);
    log_log(LOG_DEBUG,"<== _nss_ldap_assign_userpassword");
    return NSS_STATUS_TRYAGAIN;
  }
  *valptr=*buffer;
  strncpy(*valptr,pwd,vallen);
  (*valptr)[vallen]='\0';
  *buffer+=vallen+1;
  *buflen-=vallen+1;
  if (vals!=NULL)
    ldap_value_free(vals);
  log_log(LOG_DEBUG,"<== _nss_ldap_assign_userpassword");
  return NSS_STATUS_SUCCESS;
}

int has_objectclass(MYLDAP_SESSION *session,LDAPMessage *entry,const char *objectclass)
{
  char **vals;
  int i;
  LDAP *ld;
  ld=session->ls_conn;
  if (ld==NULL)
    return 0;
  vals=_nss_ldap_get_values(session,entry,"objectClass");
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

static enum nss_status
do_getrdnvalue (const char *dn,
                const char *rdntype,
                char **rval, char **buffer, size_t * buflen)
{
  char **exploded_dn;
  char *rdnvalue = NULL;
  char rdnava[64];
  size_t rdnlen = 0, rdnavalen;

  snprintf (rdnava, sizeof rdnava, "%s=", rdntype);
  rdnavalen = strlen (rdnava);

  exploded_dn = ldap_explode_dn (dn, 0);

  if (exploded_dn != NULL)
    {
      /*
       * attempt to get the naming attribute's principal
       * value by parsing the RDN. We need to support
       * multivalued RDNs (as they're essentially mandated
       * for services)
       */
#ifdef HAVE_LDAP_EXPLODE_RDN
      /*
       * use ldap_explode_rdn() API, as it's cleaner than
       * strtok(). This code has not been tested!
       */
      char **p, **exploded_rdn;

      exploded_rdn = ldap_explode_rdn (*exploded_dn, 0);
      if (exploded_rdn != NULL)
        {
          for (p = exploded_rdn; *p != NULL; p++)
            {
              if (strncasecmp (*p, rdnava, rdnavalen) == 0)
                {
                  char *r = *p + rdnavalen;

                  rdnlen = strlen (r);
                  if (*buflen <= rdnlen)
                    {
                      ldap_value_free (exploded_rdn);
                      ldap_value_free (exploded_dn);
                      return NSS_STATUS_TRYAGAIN;
                    }
                  rdnvalue = *buffer;
                  strncpy (rdnvalue, r, rdnlen);
                  break;
                }
            }
          ldap_value_free (exploded_rdn);
        }
#else /* HAVE_LDAP_EXPLODE_RDN */
      /*
       * we don't have Netscape's ldap_explode_rdn() API,
       * so we fudge it with strtok(). Note that this will
       * not handle escaping properly.
       */
      char *p, *r = *exploded_dn;
#ifdef HAVE_STRTOK_R
      char *st = NULL;
#endif /* HAVE_STRTOK_R */

#ifndef HAVE_STRTOK_R
      for (p = strtok (r, "+");
#else /* HAVE_STRTOK_R */
      for (p = strtok_r (r, "+", &st);
#endif /* not HAVE_STRTOK_R */
           p != NULL;
#ifndef HAVE_STRTOK_R
           p = strtok (NULL, "+"))
#else /* HAVE_STRTOK_R */
           p = strtok_r (NULL, "+", &st))
#endif /* not HAVE_STRTOK_R */
      {
        if (strncasecmp (p, rdnava, rdnavalen) == 0)
          {
            p += rdnavalen;
            rdnlen = strlen (p);
            if (*buflen <= rdnlen)
              {
                ldap_value_free (exploded_dn);
                return NSS_STATUS_TRYAGAIN;
              }
            rdnvalue = *buffer;
            strncpy (rdnvalue, p, rdnlen);
            break;
          }
        if (r != NULL)
          r = NULL;
      }
#endif /* not HAVE_LDAP_EXPLODE_RDN */
    }

  if (exploded_dn != NULL)
    {
      ldap_value_free (exploded_dn);
    }

  if (rdnvalue != NULL)
    {
      rdnvalue[rdnlen] = '\0';
      *buffer += rdnlen + 1;
      *buflen -= rdnlen + 1;
      *rval = rdnvalue;
      return NSS_STATUS_SUCCESS;
    }

  return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_ldap_getrdnvalue(
        MYLDAP_SESSION *session,LDAPMessage *entry,const char *rdntype,
        char **rval,char **buffer,size_t *buflen)
{
  char *dn;
  enum nss_status status;
  size_t rdnlen;

  dn=_nss_ldap_get_dn(session,entry);
  if (dn==NULL)
    return NSS_STATUS_NOTFOUND;

  status = do_getrdnvalue (dn, rdntype, rval, buffer, buflen);
#ifdef HAVE_LDAP_MEMFREE
  ldap_memfree (dn);
#else /* HAVE_LDAP_MEMFREE */
  free (dn);
#endif /* not HAVE_LDAP_MEMFREE */

  /*
   * If examining the DN failed, then pick the nominal first
   * value of cn as the canonical name (recall that attributes
   * are sets, not sequences)
   */
  if (status == NSS_STATUS_NOTFOUND)
    {
      char **vals;

      vals=_nss_ldap_get_values(session,entry,rdntype);

      if (vals != NULL)
        {
          rdnlen = strlen (*vals);
          if (*buflen > rdnlen)
            {
              char *rdnvalue = *buffer;
              strncpy (rdnvalue, *vals, rdnlen);
              rdnvalue[rdnlen] = '\0';
              *buffer += rdnlen + 1;
              *buflen -= rdnlen + 1;
              *rval = rdnvalue;
              status = NSS_STATUS_SUCCESS;
            }
          else
            {
              status = NSS_STATUS_TRYAGAIN;
            }
          ldap_value_free (vals);
        }
    }

  return status;
}

int myldap_escape(const char *src,char *buffer,size_t buflen)
{
  size_t pos=0;
  /* go over all characters in source string */
  for (;*src!='\0';src++)
  {
    /* check if char will fit */
    if (pos>=(buflen+4))
      return -1;
    /* do escaping for some characters */
    switch (*src)
    {
      case '*':
        strcpy(buffer+pos,"\\2a");
        pos+=3;
        break;
      case '(':
        strcpy(buffer+pos,"\\28");
        pos+=3;
        break;
      case ')':
        strcpy(buffer+pos,"\\29");
        pos+=3;
        break;
      case '\\':
        strcpy(buffer+pos,"\\5c");
        pos+=3;
        break;
      default:
        /* just copy character */
        buffer[pos++]=*src;
        break;
    }
  }
  /* terminate destination string */
  buffer[pos]='\0';
  return 0;
}
