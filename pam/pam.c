/*
   pam.c - pam module functions

   Copyright (C) 2009 Howard Chu
   Copyright (C) 2009-2015 Arthur de Jong

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
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

/* these are defined (before including pam_modules.h) for staticly linking */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include "common.h"
#include "compat/attrs.h"
#include "compat/pam_compat.h"

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif /* HAVE_SECURITY_PAM_APPL_H */
#ifndef HAVE_PAM_PAM_MODULES_H
#include <security/pam_modules.h>
#ifdef HAVE_SECURITY_PAM_EXT_H
#include <security/pam_ext.h>
#endif /* HAVE_SECURITY_PAM_EXT_H */
#else /* not HAVE_PAM_PAM_MODULES_H */
#include <pam/pam_modules.h>
#endif /* not HAVE_PAM_PAM_MODULES_H */

/* the name we store our context under */
#define PLD_CTX "PAM_LDAPD_CTX"

/* structure that stores the results for an nslcd call */
struct nslcd_resp {
  int res;
  char msg[1024];
};

/* this struct represents the context that the PAM module keeps
   between calls */
struct pld_ctx {
  char *username;
  struct nslcd_resp saved_authz;
  struct nslcd_resp saved_session;
  int asroot;
  char *oldpassword;
};

/* clear the context to all empty values */
static void ctx_clear(struct pld_ctx *ctx)
{
  if (ctx->username)
  {
    free(ctx->username);
    ctx->username = NULL;
  }
  ctx->saved_authz.res = PAM_SUCCESS;
  memset(ctx->saved_authz.msg, 0, sizeof(ctx->saved_authz.msg));
  ctx->saved_session.res = PAM_SUCCESS;
  memset(ctx->saved_session.msg, 0, sizeof(ctx->saved_session.msg));
  ctx->asroot = 0;
  if (ctx->oldpassword)
  {
    memset(ctx->oldpassword, 0, strlen(ctx->oldpassword));
    free(ctx->oldpassword);
    ctx->oldpassword = NULL;
  }
}

/* free the context (this is installed as handler into PAM) */
static void ctx_free(pam_handle_t UNUSED(*pamh), void *data, int UNUSED(err))
{
  struct pld_ctx *ctx = data;
  ctx_clear(ctx);
  free(ctx);
}

/* try to get the module's context, returns a PAM status code */
static int ctx_get(pam_handle_t *pamh, const char *username, struct pld_ctx **pctx)
{
  struct pld_ctx *ctx = NULL;
  int rc;
  /* try to get the context from PAM */
  rc = pam_get_data(pamh, PLD_CTX, (const void **)&ctx);
  if ((rc == PAM_SUCCESS) && (ctx != NULL))
  {
    /* if the user is different clear the context */
    if ((ctx->username != NULL) && (strcmp(ctx->username, username) != 0))
      ctx_clear(ctx);
  }
  else
  {
    /* allocate a new context */
    ctx = calloc(1, sizeof(struct pld_ctx));
    if (ctx == NULL)
    {
      pam_syslog(pamh, LOG_CRIT, "calloc(): failed to allocate memory: %s",
                 strerror(errno));
      return PAM_BUF_ERR;
    }
    ctx_clear(ctx);
    /* store the new context with the handler to free it */
    rc = pam_set_data(pamh, PLD_CTX, ctx, ctx_free);
    if (rc != PAM_SUCCESS)
    {
      ctx_free(pamh, ctx, 0);
      pam_syslog(pamh, LOG_ERR, "failed to store context: %s",
                 pam_strerror(pamh, rc));
      return rc;
    }
  }
  /* save the username in the context */
  if (ctx->username == NULL)
    ctx->username = strdup(username);
  /* return the context */
  *pctx = ctx;
  return PAM_SUCCESS;
}

/* our PAM module configuration */
struct pld_cfg {
  int nullok;
  int no_warn;
  int ignore_unknown_user;
  int ignore_authinfo_unavail;
  int debug;
  uid_t minimum_uid;
};

static void cfg_init(pam_handle_t *pamh, int flags,
                     int argc, const char **argv,
                     struct pld_cfg *cfg)
{
  int i;
  /* initialise config with defaults */
  cfg->nullok = 0;
  cfg->no_warn = 0;
  cfg->ignore_unknown_user = 0;
  cfg->ignore_authinfo_unavail = 0;
  cfg->debug = 0;
  cfg->minimum_uid = 0;
  /* go over arguments */
  for (i = 0; i < argc; i++)
  {
    if (strcmp(argv[i], "use_first_pass") == 0)
      /* ignore, this option is used by pam_get_authtok() internally */ ;
    else if (strcmp(argv[i], "try_first_pass") == 0)
      /* ignore, this option is used by pam_get_authtok() internally */ ;
    else if (strcmp(argv[i], "nullok") == 0)
      cfg->nullok = 1;
    else if (strcmp(argv[i], "use_authtok") == 0)
      /* ignore, this option is used by pam_get_authtok() internally */ ;
    else if (strcmp(argv[i], "no_warn") == 0)
      cfg->no_warn = 1;
    else if (strcmp(argv[i], "ignore_unknown_user") == 0)
      cfg->ignore_unknown_user = 1;
    else if (strcmp(argv[i], "ignore_authinfo_unavail") == 0)
      cfg->ignore_authinfo_unavail = 1;
    else if (strcmp(argv[i], "debug") == 0)
      cfg->debug = 1;
    else if (strncmp(argv[i], "minimum_uid=", 12) == 0)
      cfg->minimum_uid = (uid_t)atoi(argv[i] + 12);
    else
      pam_syslog(pamh, LOG_ERR, "unknown option: %s", argv[i]);
  }
  /* check flags */
  if (flags & PAM_SILENT)
    cfg->no_warn = 1;
}

static int init(pam_handle_t *pamh, struct pld_cfg *cfg, struct pld_ctx **ctx,
                const char **username, const char **service, const char **ruser,
                const char **rhost, const char **tty)
{
  int rc;
  struct passwd *pwent;
  /* get user name */
  rc = pam_get_user(pamh, username, NULL);
  if (rc != PAM_SUCCESS)
  {
    pam_syslog(pamh, LOG_ERR, "failed to get user name: %s", pam_strerror(pamh, rc));
    return rc;
  }
  if ((*username == NULL) || ((*username)[0] == '\0'))
  {
    pam_syslog(pamh, LOG_ERR, "got empty user name");
    return PAM_USER_UNKNOWN;
  }
  /* check uid */
  if (cfg->minimum_uid > 0)
  {
    pwent = pam_modutil_getpwnam(args->pamh, *username);
    if ((pwent != NULL) && (pwent->pw_uid < cfg->minimum_uid))
    {
      if (cfg->debug)
        pam_syslog(pamh, LOG_DEBUG, "uid below minimum_uid; user=%s uid=%ld",
                   *username, (long)pwent->pw_uid);
      return cfg->ignore_unknown_user ? PAM_IGNORE : PAM_USER_UNKNOWN;
    }
  }
  /* get our context */
  rc = ctx_get(pamh, *username, ctx);
  if (rc != PAM_SUCCESS)
    return rc;
  /* get service name */
  rc = pam_get_item(pamh, PAM_SERVICE, (PAM_ITEM_CONST void **)service);
  if (rc != PAM_SUCCESS)
  {
    pam_syslog(pamh, LOG_ERR, "failed to get service name: %s",
               pam_strerror(pamh, rc));
    return rc;
  }
  /* get more PAM information (ignore errors) */
  pam_get_item(pamh, PAM_RUSER, (PAM_ITEM_CONST void **)ruser);
  pam_get_item(pamh, PAM_RHOST, (PAM_ITEM_CONST void **)rhost);
  pam_get_item(pamh, PAM_TTY, (PAM_ITEM_CONST void **)tty);
  return PAM_SUCCESS;
}

/* map a NSLCD PAM status code to a PAM status code */
static int nslcd2pam_rc(pam_handle_t *pamh, int rc)
{
#define map(i) case NSLCD_##i: return i;
  switch (rc)
  {
    map(PAM_SUCCESS);
    map(PAM_PERM_DENIED);
    map(PAM_AUTH_ERR);
    map(PAM_CRED_INSUFFICIENT);
    map(PAM_AUTHINFO_UNAVAIL);
    map(PAM_USER_UNKNOWN);
    map(PAM_MAXTRIES);
    map(PAM_NEW_AUTHTOK_REQD);
    map(PAM_ACCT_EXPIRED);
    map(PAM_SESSION_ERR);
    map(PAM_AUTHTOK_ERR);
    map(PAM_AUTHTOK_DISABLE_AGING);
    map(PAM_IGNORE);
    map(PAM_ABORT);
    map(PAM_AUTHTOK_EXPIRED);
    default:
      pam_syslog(pamh, LOG_ERR, "unknown NSLCD_PAM_* code returned: %d", rc);
      return PAM_ABORT;
  }
}

/* check whether the specified user is handled by nslcd */
static int nslcd_request_exists(pam_handle_t *pamh, struct pld_cfg *cfg,
                                const char *username)
{
  PAM_REQUEST(
    NSLCD_ACTION_PASSWD_BYNAME,
    /* log debug message */
    pam_syslog(pamh, LOG_DEBUG, "nslcd account check; user=%s", username),
    /* write the request parameters */
    WRITE_STRING(fp, username),
    /* read the result entry (skip it completely) */
    SKIP_STRING(fp);            /* user name */
    // SKIP_STRING(fp);            /* passwd entry */
    SKIP(fp, sizeof(int32_t));  /* uid */
    SKIP(fp, sizeof(int32_t));  /* gid */
    SKIP_STRING(fp);            /* gecos */
    SKIP_STRING(fp);            /* home dir */
    SKIP_STRING(fp);            /* shell */
  )
}

/* perform an authentication call over nslcd */
static int nslcd_request_authc(pam_handle_t *pamh, struct pld_cfg *cfg,
                               const char *username, const char *service,
                               const char *ruser, const char *rhost,
                               const char *tty
                               struct nslcd_resp *authc_resp,
                               struct nslcd_resp *authz_resp)
{
  PAM_REQUEST(
    NSLCD_ACTION_PAM_AUTHC,
    /* log debug message */
    pam_syslog(pamh, LOG_DEBUG, "nslcd authentication; user=%s", username),
    /* write the request parameters */
    WRITE_STRING(fp, username);
    WRITE_STRING(fp, service);
    WRITE_STRING(fp, ruser);
    WRITE_STRING(fp, rhost);
    WRITE_STRING(fp, tty);
    // WRITE_STRING(fp, passwd),
    /* read the result entry */
    READ_PAM_CODE(fp, authc_resp->res);
    READ_STRING(fp, authc_resp->msg); /* user name */
    /* if we want the authorisation response, save it, otherwise skip it */
    if (authz_resp != NULL)
    {
      READ_PAM_CODE(fp, authz_resp->res);
      READ_STRING(fp, authz_resp->msg);
    }
    else
    {
      SKIP(fp, sizeof(int32_t));
      SKIP_STRING(fp);
    }
  )
}

/* perform an authorisation call over nslcd */
static int nslcd_request_authz(pam_handle_t *pamh, struct pld_cfg *cfg,
                               const char *username, const char *service,
                               const char *ruser, const char *rhost,
                               const char *tty, struct nslcd_resp *resp)
{
  PAM_REQUEST(
    NSLCD_ACTION_PAM_AUTHZ,
    /* log debug message */
    pam_syslog(pamh, LOG_DEBUG, "nslcd authorisation; user=%s", username),
    /* write the request parameters */
    WRITE_STRING(fp, username);
    WRITE_STRING(fp, service);
    WRITE_STRING(fp, ruser);
    WRITE_STRING(fp, rhost);
    WRITE_STRING(fp, tty),
    /* read the result entry */
    READ_PAM_CODE(fp, resp->res);
    READ_STRING(fp, resp->msg);
  )
}

/* do a session open nslcd request */
static int nslcd_request_sess_o(pam_handle_t *pamh, struct pld_cfg *cfg,
                                const char *username, const char *service,
                                const char *ruser, const char *rhost,
                                const char *tty, struct nslcd_resp *resp)
{
  PAM_REQUEST(
    NSLCD_ACTION_PAM_SESS_O,
    /* log debug message */
    pam_syslog(pamh, LOG_DEBUG, "nslcd session open; user=%s", username),
    /* write the request parameters */
    WRITE_STRING(fp, username);
    WRITE_STRING(fp, service);
    WRITE_STRING(fp, ruser);
    WRITE_STRING(fp, rhost);
    WRITE_STRING(fp, tty),
    /* read the result entry */
    READ_STRING(fp, resp->msg)
  )
}

/* do a session close nslcd request */
static int nslcd_request_sess_c(pam_handle_t *pamh, struct pld_cfg *cfg,
                                const char *username, const char *service,
                                const char *ruser, const char *rhost,
                                const char *tty, const char *sessid)
{
  PAM_REQUEST(
    NSLCD_ACTION_PAM_SESS_C,
    /* log debug message */
    pam_syslog(pamh, LOG_DEBUG, "nslcd session close; user=%s", username),
    /* write the request parameters */
    WRITE_STRING(fp, username);
    WRITE_STRING(fp, service);
    WRITE_STRING(fp, ruser);
    WRITE_STRING(fp, rhost);
    WRITE_STRING(fp, tty);
    WRITE_STRING(fp, sessid),
    /* no result entry to read */ ;
  )
}

/* do a password modification nslcd call */
static int nslcd_request_pwmod(pam_handle_t *pamh, struct pld_cfg *cfg,
                               const char *username, const char *service,
                               const char *ruser, const char *rhost,
                               const char *tty, int asroot,
                               const char *oldpasswd, const char *newpasswd,
                               struct nslcd_resp *resp)
{
  PAM_REQUEST(
    NSLCD_ACTION_PAM_PWMOD,
    /* log debug message */
    pam_syslog(pamh, LOG_DEBUG, "nslcd password modify; user=%s", username),
    /* write the request parameters */
    WRITE_STRING(fp, username);
    WRITE_STRING(fp, service);
    WRITE_STRING(fp, ruser);
    WRITE_STRING(fp, rhost);
    WRITE_STRING(fp, tty);
    WRITE_INT32(fp, asroot);
    WRITE_STRING(fp, oldpasswd);
    WRITE_STRING(fp, newpasswd),
    /* read the result entry */
    READ_PAM_CODE(fp, resp->res);
    READ_STRING(fp, resp->msg);
  )
}

static int nslcd_request_config_get(pam_handle_t *pamh, struct pld_cfg *cfg,
                                    int cfgopt, struct nslcd_resp *resp)
{
  PAM_REQUEST(
    NSLCD_ACTION_CONFIG_GET,
    /* log debug message */
    pam_syslog(pamh, LOG_DEBUG, "nslcd request config (%d)", cfgopt),
    /* write the request parameter */
    WRITE_INT32(fp, cfgopt),
    /* read the result entry */
    READ_STRING(fp, resp->msg);
  )
}

/* remap the return code based on the configuration */
static int remap_pam_rc(int rc, struct pld_cfg *cfg)
{
  if ((rc == PAM_AUTHINFO_UNAVAIL) && cfg->ignore_authinfo_unavail)
    return PAM_IGNORE;
  if ((rc == PAM_USER_UNKNOWN) && cfg->ignore_unknown_user)
    return PAM_IGNORE;
  return rc;
}

/* PAM authentication check */
int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                        int argc, const char **argv)
{
  int rc;
  struct pld_cfg cfg;
  struct pld_ctx *ctx;
  const char *username, *service;
  const char *ruser = NULL, *rhost = NULL, *tty = NULL;
  char *passwd = NULL;
  struct nslcd_resp resp;
  /* set up configuration */
  cfg_init(pamh, flags, argc, argv, &cfg);
  rc = init(pamh, &cfg, &ctx, &username, &service, &ruser, &rhost, &tty);
  if (rc != PAM_SUCCESS)
    return remap_pam_rc(rc, &cfg);
  /* if service is "passwd" and pwdmod is not allowed alert user */
  /*if (!strcmp(service, "passwd"))
  {
    rc = nslcd_request_config_get(pamh, &cfg, NSLCD_CONFIG_PAM_PASSWORD_PROHIBIT_MESSAGE,
                                  &resp);
    if ((rc == PAM_SUCCESS) && (resp.msg[0] != '\0'))
    {
      /* we silently ignore errors to get the configuration option */
      pam_syslog(pamh, LOG_NOTICE, "password change prohibited: %s; user=%s",
                 resp.msg, username);
      if (!cfg.no_warn)
        pam_error(pamh, "%s", resp.msg);
      return remap_pam_rc(PAM_PERM_DENIED, &cfg);
    }
  }*/
  /* prompt the user for a password */
  /*rc = pam_get_authtok(pamh, PAM_AUTHTOK, (const char **)&passwd, NULL);
  if (rc != PAM_SUCCESS)
  {
    pam_syslog(pamh, LOG_ERR, "failed to get password: %s",
               pam_strerror(pamh, rc));
    return rc;
  }*/
  /* check password */
  /*if (!cfg.nullok && ((passwd == NULL) || (passwd[0] == '\0')))
  {
    if (cfg.debug)
      pam_syslog(pamh, LOG_DEBUG, "user has empty password, access denied");
    return PAM_AUTH_ERR;
  }*/
  /* do the nslcd request */
  rc = nslcd_request_authc(pamh, &cfg, username, service, ruser, rhost, tty,
                            &resp, &(ctx->saved_authz));
  if (rc != PAM_SUCCESS)
    return remap_pam_rc(rc, &cfg);
  /* check the authentication result */
  if (resp.res != PAM_SUCCESS)
  {
    pam_syslog(pamh, LOG_NOTICE, "%s; user=%s",
               pam_strerror(pamh, resp.res), username);
    return remap_pam_rc(resp.res, &cfg);
  }
  /* debug log */
  if (cfg.debug)
    pam_syslog(pamh, LOG_DEBUG, "authentication succeeded");
  /* if password change is required, save old password in context */
  if ((ctx->saved_authz.res == PAM_NEW_AUTHTOK_REQD) && (ctx->oldpassword == NULL))
    ctx->oldpassword = strdup(passwd);
  /* update caller's idea of the user name */
  if ((resp.msg[0] != '\0') && (strcmp(resp.msg, username) != 0))
  {
    pam_syslog(pamh, LOG_INFO, "username changed from %s to %s",
               username, resp.msg);
    rc = pam_set_item(pamh, PAM_USER, resp.msg);
    /* empty the username in the context to not loose our context */
    if (ctx->username != NULL)
    {
      free(ctx->username);
      ctx->username = NULL;
    }
  }
  return rc;
}

/* called to update the authentication credentials */
int pam_sm_setcred(pam_handle_t UNUSED(*pamh), int UNUSED(flags),
                   int UNUSED(argc), const char UNUSED(**argv))
{
  /* we don't need to do anything here */
  return PAM_SUCCESS;
}

/* PAM authorisation check */
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                     int argc, const char **argv)
{
  int rc;
  struct pld_cfg cfg;
  struct pld_ctx *ctx;
  const char *username, *service;
  const char *ruser = NULL, *rhost = NULL, *tty = NULL;
  struct nslcd_resp authz_resp;
  const char *msg = NULL;
  /* set up configuration */
  cfg_init(pamh, flags, argc, argv, &cfg);
  rc = init(pamh, &cfg, &ctx, &username, &service, &ruser, &rhost, &tty);
  if (rc != PAM_SUCCESS)
    return remap_pam_rc(rc, &cfg);
  /* do the nslcd request */
  rc = nslcd_request_authz(pamh, &cfg, username, service, ruser, rhost, tty,
                           &authz_resp);
  if (rc != PAM_SUCCESS)
    return remap_pam_rc(rc, &cfg);
  /* check the returned authorisation value and the value from authentication */
  if (authz_resp.res != PAM_SUCCESS)
  {
    rc = authz_resp.res;
    msg = authz_resp.msg;
  }
  else if (ctx->saved_authz.res != PAM_SUCCESS)
  {
    rc = ctx->saved_authz.res;
    msg = ctx->saved_authz.msg;
  }
  if (rc != PAM_SUCCESS)
  {
    /* turn in to generic PAM error message if message is empty */
    if ((msg == NULL) || (msg[0] == '\0'))
    {
      msg = pam_strerror(pamh, rc);
      pam_syslog(pamh, LOG_NOTICE, "%s; user=%s", msg, username);
    }
    else
      pam_syslog(pamh, LOG_NOTICE, "%s; user=%s; err=%s",
                 msg, username, pam_strerror(pamh, rc));
    rc = remap_pam_rc(rc, &cfg);
    if ((rc != PAM_IGNORE) && (!cfg.no_warn))
      pam_error(pamh, "%s", msg);
    return rc;
  }
  if (cfg.debug)
    pam_syslog(pamh, LOG_DEBUG, "authorization succeeded");
  /* present any informational messages to the user */
  if ((authz_resp.msg[0] != '\0') && (!cfg.no_warn))
  {
    pam_info(pamh, "%s", authz_resp.msg);
    pam_syslog(pamh, LOG_INFO, "%s; user=%s",
               authz_resp.msg, username);
  }
  if ((ctx->saved_authz.msg[0] != '\0') && (!cfg.no_warn))
  {
    pam_info(pamh, "%s", ctx->saved_authz.msg);
    pam_syslog(pamh, LOG_INFO, "%s; user=%s",
               ctx->saved_authz.msg, username);
  }
  return PAM_SUCCESS;
}

/* PAM session open call */
int pam_sm_open_session(pam_handle_t *pamh, int flags,
                        int argc, const char **argv)
{
  int rc;
  struct pld_cfg cfg;
  struct pld_ctx *ctx;
  const char *username, *service;
  const char *ruser = NULL, *rhost = NULL, *tty = NULL;
  /* set up configuration */
  cfg_init(pamh, flags, argc, argv, &cfg);
  rc = init(pamh, &cfg, &ctx, &username, &service, &ruser, &rhost, &tty);
  if (rc != PAM_SUCCESS)
    return remap_pam_rc(rc, &cfg);
  /* do the nslcd request */
  rc = nslcd_request_sess_o(pamh, &cfg, username, service, ruser, rhost,
                            tty, &(ctx->saved_session));
  if (rc != PAM_SUCCESS)
    return remap_pam_rc(rc, &cfg);
  /* debug log */
  if (cfg.debug)
    pam_syslog(pamh, LOG_DEBUG, "session open succeeded; session_id=%s",
               ctx->saved_session.msg);
  return PAM_SUCCESS;
}

/* PAM session close call */
int pam_sm_close_session(pam_handle_t *pamh, int flags,
                         int argc, const char **argv)
{
  int rc;
  struct pld_cfg cfg;
  struct pld_ctx *ctx;
  const char *username, *service;
  const char *ruser = NULL, *rhost = NULL, *tty = NULL;
  /* set up configuration */
  cfg_init(pamh, flags, argc, argv, &cfg);
  rc = init(pamh, &cfg, &ctx, &username, &service, &ruser, &rhost, &tty);
  if (rc != PAM_SUCCESS)
    return remap_pam_rc(rc, &cfg);
  /* do the nslcd request */
  rc = nslcd_request_sess_c(pamh, &cfg, username, service, ruser, rhost,
                            tty, ctx->saved_session.msg);
  if (rc != PAM_SUCCESS)
    return remap_pam_rc(rc, &cfg);
  /* debug log */
  if (cfg.debug)
    pam_syslog(pamh, LOG_DEBUG, "session close succeeded; session_id=%s",
               ctx->saved_session.msg);
  return PAM_SUCCESS;
}

/* Change the password of the user. This function is first called with
 PAM_PRELIM_CHECK set in the flags and then without the flag. In the first
 pass it is determined whether we can contact the LDAP server and the
 provided old password is valid. In the second pass we get the new
 password and actually modify the password. */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                     int argc, const char **argv)
{
  int rc;
  struct pld_cfg cfg;
  struct pld_ctx *ctx;
  const char *username, *service;
  const char *ruser = NULL, *rhost = NULL, *tty = NULL;
  const char *oldpassword = NULL, *newpassword = NULL;
  struct passwd *pwent;
  uid_t myuid;
  struct nslcd_resp resp;
  const char *msg;
  /* set up configuration */
  cfg_init(pamh, flags, argc, argv, &cfg);
  rc = init(pamh, &cfg, &ctx, &username, &service, &ruser, &rhost, &tty);
  if (rc != PAM_SUCCESS)
    return remap_pam_rc(rc, &cfg);
  /* check if password modification is allowed */
  rc = nslcd_request_config_get(pamh, &cfg, NSLCD_CONFIG_PAM_PASSWORD_PROHIBIT_MESSAGE,
                                &resp);
  if ((rc == PAM_SUCCESS) && (resp.msg[0] != '\0'))
  {
    /* we silently ignore errors to get the configuration option */
    pam_syslog(pamh, LOG_NOTICE, "password change prohibited: %s; user=%s",
               resp.msg, username);
    if (!cfg.no_warn)
      pam_error(pamh, "%s", resp.msg);
    return remap_pam_rc(PAM_PERM_DENIED, &cfg);
  }
  /* see if we are dealing with an LDAP user first */
  rc = nslcd_request_exists(pamh, &cfg, username);
  if (rc != PAM_SUCCESS)
    return remap_pam_rc(rc, &cfg);
  /* preliminary check, just see if we can authenticate with the current password */
  if (flags & PAM_PRELIM_CHECK)
  {
    ctx->asroot = 0;
    /* see if the user is trying to modify another user's password */
    /* TODO: perhaps this can be combined with the nslcd_request_exists() call above */
    pwent = pam_modutil_getpwnam(args->pamh, username);
    myuid = getuid();
    if ((pwent != NULL) && (pwent->pw_uid != myuid) && (!(flags & PAM_CHANGE_EXPIRED_AUTHTOK)))
    {
      /* we are root so we can test if nslcd will allow us to change the
         user's password without the admin password */
      if (myuid == 0)
      {
        rc = nslcd_request_authc(pamh, &cfg, "", service, ruser, rhost, tty,
                                 "", &resp, NULL);
        if ((rc == PAM_SUCCESS) && (resp.res == PAM_SUCCESS))
        {
          ctx->asroot = 1;
          return pam_set_item(pamh, PAM_OLDAUTHTOK, "");
        }
      }
      /* try to  authenticate with the LDAP administrator password by passing
         an empty username to the authc request */
      rc = pam_get_authtok(pamh, PAM_OLDAUTHTOK, &oldpassword,
                           "LDAP administrator password: ");
      if (rc != PAM_SUCCESS)
        return rc;
      ctx->asroot = 1;
      username = "";
    }
    else if ((ctx->oldpassword != NULL) && (*ctx->oldpassword != '\0'))
    {
      /* we already have an old password stored (from a previous
         authentication phase) so we'll use that and don't re-check */
      rc = pam_set_item(pamh, PAM_OLDAUTHTOK, ctx->oldpassword);
      return remap_pam_rc(rc, &cfg);
    }
    else
    {
      /* prompt the user for a password if needed */
      rc = pam_get_authtok(pamh, PAM_OLDAUTHTOK, (const char **)&oldpassword,
                           "(current) LDAP Password: ");
      if (rc != PAM_SUCCESS)
        return rc;
    }
    /* check for empty password */
    if (!cfg.nullok && ((oldpassword == NULL) || (oldpassword[0] == '\0')))
    {
      if (cfg.debug)
        pam_syslog(pamh, LOG_DEBUG, "user has empty password, access denied");
      return PAM_AUTH_ERR;
    }
    /* try authenticating */
    rc = nslcd_request_authc(pamh, &cfg, username, service, ruser, rhost,
                             tty, oldpassword, &resp, NULL);
    if (rc != PAM_SUCCESS)
      return remap_pam_rc(rc, &cfg);
    /* handle authentication result */
    if (resp.res != PAM_SUCCESS)
      pam_syslog(pamh, LOG_NOTICE, "%s; user=%s",
                 pam_strerror(pamh, resp.res), username);
    else if (cfg.debug)
      pam_syslog(pamh, LOG_DEBUG, "authentication succeeded");
    /* remap error code */
    return remap_pam_rc(resp.res, &cfg);
  }
  /* get the old password (from the previous call) */
  rc = pam_get_item(pamh, PAM_OLDAUTHTOK, (PAM_ITEM_CONST void **)&oldpassword);
  if (rc != PAM_SUCCESS)
    return rc;
  /* prompt for new password */
  rc = pam_get_authtok(pamh, PAM_AUTHTOK, &newpassword, NULL);
  if (rc != PAM_SUCCESS)
    return rc;
  /* perform the password modification */
  rc = nslcd_request_pwmod(pamh, &cfg, username, service, ruser, rhost, tty,
                           ctx->asroot, oldpassword, newpassword, &resp);
  if (rc != PAM_SUCCESS)
    msg = pam_strerror(pamh, rc);
  else
  {
    rc = resp.res;
    msg = resp.msg;
  }
  /* remap error code */
  rc = remap_pam_rc(rc, &cfg);
  /* check the returned value */
  if (rc != PAM_SUCCESS)
  {
    pam_syslog(pamh, LOG_NOTICE, "password change failed: %s; user=%s",
               msg, username);
    if ((rc != PAM_IGNORE) && (!cfg.no_warn))
      pam_error(pamh, "%s", msg);
    return rc;
  }
  pam_syslog(pamh, LOG_NOTICE, "password changed for %s", username);
  return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module PAM_NAME(modstruct) = {
  "pam_" MODULE_NAME,
  pam_sm_authenticate,
  pam_sm_setcred,
  pam_sm_acct_mgmt,
  pam_sm_open_session,
  pam_sm_close_session,
  pam_sm_chauthtok
};
#endif /* PAM_STATIC */
