/*
   pam.c - pam module functions

   Copyright (C) 2009 Howard Chu
   Copyright (C) 2009, 2010 Arthur de Jong

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


/* this struct represents the context that the PAM module keeps
   between calls */
struct pld_ctx {
  char *user;
  char *dn;
  char *tmpluser;
  char *authzmsg;
  char *oldpassword;
  int authok;
  int authz;
  int sessid;
  char buf[1024];
};

/* clear the context to all empty values */
static void ctx_clear(struct pld_ctx *ctx)
{
  if (ctx->user)
  {
    free(ctx->user);
    ctx->user=NULL;
  }
  if (ctx->oldpassword)
  {
    memset(ctx->oldpassword,0,strlen(ctx->oldpassword));
    free(ctx->oldpassword);
    ctx->oldpassword=NULL;
  }
  ctx->dn=NULL;
  ctx->tmpluser=NULL;
  ctx->authzmsg=NULL;
  ctx->authok=0;
  ctx->authz=0;
}

/* free the context (this is installed as handler into PAM) */
static void ctx_free(pam_handle_t *UNUSED(pamh),void *data,int UNUSED(err))
{
  struct pld_ctx *ctx=data;
  ctx_clear(ctx);
  free(ctx);
}

/* try to get the module's context, returns a PAM status code */
static int ctx_get(pam_handle_t *pamh,const char *username,struct pld_ctx **pctx)
{
  struct pld_ctx *ctx=NULL;
  int rc;
  /* try to get the context from PAM */
  rc=pam_get_data(pamh,PLD_CTX,(const void **)&ctx);
  if ((rc==PAM_SUCCESS)&&(ctx!=NULL))
  {
    /* if the user is different clear the context */
    if ((ctx->user!=NULL)&&(strcmp(ctx->user,username)!=0))
      ctx_clear(ctx);
  }
  else
  {
    /* allocate a new context */
    ctx=calloc(1,sizeof(struct pld_ctx));
    if (ctx==NULL)
    {
      pam_syslog(pamh,LOG_CRIT,"calloc(): failed to allocate memory: %s",strerror(errno));
      return PAM_BUF_ERR;
    }
    ctx_clear(ctx);
    /* store the new context with the handler to free it */
    rc=pam_set_data(pamh,PLD_CTX,ctx,ctx_free);
    if (rc!=PAM_SUCCESS)
    {
      ctx_free(pamh,ctx,0);
      pam_syslog(pamh,LOG_ERR,"failed to store context: %s",pam_strerror(pamh,rc));
      return rc;
    }
  }
  /* return the context */
  *pctx=ctx;
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

static int init(pam_handle_t *pamh,int flags,int argc,const char **argv,
                struct pld_cfg *cfg,struct pld_ctx **ctx,const char **username,
                const char **service)
{
  int i;
  int rc;
  struct passwd *pwent;
  /* initialise config with defaults */
  cfg->nullok=0;
  cfg->no_warn=0;
  cfg->ignore_unknown_user=0;
  cfg->ignore_authinfo_unavail=0;
  cfg->debug=0;
  cfg->minimum_uid=0;
  /* go over arguments */
  for (i=0;i<argc;i++)
  {
    if (strcmp(argv[i],"use_first_pass")==0)
      /* ignore, this option is used by pam_get_authtok() internally */;
    else if (strcmp(argv[i],"try_first_pass")==0)
      /* ignore, this option is used by pam_get_authtok() internally */;
    else if (strcmp(argv[i],"nullok")==0)
      cfg->nullok=1;
    else if (strcmp(argv[i],"use_authtok")==0)
      /* ignore, this option is used by pam_get_authtok() internally */;
    else if (strcmp(argv[i],"no_warn")==0)
      cfg->no_warn=1;
    else if (strcmp(argv[i],"ignore_unknown_user")==0)
      cfg->ignore_unknown_user=1;
    else if (strcmp(argv[i],"ignore_authinfo_unavail")==0)
      cfg->ignore_authinfo_unavail=1;
    else if (strcmp(argv[i],"debug")==0)
      cfg->debug=1;
    else if (strncmp(argv[i],"minimum_uid=",12) == 0)
      cfg->minimum_uid=(uid_t)atoi(argv[i]+12);
    else
      pam_syslog(pamh,LOG_ERR,"unknown option: %s",argv[i]);
  }
  /* check flags */
  if (flags&PAM_SILENT)
    cfg->no_warn=1;
  /* get user name */
  rc=pam_get_user(pamh,username,NULL);
  if (rc!=PAM_SUCCESS)
  {
    pam_syslog(pamh,LOG_ERR,"failed to get user name: %s",pam_strerror(pamh,rc));
    return rc;
  }
  if ((*username==NULL)||((*username)[0]=='\0'))
  {
    pam_syslog(pamh,LOG_ERR,"got empty user name");
    return PAM_USER_UNKNOWN;
  }
  /* check uid */
  if (cfg->minimum_uid>0)
  {
    pwent=pam_modutil_getpwnam(args->pamh,*username);
    if ((pwent!=NULL)&&(pwent->pw_uid<cfg->minimum_uid))
    {
      if (cfg->debug)
        pam_syslog(pamh,LOG_DEBUG,"uid below minimum_uid; user=%s uid=%ld",*username,(long)pwent->pw_uid);
      return cfg->ignore_unknown_user?PAM_IGNORE:PAM_USER_UNKNOWN;
    }
  }
  /* get our context */
  rc=ctx_get(pamh,*username,ctx);
  if (rc!=PAM_SUCCESS)
    return rc;
  /* get service name */
  rc=pam_get_item(pamh,PAM_SERVICE,(const void **)service);
  if (rc!=PAM_SUCCESS)
  {
    pam_syslog(pamh,LOG_ERR,"failed to get service name: %s",pam_strerror(pamh,rc));
    return rc;
  }
  return PAM_SUCCESS;
}

/* map a NSLCD PAM status code to a PAM status code */
static int nslcd2pam_rc(int rc)
{
#define map(i) case NSLCD_##i: return i;
  switch(rc) {
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
    map(PAM_AUTHTOK_DISABLE_AGING);
    map(PAM_IGNORE);
    map(PAM_ABORT);
    default: return PAM_ABORT;
  }
}

/* perform an authentication call over nslcd */
static int nslcd_request_authc(pam_handle_t *pamh,struct pld_ctx *ctx,struct pld_cfg *cfg,
                               const char *username,const char *service,
                               const char *passwd)
{
  PAM_REQUEST(NSLCD_ACTION_PAM_AUTHC,
    /* log debug message */
    pam_syslog(pamh,LOG_DEBUG,"nslcd authentication; user=%s",username),
    /* write the request parameters */
    WRITE_STRING(fp,username);
    WRITE_STRING(fp,ctx->dn);
    WRITE_STRING(fp,service);
    WRITE_STRING(fp,passwd),
    /* read the result entry */
    READ_BUF_STRING(fp,ctx->tmpluser);
    READ_BUF_STRING(fp,ctx->dn);
    READ_PAM_CODE(fp,ctx->authok)
    READ_PAM_CODE(fp,ctx->authz)
    READ_BUF_STRING(fp,ctx->authzmsg);)
}

/* perform an authorisation call over nslcd */
static int nslcd_request_authz(pam_handle_t *pamh,struct pld_ctx *ctx,struct pld_cfg *cfg,
                               const char *username,const char *service,
                               const char *ruser,const char *rhost,
                               const char *tty)
{
  PAM_REQUEST(NSLCD_ACTION_PAM_AUTHZ,
    /* log debug message */
    pam_syslog(pamh,LOG_DEBUG,"nslcd authorisation; user=%s",username),
    /* write the request parameters */
    WRITE_STRING(fp,username);
    WRITE_STRING(fp,ctx->dn);
    WRITE_STRING(fp,service);
    WRITE_STRING(fp,ruser);
    WRITE_STRING(fp,rhost);
    WRITE_STRING(fp,tty),
    /* read the result entry */
    READ_BUF_STRING(fp,ctx->tmpluser);
    READ_BUF_STRING(fp,ctx->dn);
    READ_PAM_CODE(fp,ctx->authz);
    READ_BUF_STRING(fp,ctx->authzmsg);)
}

/* do a session nslcd request (open or close) */
static int nslcd_request_sess(pam_handle_t *pamh,struct pld_ctx *ctx,struct pld_cfg *cfg,int action,
                              const char *username,const char *service,
                              const char *tty,const char *rhost,
                              const char *ruser)
{
  PAM_REQUEST(action,
    /* log debug message */
    pam_syslog(pamh,LOG_DEBUG,"nslcd session %s; user=%s",
          (action==NSLCD_ACTION_PAM_SESS_O)?"open":"close",username),
    /* write the request parameters */
    WRITE_STRING(fp,username);
    WRITE_STRING(fp,ctx->dn);
    WRITE_STRING(fp,service);
    WRITE_STRING(fp,tty);
    WRITE_STRING(fp,rhost);
    WRITE_STRING(fp,ruser);
    WRITE_INT32(fp,ctx->sessid),
    /* read the result entry */
    READ_INT32(fp,ctx->sessid))
}

/* do a password modification nslcd call */
static int nslcd_request_pwmod(pam_handle_t *pamh,struct pld_ctx *ctx,struct pld_cfg *cfg,
                               const char *username,const char *service,
                               const char *oldpasswd,const char *newpasswd)
{
  PAM_REQUEST(NSLCD_ACTION_PAM_PWMOD,
    /* log debug message */
    pam_syslog(pamh,LOG_DEBUG,"nslcd password modify; user=%s",username),
    /* write the request parameters */
    WRITE_STRING(fp,username);
    WRITE_STRING(fp,ctx->dn);
    WRITE_STRING(fp,service);
    WRITE_STRING(fp,oldpasswd);
    WRITE_STRING(fp,newpasswd),
    /* read the result entry */
    READ_BUF_STRING(fp,ctx->tmpluser);
    READ_BUF_STRING(fp,ctx->dn);
    READ_PAM_CODE(fp,ctx->authz);
    READ_BUF_STRING(fp,ctx->authzmsg);)
}

/* remap the return code based on the configuration */
static int remap_pam_rc(int rc,struct pld_cfg *cfg)
{
  if ((rc==PAM_AUTHINFO_UNAVAIL)&&cfg->ignore_authinfo_unavail)
    return PAM_IGNORE;
  if ((rc==PAM_USER_UNKNOWN)&&cfg->ignore_unknown_user)
    return PAM_IGNORE;
  return rc;
}

/* PAM authentication check */
int pam_sm_authenticate(pam_handle_t *pamh,int flags,int argc,const char **argv)
{
  int rc;
  struct pld_cfg cfg;
  struct pld_ctx *ctx;
  const char *username,*service;
  char *passwd=NULL;
  /* set up configuration */
  rc=init(pamh,flags,argc,argv,&cfg,&ctx,&username,&service);
  if (rc!=PAM_SUCCESS)
    return rc;
  /* get the password */
  rc=pam_get_authtok(pamh,PAM_AUTHTOK,(const char **)&passwd,NULL);
  if (rc!=PAM_SUCCESS)
  {
    pam_syslog(pamh,LOG_ERR,"failed to get password: %s",pam_strerror(pamh,rc));
    return rc;
  }
  /* check password */
  if (!cfg.nullok&&((passwd==NULL)||(passwd[0]=='\0')))
  {
    if (cfg.debug)
      pam_syslog(pamh,LOG_DEBUG,"user has empty password, access denied");
    return PAM_AUTH_ERR;
  }
  /* do the nslcd request */
  rc=nslcd_request_authc(pamh,ctx,&cfg,username,service,passwd);
  if (rc!=PAM_SUCCESS)
    return remap_pam_rc(rc,&cfg);
  /* check the authentication result */
  rc=ctx->authok;
  if (rc!=PAM_SUCCESS)
  {
    pam_syslog(pamh,LOG_NOTICE,"%s; user=%s",pam_strerror(pamh,rc),username);
    return remap_pam_rc(rc,&cfg);
  }
  /* debug log */
  if (cfg.debug)
    pam_syslog(pamh,LOG_DEBUG,"authentication succeeded");
  /* save username */
  ctx->user=strdup(username);
  /* if password change is required, save old password in context */
  if (ctx->authz==PAM_NEW_AUTHTOK_REQD)
    ctx->oldpassword=strdup(passwd);
  /* update caller's idea of the user name */
  if ( ctx->tmpluser && ctx->tmpluser[0] && (strcmp(ctx->tmpluser,username)!=0) )
  {
    pam_syslog(pamh,LOG_INFO,"username changed from %s to %s",username,
               ctx->tmpluser);
    rc=pam_set_item(pamh,PAM_USER,ctx->tmpluser);
  }
  return rc;
}

/* called to update the authentication credentials */
int pam_sm_setcred(pam_handle_t UNUSED(*pamh),int UNUSED(flags),
                   int UNUSED(argc),const char UNUSED(**argv))
{
  /* we don't need to do anything here */
  return PAM_SUCCESS;
}

/* PAM authorisation check */
int pam_sm_acct_mgmt(pam_handle_t *pamh,int flags,int argc,const char **argv)
{
  int rc;
  struct pld_cfg cfg;
  struct pld_ctx *ctx=NULL,ctx2;
  const char *username,*service;
  const char *ruser=NULL,*rhost=NULL,*tty=NULL;
  /* set up configuration */
  rc=init(pamh,flags,argc,argv,&cfg,&ctx,&username,&service);
  if (rc!=PAM_SUCCESS)
    return rc;
  /* get more PAM information */
  pam_get_item(pamh,PAM_RUSER,(const void **)&ruser);
  pam_get_item(pamh,PAM_RHOST,(const void **)&rhost);
  pam_get_item(pamh,PAM_TTY,(const void **)&tty);
  /* call the function with a copy of the context to be able to keep the
     original context */
  ctx2.dn=ctx->dn;
  ctx2.user=ctx->user;
  /* do the nslcd request */
  rc=nslcd_request_authz(pamh,&ctx2,&cfg,username,service,ruser,rhost,tty);
  if (rc!=PAM_SUCCESS)
    return remap_pam_rc(rc,&cfg);
  /* check the returned authorisation value */
  if (ctx2.authz!=PAM_SUCCESS)
  {
    pam_syslog(pamh,LOG_NOTICE,"%s; user=%s",ctx2.authzmsg,username);
    rc=remap_pam_rc(ctx2.authz,&cfg);
    if ((rc!=PAM_IGNORE)&&(!cfg.no_warn))
      pam_error(pamh,"%s",ctx2.authzmsg);
    return rc;
  }
  /* check the original authorisation check from authentication */
  if (ctx->authz!=PAM_SUCCESS)
  {
    pam_syslog(pamh,LOG_NOTICE,"%s; user=%s",ctx->authzmsg,username);
    rc=remap_pam_rc(ctx->authz,&cfg);
    if ((rc!=PAM_IGNORE)&&(!cfg.no_warn))
      pam_error(pamh,"%s",ctx->authzmsg);
    return rc;
  }
  if (cfg.debug)
    pam_syslog(pamh,LOG_DEBUG,"authorization succeeded");
  /* present any informational messages to the user */
  if ((ctx2.authzmsg!=NULL)&&(ctx2.authzmsg[0]!='\0')&&(!cfg.no_warn))
    pam_info(pamh,"%s",ctx2.authzmsg);
  if ((ctx->authzmsg!=NULL)&&(ctx->authzmsg[0]!='\0')&&(!cfg.no_warn))
    pam_info(pamh,"%s",ctx->authzmsg);
  return PAM_SUCCESS;
}

/* PAM session open/close calls */
static int pam_sm_session(pam_handle_t *pamh,int flags,int argc,
                          const char **argv,int action)
{
  int rc;
  struct pld_cfg cfg;
  struct pld_ctx *ctx;
  const char *username,*service;
  const char *tty=NULL,*rhost=NULL,*ruser=NULL;
  /* set up configuration */
  rc=init(pamh,flags,argc,argv,&cfg,&ctx,&username,&service);
  if (rc!=PAM_SUCCESS)
    return rc;
  /* get more PAM information */
  pam_get_item(pamh,PAM_TTY,(const void **)&tty);
  pam_get_item(pamh,PAM_RHOST,(const void **)&rhost);
  pam_get_item(pamh,PAM_RUSER,(const void **)&ruser);
  /* do the nslcd request */
  rc=nslcd_request_sess(pamh,ctx,&cfg,action,username,service,tty,rhost,ruser);
  if (rc!=PAM_SUCCESS)
    return remap_pam_rc(rc,&cfg);
  /* debug log */
  if (cfg.debug)
    pam_syslog(pamh,LOG_DEBUG,"session %s succeeded; session_id=%d",
               (action==NSLCD_ACTION_PAM_SESS_O)?"open":"close",ctx->sessid);
  return PAM_SUCCESS;
}

/* PAM session open call */
int pam_sm_open_session(
  pam_handle_t *pamh,int flags,int argc,const char **argv)
{
  return pam_sm_session(pamh,flags,argc,argv,NSLCD_ACTION_PAM_SESS_O);
}

/* PAM session close call */
int pam_sm_close_session(
  pam_handle_t *pamh,int flags,int argc,const char **argv)
{
  return pam_sm_session(pamh,flags,argc,argv,NSLCD_ACTION_PAM_SESS_C);
}

/* Change the password of the user. This function is first called with
   PAM_PRELIM_CHECK set in the flags and then without the flag. In the first
   pass it is determined whether we can contact the LDAP server and the
   provided old password is valid. In the second pass we get the new
   password and actually modify the password. */
int pam_sm_chauthtok(pam_handle_t *pamh,int flags,int argc,const char **argv)
{
  int rc;
  struct pld_cfg cfg;
  struct pld_ctx *ctx;
  const char *username,*service;
  const char *oldpassword=NULL,*newpassword=NULL;
  struct passwd *pwent;
  /* set up configuration */
  rc=init(pamh,flags,argc,argv,&cfg,&ctx,&username,&service);
  if (rc!=PAM_SUCCESS)
    return rc;
  /* prelimenary check, just see if we can connect to the LDAP server
     and authenticate with the current password */
  if (flags&PAM_PRELIM_CHECK)
  {
    /* see if the user is trying to modify another user's password */
    pwent=getpwnam(username);
    if ((pwent!=NULL)&&(pwent->pw_uid!=getuid()))
    {
      /* try to  authenticate with the LDAP administrator password by passing
         an empty username to the authc request */
      rc=pam_get_authtok(pamh,PAM_OLDAUTHTOK,&oldpassword,"LDAP administrator password: ");
      if (rc!=PAM_SUCCESS)
        return rc;
      username="";
    }
    else if ((ctx->oldpassword!=NULL)&&(*ctx->oldpassword!='\0'))
      /* we already have an old password stored (from a previous
         authentication phase) so we'll use that */
      oldpassword=ctx->oldpassword;
    else
    {
      rc=pam_get_authtok(pamh,PAM_OLDAUTHTOK,(const char **)&oldpassword,"(current) LDAP Password: ");
      if (rc!=PAM_SUCCESS)
        return rc;
    }
    /* check for empty password */
    if (!cfg.nullok&&((oldpassword==NULL)||(oldpassword[0]=='\0')))
    {
      if (cfg.debug)
        pam_syslog(pamh,LOG_DEBUG,"user has empty password, access denied");
      return PAM_AUTH_ERR;
    }
    /* try authenticating */
    rc=nslcd_request_authc(pamh,ctx,&cfg,username,service,oldpassword);
    if (rc!=PAM_SUCCESS)
      return remap_pam_rc(rc,&cfg);
    /* handle authentication result */
    if (ctx->authok!=PAM_SUCCESS)
      pam_syslog(pamh,LOG_NOTICE,"%s; user=%s",pam_strerror(pamh,ctx->authok),username);
    else if (cfg.debug)
      pam_syslog(pamh,LOG_DEBUG,"authentication succeeded");
    /* remap error code */
    return remap_pam_rc(ctx->authok,&cfg);
  }
  /* get the old password (from the previous call) */
  rc=pam_get_item(pamh,PAM_OLDAUTHTOK,(const void **)&oldpassword);
  if (rc!=PAM_SUCCESS)
    return rc;
  /* get the new password */
  rc=pam_get_authtok(pamh,PAM_AUTHTOK,&newpassword,NULL);
  if (rc!=PAM_SUCCESS)
    return rc;
  /* perform the password modification */
  rc=nslcd_request_pwmod(pamh,ctx,&cfg,username,service,oldpassword,newpassword);
  if (rc==PAM_SUCCESS)
    rc=ctx->authz;
  else
    ctx->authzmsg=(char *)pam_strerror(pamh,rc);
  /* remap error code */
  rc=remap_pam_rc(rc,&cfg);
  /* check the returned value */
  if (rc!=PAM_SUCCESS)
  {
    pam_syslog(pamh,LOG_NOTICE,"password change failed: %s; user=%s",ctx->authzmsg,username);
    if ((rc!=PAM_IGNORE)&&(!cfg.no_warn))
      pam_error(pamh,"%s",ctx->authzmsg);
    return rc;
  }
  pam_syslog(pamh,LOG_NOTICE,"password changed for %s",username);
  return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_ldap_modstruct={
  "pam_ldap",
  pam_sm_authenticate,
  pam_sm_setcred,
  pam_sm_acct_mgmt,
  pam_sm_open_session,
  pam_sm_close_session,
  pam_sm_chauthtok
};
#endif /* PAM_STATIC */
