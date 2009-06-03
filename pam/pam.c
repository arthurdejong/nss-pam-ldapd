/*
   pam.c - pam module functions

   Copyright (C) 2009 Howard Chu
   Copyright (C) 2009 Arthur de Jong

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
   WARNING: this code is under development and the details of the protocol
            may change between releases.
*/

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include "common.h"
#include "compat/attrs.h"

/* these are defined (before including pam_modules.h) for staticly linking */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#ifndef HAVE_PAM_PAM_MODULES_H
#include <security/pam_modules.h>
#else
#include <pam/pam_modules.h>
#endif

#define IGNORE_UNKNOWN  1
#define IGNORE_UNAVAIL  2

#define USE_FIRST 1
#define TRY_FIRST 2
#define USE_TOKEN 4

#define PLD_CTX "PAM_LDAPD_CTX"

/* this struct represents that context that the PAM module keeps
   between calls */
typedef struct pld_ctx {
  char *user;
  char *dn;
  char *tmpluser;
  char *authzmsg;
  char *oldpw;
  int authok;
  int authz;
  int sessid;
  char buf[1024];
} pld_ctx;

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

/* clear the context to all empty values */
static void ctx_clear(pld_ctx *ctx)
{
  if (ctx->user)
  {
    free(ctx->user);
    ctx->user=NULL;
  }
  if (ctx->oldpw)
  {
    memset(ctx->oldpw,0,strlen(ctx->oldpw));
    free(ctx->oldpw);
    ctx->oldpw=NULL;
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
  pld_ctx *ctx=data;
  ctx_clear(ctx);
  free(ctx);
}

/* try to get the module's context, returns a PAM status code */
static int ctx_get(pam_handle_t *pamh,const char *username,pld_ctx **pctx)
{
  pld_ctx *ctx=NULL;
  int rc;
  /* try to get the context from PAM */
  rc=pam_get_data(pamh, PLD_CTX,(const void **)&ctx);
  if ((rc==PAM_SUCCESS)&&(ctx!=NULL))
  {
    /* if the user is different clear the context */
    if ((ctx->user!=NULL)&&(strcmp(ctx->user,username)!=0))
      ctx_clear(ctx);
  }
  else
  {
    /* allocate a new context */
    ctx=calloc(1,sizeof(*ctx));
    ctx_clear(ctx);
    if (!ctx)
      return PAM_BUF_ERR;
    /* store the new context with the handler to free it */
    rc=pam_set_data(pamh,PLD_CTX,ctx,ctx_free);
    if (rc!=PAM_SUCCESS)
      ctx_free(pamh,ctx,0);
  }
  if (rc==PAM_SUCCESS)
    *pctx=ctx;
  return rc;
}

/* ask the user for an authentication token (password) */
static int pam_get_authtok(pam_handle_t *pamh,int flags,char *prompt1,char *prompt2,char **pwd)
{
  int rc;
  char *p;
  struct pam_message msg[1], *pmsg[1];
  struct pam_response *resp;
  struct pam_conv *conv;

  *pwd=NULL;

  rc=pam_get_item(pamh,PAM_CONV,(const void **)&conv);
  if (rc==PAM_SUCCESS) {
    pmsg[0]=&msg[0];
    msg[0].msg_style=PAM_PROMPT_ECHO_OFF;
    msg[0].msg=prompt1;
    resp=NULL;
    rc=conv->conv(1,
       (const struct pam_message **)pmsg,
       &resp,conv->appdata_ptr);
  } else {
    return rc;
  }

  if (resp!=NULL) {
    if ((flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp==NULL)
    {
      free(resp);
      return PAM_AUTH_ERR;
    }

    p=resp[0].resp;
    resp[0].resp=NULL;
    free(resp);
  } else {
    return PAM_CONV_ERR;
  }

  if (prompt2) {
    msg[0].msg=prompt2;
    resp=NULL;
    rc=conv->conv(1,
       (const struct pam_message **) pmsg,
       &resp, conv->appdata_ptr);
    if (resp && resp[0].resp && !strcmp(resp[0].resp, p))
      rc=PAM_SUCCESS;
    else
      rc=PAM_AUTHTOK_RECOVERY_ERR;
    if (resp) {
      if (resp[0].resp) {
        (void) memset(resp[0].resp, 0, strlen(resp[0].resp));
        free(resp[0].resp);
      }
      free(resp);
    }
  }

  if (rc==PAM_SUCCESS)
    *pwd=p;
  else if (p) {
    memset(p, 0, strlen(p));
    free(p);
  }

  return rc;
}

/* perform an authentication call over nslcd */
static int nslcd_request_authc(pld_ctx *ctx,const char *username,const char *svc,const char *passwd)
{
  PAM_REQUEST(NSLCD_ACTION_PAM_AUTHC,
    /* write the request parameters */
    WRITE_STRING(fp,username);
    WRITE_STRING(fp,ctx->dn);
    WRITE_STRING(fp,svc);
    WRITE_STRING(fp,passwd),
    /* read the result entry */
    READ_BUF_STRING(fp,ctx->tmpluser);
    READ_BUF_STRING(fp,ctx->dn);
    READ_PAM_CODE(fp,ctx->authok)
    READ_PAM_CODE(fp,ctx->authz)
    READ_BUF_STRING(fp,ctx->authzmsg);)
}

int pam_sm_authenticate(pam_handle_t *pamh,int flags,int argc,const char **argv)
{
  int rc;
  const char *username,*svc;
  char *passwd=NULL;
  int first_pass=0,ignore_flags=0;
  int i;
  pld_ctx *ctx;
  /* go over arguments */
  for (i=0;i<argc;i++)
  {
    if (strcmp(argv[i],"use_first_pass")==0)
      first_pass|=USE_FIRST;
    else if (strcmp(argv[i],"try_first_pass")==0)
      first_pass|=TRY_FIRST;
    else if (strcmp(argv[i],"ignore_unknown_user")==0)
      ignore_flags|=IGNORE_UNKNOWN;
    else if (strcmp(argv[i],"ignore_authinfo_unavail")==0)
      ignore_flags|=IGNORE_UNAVAIL;
    else if (strcmp(argv[i], "no_warn")==0)
      /* ignore */;
    else if (strcmp(argv[i],"debug")==0)
      /* ignore */;
    else
      syslog(LOG_AUTHPRIV|LOG_ERR,"unknown option: %s",argv[i]);
  }
  /* get user name */
  rc=pam_get_user(pamh,(const char **)&username,NULL);
  if (rc!=PAM_SUCCESS)
    return rc;
  /* get our context */
  rc=ctx_get(pamh,username,&ctx);
  if (rc!=PAM_SUCCESS)
    return rc;
  /* get service name */
  rc=pam_get_item(pamh,PAM_SERVICE,(const void **)&svc);
  if (rc!=PAM_SUCCESS)
    return rc;
  /* try twice */
  for (i=0;i<2;i++)
  {
    if (!first_pass)
    {
      rc=pam_get_authtok(pamh,flags,i==0?"Password: ":"LDAP Password: ",NULL,&passwd);
      if (rc!=PAM_SUCCESS)
        return rc;
      /* exit loop after trying this password */
      i=2;
      /* store password */
      pam_set_item(pamh,PAM_AUTHTOK,passwd);
      /* clear and free password */
      memset(passwd,0,strlen(passwd));
      free(passwd);
    }
    rc=pam_get_item(pamh,PAM_AUTHTOK,(const void **)&passwd);
    if (rc==PAM_SUCCESS)
    {
      rc=nslcd_request_authc(ctx,username,svc,passwd);
      if (rc==PAM_SUCCESS)
        rc=ctx->authok;
      if ((rc==PAM_AUTHINFO_UNAVAIL)&&(ignore_flags&IGNORE_UNAVAIL))
        rc=PAM_IGNORE;
      else if ((rc==PAM_USER_UNKNOWN)&&(ignore_flags&IGNORE_UNKNOWN))
        rc=PAM_IGNORE;
    }
    if ((rc==PAM_SUCCESS)||(first_pass&USE_FIRST))
      break;
    first_pass=0;
  }
  /* save username */
  if (rc==PAM_SUCCESS) {
    ctx->user=strdup(username);
    /* if password change is required, save old password in context */
    if (ctx->authz==PAM_NEW_AUTHTOK_REQD)
      ctx->oldpw=strdup(passwd);
  }
  /* update caller's idea of the user name */
  if ( (rc==PAM_SUCCESS) && ctx->tmpluser && ctx->tmpluser[0] &&
       (strcmp(ctx->tmpluser,username)!=0) ) {
    rc=pam_set_item(pamh,PAM_USER,ctx->tmpluser);
  }
  return rc;
}

/* called to update the authentication credentials */
int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc,const char **argv)
{
  /* we don't need to do anything here */
  return PAM_SUCCESS;
}

static int pam_warn(
  struct pam_conv *aconv, const char *message, int style, int no_warn)
{
  struct pam_message msg, *pmsg;
  struct pam_response *resp;

  if (no_warn)
    return PAM_SUCCESS;

  pmsg=&msg;

  msg.msg_style=style;
  msg.msg=(char *) message;
  resp=NULL;

  return aconv->conv(1,
          (const struct pam_message **) &pmsg,
          &resp, aconv->appdata_ptr);
}

/* perform an authorisation call over nslcd */
static int nslcd_request_authz(pld_ctx *ctx,const char *username,
        const char *svc,const char *ruser,const char *rhost,const char *tty)
{
  PAM_REQUEST(NSLCD_ACTION_PAM_AUTHZ,
    /* write the request parameters */
    WRITE_STRING(fp,username);
    WRITE_STRING(fp,ctx->dn);
    WRITE_STRING(fp,svc);
    WRITE_STRING(fp,ruser);
    WRITE_STRING(fp,rhost);
    WRITE_STRING(fp,tty),
    /* read the result entry */
    READ_BUF_STRING(fp,ctx->tmpluser);
    READ_BUF_STRING(fp,ctx->dn);
    READ_PAM_CODE(fp,ctx->authz);
    READ_BUF_STRING(fp,ctx->authzmsg);)
}

int pam_sm_acct_mgmt(pam_handle_t *pamh,int flags,int argc,const char **argv)
{
  int rc;
  const char *username,*svc,*ruser,*rhost,*tty;
  int no_warn=0, ignore_flags=0;
  int i;
  struct pam_conv *appconv;
  pld_ctx *ctx=NULL, ctx2;

  for (i=0;i<argc;i++)
  {
    if (strcmp(argv[i],"use_first_pass")==0)
      ;
    else if (strcmp(argv[i],"try_first_pass")==0)
      ;
    else if (strcmp(argv[i],"no_warn")==0)
      no_warn=1;
    else if (strcmp(argv[i],"ignore_unknown_user")==0)
      ignore_flags|=IGNORE_UNKNOWN;
    else if (strcmp(argv[i],"ignore_authinfo_unavail")==0)
      ignore_flags|=IGNORE_UNAVAIL;
    else if (strcmp(argv[i],"debug")==0)
      ;
    else
      syslog(LOG_AUTHPRIV|LOG_ERR,"unknown option: %s",argv[i]);
  }

  if (flags&PAM_SILENT)
    no_warn=1;

  rc=pam_get_item(pamh,PAM_CONV,(const void **)&appconv);
  if (rc!=PAM_SUCCESS)
    return rc;

  rc=pam_get_user(pamh,(const char **)&username,NULL);
  if (rc!=PAM_SUCCESS)
    return rc;

  if ((username==NULL)||(username[0]=='\0'))
    return PAM_USER_UNKNOWN;

  rc=ctx_get(pamh,username,&ctx);
  if (rc!=PAM_SUCCESS)
    return rc;

  rc=pam_get_item(pamh,PAM_SERVICE,(const void **)&svc);
  if (rc!=PAM_SUCCESS)
    return rc;

  rc=pam_get_item (pamh,PAM_RUSER,(const void **)&ruser);
  if (rc!=PAM_SUCCESS)
    return rc;

  rc=pam_get_item (pamh,PAM_RHOST,(const void **)&rhost);
  if (rc!=PAM_SUCCESS)
    return rc;

  rc=pam_get_item (pamh,PAM_TTY,(const void **)&tty);
  if (rc!=PAM_SUCCESS)
    return rc;

  ctx2.dn=ctx->dn;
  ctx2.user=ctx->user;
  rc=nslcd_request_authz(&ctx2,username,svc,ruser,rhost,tty);
  if ((rc==PAM_AUTHINFO_UNAVAIL)&&(ignore_flags&IGNORE_UNAVAIL))
    rc=PAM_IGNORE;
  else if ((rc==PAM_USER_UNKNOWN)&&(ignore_flags&IGNORE_UNKNOWN))
    rc=PAM_IGNORE;
  if (rc!=PAM_SUCCESS) 
  {
    if (rc!=PAM_IGNORE)
      pam_warn(appconv,"LDAP authorization failed",PAM_ERROR_MSG,no_warn);
  } 
  else 
  {
    if (ctx2.authzmsg && ctx2.authzmsg[0])
      pam_warn(appconv,ctx2.authzmsg,PAM_TEXT_INFO,no_warn);
    if (ctx2.authz==PAM_SUCCESS) 
    {
      rc=ctx->authz;
      if (ctx->authzmsg && ctx->authzmsg[0])
        pam_warn(appconv,ctx->authzmsg,PAM_TEXT_INFO,no_warn);
    }
  }

  /* update caller's idea of the user name */
  if ( (rc==PAM_SUCCESS) && ctx->tmpluser && ctx->tmpluser[0] &&
       (strcmp(ctx->tmpluser,username)!=0) ) {
    rc=pam_set_item(pamh,PAM_USER,ctx->tmpluser);
  }
  return rc;
}

/* do a session nslcd request (open or close) */
static int nslcd_request_sess(pam_handle_t *pamh,pld_ctx *ctx,int action)
{
  const char *svc=NULL,*tty=NULL,*rhost=NULL,*ruser=NULL;
  PAM_REQUEST(action,
    /* get information for request (ignore errors) */
    pam_get_item(pamh,PAM_SERVICE,(const void **)&svc);
    pam_get_item(pamh,PAM_TTY,(const void **)&tty);
    pam_get_item(pamh,PAM_RHOST,(const void **)&rhost);
    pam_get_item(pamh,PAM_RUSER,(const void **)&ruser);
    /* write the request parameters */
    WRITE_STRING(fp,ctx->user);
    WRITE_STRING(fp,ctx->dn);
    WRITE_STRING(fp,svc);
    WRITE_STRING(fp,tty);
    WRITE_STRING(fp,rhost);
    WRITE_STRING(fp,ruser);
    WRITE_INT32(fp,ctx->sessid),
    /* read the result entry */
    READ_INT32(fp,ctx->sessid))
}

static int pam_sm_session(
  pam_handle_t *pamh, int flags, int argc, const char **argv,
  int action, int *no_warn)
{
  int rc, err;
  const char *username;
  int ignore_flags=0;
  int i, success=PAM_SUCCESS;
  pld_ctx *ctx=NULL;

  for (i=0;i<argc;i++)
  {
    if (strcmp(argv[i],"use_first_pass")==0)
      ;
    else if (strcmp(argv[i],"try_first_pass")==0)
      ;
    else if (strcmp(argv[i],"no_warn")==0)
      *no_warn=1;
    else if (strcmp(argv[i],"ignore_unknown_user")==0)
      ignore_flags|=IGNORE_UNKNOWN;
    else if (strcmp(argv[i],"ignore_authinfo_unavail")==0)
      ignore_flags|=IGNORE_UNAVAIL;
    else if (strcmp(argv[i],"debug")==0)
      ;
    else
      syslog(LOG_AUTHPRIV|LOG_ERR,"unknown option: %s",argv[i]);
  }

  if (flags & PAM_SILENT)
    *no_warn=1;

  rc=pam_get_user(pamh,(const char **)&username,NULL);
  if (rc!=PAM_SUCCESS)
    return rc;

  if ((username==NULL)||(username[0]=='\0'))
    return PAM_USER_UNKNOWN;

  rc=ctx_get(pamh,username,&ctx);
  if (rc!=PAM_SUCCESS)
    return rc;

  rc=nslcd_request_sess(pamh,ctx,action);
  if ((rc==PAM_AUTHINFO_UNAVAIL)&&(ignore_flags&IGNORE_UNAVAIL))
    rc=PAM_IGNORE;
  else if ((rc==PAM_USER_UNKNOWN)&&(ignore_flags&IGNORE_UNKNOWN))
    rc=PAM_IGNORE;
  return rc;
}

int pam_sm_open_session(
  pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  int rc, no_warn=0;
  struct pam_conv *appconv;

  rc=pam_get_item(pamh,PAM_CONV,(const void **)&appconv);
  if (rc!=PAM_SUCCESS)
    return rc;

  rc=pam_sm_session(pamh,flags,argc,argv,NSLCD_ACTION_PAM_SESS_O,&no_warn);
  if ((rc!=PAM_SUCCESS)&&(rc!=PAM_IGNORE))
    pam_warn(appconv,"LDAP open_session failed",PAM_ERROR_MSG,no_warn);
  return rc;
}

int pam_sm_close_session(
  pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  int rc, no_warn=0;;
  struct pam_conv *appconv;

  rc=pam_get_item(pamh,PAM_CONV,(const void **)&appconv);
  if (rc!=PAM_SUCCESS)
    return rc;

  rc=pam_sm_session(pamh,flags,argc,argv,NSLCD_ACTION_PAM_SESS_C,&no_warn);
  if ((rc!=PAM_SUCCESS)&&(rc!=PAM_IGNORE))
    pam_warn(appconv,"LDAP close_session failed",PAM_ERROR_MSG,no_warn);
  return rc;
}

/* do a password modification nslcd call */
static int nslcd_request_pwmod(pld_ctx *ctx,const char *username,const char *svc,
                    const char *oldpw,const char *newpw)
{
  PAM_REQUEST(NSLCD_ACTION_PAM_AUTHZ,
    /* write the request parameters */
    WRITE_STRING(fp,username);
    WRITE_STRING(fp,ctx->dn);
    WRITE_STRING(fp,svc);
    WRITE_STRING(fp,oldpw);
    WRITE_STRING(fp,newpw),
    /* read the result entry */
    READ_BUF_STRING(fp,ctx->tmpluser);
    READ_BUF_STRING(fp,ctx->dn);
    READ_PAM_CODE(fp,ctx->authz);
    READ_BUF_STRING(fp,ctx->authzmsg);)
}

int pam_sm_chauthtok(
  pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  int rc;
  const char *username, *p=NULL, *q=NULL, *svc;
  int first_pass=0, no_warn=0, ignore_flags=0;
  int i, success=PAM_SUCCESS;
  struct pam_conv *appconv;
  pld_ctx *ctx=NULL;

  for (i=0;i<argc;i++)
  {
    if (strcmp(argv[i],"use_first_pass")==0)
      first_pass|=USE_FIRST;
    else if (strcmp(argv[i],"try_first_pass")==0)
      first_pass|=TRY_FIRST;
    else if (strcmp(argv[i],"use_authtok")==0)
      first_pass|=USE_TOKEN;
    else if (strcmp(argv[i],"no_warn")==0)
      no_warn=1;
    else if (strcmp(argv[i],"ignore_unknown_user")==0)
      ignore_flags|=IGNORE_UNKNOWN;
    else if (strcmp(argv[i],"ignore_authinfo_unavail")==0)
      ignore_flags|=IGNORE_UNAVAIL;
    else if (strcmp(argv[i],"debug")==0)
      ;
    else
      syslog(LOG_AUTHPRIV|LOG_ERR,"unknown option: %s",argv[i]);
  }

  if (flags&PAM_SILENT)
    no_warn=1;

  rc=pam_get_item(pamh,PAM_CONV,(const void **)&appconv);
  if (rc!=PAM_SUCCESS)
    return rc;

  rc=pam_get_user(pamh,(const char **)&username,NULL);
  if (rc!=PAM_SUCCESS)
    return rc;

  if (username==NULL)
    return PAM_USER_UNKNOWN;

  rc=ctx_get(pamh,username,&ctx);
  if (rc!=PAM_SUCCESS)
    return rc;

  rc=pam_get_item(pamh,PAM_SERVICE,(const void **)&svc);
  if (rc!=PAM_SUCCESS)
    return rc;

  if (flags & PAM_PRELIM_CHECK) {
    if (getuid()) {
      if (!first_pass) {
        rc=pam_get_authtok(pamh,flags,"(current) LDAP Password: ",NULL,&p);
        if (rc==PAM_SUCCESS) {
          pam_set_item(pamh,PAM_OLDAUTHTOK,p);
          memset(p,0,strlen(p));
          free(p);
        }
      }
      rc=pam_get_item(pamh,PAM_OLDAUTHTOK,&p);
      if (rc) 
        return rc;
    } 
    else 
      rc=PAM_SUCCESS;
    if (!ctx->dn) 
    {
      rc=nslcd_request_pwmod(ctx,username,svc,p,NULL);
      if ((rc==PAM_AUTHINFO_UNAVAIL)&&(ignore_flags&IGNORE_UNAVAIL))
        rc=PAM_IGNORE;
      else if ((rc==PAM_USER_UNKNOWN)&&(ignore_flags&IGNORE_UNKNOWN))
        rc=PAM_IGNORE;
    }
    return rc;
  }

  rc=pam_get_item(pamh,PAM_OLDAUTHTOK,&p);
  if (rc) 
    return rc;

  if (!p)
    p=ctx->oldpw;

  if (first_pass) 
  {
    rc=pam_get_item(pamh,PAM_AUTHTOK,&q);
    if ((rc!=PAM_SUCCESS || !q) && (first_pass & (USE_FIRST|USE_TOKEN))) {
      if (rc==PAM_SUCCESS)
        rc=PAM_AUTHTOK_RECOVERY_ERR;
      return rc;
    }
  }
  if (!q) 
  {
    rc=pam_get_authtok(pamh, flags, "Enter new LDAP Password: ",
      "Retype new LDAP Password: ", &q);
    if (rc==PAM_SUCCESS) 
    {
      pam_set_item(pamh,PAM_AUTHTOK,q);
      memset(q,0,strlen(q));
      free(q);
      rc=pam_get_item(pamh,PAM_AUTHTOK,&q);
    }
    if (rc!=PAM_SUCCESS)
      return rc;
  }
  rc=nslcd_request_pwmod(ctx,username,svc,p,q);
  if ((rc==PAM_AUTHINFO_UNAVAIL)&&(ignore_flags&IGNORE_UNAVAIL))
    rc=PAM_IGNORE;
  else if ((rc==PAM_USER_UNKNOWN)&&(ignore_flags&IGNORE_UNKNOWN))
    rc=PAM_IGNORE;
  p=NULL; q=NULL;
  if (rc==PAM_SUCCESS) 
  {
    rc=ctx->authz;
    if (rc!=PAM_SUCCESS)
      pam_warn(appconv, ctx->authzmsg, PAM_ERROR_MSG, no_warn);
  } 
  else if (rc!=PAM_IGNORE)
    pam_warn(appconv, "LDAP pwmod failed", PAM_ERROR_MSG, no_warn);
  return rc;
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
