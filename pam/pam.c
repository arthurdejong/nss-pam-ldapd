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

#include "common.h"
#include "compat/attrs.h"
#include "compat/pam_compat.h"

/* these are defined (before including pam_modules.h) for staticly linking */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

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

#define IGNORE_UNKNOWN  1
#define IGNORE_UNAVAIL  2

#define USE_FIRST 1
#define TRY_FIRST 2
#define USE_TOKEN 4

#define PLD_CTX "PAM_LDAPD_CTX"

/* some systems don't have LOG_AUTHPRIV */
#ifndef LOG_AUTHPRIV
#define LOG_AUTHPRIV LOG_AUTH
#endif /* not LOG_AUTHPRIV */

/* this struct represents that context that the PAM module keeps
   between calls */
typedef struct pld_ctx {
  char *user;
  char *dn;
  char *tmpluser;
  char *authzmsg;
  char *oldpassword;
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
static int my_pam_get_authtok(pam_handle_t *pamh,int flags,char *prompt1,char *prompt2,const char **pwd)
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
static int nslcd_request_authc(pld_ctx *ctx,const char *username,
                               const char *service,const char *passwd)
{
  PAM_REQUEST(NSLCD_ACTION_PAM_AUTHC,
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

int pam_sm_authenticate(pam_handle_t *pamh,int flags,int argc,const char **argv)
{
  int rc;
  const char *username,*svc;
  char *passwd=NULL;
  int first_pass=0,ignore_flags=0;
  int i;
  pld_ctx *ctx;
  uid_t minimum_uid=0;
  struct passwd *pwd;
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
    else if (strncmp(argv[i], "minimum_uid=", 12) == 0)
      minimum_uid=(uid_t)atoi(argv[i]+12);
    else
      syslog(LOG_AUTHPRIV|LOG_ERR,"unknown option: %s",argv[i]);
  }
  /* get user name */
  rc=pam_get_user(pamh,(const char **)&username,NULL);
  if (rc!=PAM_SUCCESS)
    return rc;
  if ((username==NULL)||(username[0]=='\0'))
    return PAM_USER_UNKNOWN;
  /* check uid */
  if (minimum_uid>0)
  {
    pwd=pam_modutil_getpwnam(args->pamh,username);
    if ((pwd!=NULL)&&(pwd->pw_uid<minimum_uid))
      return ignore_flags&IGNORE_UNKNOWN?PAM_IGNORE:PAM_USER_UNKNOWN;
  }
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
      rc=my_pam_get_authtok(pamh,flags,i==0?"Password: ":"LDAP Password: ",NULL,(const char **)&passwd);
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
      ctx->oldpassword=strdup(passwd);
  }
  /* update caller's idea of the user name */
  if ( (rc==PAM_SUCCESS) && ctx->tmpluser && ctx->tmpluser[0] &&
       (strcmp(ctx->tmpluser,username)!=0) ) {
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

/* perform an authorisation call over nslcd */
static int nslcd_request_authz(pld_ctx *ctx,const char *username,
                               const char *service,const char *ruser,
                               const char *rhost,const char *tty)
{
  PAM_REQUEST(NSLCD_ACTION_PAM_AUTHZ,
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

int pam_sm_acct_mgmt(pam_handle_t *pamh,int flags,int argc,const char **argv)
{
  int rc;
  const char *username,*svc,*ruser,*rhost,*tty;
  int no_warn=0, ignore_flags=0;
  int i;
  pld_ctx *ctx=NULL, ctx2;
  uid_t minimum_uid=0;
  struct passwd *pwent;
  /* go over arguments */
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
    else if (strncmp(argv[i], "minimum_uid=", 12) == 0)
      minimum_uid=(uid_t)atoi(argv[i]+12);
    else
      syslog(LOG_AUTHPRIV|LOG_ERR,"unknown option: %s",argv[i]);
  }

  if (flags&PAM_SILENT)
    no_warn=1;

  /* get user name */
  rc=pam_get_user(pamh,(const char **)&username,NULL);
  if (rc!=PAM_SUCCESS)
    return rc;
  if ((username==NULL)||(username[0]=='\0'))
    return PAM_USER_UNKNOWN;
  /* check uid */
  if (minimum_uid>0)
  {
    pwent=pam_modutil_getpwnam(args->pamh,username);
    if ((pwent!=NULL)&&(pwent->pw_uid<minimum_uid))
      return ignore_flags&IGNORE_UNKNOWN?PAM_IGNORE:PAM_USER_UNKNOWN;
  }

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
      if (!no_warn)
        pam_error(pamh,"LDAP authorization failed");
  }
  else
  {
    rc=ctx2.authz;
    if (ctx2.authzmsg && ctx2.authzmsg[0])
      if (!no_warn)
        pam_info(pamh,"%s",ctx2.authzmsg);
    if (ctx2.authz==PAM_SUCCESS)
    {
      rc=ctx->authz;
      if (ctx->authzmsg && ctx->authzmsg[0])
        if (!no_warn)
          pam_info(pamh,"%s",ctx->authzmsg);
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
static int nslcd_request_sess(pld_ctx *ctx,int action,const char *service,
                              const char *tty, const char *rhost,
                              const char *ruser)
{
  PAM_REQUEST(action,
    /* write the request parameters */
    WRITE_STRING(fp,ctx->user);
    WRITE_STRING(fp,ctx->dn);
    WRITE_STRING(fp,service);
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
  int rc;
  const char *username;
  int ignore_flags=0;
  int i;
  pld_ctx *ctx=NULL;
  const char *service=NULL,*tty=NULL,*rhost=NULL,*ruser=NULL;
  uid_t minimum_uid=0;
  struct passwd *pwent;
  /* go over arguments */
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
    else if (strncmp(argv[i], "minimum_uid=", 12) == 0)
      minimum_uid=(uid_t)atoi(argv[i]+12);
    else
      syslog(LOG_AUTHPRIV|LOG_ERR,"unknown option: %s",argv[i]);
  }

  if (flags & PAM_SILENT)
    *no_warn=1;
  /* get user name */
  rc=pam_get_user(pamh,(const char **)&username,NULL);
  if (rc!=PAM_SUCCESS)
    return rc;
  if ((username==NULL)||(username[0]=='\0'))
    return PAM_USER_UNKNOWN;
  /* check uid */
  if (minimum_uid>0)
  {
    pwent=pam_modutil_getpwnam(args->pamh,username);
    if ((pwent!=NULL)&&(pwent->pw_uid<minimum_uid))
      return ignore_flags&IGNORE_UNKNOWN?PAM_IGNORE:PAM_USER_UNKNOWN;
  }

  rc=ctx_get(pamh,username,&ctx);
  if (rc!=PAM_SUCCESS)
    return rc;
  /* read PAM information */
  pam_get_item(pamh,PAM_SERVICE,(const void **)&service);
  pam_get_item(pamh,PAM_TTY,(const void **)&tty);
  pam_get_item(pamh,PAM_RHOST,(const void **)&rhost);
  pam_get_item(pamh,PAM_RUSER,(const void **)&ruser);
  /* do the nslcd request */
  rc=nslcd_request_sess(ctx,action,service,tty,rhost,ruser);
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

  rc=pam_sm_session(pamh,flags,argc,argv,NSLCD_ACTION_PAM_SESS_O,&no_warn);
  if ((rc!=PAM_SUCCESS)&&(rc!=PAM_IGNORE))
    if (!no_warn)
      pam_error(pamh,"LDAP open_session failed");
  return rc;
}

int pam_sm_close_session(
  pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  int rc, no_warn=0;

  rc=pam_sm_session(pamh,flags,argc,argv,NSLCD_ACTION_PAM_SESS_C,&no_warn);
  if ((rc!=PAM_SUCCESS)&&(rc!=PAM_IGNORE))
    if (!no_warn)
      pam_error(pamh,"LDAP close_session failed");
  return rc;
}

/* do a password modification nslcd call */
static int nslcd_request_pwmod(pld_ctx *ctx,const char *username,
                               const char *service,const char *oldpasswd,
                               const char *newpasswd)
{
  PAM_REQUEST(NSLCD_ACTION_PAM_PWMOD,
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

/* prompt for LDAP administrator password */

/* ensure that the context includes and oldpassword field */
static const char *get_old_password(pam_handle_t *pamh, int flags,pld_ctx *ctx)
{
  int rc;
  const char *oldpassword;
  /* if we already have an old password we are done */
  if ((ctx->oldpassword!=NULL)&&(*ctx->oldpassword!='\0'))
    return ctx->oldpassword;
  /* try to get the old password from the PAM stack */
  rc=pam_get_item(pamh,PAM_OLDAUTHTOK,(const void **)&oldpassword);
  if ((rc==PAM_SUCCESS)&&(oldpassword!=NULL)&&(*oldpassword!='\0'))
    return oldpassword;
  /* otherwise prompt for it */
  rc=my_pam_get_authtok(pamh,flags,"(current) LDAP Password: ",NULL,
                     (const char **)&oldpassword);
  if ((rc==PAM_SUCCESS)&&(oldpassword!=NULL)&&(*oldpassword!='\0'))
  {
    /* save the password */
    pam_set_item(pamh,PAM_OLDAUTHTOK,oldpassword);
    return oldpassword;
  }
  return NULL;
}

/* Change the password of the user. This function is first called with
   PAM_PRELIM_CHECK set in the flags and then without the flag. In the first
   pass it is determined whether we can contact the LDAP server and the
   provided old password is valid. In the second pass we get the new
   password and actually modify the password. */
int pam_sm_chauthtok(pam_handle_t *pamh,int flags,int argc,const char **argv)
{
  int rc;
  const char *username,*service;
  const char *oldpassword=NULL;
  const char *newpassword=NULL;
  int first_pass=0, no_warn=0, ignore_flags=0;
  int i;
  pld_ctx *ctx=NULL;
  uid_t minimum_uid=0;
  struct passwd *pwent;
  /* parse module options */
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
    else if (strncmp(argv[i], "minimum_uid=", 12) == 0)
      minimum_uid=(uid_t)atoi(argv[i]+12);
    else
      syslog(LOG_AUTHPRIV|LOG_ERR,"unknown option: %s",argv[i]);
  }

  if (flags&PAM_SILENT)
    no_warn=1;

  /* get user name */
  rc=pam_get_user(pamh,(const char **)&username,NULL);
  if (rc!=PAM_SUCCESS)
    return rc;
  if ((username==NULL)||(username[0]=='\0'))
    return PAM_USER_UNKNOWN;
  /* check uid */
  if (minimum_uid>0)
  {
    pwent=pam_modutil_getpwnam(args->pamh,username);
    if ((pwent!=NULL)&&(pwent->pw_uid<minimum_uid))
      return ignore_flags&IGNORE_UNKNOWN?PAM_IGNORE:PAM_USER_UNKNOWN;
  }

  rc=ctx_get(pamh,username,&ctx);
  if (rc!=PAM_SUCCESS)
    return rc;

  rc=pam_get_item(pamh,PAM_SERVICE,(const void **)&service);
  if (rc!=PAM_SUCCESS)
    return rc;
  /* TODO: if we are root we may want to authenticate with the LDAP
           administrator password (this shouldn't be a problem because
           root is unlikely to be in LDAP anyway but perhaps we can check
           the requested username and only use the administrator if that
           isn't root) */
  /* prelimenary check, just see if we can connect to the LDAP server
     and authenticate with the current password */
  if (flags&PAM_PRELIM_CHECK)
  {
    /* see if the user is trying to modify another user's password */
    pwent=getpwnam(username);
    if ((pwent!=NULL)&&(pwent->pw_uid!=getuid()))
    {
      /* prompt for the admin password */
      rc=pam_get_authtok(pamh,PAM_OLDAUTHTOK,&oldpassword,"LDAP administrator password: ");
      if (rc!=PAM_SUCCESS)
        return rc;
      /* try authenticating */
      rc=nslcd_request_authc(ctx,"",service,oldpassword);
    }
    else
    {
      /* get old (current) password */
      oldpassword=get_old_password(pamh,flags,ctx);
      /* check the old password */
      rc=nslcd_request_authc(ctx,username,service,oldpassword);
    }
    if (rc==PAM_SUCCESS)
      rc=ctx->authok;
    if ((rc==PAM_AUTHINFO_UNAVAIL)&&(ignore_flags&IGNORE_UNAVAIL))
      rc=PAM_IGNORE;
    else if ((rc==PAM_USER_UNKNOWN)&&(ignore_flags&IGNORE_UNKNOWN))
      rc=PAM_IGNORE;
    /* TODO: figure out when to return PAM_TRY_AGAIN */
    /* TODO: if password is incorrect (NSLCD_PAM_AUTH_ERR) log that */
    return rc;
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
  rc=nslcd_request_pwmod(ctx,username,service,oldpassword,newpassword);
  if (rc==PAM_SUCCESS)
    rc=ctx->authz;
  else
    ctx->authzmsg=(char *)pam_strerror(pamh,rc);
  if ((rc==PAM_AUTHINFO_UNAVAIL)&&(ignore_flags&IGNORE_UNAVAIL))
    rc=PAM_IGNORE;
  else if ((rc==PAM_USER_UNKNOWN)&&(ignore_flags&IGNORE_UNKNOWN))
    rc=PAM_IGNORE;
  else if (!no_warn)
    pam_error(pamh,"%s",ctx->authzmsg);
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
