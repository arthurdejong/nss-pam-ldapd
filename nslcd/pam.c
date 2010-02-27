/*
   pam.c - pam processing routines

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif /* HAVE_STDINT_H */

#include "common.h"
#include "log.h"
#include "myldap.h"
#include "cfg.h"
#include "attmap.h"

/* set up a connection and try to bind with the specified DN and password
   returns a NSLCD_PAM_* error code */
static int try_bind(const char *userdn,const char *password)
{
  MYLDAP_SESSION *session;
  char *username;
  int rc;
  /* set up a new connection */
  session=myldap_create_session();
  if (session==NULL)
    return NSLCD_PAM_AUTH_ERR;
  /* set up credentials for the session */
  rc=myldap_set_credentials(session,userdn,password);
  /* TODO: test rc */
  if (rc==LDAP_SUCCESS)
  {
    /* perform search for own object (just to do any kind of search) */
    username=lookup_dn2uid(session,userdn,&rc);
    if (username!=NULL)
      free(username);
  }
  /* close the session */
  myldap_session_close(session);
  /* handle the results */
  switch(rc)
  {
    case LDAP_SUCCESS:             return NSLCD_PAM_SUCCESS;
    case LDAP_INVALID_CREDENTIALS: return NSLCD_PAM_AUTH_ERR;
    default:                       return NSLCD_PAM_AUTH_ERR;
  }
}

/* ensure that both userdn and username are filled in from the entry */
static int validate_user(MYLDAP_SESSION *session,char *userdn,size_t userdnsz,
                         char *username,size_t usernamesz)
{
  MYLDAP_ENTRY *entry=NULL;
  const char *value;
  const char **values;
  /* check username for validity */
  if (!isvalidname(username))
  {
    log_log(LOG_WARNING,"\"%s\": invalid user name",username);
    return -1;
  }
  /* look up user DN if not known */
  if (userdn[0]=='\0')
  {
    /* get the user entry based on the username */
    entry=uid2entry(session,username);
    if (entry==NULL)
    {
      log_log(LOG_WARNING,"\"%s\": user not found",username);
      return -1;
    }
    /* get the DN */
    myldap_cpy_dn(entry,userdn,userdnsz);
    if (strcasecmp(userdn,"unknown")==0)
    {
      log_log(LOG_WARNING,"\"%s\": user has no DN",username);
      return -1;
    }
    /* get the "real" username */
    value=myldap_get_rdn_value(entry,attmap_passwd_uid);
    if (value==NULL)
    {
      /* get the username from the uid attribute */
      values=myldap_get_values(entry,attmap_passwd_uid);
      if ((values==NULL)||(values[0]==NULL))
        log_log(LOG_WARNING,"\"%s\": DN %s is missing a %s attribute",
                            username,userdn,attmap_passwd_uid);
      value=values[0];
    }
    /* check the username */
    if ((value==NULL)||!isvalidname(value)||strlen(value)>=usernamesz)
    {
      log_log(LOG_WARNING,"\"%s\": DN %s has invalid username",username,userdn);
      return -1;
    }
    /* check if the username is different and update it if needed */
    if (strcmp(username,value)!=0)
    {
      log_log(LOG_INFO,"username changed from \"%s\" to \"%s\"",username,value);
      strcpy(username,value);
    }
  }
  /* all check passed */
  return 0;
}

/* check authentication credentials of the user */
int nslcd_pam_authc(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  int rc;
  char username[256];
  char userdn[256];
  char servicename[64];
  char password[64];
  /* read request parameters */
  READ_STRING(fp,username);
  READ_STRING(fp,userdn);
  READ_STRING(fp,servicename);
  READ_STRING(fp,password);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_pam_authc(\"%s\",\"%s\",\"%s\",\"%s\")",
                    username,userdn,servicename,*password?"***":"");
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PAM_AUTHC);
  /* if the username is blank and rootpwmoddn is configure, try to authenticate
     as administrator, otherwise validate request as usual */
  if ((*username=='\0')&&(nslcd_cfg->ldc_rootpwmoddn!=NULL))
  {
    if (strlen(nslcd_cfg->ldc_rootpwmoddn)>=sizeof(userdn))
    {
      log_log(LOG_ERR,"nslcd_pam_authc(): rootpwmoddn will not fit in userdn");
      return -1;
    }
    strcpy(userdn,nslcd_cfg->ldc_rootpwmoddn);
  }
  else if (validate_user(session,userdn,sizeof(userdn),username,sizeof(username)))
  {
    WRITE_INT32(fp,NSLCD_RESULT_END);
    return -1;
  }
  /* try authentication */
  rc=try_bind(userdn,password);
  /* write response */
  WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
  WRITE_STRING(fp,username);
  WRITE_STRING(fp,userdn);
  WRITE_INT32(fp,rc);  /* authc */
  WRITE_INT32(fp,rc);  /* authz */
  WRITE_STRING(fp,""); /* authzmsg */
  WRITE_INT32(fp,NSLCD_RESULT_END);
  return 0;
}

/* check authorisation of the user */
int nslcd_pam_authz(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  char username[256];
  char userdn[256];
  char servicename[64];
  char ruser[32];
  char rhost[256];
  char tty[256];
  /* read request parameters */
  READ_STRING(fp,username);
  READ_STRING(fp,userdn);
  READ_STRING(fp,servicename);
  READ_STRING(fp,ruser);
  READ_STRING(fp,rhost);
  READ_STRING(fp,tty);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_pam_authz(\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")",
            username,userdn,servicename,ruser,rhost,tty);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PAM_AUTHZ);
  /* validate request and fill in the blanks */
  if (validate_user(session,userdn,sizeof(userdn),username,sizeof(username)))
  {
    WRITE_INT32(fp,NSLCD_RESULT_END);
    return -1;
  }
  /* TODO: perform any authorisation checks */
  /* write response */
  WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
  WRITE_STRING(fp,username);
  WRITE_STRING(fp,userdn);
  WRITE_INT32(fp,NSLCD_PAM_SUCCESS);  /* authz */
  WRITE_STRING(fp,""); /* authzmsg */
  WRITE_INT32(fp,NSLCD_RESULT_END);
  return 0;
}

int nslcd_pam_sess_o(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  char username[256];
  char userdn[256];
  char servicename[64];
  char tty[64],rhost[64],ruser[256];
  int32_t sessionid;
  /* read request parameters */
  READ_STRING(fp,username);
  READ_STRING(fp,userdn);
  READ_STRING(fp,servicename);
  READ_STRING(fp,tty);
  READ_STRING(fp,rhost);
  READ_STRING(fp,ruser);
  READ_INT32(fp,sessionid);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_pam_sess_o(\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")",
                    username,userdn,servicename,tty,rhost,ruser);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PAM_SESS_O);
  /* write response */
  WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
  WRITE_INT32(fp,12345);  /* session id */
  WRITE_INT32(fp,NSLCD_RESULT_END);
  return 0;
}

int nslcd_pam_sess_c(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  char username[256];
  char userdn[256];
  char servicename[64];
  char tty[64],rhost[64],ruser[256];
  int32_t sessionid;
  /* read request parameters */
  READ_STRING(fp,username);
  READ_STRING(fp,userdn);
  READ_STRING(fp,servicename);
  READ_STRING(fp,tty);
  READ_STRING(fp,rhost);
  READ_STRING(fp,ruser);
  READ_INT32(fp,sessionid);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_pam_sess_c(\"%s\",\"%s\",\"%s\",%d)",
                    username,userdn,servicename,(int)sessionid);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PAM_SESS_C);
  /* write response */
  WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
  WRITE_INT32(fp,0);  /* session id */
  WRITE_INT32(fp,NSLCD_RESULT_END);
  return 0;
}

static int try_pwmod(const char *binddn,const char *userdn,
                     const char *oldpassword,const char *newpassword)
{
  MYLDAP_SESSION *session;
  int rc;
  /* set up a new connection */
  session=myldap_create_session();
  if (session==NULL)
    return NSLCD_PAM_AUTH_ERR;
  /* set up credentials for the session */
  rc=myldap_set_credentials(session,binddn,oldpassword);
  if (rc==LDAP_SUCCESS)
  {
    /* if doing password modification as admin, don't pass old password along */
    if ((nslcd_cfg->ldc_rootpwmoddn!=NULL)&&(strcmp(binddn,nslcd_cfg->ldc_rootpwmoddn)==0))
      oldpassword=NULL;
    /* perform password modification */
    rc=myldap_passwd(session,userdn,oldpassword,newpassword);
  }
  /* close the session */
  myldap_session_close(session);
  /* return */
  return rc;
}

int nslcd_pam_pwmod(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  char username[256];
  char userdn[256];
  char servicename[64];
  char oldpassword[64];
  char newpassword[64];
  char *binddn=userdn; /* the user performing the modification */
  int rc;
  /* read request parameters */
  READ_STRING(fp,username);
  READ_STRING(fp,userdn);
  READ_STRING(fp,servicename);
  READ_STRING(fp,oldpassword);
  READ_STRING(fp,newpassword);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_pam_pwmod(\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")",
                    username,userdn,servicename,*oldpassword?"***":"",
                    *newpassword?"***":"");
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PAM_PWMOD);
  /* check if the the user passed the rootpwmoddn */
  if ((nslcd_cfg->ldc_rootpwmoddn!=NULL)&&(strcmp(userdn,nslcd_cfg->ldc_rootpwmoddn)==0))
  {
    binddn=nslcd_cfg->ldc_rootpwmoddn;
    userdn[0]='\0'; /* cause validate_user() to get the user DN */
  }
  /* validate request and fill in the blanks */
  if (validate_user(session,userdn,sizeof(userdn),username,sizeof(username)))
  {
    WRITE_INT32(fp,NSLCD_RESULT_END);
    return -1;
  }
  /* perform password modification */
  rc=try_pwmod(binddn,userdn,oldpassword,newpassword);
  /* write response */
  WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
  WRITE_STRING(fp,username);
  WRITE_STRING(fp,userdn);
  if (rc==LDAP_SUCCESS)
  {
    WRITE_INT32(fp,NSLCD_PAM_SUCCESS);
    WRITE_STRING(fp,"");
  }
  else
  {
    WRITE_INT32(fp,NSLCD_PAM_PERM_DENIED);
    WRITE_STRING(fp,ldap_err2string(rc));
  }
  WRITE_INT32(fp,NSLCD_RESULT_END);
  return 0;
}
