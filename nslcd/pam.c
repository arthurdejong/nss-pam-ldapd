/*
   pam.c - pam processing routines

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
    /* perform search for own object */
    username=lookup_dn2uid(session,userdn,&rc);
    /* TODO: return this as cannonical name */
    if (username!=NULL)
      free(username);
  }
  /* close the session */
  myldap_session_close(session);
  /* handle the results */
  switch(rc)
  {
    case LDAP_SUCCESS: return NSLCD_PAM_SUCCESS;
    case LDAP_INVALID_CREDENTIALS: return NSLCD_PAM_AUTH_ERR;
    default: return NSLCD_PAM_AUTH_ERR;
  }
}

/* Ensure that both userdn and username are set and are valid. This returns
  */
static int validate_entry(MYLDAP_ENTRY *entry,char *userdn,size_t userdnsz,
                          char *username,size_t usernamesz)
{
  const char *value;
  /* get the DN */
  myldap_cpy_dn(entry,userdn,userdnsz);
  if (strcasecmp(userdn,"unknown")==0)
  {
    log_log(LOG_WARNING,"nslcd_pam_authc(\"%s\"): user has no DN",username);
    return -1;
  }
  /* get the "real" username */
  value=myldap_get_rdn_value(entry,attmap_passwd_uid);
  if ((value==NULL)||!isvalidname(value)||strlen(value)>=usernamesz)
  {
    log_log(LOG_WARNING,"nslcd_pam_authc(\"%s\"): DN %s has invalid username",username,userdn);
    return -1;
  }
  /* compare */
  if (strcmp(username,value)!=0)
  {
    log_log(LOG_INFO,"username changed from \"%s\" to \"%s\"",username,value);
    strcpy(username,value);
  }
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
  MYLDAP_ENTRY *entry=NULL;
  /* read request parameters */
  READ_STRING(fp,username);
  READ_STRING(fp,userdn);
  READ_STRING(fp,servicename);
  READ_STRING(fp,password);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_pam_authc(\"%s\",\"%s\",\"%s\")",username,userdn,servicename);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PAM_AUTHC);
  /* validate request */
  if (!isvalidname(username))
  {
    log_log(LOG_WARNING,"nslcd_pam_authc(\"%s\"): invalid user name",username);
    WRITE_INT32(fp,NSLCD_RESULT_END);
    return -1;
  }
  if (userdn[0]=='\0')
  {
    /* get the user entry */
    entry=uid2entry(session,username);
    if (entry==NULL)
    {
      log_log(LOG_WARNING,"nslcd_pam_authc(\"%s\"): user not found",username);
      WRITE_INT32(fp,NSLCD_RESULT_END);
      return -1;
    }
    if (validate_entry(entry,userdn,sizeof(userdn),username,sizeof(username)))
    {
      WRITE_INT32(fp,NSLCD_RESULT_END);
      return -1;
    }
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
  /* read request parameters */
  READ_STRING(fp,username);
  READ_STRING(fp,userdn);
  READ_STRING(fp,servicename);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_pam_authz(\"%s\",\"%s\",\"%s\")",username,userdn,servicename);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PAM_AUTHZ);
  /* validate request */
  if (!isvalidname(username))
  {
    log_log(LOG_WARNING,"nslcd_pam_authc(\"%s\"): invalid user name",username);
    /* write a response message anyway */
    /* TODO: maybe just write NSLCD_RESULT_END to indicate failure */
    WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
    WRITE_STRING(fp,username);
    WRITE_STRING(fp,userdn);
    WRITE_INT32(fp,NSLCD_PAM_USER_UNKNOWN); /* authz */
    WRITE_STRING(fp,"invalid username");    /* authzmsg */
    WRITE_INT32(fp,NSLCD_RESULT_END);
    return -1;
  }
  if (userdn[0]=='\0')
  {
    /* perform username to DN translation */
    if (uid2dn(session,username,userdn,sizeof(userdn))==NULL)
    {
      log_log(LOG_WARNING,"nslcd_pam_authc(\"%s\"): user not found",username);
      /* return error to client */
      WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
      WRITE_STRING(fp,username);
      WRITE_STRING(fp,userdn);
      WRITE_INT32(fp,NSLCD_PAM_USER_UNKNOWN); /* authz */
      WRITE_STRING(fp,"unknown username");    /* authzmsg */
      WRITE_INT32(fp,NSLCD_RESULT_END);
      return -1;
    }
  }
  /* try dn to username lookup */
  if (dn2uid(session,userdn,username,sizeof(username))==NULL)
  {
    log_log(LOG_WARNING,"nslcd_pam_authc(\"%s\"): username not found",userdn);
    /* return error to client */
    WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
    WRITE_STRING(fp,username);
    WRITE_STRING(fp,userdn);
    WRITE_INT32(fp,NSLCD_PAM_USER_UNKNOWN); /* authz */
    WRITE_STRING(fp,"unknown username");    /* authzmsg */
    WRITE_INT32(fp,NSLCD_RESULT_END);
    return -1;
  }
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

int nslcd_pam_pwmod(TFILE *fp,MYLDAP_SESSION *session)
{
/*
  struct berval dn, uid, opw, npw;
  int32_t tmpint32;
  char dnc[1024];
  char uidc[256];
  char opwc[256];
  char npwc[256];

  READ_STRING(fp,dnc);
  dn.bv_val = dnc;
  dn.bv_len = tmpint32;
  READ_STRING(fp,uidc);
  uid.bv_val = uidc;
  uid.bv_len = tmpint32;
  READ_STRING(fp,opwc);
  opw.bv_val = opwc;
  opw.bv_len = tmpint32;
  READ_STRING(fp,npwc);
  npw.bv_val = npwc;
  npw.bv_len = tmpint32;

  Debug(LDAP_DEBUG_TRACE,"nssov_pam_pwmod(%s), %s\n",dn.bv_val,uid.bv_val,0);

  BER_BVZERO(&npw);
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PAM_PWMOD);
  WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
  WRITE_INT32(fp,PAM_SUCCESS);
  WRITE_BERVAL(fp,&npw);
*/
  return 0;
}
