/*
   pam.c - pam processing routines

   Copyright (C) 2009 Howard Chu
   Copyright (C) 2009, 2010, 2012 Arthur de Jong

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
#include <unistd.h>

#include "common.h"
#include "log.h"
#include "myldap.h"
#include "cfg.h"
#include "attmap.h"
#include "common/dict.h"
#include "common/expr.h"

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif /* not HOST_NAME_MAX */

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
  myldap_set_credentials(session,userdn,password);
  /* perform search for own object (just to do any kind of search) */
  username=lookup_dn2uid(session,userdn,&rc);
  if (username!=NULL)
    free(username);
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
      {
        log_log(LOG_WARNING,"\"%s\": DN %s is missing a %s attribute",
                            username,userdn,attmap_passwd_uid);
        return -1;
      }
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
  /* if the username is blank and rootpwmoddn is configured, try to
     authenticate as administrator, otherwise validate request as usual */
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
  if (rc==NSLCD_PAM_SUCCESS)
    log_log(LOG_DEBUG,"bind successful");
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

static void autzsearch_var_add(DICT *dict,const char *name,const char *value)
{
  size_t sz;
  char *escaped_value;
  /* allocate memory for escaped string */
  sz=((strlen(value)+8)*120)/100;
  escaped_value=(char *)malloc(sz);
  if (escaped_value==NULL)
  {
    log_log(LOG_CRIT,"autzsearch_var_add(): malloc() failed to allocate memory");
    return;
  }
  /* perform escaping of the value */
  if(myldap_escape(value,escaped_value,sz))
  {
    log_log(LOG_CRIT,"autzsearch_var_add(): myldap_escape() failed to fit in buffer");
    return;
  }
  /* add to dict */
  dict_put(dict,name,escaped_value);
}

static void autzsearch_vars_free(DICT *dict)
{
  int i;
  const char **keys;
  void *value;
  /* go over all keys and free all the values
     (they were allocated in autzsearch_var_add) */
  /* loop over dictionary contents */
  keys=dict_keys(dict);
  for (i=0;keys[i]!=NULL;i++)
  {
    value=dict_get(dict,keys[i]);
    if (value)
      free(value);
  }
  free(keys);
  /* after this values from the dict should obviously no longer be used */
}

static const char *autzsearch_var_get(const char *name,void *expander_attr)
{
  DICT *dict=(DICT *)expander_attr;
  return (const char *)dict_get(dict,name);
  /* TODO: if not set use entry to get attribute name (entry can be an
           element in the dict) */
}

static int try_autzsearch(MYLDAP_SESSION *session,DICT *dict,const char *searchfilter)
{
  char filter_buffer[4096];
  MYLDAP_SEARCH *search;
  MYLDAP_ENTRY *entry;
  static const char *attrs[2];
  int rc;
  /* build the search filter */
  if (expr_parse(searchfilter,filter_buffer,sizeof(filter_buffer),
                 autzsearch_var_get,(void *)dict)==NULL)
  {
    log_log(LOG_ERR,"invalid pam_authz_search \"%s\"",searchfilter);
    return -1;
  }
  log_log(LOG_DEBUG,"trying pam_authz_search \"%s\"",filter_buffer);
  /* perform the search */
  attrs[0]="dn";
  attrs[1]=NULL;
  /* FIXME: this only searches the first base */
  search=myldap_search(session,nslcd_cfg->ldc_bases[0],LDAP_SCOPE_SUBTREE,
                       filter_buffer,attrs,&rc);
  if (search==NULL)
  {
    log_log(LOG_ERR,"pam_authz_search \"%s\" failed: %s",
            filter_buffer,ldap_err2string(rc));
    return -1;
  }
  /* try to get an entry */
  entry=myldap_get_entry(search,NULL);
  if (entry==NULL)
  {
    log_log(LOG_ERR,"pam_authz_search \"%s\" found no matches",filter_buffer);
    return -1;
  }
  log_log(LOG_DEBUG,"pam_authz_search found \"%s\"",myldap_get_dn(entry));
  /* we've found an entry so it's OK */
  return 0;
}

/* check authorisation of the user */
int nslcd_pam_authz(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  char username[256];
  char userdn[256];
  char servicename[64];
  char ruser[256];
  char rhost[256];
  char tty[256];
  char hostname[HOST_NAME_MAX+1];
  DICT *dict;
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
  if (nslcd_cfg->ldc_pam_authz_search)
  {
    /* TODO: perform any authorisation checks */
    dict=dict_new();
    autzsearch_var_add(dict,"username",username);
    autzsearch_var_add(dict,"service",servicename);
    autzsearch_var_add(dict,"ruser",ruser);
    autzsearch_var_add(dict,"rhost",rhost);
    autzsearch_var_add(dict,"tty",tty);
    if (gethostname(hostname,sizeof(hostname))==0)
      autzsearch_var_add(dict,"hostname",hostname);
    /* TODO: fqdn */
    autzsearch_var_add(dict,"dn",userdn);
    autzsearch_var_add(dict,"uid",username);
    if (try_autzsearch(session,dict,nslcd_cfg->ldc_pam_authz_search))
    {
      WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
      WRITE_STRING(fp,username);
      WRITE_STRING(fp,userdn);
      WRITE_INT32(fp,NSLCD_PAM_PERM_DENIED);  /* authz */
      WRITE_STRING(fp,"LDAP authorisation check failed"); /* authzmsg */
      WRITE_INT32(fp,NSLCD_RESULT_END);
    }
    autzsearch_vars_free(dict);
    dict_free(dict);
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

/* perform an LDAP password modification, returns an LDAP status code */
static int try_pwmod(const char *binddn,const char *userdn,
                     const char *oldpassword,const char *newpassword)
{
  MYLDAP_SESSION *session;
  char *username;
  int rc;
  /* set up a new connection */
  session=myldap_create_session();
  if (session==NULL)
    return LDAP_UNAVAILABLE;
  /* set up credentials for the session */
  myldap_set_credentials(session,binddn,oldpassword);
  /* perform search for own object (just to do any kind of search) */
  username=lookup_dn2uid(session,userdn,&rc);
  if (username!=NULL)
    free(username);
  /* perform actual password modification */
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
