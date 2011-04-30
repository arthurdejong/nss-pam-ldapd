/*
   pam.c - pam processing routines

   Copyright (C) 2009 Howard Chu
   Copyright (C) 2009, 2010, 2011 Arthur de Jong

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
#include <time.h>

#include "common.h"
#include "log.h"
#include "myldap.h"
#include "cfg.h"
#include "attmap.h"
#include "common/dict.h"
#include "common/expr.h"

/* set up a connection and try to bind with the specified DN and password,
   returns an LDAP result code */
static int try_bind(const char *userdn,const char *password)
{
  MYLDAP_SESSION *session;
  MYLDAP_SEARCH *search;
  MYLDAP_ENTRY *entry;
  static const char *attrs[2];
  int rc;
  /* set up a new connection */
  session=myldap_create_session();
  if (session==NULL)
    return LDAP_UNAVAILABLE;
  /* set up credentials for the session */
  myldap_set_credentials(session,userdn,password);
  /* perform search for own object (just to do any kind of search) */
  attrs[0]="dn";
  attrs[1]=NULL;
  search=myldap_search(session,userdn,LDAP_SCOPE_BASE,"(objectClass=*)",attrs,&rc);
  if ((search==NULL)||(rc!=LDAP_SUCCESS))
  {
    if (rc==LDAP_SUCCESS)
      rc=LDAP_LOCAL_ERROR;
    log_log(LOG_WARNING,"lookup of %s failed: %s",userdn,ldap_err2string(rc));
  }
  else
  {
    entry=myldap_get_entry(search,&rc);
    if ((entry==NULL)||(rc!=LDAP_SUCCESS))
    {
      if (rc==LDAP_SUCCESS)
        rc=LDAP_NO_RESULTS_RETURNED;
      log_log(LOG_WARNING,"lookup of %s failed: %s",userdn,ldap_err2string(rc));
    }
  }
  /* close the session */
  myldap_session_close(session);
  /* return results */
  return rc;
}

/* ensure that both userdn and username are filled in from the entry,
   returns an LDAP result code */
static MYLDAP_ENTRY *validate_user(MYLDAP_SESSION *session,
                         char *username,int *rcp)
{
  int rc;
  MYLDAP_ENTRY *entry=NULL;
  /* check username for validity */
  if (!isvalidname(username))
  {
    log_log(LOG_WARNING,"\"%s\": name denied by validnames option",username);
    *rcp=LDAP_NO_SUCH_OBJECT;
    return NULL;
  }
  /* get the user entry based on the username */
  entry=uid2entry(session,username,&rc);
  if (entry==NULL)
  {
    if (rc==LDAP_SUCCESS)
      rc=LDAP_NO_SUCH_OBJECT;
    log_log(LOG_WARNING,"\"%s\": user not found: %s",username,ldap_err2string(rc));
    *rcp=rc;
  }
  return entry;
}

/* update the username value from the entry if needed */
static void update_username(MYLDAP_ENTRY *entry,char *username,size_t username_len)
{
  const char **values;
  const char *value;
  /* get the "real" username */
  value=myldap_get_rdn_value(entry,attmap_passwd_uid);
  if (value==NULL)
  {
    /* get the username from the uid attribute */
    values=myldap_get_values(entry,attmap_passwd_uid);
    if ((values==NULL)||(values[0]==NULL))
      log_log(LOG_WARNING,"\"%s\": DN %s is missing a %s attribute",
                          username,myldap_get_dn(entry),attmap_passwd_uid);
    value=values[0];
  }
  /* check the username */
  if ((value==NULL)||!isvalidname(value)||strlen(value)>=username_len)
  {
    log_log(LOG_WARNING,"passwd entry %s name denied by validnames option: \"%s\"",
                        myldap_get_dn(entry),username);
    return;
  }
  /* check if the username is different and update it if needed */
  if (strcmp(username,value)!=0)
  {
    log_log(LOG_INFO,"username changed from \"%s\" to \"%s\"",username,value);
    strcpy(username,value);
  }
}

static int check_shadow(MYLDAP_SESSION *session,const char *username,
                        char *authzmsg,size_t authzmsgsz,
                        int check_maxdays,int check_mindays)
{
  MYLDAP_ENTRY *entry=NULL;
  long today,lastchangedate,mindays,maxdays,warndays,inactdays,expiredate;
  unsigned long flag;
  long daysleft,inactleft;
  /* get the shadow entry */
  entry=shadow_uid2entry(session,username,NULL);
  if (entry==NULL)
    return NSLCD_PAM_SUCCESS; /* no shadow entry found, nothing to check */
  /* get today's date */
  today=(long)(time(NULL)/(60*60*24));
  /* get shadown information */
  get_shadow_properties(entry,&lastchangedate,&mindays,&maxdays,&warndays,
                        &inactdays,&expiredate,&flag);
  /* check account expiry date */
  if ((expiredate!=-1)&&(today>=expiredate))
  {
    daysleft=today-expiredate;
    mysnprintf(authzmsg,authzmsgsz-1,"account expired %ld days ago",daysleft);
    log_log(LOG_WARNING,"%s: %s",myldap_get_dn(entry),authzmsg);
    return NSLCD_PAM_ACCT_EXPIRED;
  }
  /* password expiration isn't interesting at this point because the user
     may not have authenticated with a password and if he did that would be
     checked in the authc phase */
  if (check_maxdays)
  {
    /* check lastchanged */
    if (lastchangedate==0)
    {
      mysnprintf(authzmsg,authzmsgsz-1,"need a new password");
      log_log(LOG_WARNING,"%s: %s",myldap_get_dn(entry),authzmsg);
      return NSLCD_PAM_NEW_AUTHTOK_REQD;
    }
    else if (today<lastchangedate)
      log_log(LOG_WARNING,"%s: password changed in the future",myldap_get_dn(entry));
    else if (maxdays!=-1)
    {
      /* check maxdays */
      daysleft=lastchangedate+maxdays-today;
      if (daysleft==0)
        mysnprintf(authzmsg,authzmsgsz-1,"password will expire today");
      else if (daysleft<0)
        mysnprintf(authzmsg,authzmsgsz-1,"password expired %ld days ago",-daysleft);
      /* check inactdays */
      if ((daysleft<=0)&&(inactdays!=-1))
      {
        inactleft=lastchangedate+maxdays+inactdays-today;
        if (inactleft==0)
          mysnprintf(authzmsg+strlen(authzmsg),authzmsgsz-strlen(authzmsg)-1,
                     ", account will expire today");
        else if (inactleft>0)
          mysnprintf(authzmsg+strlen(authzmsg),authzmsgsz-strlen(authzmsg)-1,
                     ", account will expire in %ld days",inactleft);
        else
        {
          mysnprintf(authzmsg+strlen(authzmsg),authzmsgsz-strlen(authzmsg)-1,
                     ", account expired %ld days ago",-inactleft);
          log_log(LOG_WARNING,"%s: %s",myldap_get_dn(entry),authzmsg);
          return NSLCD_PAM_AUTHTOK_EXPIRED;
        }
      }
      if (daysleft<=0)
      {
        /* log previously built message */
        log_log(LOG_WARNING,"%s: %s",myldap_get_dn(entry),authzmsg);
        return NSLCD_PAM_NEW_AUTHTOK_REQD;
      }
      /* check warndays */
      if ((warndays>0)&&(daysleft<=warndays))
      {
        mysnprintf(authzmsg,authzmsgsz-1,"password will expire in %ld days",daysleft);
        log_log(LOG_WARNING,"%s: %s",myldap_get_dn(entry),authzmsg);
      }
    }
  }
  if (check_mindays)
  {
    daysleft=lastchangedate+mindays-today;
    if ((mindays!=-1)&&(daysleft>0))
    {
      mysnprintf(authzmsg,authzmsgsz-1,"password cannot be changed for another %ld days",daysleft);
      log_log(LOG_WARNING,"%s: %s",myldap_get_dn(entry),authzmsg);
      return NSLCD_PAM_AUTHTOK_ERR;
    }
  }
  return NSLCD_PAM_SUCCESS;
}

/* check authentication credentials of the user */
int nslcd_pam_authc(TFILE *fp,MYLDAP_SESSION *session,uid_t calleruid)
{
  int32_t tmpint32;
  int rc;
  char username[256];
  char servicename[64];
  char password[64];
  const char *userdn;
  MYLDAP_ENTRY *entry;
  int authzrc=NSLCD_PAM_SUCCESS;
  char authzmsg[1024];
  authzmsg[0]='\0';
  /* read request parameters */
  READ_STRING(fp,username);
  SKIP_STRING(fp);
  READ_STRING(fp,servicename);
  READ_STRING(fp,password);
  /* log call */
  log_setrequest("authc=\"%s\"",username);
  log_log(LOG_DEBUG,"nslcd_pam_authc(\"%s\",\"%s\",\"%s\")",
                    username,servicename,*password?"***":"");
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PAM_AUTHC);
  /* if the username is blank and rootpwmoddn is configured, try to
     authenticate as administrator, otherwise validate request as usual */
  if ((*username=='\0')&&(nslcd_cfg->ldc_rootpwmoddn!=NULL))
  {
    userdn=nslcd_cfg->ldc_rootpwmoddn;
    /* if the caller is root we will allow the use of the rootpwmodpw option */
    if ((*password=='\0')&&(calleruid==0)&&(nslcd_cfg->ldc_rootpwmodpw!=NULL))
    {
      if (strlen(nslcd_cfg->ldc_rootpwmodpw)>=sizeof(password))
      {
        log_log(LOG_ERR,"nslcd_pam_authc(): rootpwmodpw will not fit in password");
        return -1;
      }
      strcpy(password,nslcd_cfg->ldc_rootpwmodpw);
    }
  }
  else
  {
    /* try normal authentication, lookup the user entry */
    entry=validate_user(session,username,&rc);
    if (entry==NULL)
    {
      /* for user not found we just say no result */
      if (rc==LDAP_NO_SUCH_OBJECT)
      {
        WRITE_INT32(fp,NSLCD_RESULT_END);
      }
      return -1;
    }
    userdn=myldap_get_dn(entry);
    update_username(entry,username,sizeof(username));
  }
  /* try authentication */
  rc=try_bind(userdn,password);
  if (rc==LDAP_SUCCESS)
    log_log(LOG_DEBUG,"bind successful");
  /* map result code */
  switch (rc)
  {
    case LDAP_SUCCESS:             rc=NSLCD_PAM_SUCCESS;  break;
    case LDAP_INVALID_CREDENTIALS: rc=NSLCD_PAM_AUTH_ERR; break;
    default:                       rc=NSLCD_PAM_AUTH_ERR;
  }
  /* perform shadow attribute checks */
  if (*username!='\0')
    authzrc=check_shadow(session,username,authzmsg,sizeof(authzmsg),0,0);
  /* write response */
  WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
  WRITE_STRING(fp,username);
  WRITE_STRING(fp,userdn);
  WRITE_INT32(fp,rc);
  WRITE_INT32(fp,authzrc);
  WRITE_STRING(fp,authzmsg);
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

/* perform an authorisation search, returns an LDAP status code */
static int try_autzsearch(MYLDAP_SESSION *session,const char *dn,
                          const char *username,const char *servicename,
                          const char *ruser,const char *rhost,const char *tty)
{
  char hostname[HOST_NAME_MAX+1];
  const char *fqdn;
  DICT *dict;
  char filter_buffer[1024];
  MYLDAP_SEARCH *search;
  MYLDAP_ENTRY *entry;
  static const char *attrs[2];
  int rc;
  const char *res;
  /* check whether the search filter is configured at all */
  if (!nslcd_cfg->ldc_pam_authz_search)
    return LDAP_SUCCESS;
  /* build the dictionary with variables */
  dict=dict_new();
  autzsearch_var_add(dict,"username",username);
  autzsearch_var_add(dict,"service",servicename);
  autzsearch_var_add(dict,"ruser",ruser);
  autzsearch_var_add(dict,"rhost",rhost);
  autzsearch_var_add(dict,"tty",tty);
  if (gethostname(hostname,sizeof(hostname))==0)
    autzsearch_var_add(dict,"hostname",hostname);
  if ((fqdn=getfqdn())!=NULL)
    autzsearch_var_add(dict,"fqdn",fqdn);
  autzsearch_var_add(dict,"dn",dn);
  autzsearch_var_add(dict,"uid",username);
  /* build the search filter */
  res=expr_parse(nslcd_cfg->ldc_pam_authz_search,
                 filter_buffer,sizeof(filter_buffer),
                 autzsearch_var_get,(void *)dict);
  autzsearch_vars_free(dict);
  dict_free(dict);
  if (res==NULL)
  {
    log_log(LOG_ERR,"pam_authz_search \"%s\" is invalid",nslcd_cfg->ldc_pam_authz_search);
    return LDAP_LOCAL_ERROR;
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
    return rc;
  }
  /* try to get an entry */
  entry=myldap_get_entry(search,&rc);
  if (entry==NULL)
  {
    log_log(LOG_ERR,"pam_authz_search \"%s\" found no matches",filter_buffer);
    if (rc==LDAP_SUCCESS)
      rc=LDAP_NO_SUCH_OBJECT;
    return rc;
  }
  log_log(LOG_DEBUG,"pam_authz_search found \"%s\"",myldap_get_dn(entry));
  /* we've found an entry so it's OK */
  return LDAP_SUCCESS;
}

/* check authorisation of the user */
int nslcd_pam_authz(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  int rc;
  char username[256];
  char servicename[64];
  char ruser[256],rhost[HOST_NAME_MAX+1],tty[64];
  MYLDAP_ENTRY *entry;
  char authzmsg[1024];
  authzmsg[0]='\0';
  /* read request parameters */
  READ_STRING(fp,username);
  SKIP_STRING(fp);
  READ_STRING(fp,servicename);
  READ_STRING(fp,ruser);
  READ_STRING(fp,rhost);
  READ_STRING(fp,tty);
  /* log call */
  log_setrequest("authz=\"%s\"",username);
  log_log(LOG_DEBUG,"nslcd_pam_authz(\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")",
            username,servicename,ruser,rhost,tty);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PAM_AUTHZ);
  /* validate request */
  entry=validate_user(session,username,&rc);
  if (entry==NULL)
  {
    /* for user not found we just say no result */
    if (rc==LDAP_NO_SUCH_OBJECT)
    {
      WRITE_INT32(fp,NSLCD_RESULT_END);
    }
    return -1;
  }
  /* check authorisation search */
  rc=try_autzsearch(session,myldap_get_dn(entry),username,servicename,ruser,rhost,tty);
  if (rc!=LDAP_SUCCESS)
  {
    WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
    WRITE_STRING(fp,username);
    WRITE_STRING(fp,"");
    WRITE_INT32(fp,NSLCD_PAM_PERM_DENIED);
    WRITE_STRING(fp,"LDAP authorisation check failed");
    WRITE_INT32(fp,NSLCD_RESULT_END);
    return 0;
  }
  /* perform shadow attribute checks */
  rc=check_shadow(session,username,authzmsg,sizeof(authzmsg),1,0);
  /* write response */
  WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
  WRITE_STRING(fp,username);
  WRITE_STRING(fp,myldap_get_dn(entry));
  WRITE_INT32(fp,rc);
  WRITE_STRING(fp,authzmsg);
  WRITE_INT32(fp,NSLCD_RESULT_END);
  return 0;
}

int nslcd_pam_sess_o(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  char username[256];
  char servicename[64];
  char tty[64],rhost[HOST_NAME_MAX+1],ruser[256];
  int32_t sessionid;
  /* read request parameters */
  READ_STRING(fp,username);
  SKIP_STRING(fp);
  READ_STRING(fp,servicename);
  READ_STRING(fp,tty);
  READ_STRING(fp,rhost);
  READ_STRING(fp,ruser);
  READ_INT32(fp,sessionid);
  /* log call */
  log_setrequest("sess_o=\"%s\"",username);
  log_log(LOG_DEBUG,"nslcd_pam_sess_o(\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")",
                    username,servicename,tty,rhost,ruser);
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
  char servicename[64];
  char tty[64],rhost[HOST_NAME_MAX+1],ruser[256];
  int32_t sessionid;
  /* read request parameters */
  READ_STRING(fp,username);
  SKIP_STRING(fp);
  READ_STRING(fp,servicename);
  READ_STRING(fp,tty);
  READ_STRING(fp,rhost);
  READ_STRING(fp,ruser);
  READ_INT32(fp,sessionid);
  /* log call */
  log_setrequest("sess_c=\"%s\"",username);
  log_log(LOG_DEBUG,"nslcd_pam_sess_c(\"%s\",\"%s\",%d)",
                    username,servicename,(int)sessionid);
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
  char buffer[256];
  int rc;
  /* set up a new connection */
  session=myldap_create_session();
  if (session==NULL)
    return LDAP_UNAVAILABLE;
  /* set up credentials for the session */
  myldap_set_credentials(session,binddn,oldpassword);
  /* perform search for own object (just to do any kind of search) */
  if ((lookup_dn2uid(session,userdn,&rc,buffer,sizeof(buffer))!=NULL)&&(rc==LDAP_SUCCESS))
  {
    /* if doing password modification as admin, don't pass old password along */
    if ((nslcd_cfg->ldc_rootpwmoddn!=NULL)&&(strcmp(binddn,nslcd_cfg->ldc_rootpwmoddn)==0))
      oldpassword=NULL;
    /* perform password modification */
    rc=myldap_passwd(session,userdn,oldpassword,newpassword);
    if (rc==LDAP_SUCCESS)
    {
      /* try to update the shadowLastChange attribute */
      (void)update_lastchange(session,userdn);
    }
  }
  /* close the session */
  myldap_session_close(session);
  /* return */
  return rc;
}

int nslcd_pam_pwmod(TFILE *fp,MYLDAP_SESSION *session,uid_t calleruid)
{
  int32_t tmpint32;
  int rc;
  char username[256];
  char userdn[256];
  int asroot;
  char servicename[64];
  char oldpassword[64];
  char newpassword[64];
  const char *binddn=NULL; /* the user performing the modification */
  MYLDAP_ENTRY *entry;
  char authzmsg[1024];
  authzmsg[0]='\0';
  /* read request parameters */
  READ_STRING(fp,username);
  READ_STRING(fp,userdn); /* we can't ignore userdn for now here because we
                             need it to determine the modify-as-root case */
  asroot=(nslcd_cfg->ldc_rootpwmoddn!=NULL)&&(strcmp(userdn,nslcd_cfg->ldc_rootpwmoddn)==0);
  READ_STRING(fp,servicename);
  READ_STRING(fp,oldpassword);
  READ_STRING(fp,newpassword);
  /* log call */
  log_setrequest("pwmod=\"%s\"",username);
  log_log(LOG_DEBUG,"nslcd_pam_pwmod(\"%s\",%s,\"%s\",\"%s\",\"%s\")",
                    username,asroot?"asroot":"asuser",servicename,*oldpassword?"***":"",
                    *newpassword?"***":"");
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PAM_PWMOD);
  /* validate request */
  entry=validate_user(session,username,&rc);
  if (entry==NULL)
  {
    /* for user not found we just say no result */
    if (rc==LDAP_NO_SUCH_OBJECT)
    {
      WRITE_INT32(fp,NSLCD_RESULT_END);
    }
    return -1;
  }
  /* check if the the user passed the rootpwmoddn */
  if (asroot)
  {
    binddn=nslcd_cfg->ldc_rootpwmoddn;
    /* check if rootpwmodpw should be used */
    if ((*oldpassword=='\0')&&(calleruid==0)&&(nslcd_cfg->ldc_rootpwmodpw!=NULL))
    {
      if (strlen(nslcd_cfg->ldc_rootpwmodpw)>=sizeof(oldpassword))
      {
        log_log(LOG_ERR,"nslcd_pam_pwmod(): rootpwmodpw will not fit in oldpassword");
        return -1;
      }
      strcpy(oldpassword,nslcd_cfg->ldc_rootpwmodpw);
    }
  }
  else
  {
    binddn=myldap_get_dn(entry);
    /* check whether shadow properties allow password change */
    rc=check_shadow(session,username,authzmsg,sizeof(authzmsg),0,1);
    if (rc!=NSLCD_PAM_SUCCESS)
    {
      WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
      WRITE_STRING(fp,username);
      WRITE_STRING(fp,"");
      WRITE_INT32(fp,rc);
      WRITE_STRING(fp,authzmsg);
      WRITE_INT32(fp,NSLCD_RESULT_END);
      return 0;
    }
  }
  /* perform password modification */
  rc=try_pwmod(binddn,myldap_get_dn(entry),oldpassword,newpassword);
  if (rc!=LDAP_SUCCESS)
  {
    mysnprintf(authzmsg,sizeof(authzmsg)-1,"password change failed: %s",ldap_err2string(rc));
    WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
    WRITE_STRING(fp,username);
    WRITE_STRING(fp,"");
    WRITE_INT32(fp,NSLCD_PAM_PERM_DENIED);
    WRITE_STRING(fp,authzmsg);
    WRITE_INT32(fp,NSLCD_RESULT_END);
  }
  /* write response */
  WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
  WRITE_STRING(fp,username);
  WRITE_STRING(fp,myldap_get_dn(entry));
  WRITE_INT32(fp,NSLCD_PAM_SUCCESS);
  WRITE_STRING(fp,"");
  WRITE_INT32(fp,NSLCD_RESULT_END);
  return 0;
}
