/*
   passwd.c - password entry lookup routines
   Parts of this file were part of the nss_ldap library (as ldap-pwd.c)
   which has been forked into the nss-pam-ldapd library.

   Copyright (C) 1997-2005 Luke Howard
   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007, 2008, 2009, 2010, 2011 Arthur de Jong

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
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <pthread.h>

#include "common.h"
#include "log.h"
#include "myldap.h"
#include "cfg.h"
#include "attmap.h"
#include "common/dict.h"

/* ( nisSchema.2.0 NAME 'posixAccount' SUP top AUXILIARY
 *   DESC 'Abstraction of an account with POSIX attributes'
 *   MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory )
 *   MAY ( userPassword $ loginShell $ gecos $ description ) )
 */

/* the search base for searches */
const char *passwd_bases[NSS_LDAP_CONFIG_MAX_BASES] = { NULL };

/* the search scope for searches */
int passwd_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *passwd_filter = "(objectClass=posixAccount)";

/* the attributes used in searches */
const char *attmap_passwd_uid           = "uid";
const char *attmap_passwd_userPassword  = "userPassword";
const char *attmap_passwd_uidNumber     = "uidNumber";
const char *attmap_passwd_gidNumber     = "gidNumber";
const char *attmap_passwd_gecos         = "\"${gecos:-$cn}\"";
const char *attmap_passwd_homeDirectory = "homeDirectory";
const char *attmap_passwd_loginShell    = "loginShell";

/* default values for attributes */
static const char *default_passwd_userPassword     = "*"; /* unmatchable */

/* Note that the resulting password value should be one of:
   <empty> - no password set, allow login without password
   *       - often used to prevent logins
   x       - "valid" encrypted password that does not match any valid password
             often used to indicate that the password is defined elsewhere
   other   - encrypted password, usually in crypt(3) format */

/* the attribute list to request with searches */
static const char **passwd_attrs=NULL;

/* create a search filter for searching a passwd entry
   by name, return -1 on errors */
static int mkfilter_passwd_byname(const char *name,
                                  char *buffer,size_t buflen)
{
  char safename[300];
  /* escape attribute */
  if(myldap_escape(name,safename,sizeof(safename)))
    return -1;
  /* build filter */
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%s))",
                    passwd_filter,
                    attmap_passwd_uid,safename);
}

/* create a search filter for searching a passwd entry
   by uid, return -1 on errors */
static int mkfilter_passwd_byuid(uid_t uid,
                                 char *buffer,size_t buflen)
{
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%d))",
                    passwd_filter,
                    attmap_passwd_uidNumber,(int)uid);
}

void passwd_init(void)
{
  int i;
  SET *set;
  /* set up search bases */
  if (passwd_bases[0]==NULL)
    for (i=0;i<NSS_LDAP_CONFIG_MAX_BASES;i++)
      passwd_bases[i]=nslcd_cfg->ldc_bases[i];
  /* set up scope */
  if (passwd_scope==LDAP_SCOPE_DEFAULT)
    passwd_scope=nslcd_cfg->ldc_scope;
  /* set up attribute list */
  set=set_new();
  attmap_add_attributes(set,"objectClass"); /* for testing shadowAccount */
  attmap_add_attributes(set,attmap_passwd_uid);
  attmap_add_attributes(set,attmap_passwd_userPassword);
  attmap_add_attributes(set,attmap_passwd_uidNumber);
  attmap_add_attributes(set,attmap_passwd_gidNumber);
  attmap_add_attributes(set,attmap_passwd_gecos);
  attmap_add_attributes(set,attmap_passwd_homeDirectory);
  attmap_add_attributes(set,attmap_passwd_loginShell);
  passwd_attrs=set_tolist(set);
  set_free(set);
}

/* the cache that is used in dn2uid() */
static pthread_mutex_t dn2uid_cache_mutex=PTHREAD_MUTEX_INITIALIZER;
static DICT *dn2uid_cache=NULL;
struct dn2uid_cache_entry
{
  time_t timestamp;
  char *uid;
};
#define DN2UID_CACHE_TIMEOUT (15*60)

/* Perform an LDAP lookup to translate the DN into a uid.
   This function either returns NULL or a strdup()ed string. */
char *lookup_dn2uid(MYLDAP_SESSION *session,const char *dn,int *rcp)
{
  MYLDAP_SEARCH *search;
  MYLDAP_ENTRY *entry;
  static const char *attrs[2];
  int rc=LDAP_SUCCESS;
  const char **values;
  char *uid;
  if (rcp==NULL)
    rcp=&rc;
  /* we have to look up the entry */
  attrs[0]=attmap_passwd_uid;
  attrs[1]=NULL;
  search=myldap_search(session,dn,LDAP_SCOPE_BASE,passwd_filter,attrs,rcp);
  if (search==NULL)
  {
    log_log(LOG_WARNING,"lookup of user %s failed: %s",dn,ldap_err2string(*rcp));
    return NULL;
  }
  entry=myldap_get_entry(search,rcp);
  if (entry==NULL)
  {
    if (*rcp!=LDAP_SUCCESS)
      log_log(LOG_WARNING,"lookup of user %s failed: %s",dn,ldap_err2string(*rcp));
    return NULL;
  }
  /* get uid (just use first one) */
  values=myldap_get_values(entry,attmap_passwd_uid);
  /* check the result for presence and validity */
  if ((values!=NULL)&&(values[0]!=NULL)&&isvalidname(values[0]))
    uid=strdup(values[0]);
  else
    uid=NULL;
  myldap_search_close(search);
  return uid;
}

/* Translate the DN into a user name. This function tries several aproaches
   at getting the user name, including looking in the DN for a uid attribute,
   looking in the cache and falling back to looking up a uid attribute in a
   LDAP query. */
char *dn2uid(MYLDAP_SESSION *session,const char *dn,char *buf,size_t buflen)
{
  struct dn2uid_cache_entry *cacheentry=NULL;
  char *uid;
  /* check for empty string */
  if ((dn==NULL)||(*dn=='\0'))
    return NULL;
  /* try to look up uid within DN string */
  if (myldap_cpy_rdn_value(dn,attmap_passwd_uid,buf,buflen)!=NULL)
  {
    /* check if it is valid */
    if (!isvalidname(buf))
      return NULL;
    return buf;
  }
  /* see if we have a cached entry */
  pthread_mutex_lock(&dn2uid_cache_mutex);
  if (dn2uid_cache==NULL)
    dn2uid_cache=dict_new();
  if ((dn2uid_cache!=NULL) && ((cacheentry=dict_get(dn2uid_cache,dn))!=NULL))
  {
    /* if the cached entry is still valid, return that */
    if (time(NULL) < (cacheentry->timestamp+DN2UID_CACHE_TIMEOUT))
    {
      if ((cacheentry->uid!=NULL)&&(strlen(cacheentry->uid)<buflen))
        strcpy(buf,cacheentry->uid);
      else
        buf=NULL;
      pthread_mutex_unlock(&dn2uid_cache_mutex);
      return buf;
    }
    /* leave the entry intact, just replace the uid below */
  }
  pthread_mutex_unlock(&dn2uid_cache_mutex);
  /* look up the uid using an LDAP query */
  uid=lookup_dn2uid(session,dn,NULL);
  /* store the result in the cache */
  pthread_mutex_lock(&dn2uid_cache_mutex);
  if (cacheentry==NULL)
  {
    /* allocate a new entry in the cache */
    cacheentry=(struct dn2uid_cache_entry *)malloc(sizeof(struct dn2uid_cache_entry));
    if (cacheentry!=NULL)
      dict_put(dn2uid_cache,dn,cacheentry);
  }
  else if (cacheentry->uid!=NULL)
    free(cacheentry->uid);
  /* update the cache entry */
  if (cacheentry!=NULL)
  {
    cacheentry->timestamp=time(NULL);
    cacheentry->uid=uid;
  }
  pthread_mutex_unlock(&dn2uid_cache_mutex);
  /* copy the result into the buffer */
  if ((uid!=NULL)&&(strlen(uid)<buflen))
    strcpy(buf,uid);
  else
    buf=NULL;
  return buf;
}

MYLDAP_ENTRY *uid2entry(MYLDAP_SESSION *session,const char *uid)
{
  MYLDAP_SEARCH *search=NULL;
  MYLDAP_ENTRY *entry=NULL;
  const char *base;
  int i;
  static const char *attrs[2];
  char filter[1024];
  /* if it isn't a valid username, just bail out now */
  if (!isvalidname(uid))
    return NULL;
  /* set up attributes (we don't need much) */
  attrs[0]=attmap_passwd_uid;
  attrs[1]=NULL;
  /* we have to look up the entry */
  mkfilter_passwd_byname(uid,filter,sizeof(filter));
  for (i=0;(i<NSS_LDAP_CONFIG_MAX_BASES)&&((base=passwd_bases[i])!=NULL);i++)
  {
    search=myldap_search(session,base,passwd_scope,filter,attrs,NULL);
    if (search==NULL)
      return NULL;
    entry=myldap_get_entry(search,NULL);
    if (entry!=NULL)
      return entry;
  }
  return NULL;
}

char *uid2dn(MYLDAP_SESSION *session,const char *uid,char *buf,size_t buflen)
{
  MYLDAP_ENTRY *entry;
  /* look up the entry */
  entry=uid2entry(session,uid);
  if (entry==NULL)
    return NULL;
  /* get DN */
  return myldap_cpy_dn(entry,buf,buflen);
}

/* the maximum number of uidNumber attributes per entry */
#define MAXUIDS_PER_ENTRY 5

static int write_passwd(TFILE *fp,MYLDAP_ENTRY *entry,const char *requser,
                        const uid_t *requid,uid_t calleruid)
{
  int32_t tmpint32;
  const char **tmpvalues;
  char *tmp;
  const char **usernames;
  const char *passwd;
  uid_t uids[MAXUIDS_PER_ENTRY];
  int numuids;
  char gidbuf[32];
  gid_t gid;
  char gecos[1024];
  char homedir[256];
  char shell[100];
  int i,j;
  /* get the usernames for this entry */
  usernames=myldap_get_values(entry,attmap_passwd_uid);
  if ((usernames==NULL)||(usernames[0]==NULL))
  {
    log_log(LOG_WARNING,"passwd entry %s does not contain %s value",
                        myldap_get_dn(entry),attmap_passwd_uid);
    return 0;
  }
  /* get the password for this entry */
  if (myldap_has_objectclass(entry,"shadowAccount"))
  {
    /* if the entry has a shadowAccount entry, point to that instead */
    passwd="x";
  }
  else
  {
    passwd=get_userpassword(entry,attmap_passwd_userPassword);
    if ((passwd==NULL)||(calleruid!=0))
      passwd=default_passwd_userPassword;
  }
  /* get the uids for this entry */
  if (requid!=NULL)
  {
    uids[0]=*requid;
    numuids=1;
  }
  else
  {
    tmpvalues=myldap_get_values(entry,attmap_passwd_uidNumber);
    if ((tmpvalues==NULL)||(tmpvalues[0]==NULL))
    {
      log_log(LOG_WARNING,"passwd entry %s does not contain %s value",
                          myldap_get_dn(entry),attmap_passwd_uidNumber);
      return 0;
    }
    for (numuids=0;(numuids<MAXUIDS_PER_ENTRY)&&(tmpvalues[numuids]!=NULL);numuids++)
    {
      errno=0;
      uids[numuids]=strtouid(tmpvalues[numuids],&tmp,0);
      if ((*(tmpvalues[numuids])=='\0')||(*tmp!='\0'))
      {
        log_log(LOG_WARNING,"passwd entry %s contains non-numeric %s value",
                            myldap_get_dn(entry),attmap_passwd_uidNumber);
        return 0;
      }
      else if (errno!=0)
      {
        log_log(LOG_WARNING,"passwd entry %s contains too large %s value",
                            myldap_get_dn(entry),attmap_passwd_uidNumber);
        return 0;
      }
    }
  }
  /* get the gid for this entry */
  attmap_get_value(entry,attmap_passwd_gidNumber,gidbuf,sizeof(gidbuf));
  if (gidbuf[0]=='\0')
  {
    log_log(LOG_WARNING,"passwd entry %s does not contain %s value",
                        myldap_get_dn(entry),attmap_passwd_gidNumber);
    return 0;
  }
  errno=0;
  gid=strtogid(gidbuf,&tmp,0);
  if ((gidbuf[0]=='\0')||(*tmp!='\0'))
  {
    log_log(LOG_WARNING,"passwd entry %s contains non-numeric %s value",
                        myldap_get_dn(entry),attmap_passwd_gidNumber);
    return 0;
  }
  else if (errno!=0)
  {
    log_log(LOG_WARNING,"passwd entry %s contains too large %s value",
                        myldap_get_dn(entry),attmap_passwd_gidNumber);
    return 0;
  }
  /* get the gecos for this entry */
  attmap_get_value(entry,attmap_passwd_gecos,gecos,sizeof(gecos));
  /* get the home directory for this entry */
  attmap_get_value(entry,attmap_passwd_homeDirectory,homedir,sizeof(homedir));
  if (homedir[0]=='\0')
    log_log(LOG_WARNING,"passwd entry %s does not contain %s value",
                        myldap_get_dn(entry),attmap_passwd_homeDirectory);
  /* get the shell for this entry */
  attmap_get_value(entry,attmap_passwd_loginShell,shell,sizeof(shell));
  /* write the entries */
  for (i=0;usernames[i]!=NULL;i++)
    if ((requser==NULL)||(strcmp(requser,usernames[i])==0))
    {
      if (!isvalidname(usernames[i]))
      {
        log_log(LOG_WARNING,"passwd entry %s contains invalid user name: \"%s\"",
                            myldap_get_dn(entry),usernames[i]);
      }
      else
      {
        for (j=0;j<numuids;j++)
        {
          WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
          WRITE_STRING(fp,usernames[i]);
          WRITE_STRING(fp,passwd);
          WRITE_TYPE(fp,uids[j],uid_t);
          WRITE_TYPE(fp,gid,gid_t);
          WRITE_STRING(fp,gecos);
          WRITE_STRING(fp,homedir);
          WRITE_STRING(fp,shell);
        }
      }
    }
  return 0;
}

NSLCD_HANDLE_UID(
  passwd,byname,
  char name[256];
  char filter[1024];
  READ_STRING(fp,name);
  if (!isvalidname(name)) {
    log_log(LOG_WARNING,"nslcd_passwd_byname(%s): invalid user name",name);
    return -1;
  },
  log_log(LOG_DEBUG,"nslcd_passwd_byname(%s)",name);,
  NSLCD_ACTION_PASSWD_BYNAME,
  mkfilter_passwd_byname(name,filter,sizeof(filter)),
  write_passwd(fp,entry,name,NULL,calleruid)
)

NSLCD_HANDLE_UID(
  passwd,byuid,
  uid_t uid;
  char filter[1024];
  READ_TYPE(fp,uid,uid_t);,
  log_log(LOG_DEBUG,"nslcd_passwd_byuid(%d)",(int)uid);,
  NSLCD_ACTION_PASSWD_BYUID,
  mkfilter_passwd_byuid(uid,filter,sizeof(filter)),
  write_passwd(fp,entry,NULL,&uid,calleruid)
)

NSLCD_HANDLE_UID(
  passwd,all,
  const char *filter;
  /* no parameters to read */,
  log_log(LOG_DEBUG,"nslcd_passwd_all()");,
  NSLCD_ACTION_PASSWD_ALL,
  (filter=passwd_filter,0),
  write_passwd(fp,entry,NULL,NULL,calleruid)
)
