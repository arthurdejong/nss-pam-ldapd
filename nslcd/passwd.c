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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include "common.h"
#include "log.h"
#include "myldap.h"
#include "cfg.h"
#include "attmap.h"
#include "common/dict.h"
#include "compat/strndup.h"

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
const char *attmap_passwd_userPassword  = "\"*\"";
const char *attmap_passwd_uidNumber     = "uidNumber";
const char *attmap_passwd_gidNumber     = "gidNumber";
const char *attmap_passwd_gecos         = "\"${gecos:-$cn}\"";
const char *attmap_passwd_homeDirectory = "homeDirectory";
const char *attmap_passwd_loginShell    = "loginShell";

/* special properties for objectSid-based searches
   (these are already LDAP-escaped strings) */
static char *uidSid=NULL;
static char *gidSid=NULL;

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
  if (uidSid!=NULL)
  {
    return mysnprintf(buffer,buflen,
                      "(&%s(%s=%s\\%02x\\%02x\\%02x\\%02x))",
                      passwd_filter,
                      attmap_passwd_uidNumber,uidSid,
                      (int)(uid&0xff),(int)((uid>>8)&0xff),
                      (int)((uid>>16)&0xff),(int)((uid>>24)&0xff));
  }
  else
  {
    return mysnprintf(buffer,buflen,
                      "(&%s(%s=%d))",
                      passwd_filter,
                      attmap_passwd_uidNumber,(int)uid);
  }
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
  /* special case when uidNumber or gidNumber reference objectSid */
  if (strncasecmp(attmap_passwd_uidNumber,"objectSid:",10)==0)
  {
    uidSid=sid2search(attmap_passwd_uidNumber+10);
    attmap_passwd_uidNumber=strndup(attmap_passwd_uidNumber,9);
  }
  if (strncasecmp(attmap_passwd_gidNumber,"objectSid:",10)==0)
  {
    gidSid=sid2search(attmap_passwd_gidNumber+10);
    attmap_passwd_gidNumber=strndup(attmap_passwd_gidNumber,9);
  }
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

/* checks whether the entry has a valid uidNumber attribute
   (>= nss_min_uid) */
static int entry_has_valid_uid(MYLDAP_ENTRY *entry)
{
  int i;
  const char **values;
  char *tmp;
  uid_t uid;
  /* if min_uid is not set any entry should do */
  if (nslcd_cfg->ldc_nss_min_uid==0)
    return 1;
  /* get all uidNumber attributes */
  values=myldap_get_values_len(entry,attmap_passwd_uidNumber);
  if ((values==NULL)||(values[0]==NULL))
  {
    log_log(LOG_WARNING,"passwd entry %s does not contain %s value",
                        myldap_get_dn(entry),attmap_passwd_uidNumber);
    return 0;
  }
  /* check if there is a uidNumber attributes >= min_uid */
  for (i=0;values[i]!=NULL;i++)
  {
    if (uidSid!=NULL)
      uid=(uid_t)binsid2id(values[i]);
    else
    {
      uid=(uid_t)strtol(values[i],&tmp,0);
      if ((*(values[i])=='\0')||(*tmp!='\0'))
      {
        log_log(LOG_WARNING,"passwd entry %s contains non-numeric %s value",
                            myldap_get_dn(entry),attmap_passwd_uidNumber);
        continue;
      }
    }
    if (uid>=nslcd_cfg->ldc_nss_min_uid)
      return 1;
  }
  /* nothing found */
  return 0;
}

/* Perform an LDAP lookup to translate the DN into a uid.
   This function either returns NULL or a strdup()ed string. */
char *lookup_dn2uid(MYLDAP_SESSION *session,const char *dn,int *rcp,char *buf,size_t buflen)
{
  MYLDAP_SEARCH *search;
  MYLDAP_ENTRY *entry;
  static const char *attrs[3];
  int rc=LDAP_SUCCESS;
  const char **values;
  char *uid=NULL;
  if (rcp==NULL)
    rcp=&rc;
  /* we have to look up the entry */
  attrs[0]=attmap_passwd_uid;
  attrs[1]=attmap_passwd_uidNumber;
  attrs[2]=NULL;
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
  /* check the uidNumber attribute if min_uid is set */
  if (entry_has_valid_uid(entry))
  {
    /* get uid (just use first one) */
    values=myldap_get_values(entry,attmap_passwd_uid);
    /* check the result for presence and validity */
    if ((values!=NULL)&&(values[0]!=NULL)&&isvalidname(values[0])&&(strlen(values[0])<buflen))
    {
      strcpy(buf,values[0]);
      uid=buf;
    }
  }
  /* clean up and return */
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
  uid=lookup_dn2uid(session,dn,NULL,buf,buflen);
  /* store the result in the cache */
  pthread_mutex_lock(&dn2uid_cache_mutex);
  /* try to get the entry from the cache here again because it could have
     changed in the meantime */
  cacheentry=dict_get(dn2uid_cache,dn);
  if (cacheentry==NULL)
  {
    /* allocate a new entry in the cache */
    cacheentry=(struct dn2uid_cache_entry *)malloc(sizeof(struct dn2uid_cache_entry));
    if (cacheentry!=NULL)
    {
      cacheentry->uid=NULL;
      dict_put(dn2uid_cache,dn,cacheentry);
    }
  }
  /* update the cache entry */
  if (cacheentry!=NULL)
  {
    cacheentry->timestamp=time(NULL);
    /* copy the uid if needed */
    if (cacheentry->uid==NULL)
      cacheentry->uid=uid!=NULL?strdup(uid):NULL;
    else if (strcmp(cacheentry->uid,uid)!=0)
    {
      free(cacheentry->uid);
      cacheentry->uid=uid!=NULL?strdup(uid):NULL;
    }
  }
  pthread_mutex_unlock(&dn2uid_cache_mutex);
  /* copy the result into the buffer */
  return uid;
}

MYLDAP_ENTRY *uid2entry(MYLDAP_SESSION *session,const char *uid,int *rcp)
{
  MYLDAP_SEARCH *search=NULL;
  MYLDAP_ENTRY *entry=NULL;
  const char *base;
  int i;
  static const char *attrs[3];
  char filter[1024];
  /* if it isn't a valid username, just bail out now */
  if (!isvalidname(uid))
  {
    if (rcp!=NULL)
      *rcp=LDAP_INVALID_SYNTAX;
    return NULL;
  }
  /* set up attributes (we don't need much) */
  attrs[0]=attmap_passwd_uid;
  attrs[1]=attmap_passwd_uidNumber;
  attrs[2]=NULL;
  /* we have to look up the entry */
  mkfilter_passwd_byname(uid,filter,sizeof(filter));
  for (i=0;(i<NSS_LDAP_CONFIG_MAX_BASES)&&((base=passwd_bases[i])!=NULL);i++)
  {
    search=myldap_search(session,base,passwd_scope,filter,attrs,rcp);
    if (search==NULL)
    {
      if ((rcp!=NULL)&&(*rcp==LDAP_SUCCESS))
        *rcp=LDAP_NO_SUCH_OBJECT;
      return NULL;
    }
    entry=myldap_get_entry(search,rcp);
    if ((entry!=NULL)&&(entry_has_valid_uid(entry)))
      return entry;
  }
  if ((rcp!=NULL)&&(*rcp==LDAP_SUCCESS))
    *rcp=LDAP_NO_SUCH_OBJECT;
  return NULL;
}

char *uid2dn(MYLDAP_SESSION *session,const char *uid,char *buf,size_t buflen)
{
  MYLDAP_ENTRY *entry;
  /* look up the entry */
  entry=uid2entry(session,uid,NULL);
  if (entry==NULL)
    return NULL;
  /* get DN */
  return myldap_cpy_dn(entry,buf,buflen);
}

/* the cached value of whether shadow lookups use LDAP in nsswitch.conf */
#define NSSWITCH_FILE "/etc/nsswitch.conf"
#define CACHED_UNKNOWN 22
static int cached_shadow_uses_ldap=CACHED_UNKNOWN;
static time_t cached_shadow_lastcheck=0;
#define CACHED_SHADOW_TIMEOUT (60)
static time_t nsswitch_mtime=0;

/* check whether /etc/nsswitch.conf should be related to update
   cached_shadow_uses_ldap */
static inline void check_nsswitch_reload(void)
{
  struct stat buf;
  time_t t;
  if ((cached_shadow_uses_ldap!=CACHED_UNKNOWN)&&
      ((t=time(NULL)) > (cached_shadow_lastcheck+CACHED_SHADOW_TIMEOUT)))
  {
    cached_shadow_lastcheck=t;
    if (stat(NSSWITCH_FILE,&buf))
    {
      log_log(LOG_ERR,"stat(%s) failed: %s",NSSWITCH_FILE,strerror(errno));
      /* trigger a recheck anyway */
      cached_shadow_uses_ldap=CACHED_UNKNOWN;
      return;
    }
    /* trigger a recheck if file changed */
    if (buf.st_mtime!=nsswitch_mtime)
    {
      nsswitch_mtime=buf.st_mtime;
      cached_shadow_uses_ldap=CACHED_UNKNOWN;
    }
  }
}

/* check whether shadow lookups are configured to use ldap */
static inline int shadow_uses_ldap(void)
{
  if (cached_shadow_uses_ldap==CACHED_UNKNOWN)
    cached_shadow_uses_ldap=nsswitch_db_uses_ldap(NSSWITCH_FILE,"shadow");
  return cached_shadow_uses_ldap;
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
  char gecos[100];
  char homedir[100];
  char shell[100];
  char passbuffer[64];
  int i,j;
  /* get the usernames for this entry */
  usernames=myldap_get_values(entry,attmap_passwd_uid);
  if ((usernames==NULL)||(usernames[0]==NULL))
  {
    log_log(LOG_WARNING,"passwd entry %s does not contain %s value",
                        myldap_get_dn(entry),attmap_passwd_uid);
    return 0;
  }
  /* if we are using shadow maps and this entry looks like it would return
     shadow information, make the passwd entry indicate it */
  if (myldap_has_objectclass(entry,"shadowAccount")&&shadow_uses_ldap())
  {
    passwd="x";
  }
  else
  {
    passwd=get_userpassword(entry,attmap_passwd_userPassword,passbuffer,sizeof(passbuffer));
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
    tmpvalues=myldap_get_values_len(entry,attmap_passwd_uidNumber);
    if ((tmpvalues==NULL)||(tmpvalues[0]==NULL))
    {
      log_log(LOG_WARNING,"passwd entry %s does not contain %s value",
                          myldap_get_dn(entry),attmap_passwd_uidNumber);
      return 0;
    }
    for (numuids=0;(numuids<MAXUIDS_PER_ENTRY)&&(tmpvalues[numuids]!=NULL);numuids++)
    {
      if (uidSid!=NULL)
        uids[numuids]=(uid_t)binsid2id(tmpvalues[numuids]);
      else
      {
        uids[numuids]=(uid_t)strtol(tmpvalues[numuids],&tmp,0);
        if ((*(tmpvalues[numuids])=='\0')||(*tmp!='\0'))
        {
          log_log(LOG_WARNING,"passwd entry %s contains non-numeric %s value",
                              myldap_get_dn(entry),attmap_passwd_uidNumber);
          return 0;
        }
      }
    }
  }
  /* get the gid for this entry */
  if (gidSid!=NULL)
  {
    tmpvalues=myldap_get_values_len(entry,attmap_passwd_gidNumber);
    if ((tmpvalues==NULL)||(tmpvalues[0]==NULL))
    {
      log_log(LOG_WARNING,"passwd entry %s does not contain %s value",
                          myldap_get_dn(entry),attmap_passwd_gidNumber);
      return 0;
    }
    gid=(gid_t)binsid2id(tmpvalues[0]);
  }
  else
  {
    attmap_get_value(entry,attmap_passwd_gidNumber,gidbuf,sizeof(gidbuf));
    if (gidbuf[0]=='\0')
    {
      log_log(LOG_WARNING,"passwd entry %s does not contain %s value",
                          myldap_get_dn(entry),attmap_passwd_gidNumber);
      return 0;
    }
    gid=(gid_t)strtol(gidbuf,&tmp,0);
    if ((gidbuf[0]=='\0')||(*tmp!='\0'))
    {
      log_log(LOG_WARNING,"passwd entry %s contains non-numeric %s value",
                          myldap_get_dn(entry),attmap_passwd_gidNumber);
      return 0;
    }
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
        log_log(LOG_WARNING,"passwd entry %s denied by validnames option: \"%s\"",
                            myldap_get_dn(entry),usernames[i]);
      }
      else
      {
        for (j=0;j<numuids;j++)
        {
          if (uids[j]>=nslcd_cfg->ldc_nss_min_uid)
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
    }
  return 0;
}

NSLCD_HANDLE_UID(
  passwd,byname,
  char name[256];
  char filter[1024];
  READ_STRING(fp,name);
  log_setrequest("passwd=\"%s\"",name);
  if (!isvalidname(name)) {
    log_log(LOG_WARNING,"\"%s\": name denied by validnames option",name);
    return -1;
  }
  check_nsswitch_reload();,
  NSLCD_ACTION_PASSWD_BYNAME,
  mkfilter_passwd_byname(name,filter,sizeof(filter)),
  write_passwd(fp,entry,name,NULL,calleruid)
)

NSLCD_HANDLE_UID(
  passwd,byuid,
  uid_t uid;
  char filter[1024];
  READ_TYPE(fp,uid,uid_t);
  log_setrequest("passwd=%d",(int)uid);
  if (uid<nslcd_cfg->ldc_nss_min_uid)
  {
    /* return an empty result */
    WRITE_INT32(fp,NSLCD_VERSION);
    WRITE_INT32(fp,NSLCD_ACTION_PASSWD_BYUID);
    WRITE_INT32(fp,NSLCD_RESULT_END);
  }
  check_nsswitch_reload();,
  NSLCD_ACTION_PASSWD_BYUID,
  mkfilter_passwd_byuid(uid,filter,sizeof(filter)),
  write_passwd(fp,entry,NULL,&uid,calleruid)
)

NSLCD_HANDLE_UID(
  passwd,all,
  const char *filter;
  log_setrequest("passwd(all)");
  check_nsswitch_reload();,
  NSLCD_ACTION_PASSWD_ALL,
  (filter=passwd_filter,0),
  write_passwd(fp,entry,NULL,NULL,calleruid)
)
