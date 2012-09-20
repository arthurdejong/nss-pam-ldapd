/*
   group.c - group entry lookup routines
   Parts of this file were part of the nss_ldap library (as ldap-grp.c) which
   has been forked into the nss-pam-ldapd library.

   Copyright (C) 1997-2006 Luke Howard
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
#include <string.h>
/* for gid_t */
#include <grp.h>

#include "common/set.h"
#include "common.h"
#include "log.h"
#include "myldap.h"
#include "cfg.h"
#include "attmap.h"

/* ( nisSchema.2.2 NAME 'posixGroup' SUP top STRUCTURAL
 *   DESC 'Abstraction of a group of accounts'
 *   MUST ( cn $ gidNumber )
 *   MAY ( userPassword $ memberUid $ description ) )
 *
 * apart from that the above the uniqueMember attributes may be
 * supported in a coming release (they map to DNs, which is an extra
 * lookup step)
 *
 * using nested groups (groups that are member of a group) is currently
 * not supported, this may be added in a later release
 */

/* the search base for searches */
const char *group_bases[NSS_LDAP_CONFIG_MAX_BASES] = { NULL };

/* the search scope for searches */
int group_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *group_filter = "(objectClass=posixGroup)";

/* the attributes to request with searches */
const char *attmap_group_cn            = "cn";
const char *attmap_group_userPassword  = "userPassword";
const char *attmap_group_gidNumber     = "gidNumber";
const char *attmap_group_memberUid     = "memberUid";
const char *attmap_group_uniqueMember  = "uniqueMember";

/* default values for attributes */
static const char *default_group_userPassword     = "*"; /* unmatchable */


/* the attribute list to request with searches */
static const char *group_attrs[6];

/* create a search filter for searching a group entry
   by name, return -1 on errors */
static int mkfilter_group_byname(const char *name,
                                 char *buffer,size_t buflen)
{
  char safename[300];
  /* escape attribute */
  if(myldap_escape(name,safename,sizeof(safename)))
    return -1;
  /* build filter */
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%s))",
                    group_filter,
                    attmap_group_cn,safename);
}

/* create a search filter for searching a group entry
   by gid, return -1 on errors */
static int mkfilter_group_bygid(gid_t gid,
                                char *buffer,size_t buflen)
{
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%d))",
                    group_filter,
                    attmap_group_gidNumber,(int)gid);
}

/* create a search filter for searching a group entry
   by member uid, return -1 on errors */
static int mkfilter_group_bymember(MYLDAP_SESSION *session,
                                   const char *uid,
                                   char *buffer,size_t buflen)
{
  char dn[256];
  char safeuid[300];
  char safedn[300];
  /* escape attribute */
  if(myldap_escape(uid,safeuid,sizeof(safeuid)))
    return -1;
  /* try to translate uid to DN */
  if (uid2dn(session,uid,dn,sizeof(dn))==NULL)
    return mysnprintf(buffer,buflen,
                      "(&%s(%s=%s))",
                      group_filter,
                      attmap_group_memberUid,safeuid);
  /* escape DN */
  if(myldap_escape(dn,safedn,sizeof(safedn)))
    return -1;
  /* also lookup using user DN */
  return mysnprintf(buffer,buflen,
                    "(&%s(|(%s=%s)(%s=%s)))",
                    group_filter,
                    attmap_group_memberUid,safeuid,
                    attmap_group_uniqueMember,safedn);
}

void group_init(void)
{
  int i;
  /* set up search bases */
  if (group_bases[0]==NULL)
    for (i=0;i<NSS_LDAP_CONFIG_MAX_BASES;i++)
      group_bases[i]=nslcd_cfg->ldc_bases[i];
  /* set up scope */
  if (group_scope==LDAP_SCOPE_DEFAULT)
    group_scope=nslcd_cfg->ldc_scope;
  /* set up attribute list */
  group_attrs[0]=attmap_group_cn;
  group_attrs[1]=attmap_group_userPassword;
  group_attrs[2]=attmap_group_memberUid;
  group_attrs[3]=attmap_group_gidNumber;
  group_attrs[4]=attmap_group_uniqueMember;
  group_attrs[5]=NULL;
}

static int do_write_group(
    TFILE *fp,MYLDAP_ENTRY *entry,const char **names,gid_t gids[],int numgids,
    const char *passwd,const char **members,const char *reqname)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  int i,j;
  /* write entries for all names and gids */
  for (i=0;names[i]!=NULL;i++)
  {
    if (!isvalidname(names[i]))
    {
      log_log(LOG_WARNING,"group entry %s contains invalid group name: \"%s\"",
                          myldap_get_dn(entry),names[i]);
    }
    else if ((reqname==NULL)||(strcmp(reqname,names[i])==0))
    {
      for (j=0;j<numgids;j++)
      {
        WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
        WRITE_STRING(fp,names[i]);
        WRITE_STRING(fp,passwd);
        WRITE_TYPE(fp,gids[j],gid_t);
        WRITE_STRINGLIST(fp,members);
      }
    }
  }
  return 0;
}

/* return the list of members */
static const char **getmembers(MYLDAP_ENTRY *entry,MYLDAP_SESSION *session)
{
  char buf[256];
  int i;
  const char **values;
  SET *set;
  set=set_new();
  if (set==NULL)
    return NULL;
  /* add the memberUid values */
  values=myldap_get_values(entry,attmap_group_memberUid);
  if (values!=NULL)
    for (i=0;values[i]!=NULL;i++)
    {
      /* only add valid usernames */
      if (isvalidname(values[i]))
        set_add(set,values[i]);
    }
  /* add the uniqueMember values */
  values=myldap_get_values(entry,attmap_group_uniqueMember);
  if (values!=NULL)
    for (i=0;values[i]!=NULL;i++)
    {
      /* transform the DN into a uid (dn2uid() already checks validity) */
      if (dn2uid(session,values[i],buf,sizeof(buf))!=NULL)
        set_add(set,buf);
    }
  /* return the members */
  values=set_tolist(set);
  set_free(set);
  return values;
}

/* the maximum number of gidNumber attributes per entry */
#define MAXGIDS_PER_ENTRY 5

static int write_group(TFILE *fp,MYLDAP_ENTRY *entry,const char *reqname,
                       const gid_t *reqgid,int wantmembers,
                       MYLDAP_SESSION *session)
{
  const char **names,**gidvalues;
  const char *passwd;
  const char **members;
  gid_t gids[MAXGIDS_PER_ENTRY];
  int numgids;
  char *tmp;
  int rc;
  /* get group name (cn) */
  names=myldap_get_values(entry,attmap_group_cn);
  if ((names==NULL)||(names[0]==NULL))
  {
    log_log(LOG_WARNING,"group entry %s does not contain %s value",
                        myldap_get_dn(entry),attmap_group_cn);
    return 0;
  }
  /* get the group id(s) */
  if (reqgid!=NULL)
  {
    gids[0]=*reqgid;
    numgids=1;
  }
  else
  {
    gidvalues=myldap_get_values(entry,attmap_group_gidNumber);
    if ((gidvalues==NULL)||(gidvalues[0]==NULL))
    {
      log_log(LOG_WARNING,"group entry %s does not contain %s value",
                          myldap_get_dn(entry),attmap_group_gidNumber);
      return 0;
    }
    for (numgids=0;(gidvalues[numgids]!=NULL)&&(numgids<MAXGIDS_PER_ENTRY);numgids++)
    {
      errno=0;
      gids[numgids]=strtogid(gidvalues[numgids],&tmp,0);
      if ((*(gidvalues[numgids])=='\0')||(*tmp!='\0'))
      {
        log_log(LOG_WARNING,"group entry %s contains non-numeric %s value",
                            myldap_get_dn(entry),attmap_group_gidNumber);
        return 0;
      }
      else if (errno!=0)
      {
        log_log(LOG_WARNING,"group entry %s contains too large %s value",
                            myldap_get_dn(entry),attmap_group_gidNumber);
        return 0;
      }
    }
  }
  /* get group passwd (userPassword) (use only first entry) */
  passwd=get_userpassword(entry,attmap_group_userPassword);
  if (passwd==NULL)
    passwd=default_group_userPassword;
  /* get group memebers (memberUid&uniqueMember) */
  if (wantmembers)
    members=getmembers(entry,session);
  else
    members=NULL;
  /* write entries (split to a separate function so we can ensure the call
     to free() below in case a write fails) */
  rc=do_write_group(fp,entry,names,gids,numgids,passwd,members,reqname);
  /* free and return */
  if (members!=NULL)
    free(members);
  return rc;
}

NSLCD_HANDLE(
  group,byname,
  char name[256];
  char filter[1024];
  READ_STRING(fp,name);
  if (!isvalidname(name)) {
    log_log(LOG_WARNING,"nslcd_group_byname(%s): invalid group name",name);
    return -1;
  },
  log_log(LOG_DEBUG,"nslcd_group_byname(%s)",name);,
  NSLCD_ACTION_GROUP_BYNAME,
  mkfilter_group_byname(name,filter,sizeof(filter)),
  write_group(fp,entry,name,NULL,1,session)
)

NSLCD_HANDLE(
  group,bygid,
  gid_t gid;
  char filter[1024];
  READ_TYPE(fp,gid,gid_t);,
  log_log(LOG_DEBUG,"nslcd_group_bygid(%d)",(int)gid);,
  NSLCD_ACTION_GROUP_BYGID,
  mkfilter_group_bygid(gid,filter,sizeof(filter)),
  write_group(fp,entry,NULL,&gid,1,session)
)

NSLCD_HANDLE(
  group,bymember,
  char name[256];
  char filter[1024];
  READ_STRING(fp,name);
  if (!isvalidname(name)) {
    log_log(LOG_WARNING,"nslcd_group_bymember(%s): invalid user name",name);
    return -1;
  }
  if ((nslcd_cfg->ldc_nss_initgroups_ignoreusers!=NULL)&&
      set_contains(nslcd_cfg->ldc_nss_initgroups_ignoreusers,name))
  {
    /* just end the request, returning no results */
    WRITE_INT32(fp,NSLCD_VERSION);
    WRITE_INT32(fp,NSLCD_ACTION_GROUP_BYMEMBER);
    WRITE_INT32(fp,NSLCD_RESULT_END);
    return 0;
  },
  log_log(LOG_DEBUG,"nslcd_group_bymember(%s)",name);,
  NSLCD_ACTION_GROUP_BYMEMBER,
  mkfilter_group_bymember(session,name,filter,sizeof(filter)),
  write_group(fp,entry,NULL,NULL,0,session)
)

NSLCD_HANDLE(
  group,all,
  const char *filter;
  /* no parameters to read */,
  log_log(LOG_DEBUG,"nslcd_group_all()");,
  NSLCD_ACTION_GROUP_ALL,
  (filter=group_filter,0),
  write_group(fp,entry,NULL,NULL,1,session)
)
