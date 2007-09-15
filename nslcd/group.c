/*
   group.c - group entry lookup routines
   This file was part of the nss_ldap library (as ldap-grp.c) which
   has been forked into the nss-ldapd library.

   Copyright (C) 1997-2006 Luke Howard
   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007 Arthur de Jong

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
#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <grp.h>
#include <errno.h>
#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif
#if defined(HAVE_THREAD_H)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include "ldap-nss.h"
#include "common.h"
#include "log.h"
#include "cfg.h"
#include "attmap.h"

/* FIXME: fix following problem:
          if the entry has multiple cn fields we may end up
          sending the wrong cn, we should return the requested
          cn instead, otherwise write an entry for each cn */

struct name_list
{
  char *name;
  struct name_list *next;
};

#ifdef HAVE_USERSEC_H
typedef struct ldap_initgroups_args
{
  char *grplist;
  size_t listlen;
  int depth;
  struct name_list *known_groups;
  int backlink;
}
ldap_initgroups_args_t;
#else
typedef struct ldap_initgroups_args
{
  gid_t group;
  long int *start;
  long int *size;
  gid_t **groups;
  long int limit;
  int depth;
  struct name_list *known_groups;
  int backlink;
}
ldap_initgroups_args_t;
#endif /* HAVE_USERSEC_H */

#define LDAP_NSS_MAXGR_DEPTH     16     /* maximum depth of group nesting for getgrent()/initgroups() */

#if LDAP_NSS_NGROUPS > 64
#define LDAP_NSS_BUFLEN_GROUP   (1024 + (LDAP_NSS_NGROUPS * (sizeof (char *) + LOGNAME_MAX)))
#else
#define LDAP_NSS_BUFLEN_GROUP   1024
#endif /* LDAP_NSS_NGROUPS > 64 */

#ifndef LOGNAME_MAX
#define LOGNAME_MAX 8
#endif /* LOGNAME_MAX */

#ifndef UID_NOBODY
#define UID_NOBODY      (-2)
#endif

#ifndef GID_NOBODY
#define GID_NOBODY     UID_NOBODY
#endif

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
const char *group_base = NULL;

/* the search scope for searches */
int group_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *group_filter = "(objectClass=posixGroup)";

/* the attributes to request with searches */
const char *attmap_group_cn            = "cn";
const char *attmap_group_userPassword  = "userPassword";
const char *attmap_group_gidNumber     = "gidNumber";
const char *attmap_group_memberUid     = "memberUid";
/*
const char *attmap_group_uniqueMember  = "uniqueMember";
const char *attmap_group_memberOf      = "memberOf";
*/

/* the attribute list to request with searches */
static const char *group_attrs[6];

/* create a search filter for searching a group entry
   by name, return -1 on errors */
static int mkfilter_group_byname(const char *name,
                                 char *buffer,size_t buflen)
{
  char buf2[1024];
  /* escape attribute */
  if(myldap_escape(name,buf2,sizeof(buf2)))
    return -1;
  /* build filter */
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%s))",
                    group_filter,
                    attmap_group_cn,buf2);
}

/* create a search filter for searching a group entry
   by gid, return -1 on errors */
static int mkfilter_group_bygid(gid_t gid,
                                char *buffer,size_t buflen)
{
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%d))",
                    group_filter,
                    attmap_group_gidNumber,gid);
}

static void group_init(void)
{
  /* set up base */
  if (group_base==NULL)
    group_base=nslcd_cfg->ldc_base;
  /* set up scope */
  if (group_scope==LDAP_SCOPE_DEFAULT)
    group_scope=nslcd_cfg->ldc_scope;
  /* set up attribute list */
  group_attrs[0]=attmap_group_cn;
  group_attrs[1]=attmap_group_userPassword;
  group_attrs[2]=attmap_group_memberUid;
  group_attrs[3]=attmap_group_gidNumber;
  group_attrs[4]=NULL;
/* group_attrs[4]=attmap_group_uniqueMember; */
}

/* macros for expanding the NSLCD_GROUP macro */
#define NSLCD_STRING(field)     WRITE_STRING(fp,field)
#define NSLCD_TYPE(field,type)  WRITE_TYPE(fp,field,type)
#define NSLCD_STRINGLIST(field) WRITE_STRINGLIST_NULLTERM(fp,field)
#define GROUP_NAME              result->gr_name
#define GROUP_PASSWD            result->gr_passwd
#define GROUP_GID               result->gr_gid
#define GROUP_MEMBERS           result->gr_mem

static int write_group(TFILE *fp,struct group *result)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  NSLCD_GROUP;
  return 0;
}

static enum nss_status _nss_ldap_parse_gr(
        MYLDAP_SESSION *session,LDAPMessage *e,struct ldap_state UNUSED(*state),
        void *result,char *buffer,size_t buflen)
{
  struct group *gr=(struct group *)result;
  char *gid;
  enum nss_status stat;
  /* get group gid (gidNumber) */
  stat=_nss_ldap_assign_attrval(session,e,attmap_group_gidNumber,&gid,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;
  gr->gr_gid=(*gid=='\0')?(unsigned)GID_NOBODY:(gid_t)strtoul(gid,NULL,10);
  /* get group name (cn) */
  stat=_nss_ldap_getrdnvalue(session,e,attmap_group_cn,&gr->gr_name,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;
  /* get group passwd (userPassword) */
  stat=_nss_ldap_assign_userpassword(session,e,attmap_group_userPassword,&gr->gr_passwd,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;
  /* get group memebers (memberUid) */
  stat=_nss_ldap_assign_attrvals(session,e,attmap_group_memberUid,NULL,
                                 &gr->gr_mem,&buffer,&buflen,NULL);
  return stat;
}

int nslcd_group_byname(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  char name[256];
  char filter[1024];
  /* these are here for now until we rewrite the LDAP code */
  struct group result;
  char buffer[1024];
  int retv;
  /* read request parameters */
  READ_STRING_BUF2(fp,name,sizeof(name));
  /* log call */
  log_log(LOG_DEBUG,"nslcd_group_byname(%s)",name);
  /* static buffer size check */
  if (1024<LDAP_NSS_BUFLEN_GROUP)
  {
    log_log(LOG_CRIT,"allocated buffer in nslcd_group_byname() too small");
    exit(EXIT_FAILURE);
  }
  /* do the LDAP request */
  mkfilter_group_byname(name,filter,sizeof(filter));
  group_init();
  retv=_nss_ldap_getbyname(session,&result,buffer,1024,
                           group_base,group_scope,filter,group_attrs,
                           _nss_ldap_parse_gr);
  /* write the response */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_GROUP_BYNAME);
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
    if (write_group(fp,&result))
      return -1;
  /* we're done */
  return 0;
}

int nslcd_group_bygid(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  gid_t gid;
  char filter[1024];
  /* these are here for now until we rewrite the LDAP code */
  struct group result;
  char buffer[1024];
  int retv;
  /* read request parameters */
  READ_TYPE(fp,gid,gid_t);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_group_bygid(%d)",(int)gid);
  /* static buffer size check */
  if (1024<LDAP_NSS_BUFLEN_GROUP)
  {
    log_log(LOG_CRIT,"allocated buffer in nslcd_group_byname() too small");
    exit(EXIT_FAILURE);
  }
  /* do the LDAP request */
  mkfilter_group_bygid(gid,filter,sizeof(filter));
  group_init();
  retv=_nss_ldap_getbyname(session,&result,buffer,1024,
                           group_base,group_scope,filter,
                           group_attrs,_nss_ldap_parse_gr);
  /* write the response */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_GROUP_BYGID);
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
    if (write_group(fp,&result))
      return -1;
  /* we're done */
  return 0;
}

int nslcd_group_bymember(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  char name[256];
  /* these are here for now until we rewrite the LDAP code */
  int retv;
  long int start=0,size=1024;
  long int i;
  gid_t groupsp[1024];
  /* read request parameters */
  READ_STRING_BUF2(fp,name,sizeof(name));
  /* log call */
  log_log(LOG_DEBUG,"nslcd_group_bymember(%s)",name);
  /* do the LDAP request */
  retv=NSLCD_RESULT_NOTFOUND;
  /*
  retv=group_bymember(name,&start,&size,size);
  */
  /* Note: we write some garbadge here to ensure protocol error as this
           function currently returns incorrect data */
  /* Note: what to do with group ids that are not listed as supplemental
           groups but are the user's primary group id? */
  WRITE_INT32(fp,1234);
  start=0;
  /* TODO: fix this to actually work */
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_GROUP_BYNAME);
  if (retv==NSLCD_RESULT_SUCCESS)
  {
    /* loop over the returned gids */
    for (i=0;i<start;i++)
    {
      WRITE_INT32(fp,NSLCD_RESULT_SUCCESS);
      /* Note: we will write a fake record here for now. This is because
               we want to keep the protocol but currently the only
               client application available discards non-gid information */
      WRITE_STRING(fp,""); /* group name */
      WRITE_STRING(fp,"*"); /* group passwd */
      WRITE_TYPE(fp,groupsp[i],gid_t); /* gid */
      WRITE_INT32(fp,1); /* number of members */
      WRITE_STRING(fp,name); /* member=user requested */
    }
    WRITE_INT32(fp,NSLCD_RESULT_NOTFOUND);
  }
  else
  {
    /* some error occurred */
    WRITE_INT32(fp,retv);
  }
  /* we're done */
  return 0;
}

int nslcd_group_all(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  struct ent_context context;
  /* these are here for now until we rewrite the LDAP code */
  struct group result;
  char buffer[1024];
  int retv;
  /* log call */
  log_log(LOG_DEBUG,"nslcd_group_all()");
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_GROUP_ALL);
  /* initialize context */
  _nss_ldap_ent_context_init(&context,session);
  /* loop over all results */
  group_init();
  while ((retv=_nss_ldap_getent(&context,&result,buffer,sizeof(buffer),
                                group_base,group_scope,group_filter,group_attrs,
                                _nss_ldap_parse_gr))==NSLCD_RESULT_SUCCESS)
  {
    /* write the result */
    WRITE_INT32(fp,retv);
    if (write_group(fp,&result))
      return -1;
  }
  /* write the final result code */
  WRITE_INT32(fp,retv);
  /* FIXME: if a previous call returns what happens to the context? */
  _nss_ldap_ent_context_cleanup(&context);
  /* we're done */
  return 0;
}
