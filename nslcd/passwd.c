/*
   passwd.c - password entry lookup routines
   This file was part of the nss_ldap library (as ldap-pwd.c)
   which has been forked into the nss-ldapd library.

   Copyright (C) 1997-2005 Luke Howard
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
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include <pwd.h>
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
#include <stdio.h>

#include "ldap-nss.h"
#include "common.h"
#include "log.h"
#include "attmap.h"

#ifndef UID_NOBODY
#define UID_NOBODY      (uid_t)(-2)
#endif

#ifndef GID_NOBODY
#define GID_NOBODY     (gid_t)UID_NOBODY
#endif

/* the search base for searches */
const char *passwd_base = NULL;

/* the search scope for searches */
int passwd_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *passwd_filter = "(objectClass=posixAccount)";

/* the attributes used in searches
 * ( nisSchema.2.0 NAME 'posixAccount' SUP top AUXILIARY
 *   DESC 'Abstraction of an account with POSIX attributes'
 *   MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory )
 *   MAY ( userPassword $ loginShell $ gecos $ description ) )
 */
const char *attmap_passwd_uid           = "uid";
const char *attmap_passwd_userPassword  = "userPassword";
const char *attmap_passwd_uidNumber     = "uidNumber";
const char *attmap_passwd_gidNumber     = "gidNumber";
const char *attmap_passwd_gecos         = "gecos";
const char *attmap_passwd_cn            = "cn";
const char *attmap_passwd_homeDirectory = "homeDirectory";
const char *attmap_passwd_loginShell    = "loginShell";

/* the attribute list to request with searches */
static const char *passwd_attrs[10];

/* create a search filter for searching a passwd entry
   by name, return -1 on errors */
static int mkfilter_passwd_byname(const char *name,
                                  char *buffer,size_t buflen)
{
  char buf2[1024];
  /* escape attribute */
  if(myldap_escape(name,buf2,sizeof(buf2)))
    return -1;
  /* build filter */
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%s))",
                    passwd_filter,
                    attmap_passwd_uid,buf2);
}

/* create a search filter for searching a passwd entry
   by uid, return -1 on errors */
static int mkfilter_passwd_byuid(uid_t uid,
                                 char *buffer,size_t buflen)
{
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%d))",
                    passwd_filter,
                    attmap_passwd_uidNumber,uid);
}

static void passwd_init(void)
{
  /* set up base */
  if (passwd_base==NULL)
    passwd_base=nslcd_cfg->ldc_base;
  /* set up scope */
  if (passwd_scope==LDAP_SCOPE_DEFAULT)
    passwd_scope=nslcd_cfg->ldc_scope;
  /* set up attribute list */
  passwd_attrs[0]=attmap_passwd_uid;
  passwd_attrs[1]=attmap_passwd_userPassword;
  passwd_attrs[2]=attmap_passwd_uidNumber;
  passwd_attrs[3]=attmap_passwd_gidNumber;
  passwd_attrs[4]=attmap_passwd_cn;
  passwd_attrs[5]=attmap_passwd_homeDirectory;
  passwd_attrs[6]=attmap_passwd_loginShell;
  passwd_attrs[7]=attmap_passwd_gecos;
  passwd_attrs[8]="objectClass";
  passwd_attrs[9]=NULL;
}

static inline enum nss_status _nss_ldap_assign_emptystring(
               char **valptr, char **buffer, size_t * buflen)
{
  if (*buflen < 2)
    return NSS_STATUS_TRYAGAIN;

  *valptr = *buffer;

  **valptr = '\0';

  (*buffer)++;
  (*buflen)--;

  return NSS_STATUS_SUCCESS;
}

static enum nss_status _nss_ldap_parse_pw(
        MYLDAP_ENTRY *entry,
        struct passwd *pw,char *buffer,size_t buflen)
{
  /* FIXME: fix following problem:
            if the entry has multiple uid fields we may end up
            sending the wrong uid, we should return the requested
            uid instead, otherwise write an entry for each uid
            (maybe also for uidNumber) */
  char *uid, *gid;
  enum nss_status stat;
  char tmpbuf[ sizeof( uid_t ) * 8 / 3 + 2 ];
  size_t tmplen;
  char *tmp;

  tmpbuf[ sizeof(tmpbuf) - 1 ] = '\0';

  if (myldap_has_objectclass(entry,"shadowAccount"))
    {
      /* don't include password for shadowAccount */
      if (buflen < 3)
        return NSS_STATUS_TRYAGAIN;

      pw->pw_passwd = buffer;
      strcpy (buffer, "x");
      buffer += 2;
      buflen -= 2;
    }
  else
    {
      stat=_nss_ldap_assign_userpassword(entry,attmap_passwd_userPassword,&pw->pw_passwd,&buffer,&buflen);
      if (stat != NSS_STATUS_SUCCESS)
        return stat;
    }

  stat=_nss_ldap_assign_attrval(entry,attmap_passwd_uid,&pw->pw_name,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  tmp = tmpbuf;
  tmplen = sizeof (tmpbuf) - 1;
  stat=_nss_ldap_assign_attrval(entry,attmap_passwd_uidNumber,&uid,&tmp,&tmplen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;
  pw->pw_uid = (*uid == '\0') ? UID_NOBODY : (uid_t) atol (uid);

  tmp = tmpbuf;
  tmplen = sizeof (tmpbuf) - 1;
  stat=_nss_ldap_assign_attrval(entry,attmap_passwd_gidNumber,&gid,&tmp,&tmplen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;
  pw->pw_gid = (*gid == '\0') ? GID_NOBODY : (gid_t) atol (gid);

  stat=_nss_ldap_assign_attrval(entry,attmap_passwd_gecos,&pw->pw_gecos,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    {
      pw->pw_gecos = NULL;
      stat=_nss_ldap_assign_attrval(entry,attmap_passwd_cn,&pw->pw_gecos,&buffer,&buflen);
      if (stat != NSS_STATUS_SUCCESS)
        return stat;
    }

  stat=_nss_ldap_assign_attrval(entry,attmap_passwd_homeDirectory,&pw->pw_dir,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    (void) _nss_ldap_assign_emptystring (&pw->pw_dir, &buffer, &buflen);

  stat=_nss_ldap_assign_attrval(entry,attmap_passwd_loginShell,&pw->pw_shell,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    (void) _nss_ldap_assign_emptystring (&pw->pw_shell, &buffer, &buflen);

  return NSS_STATUS_SUCCESS;
}

/* macros for expanding the NSLCD_PASSWD macro */
#define NSLCD_STRING(field)    WRITE_STRING(fp,field)
#define NSLCD_TYPE(field,type) WRITE_TYPE(fp,field,type)
#define PASSWD_NAME            result.pw_name
#define PASSWD_PASSWD          result.pw_passwd
#define PASSWD_UID             result.pw_uid
#define PASSWD_GID             result.pw_gid
#define PASSWD_GECOS           result.pw_gecos
#define PASSWD_DIR             result.pw_dir
#define PASSWD_SHELL           result.pw_shell

static int write_passwd(TFILE *fp,MYLDAP_ENTRY *entry)
{
  int32_t tmpint32;
  struct passwd result;
  char buffer[1024];
  if (_nss_ldap_parse_pw(entry,&result,buffer,sizeof(buffer))!=NSS_STATUS_SUCCESS)
    return 0;
  /* write the result code */
  WRITE_INT32(fp,NSLCD_RESULT_SUCCESS);
  /* write the entry */
  NSLCD_PASSWD;
  return 0;
}

NSLCD_HANDLE(
  passwd,byname,
  char name[256];
  char filter[1024];
  READ_STRING_BUF2(fp,name,sizeof(name));,
  log_log(LOG_DEBUG,"nslcd_passwd_byname(%s)",name);,
  NSLCD_ACTION_PASSWD_BYNAME,
  mkfilter_passwd_byname(name,filter,sizeof(filter)),
  write_passwd(fp,entry)
)

NSLCD_HANDLE(
  passwd,byuid,
  uid_t uid;
  char filter[1024];
  READ_TYPE(fp,uid,uid_t);,
  log_log(LOG_DEBUG,"nslcd_passwd_byuid(%d)",(int)uid);,
  NSLCD_ACTION_PASSWD_BYUID,
  mkfilter_passwd_byuid(uid,filter,sizeof(filter)),
  write_passwd(fp,entry)
)

NSLCD_HANDLE(
  passwd,all,
  const char *filter;
  /* no parameters to read */,
  log_log(LOG_DEBUG,"nslcd_passwd_all()");,
  NSLCD_ACTION_PASSWD_ALL,
  (filter=passwd_filter,0),
  write_passwd(fp,entry)
)
