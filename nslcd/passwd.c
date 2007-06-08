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
#include <stdio.h>

#include "ldap-nss.h"
#include "util.h"
#include "common.h"
#include "log.h"

#ifndef UID_NOBODY
#define UID_NOBODY      (-2)
#endif

#ifndef GID_NOBODY
#define GID_NOBODY     UID_NOBODY
#endif


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

static enum nss_status _nss_ldap_parse_pw (LDAPMessage * e,
                    struct ldap_state * pvt,
                    void *result, char *buffer, size_t buflen)
{
  /* FIXME: fix following problem:
            if the entry has multiple uid fields we may end up
            sending the wrong uid, we should return the requested
            uid instead, otherwise write an entry for each uid
            (maybe also for uidNumber) */
  struct passwd *pw = (struct passwd *) result;
  char *uid, *gid;
  enum nss_status stat;
  char tmpbuf[ sizeof( uid_t ) * 8 / 3 + 2 ];
  size_t tmplen;
  char *tmp;

  tmpbuf[ sizeof(tmpbuf) - 1 ] = '\0';

  if (has_objectclass(e,"shadowAccount"))
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
      stat =
        _nss_ldap_assign_userpassword (e, ATM (LM_PASSWD, userPassword),
                                       &pw->pw_passwd, &buffer, &buflen);
      if (stat != NSS_STATUS_SUCCESS)
        return stat;
    }

  stat =
    _nss_ldap_assign_attrval (e, ATM (LM_PASSWD, uid), &pw->pw_name, &buffer,
                              &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  tmp = tmpbuf;
  tmplen = sizeof (tmpbuf) - 1;
  stat =
    _nss_ldap_assign_attrval (e, AT (uidNumber), &uid, &tmp, &tmplen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;
  pw->pw_uid = (*uid == '\0') ? UID_NOBODY : (uid_t) atol (uid);

  tmp = tmpbuf;
  tmplen = sizeof (tmpbuf) - 1;
  stat =
    _nss_ldap_assign_attrval (e, ATM (LM_PASSWD, gidNumber), &gid, &tmp,
                              &tmplen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;
  pw->pw_gid = (*gid == '\0') ? GID_NOBODY : (gid_t) atol (gid);

  stat =
    _nss_ldap_assign_attrval (e, AT (gecos), &pw->pw_gecos, &buffer,
                              &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    {
      pw->pw_gecos = NULL;
      stat =
        _nss_ldap_assign_attrval (e, ATM (LM_PASSWD, cn), &pw->pw_gecos,
                                  &buffer, &buflen);
      if (stat != NSS_STATUS_SUCCESS)
        return stat;
    }

  stat =
    _nss_ldap_assign_attrval (e, AT (homeDirectory), &pw->pw_dir, &buffer,
                              &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    (void) _nss_ldap_assign_emptystring (&pw->pw_dir, &buffer, &buflen);

  stat =
    _nss_ldap_assign_attrval (e, AT (loginShell), &pw->pw_shell, &buffer,
                              &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    (void) _nss_ldap_assign_emptystring (&pw->pw_shell, &buffer, &buflen);

  return NSS_STATUS_SUCCESS;
}

/* macros for expanding the NSLCD_PASSWD macro */
#define NSLCD_STRING(field)    WRITE_STRING(fp,field)
#define NSLCD_TYPE(field,type) WRITE_TYPE(fp,field,type)
#define PASSWD_NAME   result.pw_name
#define PASSWD_PASSWD result.pw_passwd
#define PASSWD_UID    result.pw_uid
#define PASSWD_GID    result.pw_gid
#define PASSWD_GECOS  result.pw_gecos
#define PASSWD_DIR    result.pw_dir
#define PASSWD_SHELL  result.pw_shell

/* the caller should take care of opening and closing the stream */
int nslcd_passwd_byname(TFILE *fp)
{
  int32_t tmpint32;
  char name[256];
  /* these are here for now until we rewrite the LDAP code */
  struct passwd result;
  char buffer[1024];
  int errnop;
  int retv;
  struct ldap_args a;
  /* read request parameters */
  READ_STRING_BUF2(fp,name,sizeof(name));
  /* log call */
  log_log(LOG_DEBUG,"nslcd_passwd_byname(%s)",name);
  /* do the LDAP request */
  LA_INIT(a);
  LA_STRING(a)=name;
  LA_TYPE(a)=LA_TYPE_STRING;
  retv=nss2nslcd(_nss_ldap_getbyname(&a,&result,buffer,1024,&errnop,_nss_ldap_filt_getpwnam,LM_PASSWD,_nss_ldap_parse_pw));
  /* write the response */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PASSWD_BYNAME);
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
  {
    NSLCD_PASSWD;
  }
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_passwd_byuid(TFILE *fp)
{
  int32_t tmpint32;
  uid_t uid;
  /* these are here for now until we rewrite the LDAP code */
  struct passwd result;
  char buffer[1024];
  int errnop;
  int retv;
  struct ldap_args a;
  /* read request parameters */
  READ_TYPE(fp,uid,uid_t);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_passwd_byuid(%d)",(int)uid);
  /* do the LDAP request */
  LA_INIT(a);
  LA_NUMBER(a)=uid;
  LA_TYPE(a)=LA_TYPE_NUMBER;
  retv=nss2nslcd(_nss_ldap_getbyname(&a,&result,buffer,1024,&errnop,_nss_ldap_filt_getpwuid,LM_PASSWD,_nss_ldap_parse_pw));
  /* write the response */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PASSWD_BYUID);
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
  {
    NSLCD_PASSWD;
  }
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_passwd_all(TFILE *fp)
{
  int32_t tmpint32;
  /* these are here for now until we rewrite the LDAP code */
  struct ent_context *pw_context = NULL;
  struct passwd result;
  char buffer[1024];
  int errnop;
  int retv;
  /* log call */
  log_log(LOG_DEBUG,"nslcd_passwd_all()");
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PASSWD_ALL);
  /* initialize context */
  if (_nss_ldap_ent_context_init(&pw_context)==NULL)
    return -1;
  /* go over results */
  while ((retv=nss2nslcd(_nss_ldap_getent(&pw_context,&result,buffer,1024,&errnop,_nss_ldap_filt_getpwent,LM_PASSWD,_nss_ldap_parse_pw)))==NSLCD_RESULT_SUCCESS)
  {
    /* write the result */
    WRITE_INT32(fp,retv);
    NSLCD_PASSWD;
  }
  /* write the final result code */
  WRITE_INT32(fp,retv);
  WRITE_FLUSH(fp);
  /* FIXME: if some statement returns what happens to the context? */
  _nss_ldap_enter(); \
  _nss_ldap_ent_context_release(pw_context); \
  _nss_ldap_leave(); \
  /* we're done */
  return 0;
}
