/*
   passwd.c - password entry lookup routines

   Copyright (C) 1997-2005 Luke Howard
   Copyright (C) 2006 West Consulting
   Copyright (C) 2006 Arthur de Jong

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
   MA 02110-1301 USA
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

#include "ldap-nss.h"
#include "util.h"
#include "nslcd-server.h"
#include "common.h"
#include "log.h"

static struct ent_context *pw_context = NULL;

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
  struct passwd *pw = (struct passwd *) result;
  char *uid, *gid;
  enum nss_status stat;
  char tmpbuf[ sizeof( uid_t ) * 8 / 3 + 2 ];
  size_t tmplen;
  char *tmp;

  tmpbuf[ sizeof(tmpbuf) - 1 ] = '\0';

  if (_nss_ldap_oc_check (e, "shadowAccount") == NSS_STATUS_SUCCESS)
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

#ifdef HAVE_PASSWD_PW_CHANGE
 tmp = NULL;
  stat =
    _nss_ldap_assign_attrval (e, AT (shadowMax), &tmp, &buffer, &buflen);
  pw->pw_change = (stat == NSS_STATUS_SUCCESS) ? atol(tmp) * (24*60*60) : 0;

  if (pw->pw_change > 0)
    {
      tmp = NULL;
      stat =
        _nss_ldap_assign_attrval (e, AT (shadowLastChange), &tmp, &buffer,
                                  &buflen);
      if (stat == NSS_STATUS_SUCCESS)
        pw->pw_change += atol(tmp);
      else
        pw->pw_change = 0;
    }
#endif /* HAVE_PASSWD_PW_CHANGE */

#ifdef HAVE_PASSWD_PW_EXPIRE
  tmp = NULL;
  stat =
    _nss_ldap_assign_attrval (e, AT (shadowExpire), &tmp, &buffer, &buflen);
  pw->pw_expire = (stat == NSS_STATUS_SUCCESS) ? atol(tmp) * (24*60*60) : 0;
#endif /* HAVE_PASSWD_PW_EXPIRE */

  return NSS_STATUS_SUCCESS;
}

#define PASSWD_NAME   result.pw_name
#define PASSWD_PASSWD result.pw_passwd
#define PASSWD_UID    result.pw_uid
#define PASSWD_GID    result.pw_gid
#define PASSWD_GECOS  result.pw_gecos
#define PASSWD_DIR    result.pw_dir
#define PASSWD_SHELL  result.pw_shell

#define LDF_STRING(field) \
  WRITE_STRING(fp,field)

#define LDF_TYPE(field,type) \
  WRITE(fp,&(field),sizeof(type))

static enum nss_status _nss_ldap_getpwnam_r(const char *name,
                      struct passwd *result,
                      char *buffer,size_t buflen,int *errnop)
{
  LOOKUP_NAME (name, result, buffer, buflen, errnop, _nss_ldap_filt_getpwnam,
               LM_PASSWD, _nss_ldap_parse_pw, LDAP_NSS_BUFLEN_DEFAULT);
}

static enum nss_status _nss_ldap_getpwuid_r(uid_t uid,
                      struct passwd *result,
                      char *buffer,size_t buflen,int *errnop)
{
  LOOKUP_NUMBER (uid, result, buffer, buflen, errnop, _nss_ldap_filt_getpwuid,
                 LM_PASSWD, _nss_ldap_parse_pw, LDAP_NSS_BUFLEN_DEFAULT);
}

static enum nss_status _nss_ldap_setpwent(void)
{
  LOOKUP_SETENT (pw_context);
}

static enum nss_status _nss_ldap_getpwent_r(struct passwd *result,
                      char *buffer,size_t buflen,int *errnop)
{
  LOOKUP_GETENT (pw_context, result, buffer, buflen, errnop,
                 _nss_ldap_filt_getpwent, LM_PASSWD, _nss_ldap_parse_pw,
                 LDAP_NSS_BUFLEN_DEFAULT);
}

static enum nss_status _nss_ldap_endpwent(void)
{
  LOOKUP_ENDENT (pw_context);
}

/* the caller should take care of opening and closing the stream */
int nslcd_getpwnam(FILE *fp)
{
  int32_t tmpint32;
  char *name;
  /* these are here for now until we rewrite the LDAP code */
  struct passwd result;
  char buffer[1024];
  int errnop;
  int retv;
  /* read request parameters */
  READ_STRING_ALLOC(fp,name);
  /* FIXME: free() this buffer somewhere */
  /* log call */
  log_log(LOG_DEBUG,"nslcd_getpwnam(%s)",name);
  /* do the LDAP request */
  retv=nss2nslcd(_nss_ldap_getpwnam_r(name,&result,buffer,1024,&errnop));
  /* write the response */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_RT_GETPWBYNAME);
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RS_SUCCESS)
  {
    LDF_PASSWD;
  }
  WRITE_FLUSH(fp);
  log_log(LOG_DEBUG,"nslcd_getpwnam DONE");
  /* we're done */
  return 0;
}

int nslcd_getpwuid(FILE *fp)
{
  int32_t tmpint32;
  uid_t uid;
  /* these are here for now until we rewrite the LDAP code */
  struct passwd result;
  char buffer[1024];
  int errnop;
  int retv;
  /* read request parameters */
  READ_TYPE(fp,uid,uid_t);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_getpwuid(%d)",(int)uid);
  /* do the LDAP request */
  retv=nss2nslcd(_nss_ldap_getpwuid_r(uid,&result,buffer,1024,&errnop));
  /* write the response */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_RT_GETPWBYUID);
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RS_SUCCESS)
  {
    LDF_PASSWD;
  }
  WRITE_FLUSH(fp);
  log_log(LOG_DEBUG,"nslcd_getpwuid DONE");
  /* we're done */
  return 0;
}

int nslcd_getpwall(FILE *fp)
{
  int32_t tmpint32;
  /* these are here for now until we rewrite the LDAP code */
  struct passwd result;
  char buffer[1024];
  int errnop;
  int retv;
  /* log call */
  log_log(LOG_DEBUG,"nslcd_getpwall");
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_RT_GETPWALL);
  /* loop over all results */
  _nss_ldap_setpwent();
  while ((retv=nss2nslcd(_nss_ldap_getpwent_r(&result,buffer,1024,&errnop)))==NSLCD_RS_SUCCESS)
  {
    /* write the result code */
    WRITE_INT32(fp,retv);
    /* write the password entry */
    LDF_PASSWD;
    fflush(fp);
    /* STRUCT PASSWD */
  }
  /* write the result code */
  WRITE_INT32(fp,retv);
  /* FIXME: if a previous call returns what happens to the context? */
  _nss_ldap_endpwent();
  log_log(LOG_DEBUG,"nslcd_getpwall DONE");
  /* we're done */
  return 0;
}
