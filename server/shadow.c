/*
   shadow.c - service entry lookup routines
   This file was part of the nss-ldap library (as ldap-spwd.c) which
   has been forked into the nss-ldapd library.

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
#include <string.h>
#include <shadow.h>
#include <errno.h>
#ifdef HAVE_PROT_H
#define _PROT_INCLUDED
#endif
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
#include "common.h"
#include "log.h"

static enum nss_status _nss_ldap_parse_sp(LDAPMessage *e,
                    struct ldap_state *pvt,
                    void *result,char *buffer,size_t buflen)
{
  struct spwd *sp = (struct spwd *) result;
  enum nss_status stat;
  char *tmp = NULL;

  stat =
    _nss_ldap_assign_userpassword (e, ATM (LM_SHADOW, userPassword),
                                   &sp->sp_pwdp, &buffer, &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrval (e, ATM (LM_SHADOW, uid), &sp->sp_namp, &buffer,
                              &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrval (e, AT (shadowLastChange), &tmp, &buffer,
                              &buflen);
  sp->sp_lstchg = (stat == NSS_STATUS_SUCCESS) ? _nss_ldap_shadow_date (tmp) : -1;

  stat =
    _nss_ldap_assign_attrval (e, AT (shadowMax), &tmp, &buffer, &buflen);
  sp->sp_max = (stat == NSS_STATUS_SUCCESS) ? atol (tmp) : -1;

  stat =
    _nss_ldap_assign_attrval (e, AT (shadowMin), &tmp, &buffer, &buflen);
  sp->sp_min = (stat == NSS_STATUS_SUCCESS) ? atol (tmp) : -1;

  stat =
    _nss_ldap_assign_attrval (e, AT (shadowWarning), &tmp, &buffer,
                              &buflen);
  sp->sp_warn = (stat == NSS_STATUS_SUCCESS) ? atol (tmp) : -1;

  stat =
    _nss_ldap_assign_attrval (e, AT (shadowInactive), &tmp, &buffer,
                              &buflen);
  sp->sp_inact = (stat == NSS_STATUS_SUCCESS) ? atol (tmp) : -1;

  stat =
    _nss_ldap_assign_attrval (e, AT (shadowExpire), &tmp, &buffer,
                              &buflen);
  sp->sp_expire = (stat == NSS_STATUS_SUCCESS) ? _nss_ldap_shadow_date (tmp) : -1;

  stat =
    _nss_ldap_assign_attrval (e, AT (shadowFlag), &tmp, &buffer, &buflen);
  sp->sp_flag = (stat == NSS_STATUS_SUCCESS) ? atol (tmp) : 0;

  _nss_ldap_shadow_handle_flag(sp);

  return NSS_STATUS_SUCCESS;
}

/* macros for expanding the NSLCD_SHADOW macro */
#define NSLCD_STRING(field)     WRITE_STRING(fp,field)
#define NSLCD_INT32(field)      WRITE_INT32(fp,field)
#define SHADOW_NAME           result.sp_namp
#define SHADOW_PASSWD         result.sp_pwdp
#define SHADOW_LASTCHANGE     result.sp_lstchg
#define SHADOW_MINDAYS        result.sp_min
#define SHADOW_MAXDAYS        result.sp_max
#define SHADOW_WARN           result.sp_warn
#define SHADOW_INACT          result.sp_inact
#define SHADOW_EXPIRE         result.sp_expire
#define SHADOW_FLAG           result.sp_flag

int nslcd_shadow_byname(FILE *fp)
{
  int32_t tmpint32;
  char *name;
  struct ldap_args a;
  int retv;
  struct spwd result;
  char buffer[1024];
  int errnop;
  /* read request parameters */
  READ_STRING_ALLOC(fp,name);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_shadow_byname(%s)",name);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_SHADOW_BYNAME);
  /* do the LDAP request */
  LA_INIT(a);
  LA_STRING(a)=name;
  LA_TYPE(a)=LA_TYPE_STRING;
  retv=nss2nslcd(_nss_ldap_getbyname(&a,&result,buffer,1024,&errnop,_nss_ldap_filt_getspnam,LM_SHADOW,_nss_ldap_parse_sp));
  /* no more need for this string */
  free(name);
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
  {
    NSLCD_SHADOW;
  }
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_shadow_all(FILE *fp)
{
  int32_t tmpint32;
  static struct ent_context *shadow_context;
  /* these are here for now until we rewrite the LDAP code */
  struct spwd result;
  char buffer[1024];
  int errnop;
  int retv;
  /* log call */
  log_log(LOG_DEBUG,"nslcd_shadow_all()");
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_SHADOW_ALL);
  /* initialize context */
  if (_nss_ldap_ent_context_init(&shadow_context)==NULL)
    return -1;
  /* loop over all results */
  while ((retv=nss2nslcd(_nss_ldap_getent(&shadow_context,&result,buffer,1024,&errnop,_nss_ldap_filt_getspent,LM_SHADOW,_nss_ldap_parse_sp)))==NSLCD_RESULT_SUCCESS)
  {
    /* write the result */
    WRITE_INT32(fp,retv);
    NSLCD_SHADOW;
  }
  /* write the final result code */
  WRITE_INT32(fp,retv);
  WRITE_FLUSH(fp);
  /* FIXME: if a previous call returns what happens to the context? */
  _nss_ldap_enter();
  _nss_ldap_ent_context_release(shadow_context);
  _nss_ldap_leave();
  /* we're done */
  return 0;
}
