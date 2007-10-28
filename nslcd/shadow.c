/*
   shadow.c - service entry lookup routines
   This file was part of the nss_ldap library (as ldap-spwd.c) which
   has been forked into the nss-ldapd library.

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
#include <string.h>
#include <shadow.h>
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
#include "common.h"
#include "log.h"
#include "attmap.h"
#include "cfg.h"

/* ( nisSchema.2.1 NAME 'shadowAccount' SUP top AUXILIARY
 *   DESC 'Additional attributes for shadow passwords'
 *   MUST uid
 *   MAY ( userPassword $ shadowLastChange $ shadowMin
 *         shadowMax $ shadowWarning $ shadowInactive $
 *         shadowExpire $ shadowFlag $ description ) )
 */

/* the search base for searches */
const char *shadow_base = NULL;

/* the search scope for searches */
int shadow_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *shadow_filter = "(objectClass=shadowAccount)";

/* the attributes to request with searches */
const char *attmap_shadow_uid              = "uid";
const char *attmap_shadow_userPassword     = "userPassword";
const char *attmap_shadow_shadowLastChange = "shadowLastChange";
const char *attmap_shadow_shadowMin        = "shadowMin";
const char *attmap_shadow_shadowMax        = "shadowMax";
const char *attmap_shadow_shadowWarning    = "shadowWarning";
const char *attmap_shadow_shadowInactive   = "shadowInactive";
const char *attmap_shadow_shadowExpire     = "shadowExpire";
const char *attmap_shadow_shadowFlag       = "shadowFlag";

/* the attribute list to request with searches */
static const char *shadow_attrs[10];

static int mkfilter_shadow_byname(const char *name,
                                  char *buffer,size_t buflen)
{
  char buf2[1024];
  /* escape attribute */
  if(myldap_escape(name,buf2,sizeof(buf2)))
    return -1;
  /* build filter */
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%s))",
                    shadow_filter,
                    attmap_shadow_uid,buf2);
}

static void shadow_init(void)
{
  /* set up base */
  if (shadow_base==NULL)
    shadow_base=nslcd_cfg->ldc_base;
  /* set up scope */
  if (shadow_scope==LDAP_SCOPE_DEFAULT)
    shadow_scope=nslcd_cfg->ldc_scope;
  /* set up attribute list */
  shadow_attrs[0]=attmap_shadow_uid;
  shadow_attrs[1]=attmap_shadow_userPassword;
  shadow_attrs[2]=attmap_shadow_shadowLastChange;
  shadow_attrs[3]=attmap_shadow_shadowMax;
  shadow_attrs[4]=attmap_shadow_shadowMin;
  shadow_attrs[5]=attmap_shadow_shadowWarning;
  shadow_attrs[6]=attmap_shadow_shadowInactive;
  shadow_attrs[7]=attmap_shadow_shadowExpire;
  shadow_attrs[8]=attmap_shadow_shadowFlag;
  shadow_attrs[9]=NULL;
}

static int
_nss_ldap_shadow_date (const char *val)
{
  int date;

  if (nslcd_cfg->ldc_shadow_type == LS_AD_SHADOW)
    {
      date = atoll (val) / 864000000000LL - 134774LL;
      date = (date > 99999) ? 99999 : date;
    }
  else
    {
      date = atol (val);
    }

  return date;
}

#ifndef UF_DONT_EXPIRE_PASSWD
#define UF_DONT_EXPIRE_PASSWD 0x10000
#endif

static void
_nss_ldap_shadow_handle_flag (struct spwd *sp)
{
  if (nslcd_cfg->ldc_shadow_type == LS_AD_SHADOW)
    {
      if (sp->sp_flag & UF_DONT_EXPIRE_PASSWD)
        sp->sp_max = 99999;
      sp->sp_flag = 0;
    }
}

static enum nss_status _nss_ldap_parse_sp(
        MYLDAP_ENTRY *entry,
        struct spwd *sp,char *buffer,size_t buflen)
{
  enum nss_status stat;
  char *tmp = NULL;

  stat=_nss_ldap_assign_userpassword(entry,attmap_shadow_userPassword,&sp->sp_pwdp,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat=_nss_ldap_assign_attrval(entry,attmap_shadow_uid,&sp->sp_namp,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat=_nss_ldap_assign_attrval(entry,attmap_shadow_shadowLastChange,&tmp,&buffer,&buflen);
  sp->sp_lstchg = (stat == NSS_STATUS_SUCCESS) ? _nss_ldap_shadow_date (tmp) : -1;

  stat=_nss_ldap_assign_attrval(entry,attmap_shadow_shadowMax,&tmp,&buffer,&buflen);
  sp->sp_max = (stat == NSS_STATUS_SUCCESS) ? atol (tmp) : -1;

  stat=_nss_ldap_assign_attrval(entry,attmap_shadow_shadowMin,&tmp,&buffer,&buflen);
  sp->sp_min = (stat == NSS_STATUS_SUCCESS) ? atol (tmp) : -1;

  stat=_nss_ldap_assign_attrval(entry,attmap_shadow_shadowWarning,&tmp,&buffer,&buflen);
  sp->sp_warn = (stat == NSS_STATUS_SUCCESS) ? atol (tmp) : -1;

  stat=_nss_ldap_assign_attrval(entry,attmap_shadow_shadowInactive,&tmp,&buffer,&buflen);
  sp->sp_inact = (stat == NSS_STATUS_SUCCESS) ? atol (tmp) : -1;

  stat=_nss_ldap_assign_attrval(entry,attmap_shadow_shadowExpire,&tmp,&buffer,&buflen);
  sp->sp_expire = (stat == NSS_STATUS_SUCCESS) ? _nss_ldap_shadow_date (tmp) : -1;

  stat=_nss_ldap_assign_attrval(entry,attmap_shadow_shadowFlag,&tmp,&buffer,&buflen);
  sp->sp_flag = (stat == NSS_STATUS_SUCCESS) ? atol (tmp) : 0;

  _nss_ldap_shadow_handle_flag(sp);

  return NSS_STATUS_SUCCESS;
}

/* macros for expanding the NSLCD_SHADOW macro */
#define NSLCD_STRING(field)     WRITE_STRING(fp,field)
#define NSLCD_INT32(field)      WRITE_INT32(fp,field)
#define SHADOW_NAME             result.sp_namp
#define SHADOW_PASSWD           result.sp_pwdp
#define SHADOW_LASTCHANGE       result.sp_lstchg
#define SHADOW_MINDAYS          result.sp_min
#define SHADOW_MAXDAYS          result.sp_max
#define SHADOW_WARN             result.sp_warn
#define SHADOW_INACT            result.sp_inact
#define SHADOW_EXPIRE           result.sp_expire
#define SHADOW_FLAG             result.sp_flag

static int write_shadow(TFILE *fp,MYLDAP_ENTRY *entry)
{
  int32_t tmpint32;
  struct spwd result;
  char buffer[1024];
  if (_nss_ldap_parse_sp(entry,&result,buffer,sizeof(buffer))!=NSS_STATUS_SUCCESS)
    return 0;
  /* write the result code */
  WRITE_INT32(fp,NSLCD_RESULT_SUCCESS);
  /* write the entry */
  NSLCD_SHADOW;
  return 0;
}

NSLCD_HANDLE(
  shadow,byname,
  char name[256];
  char filter[1024];
  READ_STRING_BUF2(fp,name,sizeof(name));,
  log_log(LOG_DEBUG,"nslcd_shadow_byname(%s)",name);,
  NSLCD_ACTION_SHADOW_BYNAME,
  mkfilter_shadow_byname(name,filter,sizeof(filter)),
  write_shadow(fp,entry)
)

NSLCD_HANDLE(
  shadow,all,
  const char *filter;
  /* no parameters to read */,
  log_log(LOG_DEBUG,"nslcd_shadow_all()");,
  NSLCD_ACTION_SHADOW_ALL,
  (filter=shadow_filter,0),
  write_shadow(fp,entry)
)
