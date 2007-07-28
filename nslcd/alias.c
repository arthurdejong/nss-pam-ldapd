/*
   alias.c - alias entry lookup routines
   This file was part of the nss_ldap library (as ldap-alias.c)
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lber.h>
#include <ldap.h>
#include <errno.h>
#include <aliases.h>
#if defined(HAVE_THREAD_H)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include "ldap-nss.h"
#include "util.h"
#include "common.h"
#include "log.h"
#include "attmap.h"
#include "ldap-schema.h"

/* the attributes to request with searches */
static const char *attlst[3];

static void attlst_init(void)
{
  attlst[0] = attmap_alias_cn;
  attlst[1] = attmap_alias_rfc822MailMember;
  attlst[2] = NULL;
}

static enum nss_status _nss_ldap_parse_alias(
        LDAPMessage *e,struct ldap_state UNUSED(*pvt),void *result,
        char *buffer,size_t buflen)
{
  /* FIXME: fix following problem:
            if the entry has multiple cn fields we may end up
            sending the wrong cn, we should return the requested
            CN instead, otherwise write an entry for each cn */
  struct aliasent *alias=(struct aliasent *)result;
  enum nss_status stat;

  stat=_nss_ldap_getrdnvalue(e,attmap_alias_cn,&alias->alias_name,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat=_nss_ldap_assign_attrvals(e,attmap_alias_rfc822MailMember,NULL,&alias->alias_members,&buffer,&buflen,&alias->alias_members_len);

  return stat;
}

static int write_alias(LDAPMessage *e,struct ldap_state UNUSED(*pvt),TFILE *fp)
{
  int stat;
  if ((stat=_nss_ldap_write_rndvalue(fp,e,attmap_alias_cn))!=NSLCD_RESULT_SUCCESS)
    return stat;
  if ((stat=_nss_ldap_write_attrvals(fp,e,attmap_alias_rfc822MailMember))!=NSLCD_RESULT_SUCCESS)
    return stat;
  return NSLCD_RESULT_SUCCESS;
}


/* macros for expanding the NSLCD_ALIAS macro */
#define NSLCD_STRING(field)     WRITE_STRING(fp,field)
#define NSLCD_STRINGLIST(field) WRITE_STRINGLIST_NUM(fp,field,result.alias_members_len)
#define ALIAS_NAME            result.alias_name
#define ALIAS_RCPTS           result.alias_members

int nslcd_alias_byname(TFILE *fp)
{
  int32_t tmpint32;
  char name[256];
  struct ldap_args a;
  /* read request parameters */
  READ_STRING_BUF2(fp,name,sizeof(name));
  /* log call */
  log_log(LOG_DEBUG,"nslcd_alias_byname(%s)",name);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_ALIAS_BYNAME);
  /* do the LDAP request */
  LA_INIT(a);
  LA_STRING(a)=name;
  LA_TYPE(a)=LA_TYPE_STRING;
  attlst_init();
  _nss_ldap_searchbyname(&a,_nss_ldap_filt_getaliasbyname,LM_ALIASES,attlst,fp,write_alias);
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_alias_all(TFILE *fp)
{
  int32_t tmpint32,tmp2int32;
  static struct ent_context *alias_context;
  /* these are here for now until we rewrite the LDAP code */
  struct aliasent result;
  char buffer[1024];
  int errnop;
  int retv;
  /* log call */
  log_log(LOG_DEBUG,"nslcd_alias_all()");
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_ALIAS_ALL);
  /* initialize context */
  if (_nss_ldap_ent_context_init(&alias_context)==NULL)
    return -1;
  /* loop over all results */
  attlst_init();
  while ((retv=nss2nslcd(_nss_ldap_getent(&alias_context,&result,buffer,1024,&errnop,_nss_ldap_filt_getaliasent,LM_ALIASES,attlst,_nss_ldap_parse_alias)))==NSLCD_RESULT_SUCCESS)
  {
    /* write the result */
    WRITE_INT32(fp,retv);
    NSLCD_ALIAS;
  }
  /* write the final result code */
  WRITE_INT32(fp,retv);
  WRITE_FLUSH(fp);
  /* FIXME: if a previous call returns what happens to the context? */
  _nss_ldap_enter();
  _nss_ldap_ent_context_release(alias_context);
  _nss_ldap_leave();
  /* we're done */
  return 0;
}
