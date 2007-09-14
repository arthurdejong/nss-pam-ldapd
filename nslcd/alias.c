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

/* Vendor-specific attributes and object classes.
 * (Mainly from Sun.)
 * ( 1.3.6.1.4.1.42.2.27.1.2.5 NAME 'nisMailAlias' SUP top STRUCTURAL
 *   DESC 'NIS mail alias'
 *   MUST cn
 *   MAY rfc822MailMember )
 */

/* the search base for searches */
const char *alias_base = NULL;

/* the search scope for searches */
int alias_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *alias_filter = "(objectClass=nisMailAlias)";

/* the attributes to request with searches */
const char *attmap_alias_cn               = "cn";
const char *attmap_alias_rfc822MailMember = "rfc822MailMember";

/* the attribute list to request with searches */
static const char *alias_attrs[3];

/* create a search filter for searching an alias by name,
   return -1 on errors */
static int mkfilter_alias_byname(const char *name,
                                 char *buffer,size_t buflen)
{
  char buf2[1024];
  /* escape attribute */
  if (myldap_escape(name,buf2,sizeof(buf2)))
    return -1;
  /* build filter */
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%s))",
                    alias_filter,
                    attmap_alias_cn,buf2);
}

static void alias_init(void)
{
  /* set up base */
  if (alias_base==NULL)
    alias_base=nslcd_cfg->ldc_base;
  /* set up scope */
  if (alias_scope==LDAP_SCOPE_DEFAULT)
    alias_scope=nslcd_cfg->ldc_scope;
  /* set up attribute list */
  alias_attrs[0]=attmap_alias_cn;
  alias_attrs[1]=attmap_alias_rfc822MailMember;
  alias_attrs[2]=NULL;
}

static enum nss_status _nss_ldap_parse_alias(
        MYLDAP_SESSION *session,LDAPMessage *e,struct ldap_state UNUSED(*state),void *result,
        char *buffer,size_t buflen)
{
  /* FIXME: fix following problem:
            if the entry has multiple cn fields we may end up
            sending the wrong cn, we should return the requested
            CN instead, otherwise write an entry for each cn */
  struct aliasent *alias=(struct aliasent *)result;
  enum nss_status stat;

  stat=_nss_ldap_getrdnvalue(session,e,attmap_alias_cn,&alias->alias_name,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat=_nss_ldap_assign_attrvals(session,e,attmap_alias_rfc822MailMember,NULL,&alias->alias_members,&buffer,&buflen,&alias->alias_members_len);

  return stat;
}

/* macros for expanding the NSLCD_ALIAS macro */
#define NSLCD_STRING(field)     WRITE_STRING(fp,field)
#define NSLCD_STRINGLIST(field) WRITE_STRINGLIST_NUM(fp,field,result.alias_members_len)
#define ALIAS_NAME            result.alias_name
#define ALIAS_RCPTS           result.alias_members

int nslcd_alias_byname(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32,tmp2int32;
  char name[256];
  char filter[1024];
  /* these are here for now until we rewrite the LDAP code */
  struct aliasent result;
  char buffer[1024];
  int errnop;
  int retv;
  /* read request parameters */
  READ_STRING_BUF2(fp,name,sizeof(name));
  /* log call */
  log_log(LOG_DEBUG,"nslcd_alias_byname(%s)",name);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_ALIAS_BYNAME);
  /* do the LDAP request */
  mkfilter_alias_byname(name,filter,sizeof(filter));
  alias_init();
  retv=_nss_ldap_getbyname(session,&result,buffer,1024,&errnop,
                           alias_base,alias_scope,filter,alias_attrs,
                           _nss_ldap_parse_alias);
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
  {
    NSLCD_ALIAS;
  }
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_alias_all(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32,tmp2int32;
  struct ent_context context;
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
  _nss_ldap_ent_context_init(&context,session);
  /* loop over all results */
  alias_init();
  while ((retv=_nss_ldap_getent(&context,&result,buffer,sizeof(buffer),&errnop,
                                alias_base,alias_scope,alias_filter,alias_attrs,
                                _nss_ldap_parse_alias))==NSLCD_RESULT_SUCCESS)
  {
    /* write the result */
    WRITE_INT32(fp,retv);
    NSLCD_ALIAS;
  }
  /* write the final result code */
  WRITE_INT32(fp,retv);
  WRITE_FLUSH(fp);
  /* FIXME: if a previous call returns what happens to the context? */
  _nss_ldap_ent_context_cleanup(&context);
  /* we're done */
  return 0;
}
