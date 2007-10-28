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
#include <aliases.h>
#if defined(HAVE_THREAD_H)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include "ldap-nss.h"
#include "common.h"
#include "log.h"
#include "myldap.h"
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
        MYLDAP_ENTRY *entry,struct aliasent *result,
        char *buffer,size_t buflen)
{
  /* FIXME: fix following problem:
            if the entry has multiple cn fields we may end up
            sending the wrong cn, we should return the requested
            CN instead, otherwise write an entry for each cn */
  enum nss_status stat;

  stat=_nss_ldap_getrdnvalue(entry,attmap_alias_cn,&result->alias_name,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat=_nss_ldap_assign_attrvals(entry,attmap_alias_rfc822MailMember,NULL,&result->alias_members,&buffer,&buflen,&result->alias_members_len);

  return stat;
}

/* macros for expanding the NSLCD_ALIAS macro */
#define NSLCD_STRING(field)     WRITE_STRING(fp,field)
#define NSLCD_STRINGLIST(field) WRITE_STRINGLIST_NUM(fp,field,result.alias_members_len)
#define ALIAS_NAME              result.alias_name
#define ALIAS_RCPTS             result.alias_members

static int write_alias(TFILE *fp,MYLDAP_ENTRY *entry)
{
  struct aliasent result;
  char buffer[1024];
  int32_t tmpint32,tmp2int32;
  if (_nss_ldap_parse_alias(entry,&result,buffer,sizeof(buffer))!=NSS_STATUS_SUCCESS)
    return 0;
  /* write the result code */
  WRITE_INT32(fp,NSLCD_RESULT_SUCCESS);
  /* write the entry */
  NSLCD_ALIAS;
  return 0;
}

NSLCD_HANDLE(
  alias,byname,
  char name[256];
  char filter[1024];
  READ_STRING_BUF2(fp,name,sizeof(name));,
  log_log(LOG_DEBUG,"nslcd_alias_byname(%s)",name);,
  NSLCD_ACTION_ALIAS_BYNAME,
  mkfilter_alias_byname(name,filter,sizeof(filter)),
  write_alias(fp,entry)
)

NSLCD_HANDLE(
  alias,all,
  const char *filter;
  /* no parameters to read */,
  log_log(LOG_DEBUG,"nslcd_alias_all()");,
  NSLCD_ACTION_ALIAS_ALL,
  (filter=alias_filter,0),
  write_alias(fp,entry)
)
