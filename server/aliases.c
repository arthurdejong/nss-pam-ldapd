/*
   aliases.c - alias entry lookup routines

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
#include "nslcd-server.h"
#include "common.h"
#include "log.h"

static struct ent_context *alias_context = NULL;

static enum nss_status
_nss_ldap_parse_alias (LDAPMessage * e,
                       struct ldap_state * pvt,
                       void *result, char *buffer, size_t buflen)
{

  struct aliasent *alias = (struct aliasent *) result;
  enum nss_status stat;

  stat =
    _nss_ldap_getrdnvalue (e, ATM (LM_ALIASES, cn), &alias->alias_name,
                           &buffer, &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrvals (e, AT (rfc822MailMember), NULL,
                               &alias->alias_members, &buffer, &buflen,
                               &alias->alias_members_len);

  alias->alias_local = 0;

  return stat;
}

static enum nss_status
_nss_ldap_getaliasbyname_r (const char *name, struct aliasent * result,
                            char *buffer, size_t buflen, int *errnop)
{
  LOOKUP_NAME (name, result, buffer, buflen, errnop,
               _nss_ldap_filt_getaliasbyname, LM_ALIASES,
               _nss_ldap_parse_alias, LDAP_NSS_BUFLEN_DEFAULT);
}

static enum nss_status _nss_ldap_setaliasent (void)
{
  LOOKUP_SETENT (alias_context);
}

static enum nss_status _nss_ldap_endaliasent (void)
{
  LOOKUP_ENDENT (alias_context);
}

static enum nss_status
_nss_ldap_getaliasent_r (struct aliasent *result, char *buffer, size_t buflen,
                         int *errnop)
{
  LOOKUP_GETENT (alias_context, result, buffer, buflen, errnop,
                 _nss_ldap_filt_getaliasent, LM_ALIASES,
                 _nss_ldap_parse_alias, LDAP_NSS_BUFLEN_DEFAULT);
}

#define PASSWD_NAME   result.pw_name
#define PASSWD_PASSWD result.pw_passwd
#define PASSWD_UID    result.pw_uid
#define PASSWD_GID    result.pw_gid
#define PASSWD_GECOS  result.pw_gecos
#define PASSWD_DIR    result.pw_dir
#define PASSWD_SHELL  result.pw_shell

/* generic macros in development here */
#define WRITE_LOOP(fp,num,opr) \
  WRITE_INT32(fp,num); \
  for (tmp2int32=0;tmp2int32<(num);tmp2int32++) \
  { \
    opr \
  }

/* macros for expanding the LDF_ALIAS macro */
#define LDF_STRING(field)    WRITE_STRING(fp,field)
#define LDF_LOOP(field)      WRITE_LOOP(fp,result.alias_members_len,field)
#define ALIAS_NAME    result.alias_name
#define ALIAS_RCPT    result.alias_members[tmp2int32]

int nslcd_alias_byname(FILE *fp)
{
  int32_t tmpint32,tmp2int32;
  char *name;
  /* these are here for now until we rewrite the LDAP code */
  struct aliasent result;
  char buffer[1024];
  int errnop;
  int retv;
  /* read request parameters */
  READ_STRING_ALLOC(fp,name);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_alias_byname(%s)",name);
  /* do the LDAP request */
  retv=nss2nslcd(_nss_ldap_getaliasbyname_r(name,&result,buffer,1024,&errnop));
  /* no more need for this */
  free(name);
  /* write the response */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_ALIAS_BYNAME);
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
  {
    LDF_ALIAS;
  }
  WRITE_FLUSH(fp);
  log_log(LOG_DEBUG,"nslcd_alias_byname DONE");
  /* we're done */
  return 0;
}

int nslcd_alias_all(FILE *fp)
{
  int32_t tmpint32,tmp2int32;
  /* these are here for now until we rewrite the LDAP code */
  struct aliasent result;
  char buffer[1024];
  int errnop;
  int retv;
  /* log call */
  log_log(LOG_DEBUG,"nslcd_alias_all");
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_ALIAS_ALL);
  /* loop over all results */
  _nss_ldap_setaliasent();
  while ((retv=nss2nslcd(_nss_ldap_getaliasent_r(&result,buffer,1024,&errnop)))==NSLCD_RESULT_SUCCESS)
  {
    /* write the result code */
    WRITE_INT32(fp,retv);
    /* write the password entry */
    LDF_ALIAS;
    fflush(fp);
  }
  /* write the final result code */
  WRITE_INT32(fp,retv);
  /* FIXME: if a previous call returns what happens to the context? */
  _nss_ldap_endaliasent();
  log_log(LOG_DEBUG,"nslcd_alias_all DONE");
  /* we're done */
  return 0;
}
