/*
   netgroup.c - netgroup lookup routines
   This file was part of the nss_ldap library (as ldap-netgrp.c)
   which has been forked into the nss-ldapd library.
   This file also contains code that is taken from the GNU C
   Library (nss/nss_files/files-netgrp.c).

   Copyright (C) 1996, 1997, 2000 Free Software Foundation, Inc.
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
#include <stdarg.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include <assert.h>
#if defined(HAVE_THREAD_H)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif
#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#include "ldap-nss.h"
#include "common.h"
#include "log.h"
#include "attmap.h"

/* A netgroup can consist of names of other netgroups.  We have to
   track which netgroups were read and which still have to be read.  */

/* Dataset for iterating netgroups.  */
struct mynetgrent
{
  enum
  { triple_val, group_val }
  type;

  union
  {
    struct
    {
      const char *host;
      const char *user;
      const char *domain;
    }
    triple;

    const char *group;
  }
  val;

  /* Room for the data kept between the calls to the netgroup
     functions.  We must avoid global variables.  */
  char *data;
  size_t data_size;
  char *cursor;
  int first;
};

/*
 * I (Luke Howard) pulled the following macro (EXPAND), functions
 * (strip_whitespace and _nss_netgroup_parseline) and structures
 * (name_list and mynetgrent) from glibc-2.2.x.  _nss_netgroup_parseline
 * became _nss_ldap_parse_netgr after some modification.
 *
 * The rest of the code is modeled on various other _nss_ldap functions.
 */

#define EXPAND(needed)                                                        \
  do                                                                          \
    {                                                                         \
      size_t old_cursor = result->cursor - result->data;                      \
                                                                              \
      result->data_size += 512 > 2 * needed ? 512 : 2 * needed;               \
      result->data = realloc (result->data, result->data_size);               \
                                                                              \
      if (result->data == NULL)                                               \
        {                                                                     \
          stat = NSS_STATUS_UNAVAIL;                                          \
          goto out;                                                           \
        }                                                                     \
                                                                              \
      result->cursor = result->data + old_cursor;                             \
    }                                                                         \
  while (0)

/* ( nisSchema.2.8 NAME 'nisNetgroup' SUP top STRUCTURAL
 *   DESC 'Abstraction of a netgroup. May refer to other netgroups'
 *   MUST cn
 *   MAY ( nisNetgroupTriple $ memberNisNetgroup $ description ) )
 */

/* the search base for searches */
const char *netgroup_base = NULL;

/* the search scope for searches */
int netgroup_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *netgroup_filter = "(objectClass=nisNetgroup)";

/* the attributes to request with searches */
const char *attmap_netgroup_cn              = "cn";
const char *attmap_netgroup_nisNetgroupTriple = "nisNetgroupTriple";
const char *attmap_netgroup_memberNisNetgroup = "memberNisNetgroup";

/* the attribute list to request with searches */
static const char *netgroup_attrs[4];

static int mkfilter_netgroup_byname(const char *name,
                                    char *buffer,size_t buflen)
{
  char buf2[1024];
  /* escape attribute */
  if (myldap_escape(name,buf2,sizeof(buf2)))
    return -1;
  /* build filter */
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%s))",
                    netgroup_filter,
                    attmap_netgroup_cn,buf2);
}

static void netgroup_init(void)
{
  /* set up base */
  if (netgroup_base==NULL)
    netgroup_base=nslcd_cfg->ldc_base;
  /* set up scope */
  if (netgroup_scope==LDAP_SCOPE_DEFAULT)
    netgroup_scope=nslcd_cfg->ldc_scope;
  /* set up attribute list */
  netgroup_attrs[0]=attmap_netgroup_cn;
  netgroup_attrs[1]=attmap_netgroup_nisNetgroupTriple;
  netgroup_attrs[2]=attmap_netgroup_memberNisNetgroup;
  netgroup_attrs[3]=NULL;
}

static char *
strip_whitespace (char *str)
{
  char *cp = str;

  /* Skip leading spaces.  */
  while (isspace ((int) *cp))
    cp++;

  str = cp;
  while (*cp != '\0' && !isspace ((int) *cp))
    cp++;

  /* Null-terminate, stripping off any trailing spaces.  */
  *cp = '\0';

  return *str == '\0' ? NULL : str;
}

static enum nss_status
_nss_ldap_parse_netgr (void *vresultp, char *buffer, size_t buflen)
{
  struct mynetgrent *result = (struct mynetgrent *) vresultp;
  char *cp = result->cursor;
  char *user, *host, *domain;

  /* The netgroup either doesn't exist or is empty. */
  if (cp == NULL)
    return NSS_STATUS_RETURN;

  /* First skip leading spaces. */
  while (isspace ((int) *cp))
    ++cp;

  if (*cp != '(')
    {
      /* We have a list of other netgroups. */
      char *name = cp;

      while (*cp != '\0' && !isspace ((int) *cp))
        ++cp;

      if (name != cp)
        {
          /* It is another netgroup name. */
          int last = *cp == '\0';

          result->type = group_val;
          result->val.group = name;
          *cp = '\0';
          if (!last)
            ++cp;
          result->cursor = cp;
          result->first = 0;

          return NSS_STATUS_SUCCESS;
        }
      return result->first ? NSS_STATUS_NOTFOUND : NSS_STATUS_RETURN;
    }

  /* Match host name. */
  host = ++cp;
  while (*cp != ',')
    if (*cp++ == '\0')
      return result->first ? NSS_STATUS_NOTFOUND : NSS_STATUS_RETURN;

  /* Match user name. */
  user = ++cp;
  while (*cp != ',')
    if (*cp++ == '\0')
      return result->first ? NSS_STATUS_NOTFOUND : NSS_STATUS_RETURN;

  /* Match domain name. */
  domain = ++cp;
  while (*cp != ')')
    if (*cp++ == '\0')
      return result->first ? NSS_STATUS_NOTFOUND : NSS_STATUS_RETURN;
  ++cp;

  /* When we got here we have found an entry.  Before we can copy it
     to the private buffer we have to make sure it is big enough.  */
  if (cp - host > buflen)
    return NSS_STATUS_TRYAGAIN;

  strncpy (buffer, host, cp - host);
  result->type = triple_val;

  buffer[(user - host) - 1] = '\0';
  result->val.triple.host = strip_whitespace (buffer);

  buffer[(domain - host) - 1] = '\0';
  result->val.triple.user = strip_whitespace (buffer + (user - host));

  buffer[(cp - host) - 1] = '\0';
  result->val.triple.domain = strip_whitespace (buffer + (domain - host));

  /* Remember where we stopped reading. */
  result->cursor = cp;
  result->first = 0;

  return NSS_STATUS_SUCCESS;
}

static enum nss_status _nss_ldap_load_netgr(
        MYLDAP_ENTRY *entry,struct mynetgrent *result)
{
  int attr;
  int nvals;
  int valcount = 0;
  char **vals;
  char **valiter;
  enum nss_status stat = NSS_STATUS_SUCCESS;
  /* FIXME: this function is wrong because it can segfault on some occasions */

  for (attr = 0; attr < 2; attr++)
    {
      switch (attr)
        {
        case 1:
          vals=_nss_ldap_get_values(entry,attmap_netgroup_nisNetgroupTriple);
          break;
        default:
          vals=_nss_ldap_get_values(entry,attmap_netgroup_memberNisNetgroup);
          break;
        }

      nvals = ldap_count_values (vals);

      if (vals == NULL)
        continue;

      if (nvals == 0)
        {
          ldap_value_free (vals);
          continue;
        }

      if (result->data_size > 0
          && result->cursor - result->data + 1 > result->data_size)
        EXPAND (1);

      if (result->data_size > 0)
        *result->cursor++ = ' ';

      valcount += nvals;
      valiter = vals;

      while (*valiter != NULL)
        {
          int curlen = strlen (*valiter);
          if (result->cursor - result->data + curlen + 1 > result->data_size)
            EXPAND (curlen + 1);
          memcpy (result->cursor, *valiter, curlen + 1);
          result->cursor += curlen;
          valiter++;
          if (*valiter != NULL)
            *result->cursor++ = ' ';
        }
      ldap_value_free (vals);
    }

  result->first = 1;
  result->cursor = result->data;

out:

  return stat;
}

static int write_netgroup(TFILE *fp,MYLDAP_ENTRY *entry)
{
  int32_t tmpint32;
  struct mynetgrent result;
  char buffer[1024];
  enum nss_status stat=NSS_STATUS_SUCCESS;
  result.data_size=0;
  if (_nss_ldap_load_netgr(entry,&result)!=NSS_STATUS_SUCCESS)
    return 0;
  /* write the result code */
  WRITE_INT32(fp,NSLCD_RESULT_SUCCESS);
  /* write the entry */
  /* loop over all results */
  while ((stat=_nss_ldap_parse_netgr(&result,buffer,1024))==NSS_STATUS_SUCCESS)
  {
    if (result.type==triple_val)
    {
      WRITE_INT32(fp,NSLCD_RESULT_SUCCESS);
      WRITE_INT32(fp,NETGROUP_TYPE_TRIPLE);
      if (result.val.triple.host==NULL)
        { WRITE_STRING(fp,""); }
      else
        { WRITE_STRING(fp,result.val.triple.host); }
      if (result.val.triple.user==NULL)
        {  WRITE_STRING(fp,""); }
      else
        { WRITE_STRING(fp,result.val.triple.user); }
      if (result.val.triple.domain==NULL)
        { WRITE_STRING(fp,""); }
      else
        { WRITE_STRING(fp,result.val.triple.domain); }
    }
    else if (result.type==group_val)
    {
      WRITE_INT32(fp,NSLCD_RESULT_SUCCESS);
      WRITE_INT32(fp,NETGROUP_TYPE_NETGROUP);
      WRITE_STRING(fp,result.val.group);
    }
  }
  /* free data */
  if (result.data!=NULL)
    free(result.data);
  return 0;
}

NSLCD_HANDLE(
  netgroup,byname,
  char name[256];
  char filter[1024];
  READ_STRING_BUF2(fp,name,sizeof(name));,
  log_log(LOG_DEBUG,"nslcd_netgroup_byname(%s)",name);,
  NSLCD_ACTION_NETGROUP_BYNAME,
  mkfilter_netgroup_byname(name,filter,sizeof(filter)),
  write_netgroup(fp,entry)
)
