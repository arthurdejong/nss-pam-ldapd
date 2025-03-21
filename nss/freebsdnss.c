/*
   bsdnss.c - BSD NSS functions
   This file was part of the nss-pam-ldapd FreeBSD port and part of the
   nss_ldap FreeBSD port before that.

   Copyright (C) 2003 Jacques Vidrine
   Copyright (C) 2006 Artem Kazakov
   Copyright (C) 2009 Alexander V. Chernikov
   Copyright (C) 2011-2016 Arthur de Jong
   Copyright (C) 2011 Tom Judge

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

#include <string.h>
#include <errno.h>
#include <sys/param.h>
#include <netinet/in.h>

#include "prototypes.h"
#include "common.h"
#include "compat/attrs.h"

#define BUFFER_SIZE 1024

struct name_list {
  struct name_list *next;
  char *name;
};

NSS_METHOD_PROTOTYPE(__nss_compat_getgrnam_r);
NSS_METHOD_PROTOTYPE(__nss_compat_getgrgid_r);
NSS_METHOD_PROTOTYPE(__nss_compat_getgrent_r);
NSS_METHOD_PROTOTYPE(__nss_compat_setgrent);
NSS_METHOD_PROTOTYPE(__nss_compat_endgrent);
NSS_METHOD_PROTOTYPE(__freebsd_getgroupmembership);

NSS_METHOD_PROTOTYPE(__nss_compat_getpwnam_r);
NSS_METHOD_PROTOTYPE(__nss_compat_getpwuid_r);
NSS_METHOD_PROTOTYPE(__nss_compat_getpwent_r);
NSS_METHOD_PROTOTYPE(__nss_compat_setpwent);
NSS_METHOD_PROTOTYPE(__nss_compat_endpwent);

NSS_METHOD_PROTOTYPE(__nss_compat_gethostbyname);
NSS_METHOD_PROTOTYPE(__nss_compat_gethostbyname2);
NSS_METHOD_PROTOTYPE(__nss_compat_gethostbyaddr);

NSS_METHOD_PROTOTYPE(__nss_compat_getnetgrent_r);
NSS_METHOD_PROTOTYPE(__nss_compat_setnetgrent);
NSS_METHOD_PROTOTYPE(__nss_compat_endnetgrent);

static ns_mtab methods[] = {
  { NSDB_GROUP, "getgrnam_r", __nss_compat_getgrnam_r, (void *)NSS_NAME(getgrnam_r) },
  { NSDB_GROUP, "getgrgid_r", __nss_compat_getgrgid_r, (void *)NSS_NAME(getgrgid_r) },
  { NSDB_GROUP, "getgrent_r", __nss_compat_getgrent_r, (void *)NSS_NAME(getgrent_r) },
  { NSDB_GROUP, "setgrent",   __nss_compat_setgrent,   (void *)NSS_NAME(setgrent) },
  { NSDB_GROUP, "endgrent",   __nss_compat_endgrent,   (void *)NSS_NAME(endgrent) },
  { NSDB_GROUP, "getgroupmembership", __freebsd_getgroupmembership, NULL },

  { NSDB_PASSWD, "getpwnam_r", __nss_compat_getpwnam_r, (void *)NSS_NAME(getpwnam_r) },
  { NSDB_PASSWD, "getpwuid_r", __nss_compat_getpwuid_r, (void *)NSS_NAME(getpwuid_r) },
  { NSDB_PASSWD, "getpwent_r", __nss_compat_getpwent_r, (void *)NSS_NAME(getpwent_r) },
  { NSDB_PASSWD, "setpwent",   __nss_compat_setpwent,   (void *)NSS_NAME(setpwent) },
  { NSDB_PASSWD, "endpwent",   __nss_compat_endpwent,   (void *)NSS_NAME(endpwent) },

  { NSDB_HOSTS, "gethostbyname",  __nss_compat_gethostbyname,  (void *)NSS_NAME(gethostbyname_r) },
  { NSDB_HOSTS, "gethostbyaddr",  __nss_compat_gethostbyaddr,  (void *)NSS_NAME(gethostbyaddr_r) },
  { NSDB_HOSTS, "gethostbyname2", __nss_compat_gethostbyname2, (void *)NSS_NAME(gethostbyname2_r) },

  { NSDB_GROUP_COMPAT, "getgrnam_r", __nss_compat_getgrnam_r, (void *)NSS_NAME(getgrnam_r) },
  { NSDB_GROUP_COMPAT, "getgrgid_r", __nss_compat_getgrgid_r, (void *)NSS_NAME(getgrgid_r) },
  { NSDB_GROUP_COMPAT, "getgrent_r", __nss_compat_getgrent_r, (void *)NSS_NAME(getgrent_r) },
  { NSDB_GROUP_COMPAT, "setgrent",   __nss_compat_setgrent,   (void *)NSS_NAME(setgrent) },
  { NSDB_GROUP_COMPAT, "endgrent",   __nss_compat_endgrent,   (void *)NSS_NAME(endgrent) },

  { NSDB_PASSWD_COMPAT, "getpwnam_r", __nss_compat_getpwnam_r, (void *)NSS_NAME(getpwnam_r) },
  { NSDB_PASSWD_COMPAT, "getpwuid_r", __nss_compat_getpwuid_r, (void *)NSS_NAME(getpwuid_r) },
  { NSDB_PASSWD_COMPAT, "getpwent_r", __nss_compat_getpwent_r, (void *)NSS_NAME(getpwent_r) },
  { NSDB_PASSWD_COMPAT, "setpwent",   __nss_compat_setpwent,   (void *)NSS_NAME(setpwent) },
  { NSDB_PASSWD_COMPAT, "endpwent",   __nss_compat_endpwent,   (void *)NSS_NAME(endpwent) },

  { NSDB_NETGROUP, "getnetgrent_r", __nss_compat_getnetgrent_r, (void *)NSS_NAME(getnetgrent_r) },
  { NSDB_NETGROUP, "setnetgrent", __nss_compat_setnetgrent, (void *)NSS_NAME(setnetgrent) },
  { NSDB_NETGROUP, "endnetgrent", __nss_compat_endnetgrent, (void *)NSS_NAME(endnetgrent) },
};

typedef nss_status_t (*gethbn_t)(const char *, struct hostent *, char *, size_t, int *, int *);
typedef nss_status_t (*gethba_t)(struct in_addr *, int, int, struct hostent *, char *, size_t, int *, int *);

int __nss_compat_gethostbyname(void UNUSED(*retval), void *mdata, va_list ap)
{
  gethbn_t fn;
  const char *name;
  struct hostent *result;
  char buffer[BUFFER_SIZE];
  int errnop;
  int h_errnop;
  int af;
  nss_status_t status;
  fn = (gethbn_t)mdata;
  name = va_arg(ap, const char *);
  af = va_arg(ap, int);
  result = va_arg(ap, struct hostent *);
  status = fn(name, result, buffer, sizeof(buffer), &errnop, &h_errnop);
  status = __nss_compat_result(status, errnop);
  h_errno = h_errnop;
  return status;
}

int __nss_compat_gethostbyname2(void UNUSED(*retval), void *mdata, va_list ap)
{
  gethbn_t fn;
  const char *name;
  struct hostent *result;
  char buffer[BUFFER_SIZE];
  int errnop;
  int h_errnop;
  int af;
  nss_status_t status;
  fn = (gethbn_t)mdata;
  name = va_arg(ap, const char *);
  af = va_arg(ap, int);
  result = va_arg(ap, struct hostent *);
  status = fn(name, result, buffer, sizeof(buffer), &errnop, &h_errnop);
  status = __nss_compat_result(status, errnop);
  h_errno = h_errnop;
  return status;
}

int __nss_compat_gethostbyaddr(void UNUSED(*retval), void *mdata, va_list ap)
{
  gethba_t fn;
  struct in_addr *addr;
  int len;
  int type;
  struct hostent *result;
  char buffer[BUFFER_SIZE];
  int errnop;
  int h_errnop;
  nss_status_t status;
  fn = (gethba_t)mdata;
  addr = va_arg(ap, struct in_addr *);
  len = va_arg(ap, int);
  type = va_arg(ap, int);
  result = va_arg(ap, struct hostent *);
  status = fn(addr, len, type, result, buffer, sizeof(buffer), &errnop, &h_errnop);
  status = __nss_compat_result(status, errnop);
  h_errno = h_errnop;
  return status;
}

static int __gr_addgid(gid_t gid, gid_t *groups, int maxgrp, int *groupc)
{
  int ret, dupc;
  /* skip duplicates */
  for (dupc = 0; dupc < MIN(maxgrp, *groupc); dupc++)
  {
    if (groups[dupc] == gid)
      return 1;
  }
  ret = 1;
  if (*groupc < maxgrp) /* add this gid */
    groups[*groupc] = gid;
  else
    ret = 0;
  (*groupc)++;
  return ret;
}

int __freebsd_getgroupmembership(void UNUSED(*retval), void UNUSED(*mdata_),
                                 va_list ap)
{
  int err;
  nss_status_t s;
  gid_t group;
  gid_t *tmpgroups;
  const char *user;
  gid_t *groups;
  int maxgrp, *grpcnt;
  int i;
  long int lstart, lsize;
  user = va_arg(ap, const char *);
  group = va_arg(ap, gid_t);
  groups = va_arg(ap, gid_t *);
  maxgrp = va_arg(ap, int);
  grpcnt = va_arg(ap, int *);
  tmpgroups = malloc(maxgrp * sizeof(gid_t));
  if (tmpgroups == NULL)
    return NSS_STATUS_UNAVAIL;
  /* insert primary membership */
  __gr_addgid(group, groups, maxgrp, grpcnt);
  lstart = 0;
  lsize = maxgrp;
  s = NSS_NAME(initgroups_dyn)(user, group, &lstart, &lsize, &tmpgroups, 0, &err);
  if (s == NSS_STATUS_SUCCESS)
  {
    for (i = 0; i < lstart; i++)
      __gr_addgid(tmpgroups[i], groups, maxgrp, grpcnt);
    s = NSS_STATUS_NOTFOUND;
  }
  free(tmpgroups);
  return __nss_compat_result(s, 0);
}

ns_mtab *nss_module_register(const char UNUSED(*source), unsigned int *mtabsize,
                             nss_module_unregister_fn *unreg)
{
  *mtabsize = sizeof(methods) / sizeof(methods[0]);
  *unreg = NULL;
  return methods;
}

static void *_netgr_result;

int __nss_compat_getnetgrent_r(void UNUSED(*retval), void *mdata, va_list ap)
{
  nss_status_t (*fn)(struct __netgrent *, char *, size_t, int *);
  char **hostp, **userp, **domp;
  char *buffer;
  size_t bufsize;
  enum nss_status rv;
  int *errorp;
  int ret;
  struct name_list *netlist;
  struct __netgrent *netgr;

  fn = (nss_status_t (*)(struct __netgrent *, char *, size_t, int *))mdata;
  hostp = va_arg(ap, char **);
  userp = va_arg(ap, char **);
  domp = va_arg(ap, char **);
  buffer = va_arg(ap, char *);
  bufsize = va_arg(ap, size_t);
  errorp = va_arg(ap, int *);

  do {
    *errorp = 0;
    rv = fn(_netgr_result, buffer, bufsize,
        errorp);

    ret = __nss_compat_result(rv, *errorp);
    netgr = (struct __netgrent *)_netgr_result;

    switch (ret){
      case NS_SUCCESS:
        if (netgr->type == group_val){
          netlist = (struct name_list *)malloc(sizeof(struct name_list));
          netlist->next = netgr->needed_groups;
          netlist->name = strdup(netgr->val.group);
          netgr->needed_groups = netlist;
          ret = NS_TRYAGAIN;
        }else{
          *hostp = (char *)netgr->val.triple.host;
          *userp = (char *)netgr->val.triple.user;
          *domp = (char *)netgr->val.triple.domain;
          return (NS_SUCCESS);
        }
        break;
      case NS_RETURN:
        netlist = netgr->needed_groups;
        if(netlist != NULL){
          NSS_NAME(setnetgrent)(netlist->name, netgr);
          netgr->needed_groups = netlist->next;
          free(netlist->name);
          free(netlist);
          ret = NS_TRYAGAIN;
        }
        break;
      default:
        ;
    }
  } while (ret == NS_TRYAGAIN);

  return ret;
}

int __nss_compat_setnetgrent(void UNUSED(*retval), void *mdata, va_list ap)
{
  nss_status_t (*fn)(const char *, struct __netgrent *);
  const char *netgroup;

  fn = (nss_status_t (*)(const char *, struct __netgrent *))mdata;
  netgroup = va_arg(ap, const char *);

  if (_netgr_result != NULL)
    free(_netgr_result);
  _netgr_result = calloc(1, sizeof(struct __netgrent));
  if (_netgr_result == NULL)
    return (NS_TRYAGAIN);

  return (fn(netgroup, _netgr_result));
}

int __nss_compat_endnetgrent(void UNUSED(*retval), void *mdata, va_list UNUSED(ap))
{
  nss_status_t (*fn)(struct __netgrent *);
  int ret;

  fn = (nss_status_t (*)(struct __netgrent *))mdata;
  ret = fn(_netgr_result);
  free(_netgr_result);
  _netgr_result = NULL;
  return (ret);
}
