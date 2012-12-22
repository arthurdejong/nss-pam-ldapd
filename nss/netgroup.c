/*
   netgroup.c - NSS lookup functions for netgroup entries

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007, 2008, 2010, 2012 Arthur de Jong
   Copyright (C) 2010 Symas Corporation

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
#include <errno.h>

#include "prototypes.h"
#include "common.h"
#include "compat/attrs.h"
#include "common/set.h"

/* we redefine this here because we need to return NSS_STATUS_RETURN
   instead of NSS_STATUS_NOTFOUND */
#undef ERROR_OUT_NOSUCCESS
#define ERROR_OUT_NOSUCCESS(fp)                                             \
  (void)tio_close(fp);                                                      \
  fp = NULL;                                                                \
  return NSS_STATUS_RETURN;

/* function for reading a single result entry */
static nss_status_t read_netgrent(TFILE *fp, struct __netgrent *result,
                                  char *buffer, size_t buflen, int *errnop)
{
  int32_t tmpint32;
  int type;
  size_t bufptr = 0;
  /* read netgroup type */
  READ_INT32(fp, type);
  if (type == NSLCD_NETGROUP_TYPE_NETGROUP)
  {
    /* the response is a reference to another netgroup */
    result->type = group_val;
    READ_BUF_STRING(fp, result->val.group);
  }
  else if (type == NSLCD_NETGROUP_TYPE_TRIPLE)
  {
    /* the response is a host/user/domain triple */
    result->type = triple_val;
    /* read host and revert to NULL on empty string */
    READ_BUF_STRING(fp, result->val.triple.host);
    if (result->val.triple.host[0] == '\0')
    {
      result->val.triple.host = NULL;
      bufptr--; /* free unused space */
    }
    /* read user and revert to NULL on empty string */
    READ_BUF_STRING(fp, result->val.triple.user);
    if (result->val.triple.user[0] == '\0')
    {
      result->val.triple.user = NULL;
      bufptr--; /* free unused space */
    }
    /* read domain and revert to NULL on empty string */
    READ_BUF_STRING(fp, result->val.triple.domain);
    if (result->val.triple.domain[0] == '\0')
    {
      result->val.triple.domain = NULL;
      bufptr--; /* free unused space */
    }
  }
  else
    return NSS_STATUS_UNAVAIL;
  /* we're done */
  return NSS_STATUS_SUCCESS;
}

#ifdef NSS_FLAVOUR_GLIBC

/* thread-local file pointer to an ongoing request */
static __thread TFILE *netgrentfp;

/* start a request to get a netgroup by name */
nss_status_t _nss_ldap_setnetgrent(const char *group,
                                   struct __netgrent UNUSED(*result))
{
  /* we cannot use NSS_SETENT() here because we have a parameter that is only
     available in this function */
  int32_t tmpint32;
  int errnocp;
  int *errnop;
  if (!_nss_ldap_enablelookups)
    return NSS_STATUS_UNAVAIL;
  errnop = &errnocp;
  /* check parameter */
  if ((group == NULL) || (group[0] == '\0'))
    return NSS_STATUS_UNAVAIL;
  /* open a new stream and write the request */
  NSLCD_REQUEST(netgrentfp, NSLCD_ACTION_NETGROUP_BYNAME,
                WRITE_STRING(netgrentfp, group));
  return NSS_STATUS_SUCCESS;
}

/* get a single netgroup tuple from the stream */
nss_status_t _nss_ldap_getnetgrent_r(struct __netgrent *result,
                                     char *buffer, size_t buflen, int *errnop)
{
  NSS_GETENT(netgrentfp, NSLCD_ACTION_NETGROUP_BYNAME,
             read_netgrent(netgrentfp, result, buffer, buflen, errnop));
}

/* close the stream opened with setnetgrent() above */
nss_status_t _nss_ldap_endnetgrent(struct __netgrent UNUSED(*result))
{
  NSS_ENDENT(netgrentfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

/* this is the backend structure for the {set,get,end}ent() functions */
struct setnetgrent_backend {
  nss_backend_op_t *ops; /* function-pointer table */
  int n_ops;             /* number of function pointers */
  TFILE *fp;             /* the file pointer for {set,get,end}ent() functions */
  SET *seen_groups;      /* netgroups seen, for loop detection */
  SET *unseen_groups;    /* netgroups that need to be chased */
};

/* easy way to get sets from back-end */
#define NETGROUP_BE(be) ((struct setnetgrent_backend*)(be))

/* access arguments */
#define SETNETGRENT_ARGS(args) ((struct nss_setnetgrent_args *)(args))
#define GETNETGRENT_ARGS(args) ((struct nss_getnetgrent_args *)(args))

/* return a netgroup that has not been traversed */
static char *find_unseen_netgroup(nss_backend_t *be)
{
  char *group;
  while (1)
  {
    group = set_pop(NETGROUP_BE(be)->unseen_groups);
    if (group == NULL)
      return NULL;
    if (!set_contains(NETGROUP_BE(be)->seen_groups, group))
    {
      set_add(NETGROUP_BE(be)->seen_groups, group);
      return group;
    }
  }
}

static nss_status_t netgroup_nslcd_setnetgrent(nss_backend_t *be,
                                               const char *group, int *errnop)
{
  /* we cannot use NSS_SETENT() here because we have a parameter that is only
     available in this function */
  int32_t tmpint32;
  /* check parameter */
  if ((group == NULL) || (group[0] == '\0'))
    return NSS_STATUS_UNAVAIL;
  /* open a new stream and write the request */
  NSLCD_REQUEST(NETGROUP_BE(be)->fp, NSLCD_ACTION_NETGROUP_BYNAME,
                WRITE_STRING(NETGROUP_BE(be)->fp, group));
  return NSS_STATUS_SUCCESS;
}

static nss_status_t netgroup_nslcd_getnetgrent(nss_backend_t *be,
                                               struct __netgrent *result,
                                               char *buffer, size_t buflen,
                                               void *args)
{
  NSS_GETENT(NETGROUP_BE(be)->fp, NSLCD_ACTION_NETGROUP_BYNAME,
             read_netgrent(NETGROUP_BE(be)->fp, result, buffer, buflen,
                           errnop));
}

static nss_status_t netgroup_setnetgrent_setnetgrent(nss_backend_t
                                                     UNUSED(*be),
                                                     void UNUSED(*args))
{
  return NSS_STATUS_SUCCESS;
}

static nss_status_t netgroup_setnetgrent_getnetgrent(nss_backend_t *be,
                                                     void *args)
{
  struct __netgrent result;
  char *group = NULL;
  int done = 0;
  nss_status_t status, rc;
  GETNETGRENT_ARGS(args)->status = NSS_NETGR_NO;
  while (!done)
  {
    status = netgroup_nslcd_getnetgrent(be, &result, GETNETGRENT_ARGS(args)->buffer,
                                        GETNETGRENT_ARGS(args)->buflen, args);
    if (status != NSS_STATUS_SUCCESS)
    {
      if (errno == ENOENT)
      {
        /* done with the current netgroup */
        /* explore nested netgroup, if any */
        int found = 0;
        while (!found)
        {
          /* find a nested netgroup to pursue further */
          group = find_unseen_netgroup(be);
          if (group == NULL)
          {
            /* no more netgroup */
            found = 1;
            done = 1;
            errno = ENOENT; /* TODO: probably don't do this */
          }
          else
          {
            rc = netgroup_nslcd_setnetgrent(be, group, &NSS_ARGS(args)->erange);
            if (rc == NSS_STATUS_SUCCESS)
              found = 1;
            free(group);
            group = NULL;
          }
        } /* while !found */
      }
      else
      { /* err != ENOENT */
        done = 1;
      }
    }
    else
    { /* status == NSS_STATUS_SUCCESS */
      if (result.type == group_val)
      {
        /* a netgroup nested within the current netgroup */
        set_add(NETGROUP_BE(be)->unseen_groups, result.val.group);
      }
      else if (result.type == triple_val)
      {
        GETNETGRENT_ARGS(args)->retp[NSS_NETGR_MACHINE] = result.val.triple.host;
        GETNETGRENT_ARGS(args)->retp[NSS_NETGR_USER] = result.val.triple.user;
        GETNETGRENT_ARGS(args)->retp[NSS_NETGR_DOMAIN] = result.val.triple.domain;
        GETNETGRENT_ARGS(args)->status = NSS_NETGR_FOUND;
        done = 1;
      }
      else
      {
        /* NSS_STATUS_SUCCESS, but type is not group_val or triple_val */
        /* should not be here, log a message */
        status = NSS_STATUS_NOTFOUND;
        done = 1;
      }
    }
  } /* while !done */
  return status;
}

static nss_status_t netgroup_setnetgrent_endnetgrent(nss_backend_t
                                                     UNUSED(*be),
                                                     void UNUSED(*args))
{
  NSS_ENDENT(NETGROUP_BE(be)->fp);
}

static nss_status_t netgroup_setnetgrent_destructor(nss_backend_t *be,
                                                    void *UNUSED(args))
{
  struct setnetgrent_backend *ngbe = (struct setnetgrent_backend *)be;
  if (ngbe->fp != NULL)
    (void)tio_close(ngbe->fp);
  set_free(ngbe->seen_groups);
  set_free(ngbe->unseen_groups);
  free(ngbe);
  return NSS_STATUS_SUCCESS;
}

static nss_backend_op_t netgroup_setnetgrent_ops[] = {
  netgroup_setnetgrent_destructor,
  netgroup_setnetgrent_endnetgrent,
  netgroup_setnetgrent_setnetgrent,
  netgroup_setnetgrent_getnetgrent,
};

static nss_status_t netgroup_setnetgrent_constructor(nss_backend_t *be, void *args)
{
  struct setnetgrent_backend *ngbe;
  nss_status_t retv;
  NSS_AVAILCHECK;
  SETNETGRENT_ARGS(args)->iterator = NULL; /* initialize */
  /* allocate a back-end specific to this request */
  ngbe = (struct setnetgrent_backend *)malloc(sizeof(struct setnetgrent_backend));
  if (ngbe == NULL)
    return NSS_STATUS_UNAVAIL;
  ngbe->ops = netgroup_setnetgrent_ops;
  ngbe->n_ops = sizeof(netgroup_setnetgrent_ops) / sizeof(nss_backend_op_t);
  ngbe->fp = NULL;
  ngbe->seen_groups = set_new();
  ngbe->unseen_groups = set_new();
  /* start the first search */
  retv = netgroup_nslcd_setnetgrent(be, SETNETGRENT_ARGS(args)->netgroup,
                                    &NSS_ARGS(args)->erange);
  if (retv != NSS_STATUS_SUCCESS)
  {
    netgroup_setnetgrent_destructor(be, args);
    return retv;
  }
  /* return the new back-end */
  SETNETGRENT_ARGS(args)->iterator = (nss_backend_t *)ngbe;
  return NSS_STATUS_SUCCESS;
}

static nss_backend_op_t netgroup_ops[] = {
  nss_ldap_destructor,
  NULL,
  NULL,
  NULL,
  NULL, /* TODO:_nss_ldap_netgr_in */
  netgroup_setnetgrent_constructor
};

nss_backend_t *_nss_ldap_netgroup_constr(const char UNUSED(*db_name),
                                         const char UNUSED(*src_name),
                                         const char UNUSED(*cfg_args))
{
  return nss_ldap_constructor(netgroup_ops, sizeof(netgroup_ops));
}

#endif /* NSS_FLAVOUR_SOLARIS */
