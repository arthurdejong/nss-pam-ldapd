/*
   netgroup.c - NSS lookup functions for netgroup entries

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006-2015 Arthur de Jong
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

/* function for reading a single result entry */
static nss_status_t read_netgrent_line(TFILE *fp, struct __netgrent *result,
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
    return NSS_STATUS_SUCCESS;
  }
  else if (type == NSLCD_NETGROUP_TYPE_TRIPLE)
  {
    /* the response is a host/user/domain triple */
    result->type = triple_val;
    /* read host and revert to NULL on empty string */
    READ_BUF_STRING(fp, result->val.triple.host);
#ifdef NSS_FLAVOUR_GLIBC
    if (result->val.triple.host[0] == '\0')
    {
      result->val.triple.host = NULL;
      bufptr--; /* free unused space */
    }
#endif /* NSS_FLAVOUR_GLIBC */
    /* read user and revert to NULL on empty string */
    READ_BUF_STRING(fp, result->val.triple.user);
#ifdef NSS_FLAVOUR_GLIBC
    if (result->val.triple.user[0] == '\0')
    {
      result->val.triple.user = NULL;
      bufptr--; /* free unused space */
    }
#endif /* NSS_FLAVOUR_GLIBC */
    /* read domain and revert to NULL on empty string */
    READ_BUF_STRING(fp, result->val.triple.domain);
#ifdef NSS_FLAVOUR_GLIBC
    if (result->val.triple.domain[0] == '\0')
    {
      result->val.triple.domain = NULL;
      bufptr--; /* free unused space */
    }
#endif /* NSS_FLAVOUR_GLIBC */
    return NSS_STATUS_SUCCESS;
  }
  else if (type == NSLCD_NETGROUP_TYPE_END)
    /* make NSS_NAME(getnetgrent_r)() indicate the end of the netgroup */
    return NSS_STATUS_RETURN;
  /* we got something unexpected */
  ERROR_OUT_NOSUCCESS(fp);
  return NSS_STATUS_UNAVAIL;
}

#ifdef NSS_FLAVOUR_GLIBC

/* thread-local file pointer to an ongoing request */
static TLS TFILE *netgrentfp;

/* start a request to get a netgroup by name */
nss_status_t NSS_NAME(setnetgrent)(const char *group,
                                   struct __netgrent UNUSED(*result))
{
  /* we cannot use NSS_SETENT() here because we have a parameter that is only
     available in this function */
  int32_t tmpint32;
  int errnocp;
  int *errnop = &errnocp;
  NSS_EXTRA_DEFS
  NSS_AVAILCHECK;
  /* check parameter */
  if ((group == NULL) || (group[0] == '\0'))
    return NSS_STATUS_UNAVAIL;
  /* open a new stream and write the request */
  NSLCD_REQUEST(netgrentfp, NSLCD_ACTION_NETGROUP_BYNAME,
                WRITE_STRING(netgrentfp, group));
  /* read response code */
  READ_RESPONSE_CODE(netgrentfp);
  SKIP_STRING(netgrentfp); /* netgroup name */
  return NSS_STATUS_SUCCESS;
}

/* get a single netgroup tuple from the stream */
nss_status_t NSS_NAME(getnetgrent_r)(struct __netgrent *result,
                                     char *buffer, size_t buflen, int *errnop)
{
  nss_status_t retv;
  NSS_EXTRA_DEFS;
  NSS_AVAILCHECK;
  NSS_BUFCHECK;
  /* check that we have a valid file descriptor */
  if (netgrentfp == NULL)
    return NSS_STATUS_UNAVAIL;
  /* prepare for buffer errors */
  tio_mark(netgrentfp);
  /* read a response */
  retv = read_netgrent_line(netgrentfp, result, buffer, buflen, errnop);
  /* check read result */
  if (retv == NSS_STATUS_TRYAGAIN)
  {
    /* if we have a full buffer try to reset the stream */
    if (tio_reset(netgrentfp))
    {
      /* reset failed, we close and give up with a permanent error
         because we cannot retry just the getent() call because it
         may not be only the first entry that failed */
      tio_close(netgrentfp);
      netgrentfp = NULL;
      *errnop = EINVAL;
      return NSS_STATUS_UNAVAIL;
    }
  }
  else if ((retv != NSS_STATUS_SUCCESS) && (retv != NSS_STATUS_RETURN))
    netgrentfp = NULL; /* file should be closed by now */
  return retv;
}

/* close the stream opened with setnetgrent() above */
nss_status_t NSS_NAME(endnetgrent)(struct __netgrent UNUSED(*result))
{
  NSS_ENDENT(netgrentfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

/* this is the custom backend structure for the {set,get,end}ent() functions */
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
#define INNETGR_ARGS(ARGS)     ((struct nss_innetgr_args *)(args))

/* return a netgroup that has not been traversed (the caller should use
   free() to free it) */
static char *find_unseen_netgroup(struct setnetgrent_backend *be)
{
  char *group;
  while (1)
  {
    group = set_pop(be->unseen_groups);
    if (group == NULL)
      return NULL;
    if (!set_contains(be->seen_groups, group))
      return group;
    free(group);
  }
}

static nss_status_t start_netgroup_request(struct setnetgrent_backend *be,
                                           const char *group)
{
  /* we cannot use NSS_SETENT() here because we have a parameter that is only
     available in this function */
  int32_t tmpint32;
  int *errnop = &errno;
  /* check parameter */
  if ((group == NULL) || (group[0] == '\0'))
    return NSS_STATUS_UNAVAIL;
  set_add(be->seen_groups, group);
  /* open a new stream and write the request */
  NSLCD_REQUEST(NETGROUP_BE(be)->fp, NSLCD_ACTION_NETGROUP_BYNAME,
                WRITE_STRING(NETGROUP_BE(be)->fp, group));
  /* read response code */
  READ_RESPONSE_CODE(NETGROUP_BE(be)->fp);
  SKIP_STRING(NETGROUP_BE(be)->fp); /* netgroup name */
  return NSS_STATUS_SUCCESS;
}

static nss_status_t netgroup_setnetgrent_setnetgrent(nss_backend_t UNUSED(*be),
                                                     void UNUSED(*args))
{
  return NSS_STATUS_SUCCESS;
}

static nss_status_t netgroup_setnetgrent_getnetgrent(nss_backend_t *be,
                                                     void *args)
{
  struct __netgrent result;
  nss_status_t retv;
  /* check that we have a valid file descriptor */
  if (NETGROUP_BE(be)->fp == NULL)
    return NSS_STATUS_UNAVAIL;
  /* go over the result lines */
  while (1)
  {
    /* prepare for buffer errors */
    tio_mark(NETGROUP_BE(be)->fp);
    /* read single line from the netgroup information */
    retv = read_netgrent_line(NETGROUP_BE(be)->fp, &result, GETNETGRENT_ARGS(args)->buffer,
                              GETNETGRENT_ARGS(args)->buflen, &errno);
    /* check read result */
    if ((retv == NSS_STATUS_SUCCESS) && (result.type == group_val))
    {
      /* a netgroup nested within the current netgroup */
      set_add(NETGROUP_BE(be)->unseen_groups, result.val.group);
    }
    else if ((retv == NSS_STATUS_SUCCESS) && (result.type == triple_val))
    {
      /* a netgroup line we can return */
      GETNETGRENT_ARGS(args)->status = NSS_NETGR_FOUND;
      GETNETGRENT_ARGS(args)->retp[NSS_NETGR_MACHINE] = (char *)result.val.triple.host;
      GETNETGRENT_ARGS(args)->retp[NSS_NETGR_USER] = (char *)result.val.triple.user;
      GETNETGRENT_ARGS(args)->retp[NSS_NETGR_DOMAIN] = (char *)result.val.triple.domain;
      return NSS_STATUS_SUCCESS;
    }
    else if (retv == NSS_STATUS_TRYAGAIN)
    {
      /* we have a full buffer, try to reset the stream */
      if (tio_reset(NETGROUP_BE(be)->fp))
      {
        /* reset failed, we close and give up with a permanent error
           because we cannot retry just the getent() call because it
           may not be only the first entry that failed */
        tio_close(NETGROUP_BE(be)->fp);
        NETGROUP_BE(be)->fp = NULL;
        return NSS_STATUS_UNAVAIL;
      }
      GETNETGRENT_ARGS(args)->status = NSS_NETGR_NOMEM;
      return NSS_STATUS_TRYAGAIN;
    }
    else if (retv == NSS_STATUS_RETURN)
    {
      /* done with the current netgroup */
      tio_close(NETGROUP_BE(be)->fp);
      NETGROUP_BE(be)->fp = NULL;
      /* explore nested netgroups, if any */
      while (retv != NSS_STATUS_SUCCESS)
      {
        /* find a nested netgroup to pursue further */
        char *group = find_unseen_netgroup(NETGROUP_BE(be));
        if (group == NULL)
        {
          /* no more netgroups to explore */
          GETNETGRENT_ARGS(args)->status = NSS_NETGR_NO;
          return NSS_STATUS_SUCCESS;
        }
        /* start a new search with this netgroup */
        retv = start_netgroup_request(NETGROUP_BE(be), group);
        free(group);
      }
    }
    else
    {
      /* some error occurred when reading the line (stream should be closed by now) */
      NETGROUP_BE(be)->fp = NULL;
      GETNETGRENT_ARGS(args)->status = NSS_NETGR_NO;
      return retv;
    }
  }
}

static nss_status_t netgroup_setnetgrent_endnetgrent(nss_backend_t *be,
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

static nss_status_t netgroup_setnetgrent_constructor(nss_backend_t UNUSED(*be),
                                                     void *args)
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
  retv = start_netgroup_request(ngbe, SETNETGRENT_ARGS(args)->netgroup);
  if (retv != NSS_STATUS_SUCCESS)
  {
    netgroup_setnetgrent_destructor((nss_backend_t *)ngbe, args);
    return retv;
  }
  /* return the new back-end */
  SETNETGRENT_ARGS(args)->iterator = (nss_backend_t *)ngbe;
  return NSS_STATUS_SUCCESS;
}

static nss_status_t netgroup_innetgr(nss_backend_t UNUSED(*be),
                                     void *args)
{
  unsigned int i;
  nss_status_t res = NSS_SUCCESS;
  struct nss_setnetgrent_args set_args;
  struct nss_getnetgrent_args get_args;
  const char *host = NULL, *user = NULL, *domain = NULL;
  /* get the host, user and domain arguments */
  if ((args == NULL) ||
      (INNETGR_ARGS(args)->arg[NSS_NETGR_MACHINE].argc > 1) ||
      (INNETGR_ARGS(args)->arg[NSS_NETGR_USER].argc > 1) ||
      (INNETGR_ARGS(args)->arg[NSS_NETGR_DOMAIN].argc > 1))
    return NSS_STATUS_UNAVAIL;
  if (INNETGR_ARGS(args)->arg[NSS_NETGR_MACHINE].argc == 1)
    host = INNETGR_ARGS(args)->arg[NSS_NETGR_MACHINE].argv[0];
  if (INNETGR_ARGS(args)->arg[NSS_NETGR_USER].argc == 1)
    user = INNETGR_ARGS(args)->arg[NSS_NETGR_USER].argv[0];
  if (INNETGR_ARGS(args)->arg[NSS_NETGR_DOMAIN].argc == 1)
    domain = INNETGR_ARGS(args)->arg[NSS_NETGR_DOMAIN].argv[0];
  /* go over the list of provided groups */
  INNETGR_ARGS(args)->status = NSS_NETGR_NO;
  for (i = 0; i < INNETGR_ARGS(args)->groups.argc; i++)
  {
    /* prepare calling {set,get,end}netgrent() */
    set_args.netgroup = INNETGR_ARGS(args)->groups.argv[i];
    res = netgroup_setnetgrent_constructor(NULL, &set_args);
    if (res != NSS_SUCCESS)
      break;
    /* we skip setnetgrent because it does nothing in our case */
    /* call getnetgrent until we find an error, no more or a match */
    while (1)
    {
      res = netgroup_setnetgrent_getnetgrent(set_args.iterator, &get_args);
      /* see if we have an error or are at the end of the results */
      if ((res != NSS_SUCCESS) || (get_args.status != NSS_NETGR_FOUND))
        break;
      /* see if we have a match */
      if (((host == NULL) || (strcmp(host, get_args.retp[NSS_NETGR_MACHINE]) == 0)) &&
          ((user == NULL) || (strcmp(user, get_args.retp[NSS_NETGR_USER]) == 0)) &&
          ((domain == NULL) || (strcmp(domain, get_args.retp[NSS_NETGR_DOMAIN]) == 0)))
      {
        INNETGR_ARGS(args)->status = NSS_NETGR_FOUND;
        break;
      }
    }
    (void)netgroup_setnetgrent_endnetgrent(set_args.iterator, NULL);
    (void)netgroup_setnetgrent_destructor(set_args.iterator, NULL);
    if (res != NSS_SUCCESS)
      break;
    /* check if we have a match */
    if (INNETGR_ARGS(args)->status == NSS_NETGR_FOUND)
      break;
  }
  return res;
}

static nss_backend_op_t netgroup_ops[] = {
  nss_ldap_destructor,
  NULL,
  NULL,
  NULL,
  netgroup_innetgr,
  netgroup_setnetgrent_constructor
};

nss_backend_t *NSS_NAME(netgroup_constr)(const char UNUSED(*db_name),
                                         const char UNUSED(*src_name),
                                         const char UNUSED(*cfg_args))
{
  return nss_ldap_constructor(netgroup_ops, sizeof(netgroup_ops));
}

#endif /* NSS_FLAVOUR_SOLARIS */
