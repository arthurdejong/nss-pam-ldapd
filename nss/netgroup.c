/*
   netgroup.c - NSS lookup functions for netgroup entries

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007, 2008, 2010 Arthur de Jong
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

#ifdef HAVE_NSSWITCH_H
#include <nss_common.h>
#include <nss_dbdefs.h>
#include <nsswitch.h>
#endif /* HAVE_NSSWITCH_H */


#ifdef HAVE_NSSWITCH_H

static nss_backend_op_t netgroup_ops[];
static nss_status_t _nss_ldap_netgroup_destr(nss_backend_t *_ngbe,void *args);

/* find a netgroup that has not been traversed */
static char *_nss_ldap_chase_netgroup(nss_ldap_netgr_backend_t *ngbe)
{
  nss_status_t status;
  char *group=NULL;
  int found=0;
  if (!ngbe->needed_groups)
  {
   /* exhausted all netgroups */
   return NULL;
  }
  while (ngbe->needed_groups&&!found)
  {
    if (_nss_ldap_namelist_find(ngbe->known_groups,
                                ngbe->needed_groups->name))
    {
       /* netgroup seen before,ignore it */
       _nss_ldap_namelist_pop(&ngbe->needed_groups);
    }
    else
      found=1;
  }
  if (found)
  {
    group=strdup(ngbe->needed_groups->name);
    status=_nss_ldap_namelist_push(&ngbe->known_groups,
                                   ngbe->needed_groups->name);
    _nss_ldap_namelist_pop(&ngbe->needed_groups);
  }
  return group;
}
#endif /* HAVE_NSSWITCH_H */

/* we redefine this here because we need to return NSS_STATUS_RETURN
   instead of NSS_STATUS_NOTFOUND */
#undef ERROR_OUT_NOSUCCESS
#define ERROR_OUT_NOSUCCESS(fp) \
  (void)tio_close(fp); \
  fp=NULL; \
  return NSS_STATUS_RETURN;

/* function for reading a single result entry */
static nss_status_t read_netgrent(
        TFILE *fp,struct __netgrent *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32;
  int type;
  size_t bufptr=0;
  /* read netgroup type */
  READ_INT32(fp,type);
  if (type==NSLCD_NETGROUP_TYPE_NETGROUP)
  {
    /* the response is a reference to another netgroup */
    result->type=group_val;
    READ_BUF_STRING(fp,result->val.group);
  }
  else if (type==NSLCD_NETGROUP_TYPE_TRIPLE)
  {
    /* the response is a host/user/domain triple */
    result->type=triple_val;
    /* read host and revert to NULL on empty string */
    READ_BUF_STRING(fp,result->val.triple.host);
    if (result->val.triple.host[0]=='\0')
    {
      result->val.triple.host=NULL;
      bufptr--; /* free unused space */
    }
    /* read user and revert to NULL on empty string */
    READ_BUF_STRING(fp,result->val.triple.user);
    if (result->val.triple.user[0]=='\0')
    {
      result->val.triple.user=NULL;
      bufptr--; /* free unused space */
    }
    /* read domain and revert to NULL on empty string */
    READ_BUF_STRING(fp,result->val.triple.domain);
    if (result->val.triple.domain[0]=='\0')
    {
      result->val.triple.domain=NULL;
      bufptr--; /* free unused space */
    }
  }
  else
    return NSS_STATUS_UNAVAIL;
  /* we're done */
  return NSS_STATUS_SUCCESS;
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *netgrentfp;

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_ldap_setnetgrent(nss_backend_t *be,void *_args)
{
  return NSS_STATUS_SUCCESS;
}
#endif /* HAVE_NSSWITCH_H */

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_nslcd_setnetgrent(
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_setnetgrent(
#endif /* HAVE_NSSWITCH_H */
        const char *group,struct __netgrent UNUSED(* result))
{
  /* we cannot use NSS_SETENT() here because we have a parameter that is only
     available in this function */
  int32_t tmpint32;
  int errnocp;
  int *errnop;
  if (!_nss_ldap_enablelookups)
    return NSS_STATUS_UNAVAIL;
  errnop=&errnocp;
  /* check parameter */
  if ((group==NULL)||(group[0]=='\0'))
    return NSS_STATUS_UNAVAIL;
  /* open a new stream and write the request */
  NSLCD_REQUEST(netgrentfp,NSLCD_ACTION_NETGROUP_BYNAME,WRITE_STRING(netgrentfp,group));
  return NSS_STATUS_SUCCESS;
}

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_nslcd_getnetgrent_r(
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_getnetgrent_r(
#endif /* HAVE_NSSWITCH_H */
        struct __netgrent *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(netgrentfp,NSLCD_ACTION_NETGROUP_BYNAME,
             read_netgrent(netgrentfp,result,buffer,buflen,errnop));
}

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_ldap_endnetgrent(nss_backend_t *be,void *args)
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_endnetgrent(struct __netgrent UNUSED(* result))
#endif /* HAVE_NSSWITCH_H */
{
  NSS_ENDENT(netgrentfp);
}

#ifdef HAVE_NSSWITCH_H

nss_status_t _nss_ldap_getnetgrent_r(nss_backend_t *_be,void *_args)
{
  nss_ldap_netgr_backend_t *ngbe=(nss_ldap_netgr_backend_t *)_be;
  struct nss_getnetgrent_args *args=(struct nss_getnetgrent_args *)_args;
  struct __netgrent result;
  char *group=NULL;
  int done=0;
  int err;
  nss_status_t status,rc;
  args->status=NSS_NETGR_NO;
  while (!done)
  {
    status=_nss_nslcd_getnetgrent_r(&result,args->buffer,args->buflen,
                &err);
    if (status!=NSS_STATUS_SUCCESS)
    {
      if (err==ENOENT)
      {
        /* done with the current netgroup */
        /* explore nested netgroup,if any */
        int found=0;
        while (!found)
        {
          /* find a nested netgroup to pursue further */
          group=_nss_ldap_chase_netgroup(ngbe);
          if (!group)
          {
            /* no more netgroup */
            found=1; done = 1;
            errno=ENOENT;
          }
          else
          {
            rc=_nss_nslcd_setnetgrent(group,&result);
            if (rc==NSS_STATUS_SUCCESS)
              found=1;
            free(group);
            group=NULL;
          }
        } /* while !found */
      }
      else
      { /* err!=ENOENT */
        done=1;
      }
    }
    else
    { /* status==NSS_STATUS_SUCCESS */
      if (result.type==group_val)
      {
        /* a netgroup nested within the current netgroup */
        rc=_nss_ldap_namelist_push(&ngbe->needed_groups,result.val.group);
        if (rc!=NSS_STATUS_SUCCESS)
        {
          /* unable to push the group name for later netgroup */
        }
      }
      else if (result.type==triple_val)
      {
        args->retp[NSS_NETGR_MACHINE]=result.val.triple.host;
        args->retp[NSS_NETGR_USER]=result.val.triple.user;
        args->retp[NSS_NETGR_DOMAIN]=result.val.triple.domain;
        args->status=NSS_NETGR_FOUND;
        done=1;
      }
      else
      {
        /* NSS_STATUS_SUCCESS,but type is not group_val or triple_val */
        /* should not be here,log a message */
        status=NSS_STATUS_NOTFOUND;
        done=1;
      }
    }
  } /* while !done */
  return status;
}

static nss_status_t _nss_ldap_netgr_set(nss_backend_t *be,void *_args)
{
  nss_status_t stat;
  struct nss_setnetgrent_args *args;
  nss_ldap_netgr_backend_t *ngbe;
  struct __netgrent result;
  char *group=NULL;
  args=(struct nss_setnetgrent_args *)_args;
  args->iterator=NULL;        /* initialize */
  ngbe=(nss_ldap_netgr_backend_t *)malloc(sizeof(*ngbe));
  if (ngbe==NULL)
    return NSS_STATUS_UNAVAIL;
  ngbe->ops=netgroup_ops;
  ngbe->n_ops=6;
  ngbe->state=NULL;
  ngbe->known_groups=NULL;
  ngbe->needed_groups=NULL;
  stat=_nss_ldap_default_constr((nss_ldap_backend_t *)ngbe);
  if (stat!=NSS_STATUS_SUCCESS)
  {
    free(ngbe);
    return stat;
  }
  group=(char *)args->netgroup;
  stat=_nss_nslcd_setnetgrent(group,&result);
  if (stat!=NSS_STATUS_SUCCESS)
  {
    _nss_ldap_default_destr((nss_backend_t *)ngbe,NULL);
    return stat;
  }
  /* place the group name in known list */
  stat=_nss_ldap_namelist_push(&ngbe->known_groups,group);
  if (stat!=NSS_STATUS_SUCCESS)
  {
    _nss_ldap_netgroup_destr((nss_backend_t *)ngbe,NULL);
    return stat;
  }
  args->iterator=(nss_backend_t *)ngbe;
  return stat;
}

static nss_status_t _nss_ldap_netgroup_destr(nss_backend_t *_ngbe,void *args)
{
  nss_ldap_netgr_backend_t *ngbe=(nss_ldap_netgr_backend_t *)_ngbe;
  /* free list of nested netgroups */
  _nss_ldap_namelist_destroy(&ngbe->known_groups);
  _nss_ldap_namelist_destroy(&ngbe->needed_groups);
  return _nss_ldap_default_destr(_ngbe,args);
}

static nss_backend_op_t netgroup_ops[]={
  _nss_ldap_netgroup_destr,          /* NSS_DBOP_DESTRUCTOR */
  _nss_ldap_endnetgrent,             /* NSS_DBOP_ENDENT */
  _nss_ldap_setnetgrent,             /* NSS_DBOP_SETNET */
  _nss_ldap_getnetgrent_r,           /* NSS_DBOP_GETENT */
  NULL,/* TODO:_nss_ldap_netgr_in,*/ /* NSS_DBOP_NETGROUP_IN */
  _nss_ldap_netgr_set                /* NSS_DBOP_NETGROUP_SET */
};

nss_backend_t *_nss_ldap_netgroup_constr(const char *db_name,
                           const char *src_name,const char *cfg_args)
{
  nss_ldap_netgr_backend_t *be;
  if (!(be=(nss_ldap_netgr_backend_t *)malloc(sizeof(*be))))
    return NULL;
  be->ops=netgroup_ops;
  be->n_ops=sizeof(netgroup_ops)/sizeof(nss_backend_op_t);
  be->known_groups=NULL;
  be->needed_groups=NULL;
  if (_nss_ldap_default_constr((nss_ldap_backend_t *)be)!=NSS_STATUS_SUCCESS)
  {
    free(be);
    return NULL;
  }
  return (nss_backend_t *)be;
}

#endif /* HAVE_NSSWITCH_H */
