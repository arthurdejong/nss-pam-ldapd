/*
   group.c - NSS lookup functions for group database

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007, 2008, 2009, 2010 Arthur de Jong
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

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "prototypes.h"
#include "common.h"
#include "compat/attrs.h"

static nss_status_t read_group(
        TFILE *fp,struct group *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  size_t bufptr=0;
  READ_BUF_STRING(fp,result->gr_name);
  READ_BUF_STRING(fp,result->gr_passwd);
  READ_TYPE(fp,result->gr_gid,gid_t);
  READ_BUF_STRINGLIST(fp,result->gr_mem);
  return NSS_STATUS_SUCCESS;
}

/* read all group entries from the stream and add
   gids of these groups to the list */
static nss_status_t read_gids(
        TFILE *fp,gid_t skipgroup,long int *start,
#ifndef HAVE_NSSWITCH_H
        long int *size,
#endif /* HAVE_NSSWITCH_H */
        gid_t **groupsp,long int limit,int *errnop)
{
  int32_t res=(int32_t)NSLCD_RESULT_BEGIN;
  int32_t tmpint32,tmp2int32,tmp3int32;
  gid_t gid;
  gid_t *newgroups;
  long int newsize;
  /* loop over results */
  while (res==(int32_t)NSLCD_RESULT_BEGIN)
  {
    /* skip group name */
    SKIP_STRING(fp);
    /* skip passwd entry */
    SKIP_STRING(fp);
    /* read gid */
    READ_TYPE(fp,gid,gid_t);
    /* skip members */
    SKIP_STRINGLIST(fp);
    /* only add the group to the list if it is not the specified group */
    if (gid!=skipgroup)
    {
      /* check if we reached the limit */
      if ( (limit>0) && (*start>=limit) )
        return NSS_STATUS_TRYAGAIN;
      /* check if our buffer is large enough */
#ifndef HAVE_NSSWITCH_H
      if ((*start)>=(*size))
      {
        /* for some reason Glibc expects us to grow the array (completely
           different from all other NSS functions) */
        /* calculate new size */
        newsize=2*(*size);
        if ( (limit>0) && (*start>=limit) )
          newsize=limit;
        /* allocate new memory */
        newgroups=realloc(*groupsp,newsize*sizeof(gid_t));
        if (newgroups==NULL)
          return NSS_STATUS_TRYAGAIN;
        *groupsp=newgroups;
        *size=newsize;
      }
      /* add gid to list */
#endif /* HAVE_NSSWITCH_H */
      (*groupsp)[(*start)++]=gid;
    }
    /* read next response code
      (don't bail out on not success since we just want to build
      up a list) */
    READ_TYPE(fp,res,int32_t);
  }
  /* return the proper status code */
  return NSS_STATUS_SUCCESS;
}

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_nslcd_getgrnam_r(
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_getgrnam_r(
#endif /* HAVE_NSSWITCH_H */
        const char *name,struct group *result,char *buffer,
        size_t buflen,int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_GROUP_BYNAME,
             name,
             read_group(fp,result,buffer,buflen,errnop));
}

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_nslcd_getgrgid_r(
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_getgrgid_r(
#endif /* HAVE_NSSWITCH_H */
        gid_t gid,struct group *result,char *buffer,
        size_t buflen,int *errnop)
{
  NSS_BYTYPE(NSLCD_ACTION_GROUP_BYGID,
             gid,gid_t,
             read_group(fp,result,buffer,buflen,errnop));
}

/* this function returns a list of groups, documentation for the
   interface is scarce (any pointers are welcome) but this is
   what is assumed the parameters mean:

   user      IN     - the user name to find groups for
   skipgroup IN     - a group to not include in the list
   *start    IN/OUT - where to write in the array, is incremented
   *size     IN/OUT - the size of the supplied array (gid_t entries, not bytes)
   **groupsp IN/OUT - pointer to the array of returned groupids
   limit     IN     - the maxium size of the array
   *errnop   OUT    - for returning errno
*/
nss_status_t _nss_ldap_initgroups_dyn(
        const char *user,gid_t skipgroup,long int *start,
#ifndef HAVE_NSSWITCH_H
        long int *size,
#endif /* HAVE_NSSWITCH_H */
        gid_t **groupsp,long int limit,int *errnop)
{
#ifdef HAVE_NSSWITCH_H
   long int buffer_size=limit;
   long int *size=&buffer_size;
#endif /* HAVE_NSSWITCH_H */
/* temporarily map the buffer and buflen names so the check in NSS_BYNAME
   for validity of the buffer works (renaming the parameters may cause
   confusion) */
#define buffer groupsp
#define buflen *size
#ifdef HAVE_NSSWITCH_H
  NSS_BYNAME(NSLCD_ACTION_GROUP_BYMEMBER,
             user,
             read_gids(fp,skipgroup,start,groupsp,limit,errnop));
#else  /* not HAVE_NSSWITCH_H */
  NSS_BYNAME(NSLCD_ACTION_GROUP_BYMEMBER,
             user,
             read_gids(fp,skipgroup,start,size,groupsp,limit,errnop));
#endif /* not HAVE_NSSWITCH_H */
#undef buffer
#undef buflen
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *grentfp;

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_ldap_setgrent(nss_backend_t *gr_context,void *args)
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_setgrent(int UNUSED(stayopen))
#endif /* HAVE_NSSWITCH_H */
{
  NSS_SETENT(grentfp);
}

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_nslcd_getgrent_r(
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_getgrent_r(
#endif /* HAVE_NSSWITCH_H */
        struct group *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(grentfp,NSLCD_ACTION_GROUP_ALL,
             read_group(grentfp,result,buffer,buflen,errnop));
}

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_ldap_endgrent(nss_backend_t *gr_context,void *args)
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_endgrent(void)
#endif /* HAVE_NSSWITCH_H */
{
  NSS_ENDENT(grentfp);
}

#ifdef HAVE_NSSWITCH_H

static nss_status_t _nss_ldap_getgrnam_r(nss_backend_t *be,void *args)
{
  char *name=(char *)NSS_ARGS(args)->key.name;
  struct group priv_gr;
  struct group *gr=NSS_ARGS(args)->buf.result?(struct group *)NSS_ARGS(args)->buf.result:&priv_gr;
  char *data_ptr;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  nss_status_t status;
  status=_nss_nslcd_getgrnam_r(name,gr,buffer,buflen,&errno);
  if (status!=NSS_STATUS_SUCCESS)
    return status;
  if (!NSS_ARGS(args)->buf.result)
  {
    /* result==NULL, return file format */
    data_ptr=(char *)malloc(buflen);
    sprintf(data_ptr,"%s:%s:%d:",gr->gr_name,gr->gr_passwd,(int) gr->gr_gid);
    if (gr->gr_mem)
    {
      int i;
      for (i=0; gr->gr_mem[i]; i++)
      {
        if (i)
          strcat(data_ptr,",");
        strcat(data_ptr,gr->gr_mem[i]);
      }
    }
    strcpy(NSS_ARGS(args)->buf.buffer,data_ptr);
    free(data_ptr);
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.buffer;
    NSS_ARGS(args)->returnlen=strlen(NSS_ARGS(args)->buf.buffer);
  }
  else
  { /* result!=NULL */
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;
  }
  return status;
}

static nss_status_t _nss_ldap_getgrgid_r(nss_backend_t *be,void *args)
{
  gid_t gid=NSS_ARGS(args)->key.gid;
  struct group priv_gr;
  struct group *gr=NSS_ARGS(args)->buf.result?(struct group *)NSS_ARGS(args)->buf.result:&priv_gr;
  char *data_ptr;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  nss_status_t status;
  status=_nss_nslcd_getgrgid_r(gid,gr,buffer,buflen,&errno);
  if (status!=NSS_STATUS_SUCCESS)
    return status;
  if (!NSS_ARGS(args)->buf.result)
  {
    /* result==NULL, return file format */
    data_ptr=(char *)malloc(buflen);
    sprintf(data_ptr,"%s:%s:%d:",gr->gr_name,gr->gr_passwd,(int) gr->gr_gid);
    if (gr->gr_mem)
    {
      int i;
      for (i=0; gr->gr_mem[i]; i++)
      {
        if (i)
          strcat(data_ptr,",");
        strcat(data_ptr,gr->gr_mem[i]);
      }
    }
    strcpy(NSS_ARGS(args)->buf.buffer,data_ptr);
    free(data_ptr);
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.buffer;
    NSS_ARGS(args)->returnlen=strlen(NSS_ARGS(args)->buf.buffer);
  }
  else
  { /* result!=NULL */
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;
  }
  return status;
}

static nss_status_t _nss_ldap_getgrent_r(nss_backend_t *gr_context,void *args)
{
  struct group priv_gr;
  struct group *gr=NSS_ARGS(args)->buf.result?(struct group *)NSS_ARGS(args)->buf.result:&priv_gr;
  char *data_ptr;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  nss_status_t status;

  status=_nss_nslcd_getgrent_r(gr,buffer,buflen,&errno);

  if (status!=NSS_STATUS_SUCCESS)
    return status;

  if (!NSS_ARGS(args)->buf.result)
  {
    /* result==NULL, return file format */
    data_ptr=(char *)malloc(buflen);
    sprintf(data_ptr,"%s:%s:%d:",gr->gr_name,gr->gr_passwd,(int)gr->gr_gid);
    if (gr->gr_mem)
    {
      int i;
      for (i=0; gr->gr_mem[i]; i++)
      {
        if (i)
          strcat(data_ptr,",");
        strcat(data_ptr,gr->gr_mem[i]);
      }
    }
    strcpy(NSS_ARGS(args)->buf.buffer,data_ptr);
    free(data_ptr);

    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.buffer;
    NSS_ARGS(args)->returnlen=strlen(NSS_ARGS(args)->buf.buffer);
  }
  else
  { /* result!=NULL */
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;
  }
  return status;
}

static nss_status_t _nss_ldap_group_destr(nss_backend_t *gr_context,void *args)
{
  return _nss_ldap_default_destr(gr_context,args);
}

static nss_status_t _nss_ldap_getgroupsbymember_r(nss_backend_t *gr_context,void *args)
{
  struct nss_groupsbymem *argp=(struct nss_groupsbymem *)args;
  char *user=(char *)argp->username;
  nss_status_t status;
  long int limit=(long int) argp->maxgids;
  long int start=(long int) argp->numgids;
  gid_t skipgroup;
  int i;

  if (start > 0)
    skipgroup=argp->gid_array[0];

  status=_nss_ldap_initgroups_dyn(
                user,
                (start > 0)?skipgroup:-1,
                &start,
                (gid_t **)&argp->gid_array,
                limit,
                &errno);
  argp->numgids=(int)start;

  return status;
}

static nss_backend_op_t group_ops[]={
  _nss_ldap_group_destr,
  _nss_ldap_endgrent,
  _nss_ldap_setgrent,
  _nss_ldap_getgrent_r,
  _nss_ldap_getgrnam_r,
  _nss_ldap_getgrgid_r,
  _nss_ldap_getgroupsbymember_r
};

nss_backend_t *_nss_ldap_group_constr(const char *db_name,
                        const char *src_name,const char *cfg_args)
{
  nss_ldap_backend_t *be;
  if (!(be=(nss_ldap_backend_t *)malloc(sizeof(*be))))
    return NULL;
  be->ops=group_ops;
  be->n_ops=sizeof(group_ops)/sizeof(nss_backend_op_t);
  /* a NOOP at the moment */
  if (_nss_ldap_default_constr(be)!=NSS_STATUS_SUCCESS)
    return NULL;
  return (nss_backend_t *)be;
}

#endif /* HAVE_NSSWITCH_H */
