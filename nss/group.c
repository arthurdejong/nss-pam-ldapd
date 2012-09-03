/*
   group.c - NSS lookup functions for group database

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007, 2008, 2009, 2010, 2012 Arthur de Jong
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

/* read a single group entry from the stream */
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
        TFILE *fp,gid_t skipgroup,long int *start,long int *size,
        gid_t **groupsp,long int limit,int *errnop)
{
  int32_t res=(int32_t)NSLCD_RESULT_BEGIN;
  int32_t tmpint32,tmp2int32,tmp3int32;
  gid_t gid;
#ifdef NSS_FLAVOUR_GLIBC
  gid_t *newgroups;
  long int newsize;
#endif /* NSS_FLAVOUR_GLIBC */
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
#ifdef NSS_FLAVOUR_GLIBC
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
#endif /* NSS_FLAVOUR_GLIBC */
      /* add gid to list */
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

#ifdef NSS_FLAVOUR_GLIBC

/* get a group entry by name */
nss_status_t _nss_ldap_getgrnam_r(
        const char *name,struct group *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_GROUP_BYNAME,
             name,
             read_group(fp,result,buffer,buflen,errnop));
}

/* get a group entry by numeric gid */
nss_status_t _nss_ldap_getgrgid_r(
        gid_t gid,struct group *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYTYPE(NSLCD_ACTION_GROUP_BYGID,
             gid,gid_t,
             read_group(fp,result,buffer,buflen,errnop));
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *grentfp;

/* start a request to read all groups */
nss_status_t _nss_ldap_setgrent(int UNUSED(stayopen))
{
  NSS_SETENT(grentfp);
}

/* read a single group from the stream */
nss_status_t _nss_ldap_getgrent_r(
        struct group *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(grentfp,NSLCD_ACTION_GROUP_ALL,
             read_group(grentfp,result,buffer,buflen,errnop));
}

/* close the stream opened with setgrent() above */
nss_status_t _nss_ldap_endgrent(void)
{
  NSS_ENDENT(grentfp);
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
        long int *size,gid_t **groupsp,long int limit,int *errnop)
{
/* temporarily map the buffer and buflen names so the check in NSS_BYNAME
   for validity of the buffer works (renaming the parameters may cause
   confusion) */
#define buffer groupsp
#define buflen *size
  NSS_BYNAME(NSLCD_ACTION_GROUP_BYMEMBER,
             user,
             read_gids(fp,skipgroup,start,size,groupsp,limit,errnop));
#undef buffer
#undef buflen
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN

static nss_status_t read_groupstring(TFILE *fp,nss_XbyY_args_t *args)
{
  struct group result;
  nss_status_t retv;
  char *buffer;
  int i;
  /* read the group into a temporary buffer */
  buffer=(char *)malloc(args->buf.buflen);
  if (buffer==NULL)
    return NSS_STATUS_UNAVAIL;
  retv=read_group(fp,&result,buffer,args->buf.buflen,&NSS_ARGS(args)->erange);
  if (retv!=NSS_STATUS_SUCCESS)
  {
    free(buffer);
    return retv;
  }
  /* make a string representation */
  snprintf(args->buf.buffer,args->buf.buflen,
           "%s:%s:%d:",result.gr_name,result.gr_passwd,(int)result.gr_gid);
  args->buf.buffer[args->buf.buflen-1]='\0';
  if (result.gr_mem)
    for (i=0;result.gr_mem[i];i++)
    {
      if (i)
        strncat(args->buf.buffer,",",args->buf.buflen-strlen(args->buf.buffer)-1);
      strncat(args->buf.buffer,result.gr_mem[i],args->buf.buflen-strlen(args->buf.buffer)-1);
    }
  free(buffer);
  /* check if buffer overflowed */
  if (strlen(args->buf.buffer)>=args->buf.buflen-1)
    return NSS_STATUS_TRYAGAIN;
  NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.buffer;
  NSS_ARGS(args)->returnlen=strlen(NSS_ARGS(args)->buf.buffer);
  return NSS_STATUS_SUCCESS;
}

#define READ_RESULT(fp) \
  NSS_ARGS(args)->buf.result? \
    read_group(fp,(struct group *)NSS_ARGS(args)->buf.result,NSS_ARGS(args)->buf.buffer,NSS_ARGS(args)->buf.buflen,&NSS_ARGS(args)->erange): \
    read_groupstring(fp,args); \
  if ((NSS_ARGS(args)->buf.result)&&(retv==NSS_STATUS_SUCCESS)) \
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;

#else /* not HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

#define READ_RESULT(fp) \
  read_group(fp,(struct group *)NSS_ARGS(args)->buf.result,NSS_ARGS(args)->buf.buffer,NSS_ARGS(args)->buf.buflen,&NSS_ARGS(args)->erange); \
  if (retv==NSS_STATUS_SUCCESS) \
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;

#endif /* not HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

static nss_status_t group_getgrnam(nss_backend_t UNUSED(*be),void *args)
{
  NSS_BYNAME(NSLCD_ACTION_GROUP_BYNAME,
             NSS_ARGS(args)->key.name,
             READ_RESULT(fp));
}

static nss_status_t group_getgrgid(nss_backend_t UNUSED(*be),void *args)
{
  NSS_BYTYPE(NSLCD_ACTION_GROUP_BYGID,
             NSS_ARGS(args)->key.gid,gid_t,
             READ_RESULT(fp));
}

static nss_status_t group_setgrent(nss_backend_t *be,void UNUSED(*args))
{
  NSS_SETENT(LDAP_BE(be)->fp);
}

static nss_status_t group_getgrent(nss_backend_t *be,void *args)
{
  NSS_GETENT(LDAP_BE(be)->fp,NSLCD_ACTION_GROUP_ALL,
             READ_RESULT((LDAP_BE(be)->fp)));
}

static nss_status_t group_endgrent(nss_backend_t *be,void UNUSED(*args))
{
  NSS_ENDENT(LDAP_BE(be)->fp);
}

/*
static nss_status_t get_initgroups_dyn(
        const char *user,gid_t skipgroup,long int *start,
        gid_t **groupsp,long int limit,int *errnop)
*/
static nss_status_t group_getgroupsbymember(nss_backend_t UNUSED(*be),void *args)
{
  struct nss_groupsbymem *argp=(struct nss_groupsbymem *)args;
  long int start=(long int)argp->numgids;
  gid_t skipgroup=(start>0)?argp->gid_array[0]:(gid_t)-1;
  NSS_BYNAME(NSLCD_ACTION_GROUP_BYMEMBER,
             argp->username,
             read_gids(fp,skipgroup,&start,NULL,(gid_t **)&argp->gid_array,argp->maxgids,&NSS_ARGS(args)->erange);
             argp->numgids=(int)start;);
}

static nss_backend_op_t group_ops[]={
  nss_ldap_destructor,
  group_endgrent,
  group_setgrent,
  group_getgrent,
  group_getgrnam,
  group_getgrgid,
  group_getgroupsbymember
};

nss_backend_t *_nss_ldap_group_constr(const char UNUSED(*db_name),
                  const char UNUSED(*src_name),const char UNUSED(*cfg_args))
{
  return nss_ldap_constructor(group_ops,sizeof(group_ops));
}

#endif /* NSS_FLAVOUR_SOLARIS */
