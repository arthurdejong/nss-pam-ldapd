/*
   group.c - NSS lookup functions for group database

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

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "prototypes.h"
#include "common.h"
#include "compat/attrs.h"

/* read a single group entry from the stream */
static nss_status_t read_group(TFILE *fp, struct group *result,
                               char *buffer, size_t buflen, int *errnop)
{
  int32_t tmpint32, tmp2int32, tmp3int32;
  size_t bufptr = 0;
  memset(result, 0, sizeof(struct group));
  READ_BUF_STRING(fp, result->gr_name);
  READ_BUF_STRING(fp, result->gr_passwd);
  READ_INT32(fp, result->gr_gid);
  READ_BUF_STRINGLIST(fp, result->gr_mem);
  return NSS_STATUS_SUCCESS;
}

/* read all group entries from the stream and add
   gids of these groups to the list */
static nss_status_t read_gids(TFILE *fp, gid_t skipgroup, long int *start,
                              long int *size, gid_t **groupsp,
                              long int limit, int *errnop)
{
  int32_t res = (int32_t)NSLCD_RESULT_BEGIN;
  int32_t tmpint32, tmp2int32, tmp3int32;
  gid_t gid;
#ifdef NSS_FLAVOUR_GLIBC
  gid_t *newgroups;
  long int newsize;
#endif /* NSS_FLAVOUR_GLIBC */
  /* loop over results */
  while (res == (int32_t)NSLCD_RESULT_BEGIN)
  {
    /* skip group name */
    SKIP_STRING(fp);
    /* skip passwd entry */
    SKIP_STRING(fp);
    /* read gid */
    READ_INT32(fp, gid);
    /* skip members */
    SKIP_STRINGLIST(fp);
    /* only add the group to the list if it is not the specified group */
    if (gid != skipgroup)
    {
#ifdef NSS_FLAVOUR_GLIBC
      /* check if we reached the limit */
      if ((limit > 0) && (*start >= limit))
        return NSS_STATUS_TRYAGAIN;
      /* check if our buffer is large enough */
      if ((*start) >= (*size))
      {
        /* for some reason Glibc expects us to grow the array (completely
           different from all other NSS functions) */
        /* calculate new size */
        newsize = 2 * (*size);
        if ((limit > 0) && (*start >= limit))
          newsize = limit;
        /* allocate new memory */
        newgroups = realloc(*groupsp, newsize * sizeof(gid_t));
        if (newgroups == NULL)
          return NSS_STATUS_TRYAGAIN;
        *groupsp = newgroups;
        *size = newsize;
      }
#endif /* NSS_FLAVOUR_GLIBC */
#ifdef NSS_FLAVOUR_SOLARIS
      /* check if we reached the limit */
      if ((limit > 0) && (*start >= limit))
      {
        *errnop = 1; /* this is args->erange */
        return NSS_STATUS_NOTFOUND;
      }
#endif /* NSS_FLAVOUR_SOLARIS */
      /* add gid to list */
      (*groupsp)[(*start)++] = gid;
    }
    /* read next response code (don't bail out on not success since we
       just want to build up a list) */
    READ_INT32(fp, res);
  }
  /* return the proper status code */
  return NSS_STATUS_SUCCESS;
}

#ifdef NSS_FLAVOUR_GLIBC

/* get a group entry by name */
nss_status_t NSS_NAME(getgrnam_r)(const char *name, struct group *result,
                                  char *buffer, size_t buflen, int *errnop)
{
  NSS_GETONE(NSLCD_ACTION_GROUP_BYNAME,
             WRITE_STRING(fp, name),
             read_group(fp, result, buffer, buflen, errnop));
}

/* get a group entry by numeric gid */
nss_status_t NSS_NAME(getgrgid_r)(gid_t gid, struct group *result,
                                  char *buffer, size_t buflen, int *errnop)
{
  NSS_GETONE(NSLCD_ACTION_GROUP_BYGID,
             WRITE_INT32(fp, gid),
             read_group(fp, result, buffer, buflen, errnop));
}

/* thread-local file pointer to an ongoing request */
static TLS TFILE *grentfp;

/* start a request to read all groups */
nss_status_t NSS_NAME(setgrent)(int UNUSED(stayopen))
{
  NSS_SETENT(grentfp);
}

/* read a single group from the stream */
nss_status_t NSS_NAME(getgrent_r)(struct group *result,
                                  char *buffer, size_t buflen, int *errnop)
{
  NSS_GETENT(grentfp, NSLCD_ACTION_GROUP_ALL,
             read_group(grentfp, result, buffer, buflen, errnop));
}

/* close the stream opened with setgrent() above */
nss_status_t NSS_NAME(endgrent)(void)
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
nss_status_t NSS_NAME(initgroups_dyn)(const char *user, gid_t skipgroup,
                                      long int *start, long int *size,
                                      gid_t **groupsp, long int limit,
                                      int *errnop)
{
/* temporarily map the buffer and buflen names so the check in NSS_GETONE
   for validity of the buffer works (renaming the parameters may cause
   confusion) */
#define buffer groupsp
#define buflen *size
  NSS_GETONE(NSLCD_ACTION_GROUP_BYMEMBER,
             WRITE_STRING(fp, user),
             read_gids(fp, skipgroup, start, size, groupsp, limit, errnop));
#undef buffer
#undef buflen
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN
static char *group2str(struct group *result, char *buffer, size_t buflen)
{
  int res, i;
  res = snprintf(buffer, buflen, "%s:%s:%d:", result->gr_name,
                 result->gr_passwd, (int)result->gr_gid);
  if ((res < 0) || (res >= (int)buflen))
    return NULL;
  if (result->gr_mem)
    for (i = 0; result->gr_mem[i]; i++)
    {
      if (i)
        strlcat(buffer, ",", buflen);
      strlcat(buffer, result->gr_mem[i], buflen);
    }
  /* check if buffer overflowed */
  if (strlen(buffer) >= buflen - 1)
    return NULL;
  return buffer;
}
#endif /* HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

static nss_status_t read_result(TFILE *fp, nss_XbyY_args_t *args)
{
  READ_RESULT(group, &args->erange);
}

static nss_status_t group_getgrnam(nss_backend_t UNUSED(*be), void *args)
{
  NSS_GETONE(NSLCD_ACTION_GROUP_BYNAME,
             WRITE_STRING(fp, NSS_ARGS(args)->key.name),
             read_result(fp, args));
}

static nss_status_t group_getgrgid(nss_backend_t UNUSED(*be), void *args)
{
  NSS_GETONE(NSLCD_ACTION_GROUP_BYGID,
             WRITE_INT32(fp, NSS_ARGS(args)->key.gid),
             read_result(fp, args));
}

static nss_status_t group_setgrent(nss_backend_t *be, void UNUSED(*args))
{
  NSS_SETENT(LDAP_BE(be)->fp);
}

static nss_status_t group_getgrent(nss_backend_t *be, void *args)
{
  NSS_GETENT(LDAP_BE(be)->fp, NSLCD_ACTION_GROUP_ALL,
             read_result(LDAP_BE(be)->fp, args));
}

static nss_status_t group_endgrent(nss_backend_t *be, void UNUSED(*args))
{
  NSS_ENDENT(LDAP_BE(be)->fp);
}

static nss_status_t group_getgroupsbymember(nss_backend_t UNUSED(*be), void *args)
{
  struct nss_groupsbymem *argp = (struct nss_groupsbymem *)args;
  long int start = (long int)argp->numgids;
  gid_t skipgroup = (start > 0) ? argp->gid_array[0] : (gid_t)-1;
  NSS_GETONE(NSLCD_ACTION_GROUP_BYMEMBER,
             WRITE_STRING(fp, argp->username),
             read_gids(fp, skipgroup, &start, NULL, (gid_t **)&argp->gid_array,
                       argp->maxgids, &NSS_ARGS(args)->erange);
             argp->numgids = (int)start);
}

static nss_backend_op_t group_ops[] = {
  nss_ldap_destructor,
  group_endgrent,
  group_setgrent,
  group_getgrent,
  group_getgrnam,
  group_getgrgid,
  group_getgroupsbymember
};

nss_backend_t *NSS_NAME(group_constr)(const char UNUSED(*db_name),
                                      const char UNUSED(*src_name),
                                      const char UNUSED(*cfg_args))
{
  return nss_ldap_constructor(group_ops, sizeof(group_ops));
}

#endif /* NSS_FLAVOUR_SOLARIS */
