/*
   aliases.c - NSS lookup functions for aliases database

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006-2015 Arthur de Jong

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

#include "prototypes.h"
#include "common.h"

/* read an alias entry from the stream */
static nss_status_t read_aliasent(TFILE *fp, struct aliasent *result,
                                  char *buffer, size_t buflen, int *errnop)
{
  int32_t tmpint32, tmp2int32, tmp3int32;
  size_t bufptr = 0;
  memset(result, 0, sizeof(struct aliasent));
  /* read the name of the alias */
  READ_BUF_STRING(fp, result->alias_name);
  /* read the members */
  READ_BUF_STRINGLIST(fp, result->alias_members);
  /* tmp3int32 holds the number of entries read */
  result->alias_members_len = tmp3int32;
  /* fill in remaining gaps in struct */
  result->alias_local = 0;
  /* we're done */
  return NSS_STATUS_SUCCESS;
}

/* get an alias entry by name */
nss_status_t NSS_NAME(getaliasbyname_r)(const char *name,
                                        struct aliasent *result,
                                        char *buffer, size_t buflen,
                                        int *errnop)
{
  NSS_GETONE(NSLCD_ACTION_ALIAS_BYNAME,
             WRITE_STRING(fp, name),
             read_aliasent(fp, result, buffer, buflen, errnop));
}

/* thread-local file pointer to an ongoing request */
static TLS TFILE *aliasentfp;

/* start a request to read all aliases */
nss_status_t NSS_NAME(setaliasent)(void)
{
  NSS_SETENT(aliasentfp);
}

/* read a single alias entry from the stream */
nss_status_t NSS_NAME(getaliasent_r)(struct aliasent *result,
                                     char *buffer, size_t buflen, int *errnop)
{
  NSS_GETENT(aliasentfp, NSLCD_ACTION_ALIAS_ALL,
             read_aliasent(aliasentfp, result, buffer, buflen, errnop));
}

/* close the stream opened with setaliasent() above */
nss_status_t NSS_NAME(endaliasent)(void)
{
  NSS_ENDENT(aliasentfp);
}
