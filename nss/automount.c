/*
   automount.c - NSS lookup functions for automounter maps

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

#include <stdlib.h>
#include <string.h>
#include <nss.h>
#include <errno.h>

#include "prototypes.h"
#include "nslcd-client.h"
#include "common.h"

/* macros for expanding the LDF_AUTOMOUNT macro */
#define LDF_STRING(field)     READ_STRING_BUF(fp,field)
#define AUTOMOUNT_KEY         *canon_key
#define AUTOMOUNT_INFO        *value

#define AUTOMOUNT_CONTEXT_MAGIC 0x83451830

struct automount_context
{
  char *mapname;
  FILE *fp;       /* for getautomntent() call */
  int32_t magic;  /* for sanity checks */
};

static enum nss_status read_automount(
        FILE *fp,const char **canon_key,const char **value,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32;
  size_t bufptr=0;
  /* auto-genereted read code */
  LDF_AUTOMOUNT;
  /* we're done */
  return NSS_STATUS_SUCCESS;
}

/* this function initiates a structure for doing queries
   using getautomountbyname() and getautomountent() */
enum nss_status _nss_ldap_setautomntent(
        const char *mapname,void **private)
{
  struct automount_context *context;
  /* allocate memory */
  context=malloc(sizeof(struct automount_context));
  if (context==NULL)
    return NSS_STATUS_UNAVAIL;
  /* store mapname */
  context->mapname=strdup(mapname);
  if (context->mapname==NULL)
  {
    free(context);
    return NSS_STATUS_UNAVAIL;
  }
  /* clear file handle and store magic */
  context->fp=NULL;
  context->magic=AUTOMOUNT_CONTEXT_MAGIC;
  /* return context */
  *private=context;
  return NSS_STATUS_SUCCESS;
}

/* this searches for an automounter key within the automounter
   map initialized by setautomountent() */
enum nss_status _nss_ldap_getautomntbyname_r(
        void *private,const char *key,const char **canon_key,
        const char **value,char *buffer,size_t buflen,int *errnop)
{
  struct automount_context *context;
  FILE *fp;
  int32_t tmpint32;
  enum nss_status retv;
  /* check context */
  context=(struct automount_context *)private;
  if ((context==NULL)||(context->magic!=AUTOMOUNT_CONTEXT_MAGIC))
    return NSS_STATUS_UNAVAIL;
  /* open socket and write request */
  OPEN_SOCK(fp);
  WRITE_REQUEST(fp,NSLCD_ACTION_AUTOMOUNT_BYNAME);
  WRITE_STRING(fp,context->mapname);
  WRITE_STRING(fp,key);
  WRITE_FLUSH(fp);
  /* read response header */
  READ_RESPONSEHEADER(fp,NSLCD_ACTION_AUTOMOUNT_BYNAME);
  /* read response */
  READ_RESPONSE_CODE(fp);
  retv=read_automount(fp,canon_key,value,buffer,buflen,errnop);
  if (retv!=NSS_STATUS_SUCCESS)
    return retv;
  /* close socket and we're done */
  fclose(fp);
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_getautomntent_r(
        void *private,const char **canon_key,const char **value,
        char *buffer,size_t buflen,int *errnop)
{
  struct automount_context *context;
  int32_t tmpint32;
  enum nss_status retv;
  /* check context */
  context=(struct automount_context *)private;
  if ((context==NULL)||(context->magic!=AUTOMOUNT_CONTEXT_MAGIC))
    return NSS_STATUS_UNAVAIL;
  /* if we don't have a file descriptor, begin a request now */
  if (context->fp==NULL)
  {
    /* open a new stream and write the request */
    OPEN_SOCK(context->fp);
    WRITE_REQUEST(context->fp,NSLCD_ACTION_AUTOMOUNT_ALL);
    WRITE_FLUSH(context->fp);
    /* read response header */
    READ_RESPONSEHEADER(context->fp,NSLCD_ACTION_AUTOMOUNT_ALL);
  }
  /* read a response */
  READ_RESPONSE_CODE(context->fp);
  retv=read_automount(context->fp,canon_key,value,buffer,buflen,errnop);
  if (retv!=NSS_STATUS_SUCCESS)
  {
    /* remove reference to fp from context */
    context->fp=NULL;
    return retv;
  }
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_endautomntent(void **private)
{
  struct automount_context *context;
  /* check private */
  if (private==NULL)
    return NSS_STATUS_UNAVAIL;
  /* check context */
  context=(struct automount_context *)*private;
  if ((context==NULL)||(context->magic!=AUTOMOUNT_CONTEXT_MAGIC))
    return NSS_STATUS_UNAVAIL;
  /* close any connections */
  if (context->fp!=NULL)
    fclose(context->fp);
  /* free memory */
  free(context->mapname);
  free(context);
  /* invalidate reference */
  *private=NULL;
  /* we're done */
  return NSS_STATUS_SUCCESS;
}
