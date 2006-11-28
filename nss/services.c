/*
   service.c - NSS lookup functions for services database

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

#include <string.h>
#include <nss.h>
#include <errno.h>

#include "prototypes.h"
#include "common.h"

/* macros for expanding the NSLCD_SERVICE macro */
#define NSLCD_STRING(field)     READ_STRING_BUF(fp,field)
#define NSLCD_STRINGLIST(field) READ_STRINGLIST_NULLTERM(fp,field)
#define NSLCD_INT32(field)      READ_INT32(fp,field)
#define SERVICE_NAME          result->s_name
#define SERVICE_ALIASES       result->s_aliases
#define SERVICE_NUMBER        port
#define SERVICE_PROTOCOL      result->s_proto

static enum nss_status read_servent(
        FILE *fp,struct servent *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  int port;
  size_t bufptr=0;
  /* auto-genereted read code */
  NSLCD_SERVICE;
  /* store number in network byte order */
  result->s_port=ntohs(port);
  /* we're done */
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_getservbyname_r(const char *name,const char *protocol,struct servent *result,char *buffer,size_t buflen,int *errnop)
{
  FILE *fp;
  int32_t tmpint32;
  enum nss_status retv;
  /* open socket and write request */
  OPEN_SOCK(fp);
  WRITE_REQUEST(fp,NSLCD_ACTION_SERVICE_BYNAME);
  /* write the parameters */
  WRITE_STRING(fp,name);
  /* fall back to empty string in case of NULL */
  if (protocol==NULL)
    protocol="";
  WRITE_STRING(fp,protocol);
  WRITE_FLUSH(fp);
  /* read response */
  READ_RESPONSEHEADER(fp,NSLCD_ACTION_SERVICE_BYNAME);
  READ_RESPONSE_CODE(fp);
  retv=read_servent(fp,result,buffer,buflen,errnop);
  /* check read result */
  if (retv!=NSS_STATUS_SUCCESS)
    return retv;
  /* close socket and we're done */
  fclose(fp);
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_getservbyport_r(int port,const char *protocol,struct servent *result,char *buffer,size_t buflen,int *errnop)
{
  FILE *fp;
  int32_t tmpint32;
  enum nss_status retv;
  /* open socket and write request */
  OPEN_SOCK(fp);
  WRITE_REQUEST(fp,NSLCD_ACTION_SERVICE_BYNUMBER);
  /* write the parameters */
  WRITE_INT32(fp,ntohs(port));
  /* fall back to empty string in case of NULL */
  if (protocol==NULL)
    protocol="";
  WRITE_STRING(fp,protocol);
  WRITE_FLUSH(fp);
  /* read response */
  READ_RESPONSEHEADER(fp,NSLCD_ACTION_SERVICE_BYNUMBER);
  READ_RESPONSE_CODE(fp);
  retv=read_servent(fp,result,buffer,buflen,errnop);
  /* check read result */
  if (retv!=NSS_STATUS_SUCCESS)
    return retv;
  /* close socket and we're done */
  fclose(fp);
  return NSS_STATUS_SUCCESS;
}

/* thread-local file pointer to an ongoing request */
static __thread FILE *protoentfp;

enum nss_status _nss_ldap_setservent(int stayopen)
{
  NSS_SETENT(protoentfp,NSLCD_ACTION_SERVICE_ALL);
}

enum nss_status _nss_ldap_getservent_r(struct servent *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(protoentfp,read_servent);
}

enum nss_status _nss_ldap_endservent(void)
{
  NSS_ENDENT(protoentfp);
}
