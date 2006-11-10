/*
   ethers.c - NSS lookup functions for ethers database

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

#include "exports.h"
#include "nslcd-client.h"
#include "common.h"

/* macros for expanding the LDF_ETHER macro */
#define LDF_STRING(field)     READ_STRING_BUF(fp,field)
#define LDF_TYPE(field,type)  READ_TYPE(fp,field,type)
#define ETHER_NAME            result->e_name
#define ETHER_ADDR            result->e_addr

/* map a hostname to the corresponding ethernet address */
enum nss_status _nss_ldap_gethostton_r(
        const char *name,struct etherent *result,
        char *buffer,size_t buflen,int *errnop)
{
  FILE *fp;
  int32_t tmpint32;
  size_t bufptr=0;
  /* open socket and write request */
  OPEN_SOCK(fp);
  WRITE_REQUEST(fp,NSLCD_ACTION_ETHER_BYNAME);
  WRITE_STRING(fp,name);
  WRITE_FLUSH(fp);
  /* read response */
  READ_RESPONSEHEADER(fp,NSLCD_ACTION_ETHER_BYNAME);
  READ_RESPONSE_CODE(fp);
  LDF_ETHER;
  /* close socket and we're done */
  fclose(fp);
  return NSS_STATUS_SUCCESS;
}

/* map an ethernet address to the corresponding hostname */
enum nss_status _nss_ldap_getntohost_r(
        const struct ether_addr *addr,struct etherent *result,
        char *buffer,size_t buflen,int *errnop)
{
  FILE *fp;
  int32_t tmpint32;
  size_t bufptr=0;
  /* open socket and write request */
  OPEN_SOCK(fp);
  WRITE_REQUEST(fp,NSLCD_ACTION_ETHER_BYNAME);
  WRITE_TYPE(fp,addr,u_int8_t[6]);
  WRITE_FLUSH(fp);
  /* read response */
  READ_RESPONSEHEADER(fp,NSLCD_ACTION_ETHER_BYNAME);
  READ_RESPONSE_CODE(fp);
  LDF_ETHER;
  /* close socket and we're done */
  fclose(fp);
  return NSS_STATUS_SUCCESS;
}

/* thread-local file pointer to an ongoing request */
static __thread FILE *etherentfp;
#define fp etherentfp

enum nss_status _nss_ldap_setetherent(int stayopen)
{
  NSS_SETENT(NSLCD_ACTION_ETHER_ALL);
}

enum nss_status _nss_ldap_getetherent_r(
        struct etherent *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32;
  size_t bufptr=0;
  /* check that we have a valid file descriptor */
  if (fp==NULL)
  {
    *errnop=ENOENT;
    return NSS_STATUS_UNAVAIL;
  }
  /* read a response */
  READ_RESPONSE_CODE(fp);
  LDF_ETHER;
  /* return result code */
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_endetherent(void)
{
  NSS_ENDENT();
}
