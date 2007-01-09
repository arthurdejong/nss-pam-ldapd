/*
   ethers.c - NSS lookup functions for ethers database

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006 Arthur de Jong

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
#include <nss.h>
#include <errno.h>

#include "prototypes.h"
#include "common.h"

/* macros for expanding the NSLCD_ETHER macro */
#define NSLCD_STRING(field)     READ_STRING_BUF(fp,field)
#define NSLCD_TYPE(field,type)  READ_TYPE(fp,field,type)
#define ETHER_NAME            result->e_name
#define ETHER_ADDR            result->e_addr

static enum nss_status read_etherent(
        FILE *fp,struct etherent *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32;
  size_t bufptr=0;
  /* auto-genereted read code */
  NSLCD_ETHER;
  /* we're done */
  return NSS_STATUS_SUCCESS;
}

/* map a hostname to the corresponding ethernet address */
enum nss_status _nss_ldap_gethostton_r(
        const char *name,struct etherent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_ETHER_BYNAME,name,read_etherent);
}

/* map an ethernet address to the corresponding hostname */
enum nss_status _nss_ldap_getntohost_r(
        const struct ether_addr *addr,struct etherent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYTYPE(NSLCD_ACTION_ETHER_BYETHER,*addr,u_int8_t[6],read_etherent);
}

/* thread-local file pointer to an ongoing request */
static __thread FILE *etherentfp;

enum nss_status _nss_ldap_setetherent(int stayopen)
{
  NSS_SETENT(etherentfp,NSLCD_ACTION_ETHER_ALL);
}

enum nss_status _nss_ldap_getetherent_r(
        struct etherent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(etherentfp,read_etherent);
}

enum nss_status _nss_ldap_endetherent(void)
{
  NSS_ENDENT(etherentfp);
}
