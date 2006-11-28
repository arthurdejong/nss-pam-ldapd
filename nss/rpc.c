/*
   rpc.c - NSS lookup functions for rpc database

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

/* macros for expanding the NSLCD_RPC macro */
#define NSLCD_STRING(field)     READ_STRING_BUF(fp,field)
#define NSLCD_STRINGLIST(field) READ_STRINGLIST_NULLTERM(fp,field)
#define NSLCD_INT32(field)      READ_INT32(fp,field)
#define RPC_NAME              result->r_name
#define RPC_ALIASES           result->r_aliases
#define RPC_NUMBER            result->r_number

static enum nss_status read_rpcent(
        FILE *fp,struct rpcent *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  size_t bufptr=0;
  /* auto-genereted read code */
  NSLCD_RPC;
  /* we're done */
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_getrpcbyname_r(const char *name,struct rpcent *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_RPC_BYNAME,name,read_rpcent);
}

enum nss_status _nss_ldap_getrpcbynumber_r(int number,struct rpcent *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_BYINT32(NSLCD_ACTION_RPC_BYNUMBER,number,read_rpcent);
}

/* thread-local file pointer to an ongoing request */
static __thread FILE *protoentfp;

enum nss_status _nss_ldap_setrpcent(int stayopen)
{
  NSS_SETENT(protoentfp,NSLCD_ACTION_RPC_ALL);
}

enum nss_status _nss_ldap_getrpcent_r(struct rpcent *result,char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(protoentfp,read_rpcent);
}

enum nss_status _nss_ldap_endrpcent(void)
{
  NSS_ENDENT(protoentfp);
}
