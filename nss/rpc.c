/*
   rpc.c - NSS lookup functions for rpc database

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007, 2008, 2010 Arthur de Jong

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
#include "compat/attrs.h"

/* read a sinlge rpc entry from the stream */
static nss_status_t read_rpcent(
        TFILE *fp,struct rpcent *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  size_t bufptr=0;
  READ_BUF_STRING(fp,result->r_name);
  READ_BUF_STRINGLIST(fp,result->r_aliases);
  READ_INT32(fp,result->r_number);
  return NSS_STATUS_SUCCESS;
}

/* get a rpc entry by name */
nss_status_t _nss_ldap_getrpcbyname_r(
        const char *name,struct rpcent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_RPC_BYNAME,
             name,
             read_rpcent(fp,result,buffer,buflen,errnop));
}

/* get a rpc entry by number */
nss_status_t _nss_ldap_getrpcbynumber_r(
        int number,struct rpcent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYINT32(NSLCD_ACTION_RPC_BYNUMBER,
              number,
              read_rpcent(fp,result,buffer,buflen,errnop));
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *rpcentfp;

/* request a stream to list all rpc entries */
nss_status_t _nss_ldap_setrpcent(int UNUSED(stayopen))
{
  NSS_SETENT(rpcentfp);
}

/* get an rpc entry from the list */
nss_status_t _nss_ldap_getrpcent_r(
        struct rpcent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(rpcentfp,NSLCD_ACTION_RPC_ALL,
             read_rpcent(rpcentfp,result,buffer,buflen,errnop));
}

/* close the stream opened by setrpcent() above */
nss_status_t _nss_ldap_endrpcent(void)
{
  NSS_ENDENT(rpcentfp);
}
