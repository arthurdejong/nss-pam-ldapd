/*
   rpc.c - rpc name lookup routines
   This file was part of the nss_ldap library (as ldap-rpc.c) which
   has been forked into the nss-ldapd library.

   Copyright (C) 1997-2005 Luke Howard
   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007 Arthur de Jong

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

/*
   Determine the canonical name of the RPC with _nss_ldap_getrdnvalue(),
   and assign any values of "cn" which do NOT match this canonical name
   as aliases.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_RPC_RPCENT_H
#include <rpc/rpcent.h>
#else
#include <netdb.h>
#endif
#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif
#if defined(HAVE_THREAD_H)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include "ldap-nss.h"
#include "common.h"
#include "log.h"
#include "attmap.h"

/* ( nisSchema.2.5 NAME 'oncRpc' SUP top STRUCTURAL
 *   DESC 'Abstraction of an Open Network Computing (ONC)
 *         [RFC1057] Remote Procedure Call (RPC) binding.
 *         This class maps an ONC RPC number to a name.
 *         The distinguished value of the cn attribute denotes
 *         the RPC service's canonical name'
 *   MUST ( cn $ oncRpcNumber )
 *   MAY description )
 */

/* the search base for searches */
const char *rpc_base = NULL;

/* the search scope for searches */
int rpc_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *rpc_filter = "(objectClass=oncRpc)";

/* the attributes to request with searches */
const char *attmap_rpc_cn               = "cn";
const char *attmap_rpc_oncRpcNumber     = "oncRpcNumber";

/* the attribute list to request with searches */
static const char *rpc_attrs[3];

static int mkfilter_rpc_byname(const char *name,
                               char *buffer,size_t buflen)
{
  char buf2[1024];
  /* escape attribute */
  if (myldap_escape(name,buf2,sizeof(buf2)))
    return -1;
  /* build filter */
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%s))",
                    rpc_filter,
                    attmap_rpc_cn,buf2);
}

static int mkfilter_rpc_bynumber(int number,
                                 char *buffer,size_t buflen)
{
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%d))",
                    rpc_filter,
                    attmap_rpc_oncRpcNumber,number);
}

static void rpc_init(void)
{
  /* set up base */
  if (rpc_base==NULL)
    rpc_base=nslcd_cfg->ldc_base;
  /* set up scope */
  if (rpc_scope==LDAP_SCOPE_DEFAULT)
    rpc_scope=nslcd_cfg->ldc_scope;
  /* set up attribute list */
  rpc_attrs[0]=attmap_rpc_cn;
  rpc_attrs[1]=attmap_rpc_oncRpcNumber;
  rpc_attrs[2]=NULL;
}

static enum nss_status _nss_ldap_parse_rpc(
        MYLDAP_ENTRY *entry,
        struct rpcent *rpc,char *buffer,size_t buflen)
{
  char *number;
  enum nss_status stat;

  stat=_nss_ldap_getrdnvalue(entry,attmap_rpc_cn,&rpc->r_name,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat=_nss_ldap_assign_attrval(entry,attmap_rpc_oncRpcNumber,&number,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  rpc->r_number = atol (number);

  stat=_nss_ldap_assign_attrvals(entry,attmap_rpc_cn,rpc->r_name,&rpc->r_aliases,&buffer,&buflen,NULL);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  return NSS_STATUS_SUCCESS;
}

/* macros for expanding the NSLCD_RPC macro */
#define NSLCD_STRING(field)     WRITE_STRING(fp,field)
#define NSLCD_STRINGLIST(field) WRITE_STRINGLIST_NULLTERM(fp,field)
#define NSLCD_INT32(field)      WRITE_INT32(fp,field)
#define RPC_NAME                result.r_name
#define RPC_ALIASES             result.r_aliases
#define RPC_NUMBER              result.r_number

/* write a single rpc entry to the stream */
static int write_rpc(TFILE *fp,MYLDAP_ENTRY *entry)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  struct rpcent result;
  char buffer[1024];
  if (_nss_ldap_parse_rpc(entry,&result,buffer,sizeof(buffer))!=NSS_STATUS_SUCCESS)
    return 0;
  /* write the result code */
  WRITE_INT32(fp,NSLCD_RESULT_SUCCESS);
  /* write the entry */
  NSLCD_RPC;
  return 0;
}

NSLCD_HANDLE(
  rpc,byname,
  char name[256];
  char filter[1024];
  READ_STRING_BUF2(fp,name,sizeof(name));,
  log_log(LOG_DEBUG,"nslcd_rpc_byname(%s)",name);,
  NSLCD_ACTION_RPC_BYNAME,
  mkfilter_rpc_byname(name,filter,sizeof(filter)),
  write_rpc(fp,entry)
)

NSLCD_HANDLE(
  rpc,bynumber,
  int number;
  char filter[1024];
  READ_INT32(fp,number);,
  log_log(LOG_DEBUG,"nslcd_rpc_bynumber(%d)",number);,
  NSLCD_ACTION_RPC_BYNUMBER,
  mkfilter_rpc_bynumber(number,filter,sizeof(filter)),
  write_rpc(fp,entry)
)

NSLCD_HANDLE(
  rpc,all,
  const char *filter;
  /* no parameters to read */,
  log_log(LOG_DEBUG,"nslcd_rpc_all()");,
  NSLCD_ACTION_RPC_ALL,
  (filter=rpc_filter,0),
  write_rpc(fp,entry)
)
