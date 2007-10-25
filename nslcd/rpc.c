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

/* macros for expanding the NSLCD_RPC macro */
#define NSLCD_STRING(field)     WRITE_STRING(fp,field)
#define NSLCD_STRINGLIST(field) WRITE_STRINGLIST_NULLTERM(fp,field)
#define NSLCD_INT32(field)      WRITE_INT32(fp,field)
#define RPC_NAME                result->r_name
#define RPC_ALIASES             result->r_aliases
#define RPC_NUMBER              result->r_number

/* write a single rpc entry to the stream */
static int write_rpcent(TFILE *fp,struct rpcent *result)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  NSLCD_RPC;
  return 0;
}

static enum nss_status _nss_ldap_parse_rpc(
        MYLDAP_SESSION *session,LDAPMessage *e,struct ldap_state UNUSED(*state),
        void *result,char *buffer,size_t buflen)
{

  struct rpcent *rpc = (struct rpcent *) result;
  char *number;
  enum nss_status stat;

  stat=_nss_ldap_getrdnvalue(session,e,attmap_rpc_cn,&rpc->r_name,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat=_nss_ldap_assign_attrval(session,e,attmap_rpc_oncRpcNumber,&number,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  rpc->r_number = atol (number);

  stat=_nss_ldap_assign_attrvals(session,e,attmap_rpc_cn,rpc->r_name,&rpc->r_aliases,&buffer,&buflen,NULL);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  return NSS_STATUS_SUCCESS;
}

int nslcd_rpc_byname(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  char name[256];
  char filter[1024];
  /* these are here for now until we rewrite the LDAP code */
  struct rpcent result;
  char buffer[1024];
  int retv;
  /* read request parameters */
  READ_STRING_BUF2(fp,name,sizeof(name));
  /* log call */
  log_log(LOG_DEBUG,"nslcd_rpc_byname(%s)",name);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_RPC_BYNAME);
  /* do the LDAP request */
  mkfilter_rpc_byname(name,filter,sizeof(filter));
  rpc_init();
  retv=_nss_ldap_getbyname(session,&result,buffer,1024,
                           rpc_base,rpc_scope,filter,rpc_attrs,
                           _nss_ldap_parse_rpc);
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
    write_rpcent(fp,&result);
  /* we're done */
  return 0;
}

int nslcd_rpc_bynumber(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  int number;
  char filter[1024];
  /* these are here for now until we rewrite the LDAP code */
  struct rpcent result;
  char buffer[1024];
  int retv;
  /* read request parameters */
  READ_INT32(fp,number);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_rpc_bynumber(%d)",number);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_RPC_BYNUMBER);
  /* do the LDAP request */
  mkfilter_rpc_bynumber(number,filter,sizeof(filter));
  rpc_init();
  retv=_nss_ldap_getbyname(session,&result,buffer,1024,
                           rpc_base,rpc_scope,filter,rpc_attrs,
                           _nss_ldap_parse_rpc);
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
    write_rpcent(fp,&result);
  /* we're done */
  return 0;
}

int nslcd_rpc_all(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  struct ent_context context;
  /* these are here for now until we rewrite the LDAP code */
  struct rpcent result;
  char buffer[1024];
  int retv;
  /* log call */
  log_log(LOG_DEBUG,"nslcd_rpc_all()");
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_RPC_ALL);
  /* initialize context */
  _nss_ldap_ent_context_init(&context,session);
  /* loop over all results */
  rpc_init();
  while ((retv=_nss_ldap_getent(&context,&result,buffer,sizeof(buffer),
                                rpc_base,rpc_scope,rpc_filter,rpc_attrs,
                                _nss_ldap_parse_rpc))==NSLCD_RESULT_SUCCESS)
  {
    /* write the result code */
    WRITE_INT32(fp,retv);
    /* write the entry */
    write_rpcent(fp,&result);
  }
  /* write the final result code */
  WRITE_INT32(fp,retv);
  /* FIXME: if a previous call returns what happens to the context? */
  _nss_ldap_ent_context_cleanup(&context);
  /* we're done */
  return 0;
}
