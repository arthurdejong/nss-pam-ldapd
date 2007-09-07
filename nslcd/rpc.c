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
#include <errno.h>
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
#include "util.h"
#include "common.h"
#include "log.h"
#include "attmap.h"
#include "ldap-schema.h"

/* macros for expanding the NSLCD_RPC macro */
#define NSLCD_STRING(field)     WRITE_STRING(fp,field)
#define NSLCD_STRINGLIST(field) WRITE_STRINGLIST_NULLTERM(fp,field)
#define NSLCD_INT32(field)      WRITE_INT32(fp,field)
#define RPC_NAME              result->r_name
#define RPC_ALIASES           result->r_aliases
#define RPC_NUMBER            result->r_number

/* the attributes to request with searches */
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
                    "(&(%s=%s)(%s=%s))",
                    attmap_objectClass,attmap_rpc_objectClass,
                    attmap_rpc_cn,buf2);
}

static int mkfilter_rpc_bynumber(int number,
                                 char *buffer,size_t buflen)
{
  return mysnprintf(buffer,buflen,
                    "(&(%s=%s)(%s=%d))",
                    attmap_objectClass,attmap_rpc_objectClass,
                    attmap_rpc_oncRpcNumber,number);
}

static int mkfilter_rpc_all(char *buffer,size_t buflen)
{
  /* build filter */
  return mysnprintf(buffer,buflen,
                    "(%s=%s)",
                    attmap_objectClass,attmap_rpc_objectClass);
}

static void rpc_attrs_init(void)
{
  rpc_attrs[0]=attmap_rpc_cn;
  rpc_attrs[1]=attmap_rpc_oncRpcNumber;
  rpc_attrs[2]=NULL;
}

/* write a single rpc entry to the stream */
static int write_rpcent(TFILE *fp,struct rpcent *result)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  NSLCD_RPC;
  return 0;
}

static enum nss_status _nss_ldap_parse_rpc (LDAPMessage * e,
                     struct ldap_state UNUSED(*pvt),
                     void *result, char *buffer, size_t buflen)
{

  struct rpcent *rpc = (struct rpcent *) result;
  char *number;
  enum nss_status stat;

  stat =
    _nss_ldap_getrdnvalue (e, attmap_rpc_cn, &rpc->r_name, &buffer,
                           &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrval (e, attmap_rpc_oncRpcNumber, &number, &buffer,
                              &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  rpc->r_number = atol (number);

  stat =
    _nss_ldap_assign_attrvals (e, attmap_rpc_cn, rpc->r_name,
                               &rpc->r_aliases, &buffer, &buflen, NULL);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  return NSS_STATUS_SUCCESS;
}

int nslcd_rpc_byname(TFILE *fp)
{
  int32_t tmpint32;
  char name[256];
  char filter[1024];
  /* these are here for now until we rewrite the LDAP code */
  struct rpcent result;
  char buffer[1024];
  int errnop;
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
  rpc_attrs_init();
  retv=_nss_ldap_getbyname(&result,buffer,1024,&errnop,LM_RPC,
                           NULL,filter,rpc_attrs,_nss_ldap_parse_rpc);
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
    write_rpcent(fp,&result);
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_rpc_bynumber(TFILE *fp)
{
  int32_t tmpint32;
  int number;
  char filter[1024];
  /* these are here for now until we rewrite the LDAP code */
  struct rpcent result;
  char buffer[1024];
  int errnop;
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
  rpc_attrs_init();
  retv=_nss_ldap_getbyname(&result,buffer,1024,&errnop,LM_RPC,
                           NULL,filter,rpc_attrs,_nss_ldap_parse_rpc);
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
    write_rpcent(fp,&result);
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_rpc_all(TFILE *fp)
{
  int32_t tmpint32;
  struct ent_context *rpc_context;
  char filter[1024];
  /* these are here for now until we rewrite the LDAP code */
  struct rpcent result;
  char buffer[1024];
  int errnop;
  int retv;
  /* log call */
  log_log(LOG_DEBUG,"nslcd_rpc_all()");
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_RPC_ALL);
  /* initialize context */
  if (_nss_ldap_ent_context_init(&rpc_context)==NULL)
    return -1;
  /* loop over all results */
  mkfilter_rpc_all(filter,sizeof(filter));
  rpc_attrs_init();
  while ((retv=_nss_ldap_getent(&rpc_context,&result,buffer,sizeof(buffer),&errnop,
                                NULL,filter,rpc_attrs,LM_RPC,_nss_ldap_parse_rpc))==NSLCD_RESULT_SUCCESS)
  {
    /* write the result code */
    WRITE_INT32(fp,retv);
    /* write the entry */
    write_rpcent(fp,&result);
  }
  /* write the final result code */
  WRITE_INT32(fp,retv);
  WRITE_FLUSH(fp);
  /* FIXME: if a previous call returns what happens to the context? */
  _nss_ldap_enter();
  _nss_ldap_ent_context_release(rpc_context);
  _nss_ldap_leave();
  /* we're done */
  return 0;
}
