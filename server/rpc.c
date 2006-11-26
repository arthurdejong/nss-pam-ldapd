/*
   rpc.c - rpc name lookup routines
   This file was part of the nss-ldap library (as ldap-rpc.c) which
   has been forked into the nss-ldapd library.

   Copyright (C) 1997-2005 Luke Howard
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
#include "nslcd-server.h"
#include "common.h"
#include "log.h"

/* macros for expanding the LDF_RPC macro */
#define LDF_STRING(field)     WRITE_STRING(fp,field)
#define LDF_STRINGLIST(field) WRITE_STRINGLIST_NULLTERM(fp,field)
#define LDF_INT32(field)      WRITE_INT32(fp,field)
#define RPC_NAME              result->r_name
#define RPC_ALIASES           result->r_aliases
#define RPC_NUMBER            result->r_number

/* write a single rpc entry to the stream */
static int write_rpcent(FILE *fp,struct rpcent *result)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  LDF_RPC;
  return 0;
}

static enum nss_status _nss_ldap_parse_rpc (LDAPMessage * e,
                     struct ldap_state * pvt,
                     void *result, char *buffer, size_t buflen)
{

  struct rpcent *rpc = (struct rpcent *) result;
  char *number;
  enum nss_status stat;

  stat =
    _nss_ldap_getrdnvalue (e, ATM (LM_RPC, cn), &rpc->r_name, &buffer,
                           &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrval (e, AT (oncRpcNumber), &number, &buffer,
                              &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  rpc->r_number = atol (number);

  stat =
    _nss_ldap_assign_attrvals (e, ATM (LM_RPC, cn), rpc->r_name,
                               &rpc->r_aliases, &buffer, &buflen, NULL);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  return NSS_STATUS_SUCCESS;
}

int nslcd_rpc_byname(FILE *fp)
{
  int32_t tmpint32;
  char *name;
  struct ldap_args a;
  /* these are here for now until we rewrite the LDAP code */
  struct rpcent result;
  char buffer[1024];
  int errnop;
  int retv;
  /* read request parameters */
  READ_STRING_ALLOC(fp,name);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_rpc_byname(%s)",name);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_RPC_BYNAME);
  /* do the LDAP request */
  LA_INIT(a);
  LA_STRING(a)=name;
  LA_TYPE(a)=LA_TYPE_STRING;
  retv=nss2nslcd(_nss_ldap_getbyname(&a,&result,buffer,1024,&errnop,_nss_ldap_filt_getrpcbyname,LM_RPC,_nss_ldap_parse_rpc));
  /* no more need for this string */
  free(name);
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
    write_rpcent(fp,&result);
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_rpc_bynumber(FILE *fp)
{
  int32_t tmpint32;
  int number;
  struct ldap_args a;
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
  LA_INIT(a);
  LA_NUMBER(a)=number;
  LA_TYPE(a)=LA_TYPE_NUMBER;
  retv=nss2nslcd(_nss_ldap_getbyname(&a,&result,buffer,1024,&errnop,_nss_ldap_filt_getrpcbynumber,LM_RPC,_nss_ldap_parse_rpc));
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
    write_rpcent(fp,&result);
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_rpc_all(FILE *fp)
{
  int32_t tmpint32;
  static struct ent_context *rpc_context;
  /* these are here for now until we rewrite the LDAP code */
  struct rpcent result;
  char buffer[1024];
  int errnop;
  int retv;
  /* log call */
  log_log(LOG_DEBUG,"nslcd_rpccol_all()");
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_RPC_ALL);
  /* initialize context */
  if (_nss_ldap_ent_context_init(&rpc_context)==NULL)
    return -1;
  /* loop over all results */
  while ((retv=nss2nslcd(_nss_ldap_getent(&rpc_context,&result,buffer,1024,&errnop,_nss_ldap_filt_getrpcent,LM_RPC,_nss_ldap_parse_rpc)))==NSLCD_RESULT_SUCCESS)
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
