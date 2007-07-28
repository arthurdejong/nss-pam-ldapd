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
static const char *attlst[3];

static void attlst_init(void)
{
  attlst[0] = attmap_rpc_cn;
  attlst[1] = attmap_rpc_oncRpcNumber;
  attlst[2] = NULL;
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
  struct ldap_args a;
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
  LA_INIT(a);
  LA_STRING(a)=name;
  LA_TYPE(a)=LA_TYPE_STRING;
  attlst_init();
  retv=nss2nslcd(_nss_ldap_getbyname(&a,&result,buffer,1024,&errnop,_nss_ldap_filt_getrpcbyname,LM_RPC,attlst,_nss_ldap_parse_rpc));
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
  attlst_init();
  retv=nss2nslcd(_nss_ldap_getbyname(&a,&result,buffer,1024,&errnop,_nss_ldap_filt_getrpcbynumber,LM_RPC,attlst,_nss_ldap_parse_rpc));
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
  static struct ent_context *rpc_context;
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
  attlst_init();
  while ((retv=nss2nslcd(_nss_ldap_getent(&rpc_context,&result,buffer,1024,&errnop,_nss_ldap_filt_getrpcent,LM_RPC,attlst,_nss_ldap_parse_rpc)))==NSLCD_RESULT_SUCCESS)
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
