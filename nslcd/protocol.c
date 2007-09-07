/*
   protocol.c - network address entry lookup routines
   This file was part of the nss_ldap library (as ldap-proto.c)
   which has been forked into the nss-ldapd library.

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
#include <netdb.h>
#include <errno.h>
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

/* the attributes to request with searches */
static const char *protocol_attrs[3];

static int mkfilter_protocol_byname(const char *name,
                                    char *buffer,size_t buflen)
{
  char buf2[1024];
  /* escape attribute */
  if (myldap_escape(name,buf2,sizeof(buf2)))
    return -1;
  /* build filter */
  return mysnprintf(buffer,buflen,
                    "(&(%s=%s)(%s=%s))",
                    attmap_objectClass,attmap_protocol_objectClass,
                    attmap_protocol_cn,buf2);
}

/* create a search filter for searching a protocol entry
   by uid, return -1 on errors */
static int mkfilter_protocol_bynumber(int protocol,
                                      char *buffer,size_t buflen)
{
  return snprintf(buffer,buflen,
                  "(&(%s=%s)(%s=%d))",
                  attmap_objectClass,attmap_protocol_objectClass,
                  attmap_protocol_ipProtocolNumber,protocol);
}

/* create a search filter for enumerating all protocol
   entries, return -1 on errors */
static int mkfilter_protocol_all(char *buffer,size_t buflen)
{
  return mysnprintf(buffer,buflen,
                    "(%s=%s)",
                    attmap_objectClass,attmap_protocol_objectClass);
}

static void protocol_attrs_init(void)
{
  protocol_attrs[0]=attmap_protocol_cn;
  protocol_attrs[1]=attmap_protocol_ipProtocolNumber;
  protocol_attrs[2]=NULL;
}

static enum nss_status _nss_ldap_parse_proto (LDAPMessage *e,
                       struct ldap_state UNUSED(*pvt),
                       void *result, char *buffer, size_t buflen)
{

  struct protoent *proto = (struct protoent *) result;
  char *number;
  enum nss_status stat;

  stat =
    _nss_ldap_getrdnvalue (e, attmap_protocol_cn, &proto->p_name,
                           &buffer, &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrval (e, attmap_protocol_ipProtocolNumber, &number, &buffer,
                              &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  proto->p_proto = atoi (number);

  stat =
    _nss_ldap_assign_attrvals (e, attmap_protocol_cn, proto->p_name,
                               &proto->p_aliases, &buffer, &buflen, NULL);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  return NSS_STATUS_SUCCESS;
}

/* macros for expanding the NSLCD_PROTOCOL macro */
#define NSLCD_STRING(field)     WRITE_STRING(fp,field)
#define NSLCD_STRINGLIST(field) WRITE_STRINGLIST_NULLTERM(fp,field)
#define NSLCD_INT32(field)      WRITE_INT32(fp,field)
#define PROTOCOL_NAME         result.p_name
#define PROTOCOL_ALIASES      result.p_aliases
#define PROTOCOL_NUMBER       result.p_proto

int nslcd_protocol_byname(TFILE *fp)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  char name[256];
  char filter[1024];
  /* these are here for now until we rewrite the LDAP code */
  struct protoent result;
  char buffer[1024];
  int errnop;
  int retv;
  /* read request parameters */
  READ_STRING_BUF2(fp,name,sizeof(name));
  /* log call */
  log_log(LOG_DEBUG,"nslcd_protocol_byname(%s)",name);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PROTOCOL_BYNAME);
  /* do the LDAP request */
  mkfilter_protocol_byname(name,filter,sizeof(filter));
  protocol_attrs_init();
  retv=_nss_ldap_getbyname(&result,buffer,1024,&errnop,LM_PROTOCOLS,
                           NULL,filter,protocol_attrs,_nss_ldap_parse_proto);
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
  {
    NSLCD_PROTOCOL;
  }
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_protocol_bynumber(TFILE *fp)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  int protocol;
  char filter[1024];
  /* these are here for now until we rewrite the LDAP code */
  struct protoent result;
  char buffer[1024];
  int errnop;
  int retv;
  /* read request parameters */
  READ_INT32(fp,protocol);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_protocol_bynumber(%d)",protocol);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PROTOCOL_BYNUMBER);
  /* do the LDAP request */
  mkfilter_protocol_bynumber(protocol,filter,sizeof(filter));
  protocol_attrs_init();
  retv=_nss_ldap_getbyname(&result,buffer,1024,&errnop,LM_PROTOCOLS,
                           NULL,filter,protocol_attrs,_nss_ldap_parse_proto);
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
  {
    NSLCD_PROTOCOL;
  }
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_protocol_all(TFILE *fp)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  static struct ent_context *protocol_context;
  /* these are here for now until we rewrite the LDAP code */
  struct protoent result;
  char buffer[1024];
  int errnop;
  int retv;
  /* log call */
  log_log(LOG_DEBUG,"nslcd_protocol_all()");
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PROTOCOL_ALL);
  /* initialize context */
  if (_nss_ldap_ent_context_init(&protocol_context)==NULL)
    return -1;
  /* loop over all results */
  protocol_attrs_init();
  while ((retv=nss2nslcd(_nss_ldap_getent(&protocol_context,&result,buffer,1024,&errnop,_nss_ldap_filt_getprotoent,LM_PROTOCOLS,protocol_attrs,_nss_ldap_parse_proto)))==NSLCD_RESULT_SUCCESS)
  {
    /* write the result code */
    WRITE_INT32(fp,retv);
    /* write the entry */
    NSLCD_PROTOCOL;
  }
  /* write the final result code */
  WRITE_INT32(fp,retv);
  WRITE_FLUSH(fp);
  /* FIXME: if a previous call returns what happens to the context? */
  _nss_ldap_enter();
  _nss_ldap_ent_context_release(protocol_context);
  _nss_ldap_leave();
  /* we're done */
  return 0;
}
