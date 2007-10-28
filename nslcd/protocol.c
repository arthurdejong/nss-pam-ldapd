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

/* the search base for searches */
const char *protocol_base = NULL;

/* the search scope for searches */
int protocol_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *protocol_filter = "(objectClass=ipProtocol)";

/* the attributes used in searches
 * ( nisSchema.2.4 NAME 'ipProtocol' SUP top STRUCTURAL
 *   DESC 'Abstraction of an IP protocol. Maps a protocol number
 *         to one or more names. The distinguished value of the cn
 *         attribute denotes the protocol's canonical name'
 *   MUST ( cn $ ipProtocolNumber )
 *    MAY description )
 */
const char *attmap_protocol_cn               = "cn";
const char *attmap_protocol_ipProtocolNumber = "ipProtocolNumber";

/* the attribute list to request with searches */
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
                    "(&%s(%s=%s))",
                    protocol_filter,
                    attmap_protocol_cn,buf2);
}

/* create a search filter for searching a protocol entry
   by uid, return -1 on errors */
static int mkfilter_protocol_bynumber(int protocol,
                                      char *buffer,size_t buflen)
{
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%d))",
                    protocol_filter,
                    attmap_protocol_ipProtocolNumber,protocol);
}

static void protocol_init(void)
{
  /* set up base */
  if (protocol_base==NULL)
    protocol_base=nslcd_cfg->ldc_base;
  /* set up scope */
  if (protocol_scope==LDAP_SCOPE_DEFAULT)
    protocol_scope=nslcd_cfg->ldc_scope;
  /* set up attribute list */
  protocol_attrs[0]=attmap_protocol_cn;
  protocol_attrs[1]=attmap_protocol_ipProtocolNumber;
  protocol_attrs[2]=NULL;
}

static enum nss_status _nss_ldap_parse_proto(
        MYLDAP_ENTRY *entry,
        struct protoent *proto,char *buffer,size_t buflen)
{
  char *number;
  enum nss_status stat;

  stat=_nss_ldap_getrdnvalue(entry,attmap_protocol_cn,&proto->p_name,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat=_nss_ldap_assign_attrval(entry,attmap_protocol_ipProtocolNumber,&number,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  proto->p_proto = atoi (number);

  stat=_nss_ldap_assign_attrvals (entry,attmap_protocol_cn,proto->p_name,&proto->p_aliases,&buffer,&buflen,NULL);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  return NSS_STATUS_SUCCESS;
}

/* macros for expanding the NSLCD_PROTOCOL macro */
#define NSLCD_STRING(field)     WRITE_STRING(fp,field)
#define NSLCD_STRINGLIST(field) WRITE_STRINGLIST_NULLTERM(fp,field)
#define NSLCD_INT32(field)      WRITE_INT32(fp,field)
#define PROTOCOL_NAME           result.p_name
#define PROTOCOL_ALIASES        result.p_aliases
#define PROTOCOL_NUMBER         result.p_proto

static int write_protocol(TFILE *fp,MYLDAP_ENTRY *entry)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  struct protoent result;
  char buffer[1024];
  if (_nss_ldap_parse_proto(entry,&result,buffer,sizeof(buffer))!=NSS_STATUS_SUCCESS)
    return 0;
  /* write the result code */
  WRITE_INT32(fp,NSLCD_RESULT_SUCCESS);
  /* write the entry */
  NSLCD_PROTOCOL;
  return 0;
}

NSLCD_HANDLE(
  protocol,byname,
  char name[256];
  char filter[1024];
  READ_STRING_BUF2(fp,name,sizeof(name));,
  log_log(LOG_DEBUG,"nslcd_protocol_byname(%s)",name);,
  NSLCD_ACTION_PROTOCOL_BYNAME,
  mkfilter_protocol_byname(name,filter,sizeof(filter)),
  write_protocol(fp,entry)
)

NSLCD_HANDLE(
  protocol,bynumber,
  int protocol;
  char filter[1024];
  READ_INT32(fp,protocol);,
  log_log(LOG_DEBUG,"nslcd_protocol_bynumber(%d)",protocol);,
  NSLCD_ACTION_PROTOCOL_BYNUMBER,
  mkfilter_protocol_bynumber(protocol,filter,sizeof(filter)),
  write_protocol(fp,entry)
)

NSLCD_HANDLE(
  protocol,all,
  const char *filter;
  /* no parameters to read */,
  log_log(LOG_DEBUG,"nslcd_protocol_all()");,
  NSLCD_ACTION_PROTOCOL_ALL,
  (filter=protocol_filter,0),
  write_protocol(fp,entry)
)
