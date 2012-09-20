/*
   protocol.c - network address entry lookup routines
   Parts of this file were part of the nss_ldap library (as ldap-proto.c)
   which has been forked into the nss-pam-ldapd library.

   Copyright (C) 1997-2005 Luke Howard
   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007, 2009, 2010, 2011 Arthur de Jong

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "log.h"
#include "myldap.h"
#include "cfg.h"
#include "attmap.h"

/* ( nisSchema.2.4 NAME 'ipProtocol' SUP top STRUCTURAL
 *   DESC 'Abstraction of an IP protocol. Maps a protocol number
 *         to one or more names. The distinguished value of the cn
 *         attribute denotes the protocol's canonical name'
 *   MUST ( cn $ ipProtocolNumber )
 *    MAY description )
 */

/* the search base for searches */
const char *protocol_bases[NSS_LDAP_CONFIG_MAX_BASES] = { NULL };

/* the search scope for searches */
int protocol_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *protocol_filter = "(objectClass=ipProtocol)";

/* the attributes used in searches */
const char *attmap_protocol_cn               = "cn";
const char *attmap_protocol_ipProtocolNumber = "ipProtocolNumber";

/* the attribute list to request with searches */
static const char *protocol_attrs[3];

static int mkfilter_protocol_byname(const char *name,
                                    char *buffer,size_t buflen)
{
  char safename[300];
  /* escape attribute */
  if (myldap_escape(name,safename,sizeof(safename)))
    return -1;
  /* build filter */
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%s))",
                    protocol_filter,
                    attmap_protocol_cn,safename);
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

void protocol_init(void)
{
  int i;
  /* set up search bases */
  if (protocol_bases[0]==NULL)
    for (i=0;i<NSS_LDAP_CONFIG_MAX_BASES;i++)
      protocol_bases[i]=nslcd_cfg->ldc_bases[i];
  /* set up scope */
  if (protocol_scope==LDAP_SCOPE_DEFAULT)
    protocol_scope=nslcd_cfg->ldc_scope;
  /* set up attribute list */
  protocol_attrs[0]=attmap_protocol_cn;
  protocol_attrs[1]=attmap_protocol_ipProtocolNumber;
  protocol_attrs[2]=NULL;
}

static int write_protocol(TFILE *fp,MYLDAP_ENTRY *entry,const char *reqname)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  const char *name;
  const char **aliases;
  const char **protos;
  char *tmp;
  int proto;
  int i;
  /* get the most canonical name */
  name=myldap_get_rdn_value(entry,attmap_protocol_cn);
  /* get the other names for the protocol */
  aliases=myldap_get_values(entry,attmap_protocol_cn);
  if ((aliases==NULL)||(aliases[0]==NULL))
  {
    log_log(LOG_WARNING,"protocol entry %s does not contain %s value",
                        myldap_get_dn(entry),attmap_protocol_cn);
    return 0;
  }
  /* if the protocol name is not yet found, get the first entry */
  if (name==NULL)
    name=aliases[0];
  /* check case of returned protocol entry */
  if ((reqname!=NULL)&&(strcmp(reqname,name)!=0))
  {
    for (i=0;(aliases[i]!=NULL)&&(strcmp(reqname,aliases[i])!=0);i++)
      /* nothing here */ ;
    if (aliases[i]==NULL)
      return 0; /* neither the name nor any of the aliases matched */
  }
  /* get the protocol number */
  protos=myldap_get_values(entry,attmap_protocol_ipProtocolNumber);
  if ((protos==NULL)||(protos[0]==NULL))
  {
    log_log(LOG_WARNING,"protocol entry %s does not contain %s value",
                        myldap_get_dn(entry),attmap_protocol_ipProtocolNumber);
    return 0;
  }
  else if (protos[1]!=NULL)
  {
    log_log(LOG_WARNING,"protocol entry %s contains multiple %s values",
                        myldap_get_dn(entry),attmap_protocol_ipProtocolNumber);
  }
  errno=0;
  proto=(int)strtol(protos[0],&tmp,0);
  if ((*(protos[0])=='\0')||(*tmp!='\0'))
  {
    log_log(LOG_WARNING,"protocol entry %s contains non-numeric %s value",
                        myldap_get_dn(entry),attmap_protocol_ipProtocolNumber);
    return 0;
  }
  else if (errno!=0)
  {
    log_log(LOG_WARNING,"protocol entry %s contains too large %s value",
                        myldap_get_dn(entry),attmap_protocol_ipProtocolNumber);
    return 0;
  }
  /* write entry */
  WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
  WRITE_STRING(fp,name);
  WRITE_STRINGLIST_EXCEPT(fp,aliases,name);
  WRITE_INT32(fp,proto);
  return 0;
}

NSLCD_HANDLE(
  protocol,byname,
  char name[256];
  char filter[1024];
  READ_STRING(fp,name);,
  log_log(LOG_DEBUG,"nslcd_protocol_byname(%s)",name);,
  NSLCD_ACTION_PROTOCOL_BYNAME,
  mkfilter_protocol_byname(name,filter,sizeof(filter)),
  write_protocol(fp,entry,name)
)

NSLCD_HANDLE(
  protocol,bynumber,
  int protocol;
  char filter[1024];
  READ_INT32(fp,protocol);,
  log_log(LOG_DEBUG,"nslcd_protocol_bynumber(%d)",protocol);,
  NSLCD_ACTION_PROTOCOL_BYNUMBER,
  mkfilter_protocol_bynumber(protocol,filter,sizeof(filter)),
  write_protocol(fp,entry,NULL)
)

NSLCD_HANDLE(
  protocol,all,
  const char *filter;
  /* no parameters to read */,
  log_log(LOG_DEBUG,"nslcd_protocol_all()");,
  NSLCD_ACTION_PROTOCOL_ALL,
  (filter=protocol_filter,0),
  write_protocol(fp,entry,NULL)
)
