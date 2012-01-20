/*
   rpc.c - rpc name lookup routines
   Parts of this file were part of the nss_ldap library (as ldap-rpc.c) which
   has been forked into the nss-pam-ldapd library.

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
const char *rpc_bases[NSS_LDAP_CONFIG_MAX_BASES] = { NULL };

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
  char safename[300];
  /* escape attribute */
  if (myldap_escape(name,safename,sizeof(safename)))
    return -1;
  /* build filter */
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%s))",
                    rpc_filter,
                    attmap_rpc_cn,safename);
}

static int mkfilter_rpc_bynumber(int number,
                                 char *buffer,size_t buflen)
{
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%d))",
                    rpc_filter,
                    attmap_rpc_oncRpcNumber,number);
}

void rpc_init(void)
{
  int i;
  /* set up search bases */
  if (rpc_bases[0]==NULL)
    for (i=0;i<NSS_LDAP_CONFIG_MAX_BASES;i++)
      rpc_bases[i]=nslcd_cfg->ldc_bases[i];
  /* set up scope */
  if (rpc_scope==LDAP_SCOPE_DEFAULT)
    rpc_scope=nslcd_cfg->ldc_scope;
  /* set up attribute list */
  rpc_attrs[0]=attmap_rpc_cn;
  rpc_attrs[1]=attmap_rpc_oncRpcNumber;
  rpc_attrs[2]=NULL;
}

/* write a single rpc entry to the stream */
static int write_rpc(TFILE *fp,MYLDAP_ENTRY *entry,const char *reqname)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  const char *name;
  const char **aliases;
  const char **numbers;
  char *tmp;
  int number;
  int i;
  /* get the most canonical name */
  name=myldap_get_rdn_value(entry,attmap_rpc_cn);
  /* get the other names for the rpc entries */
  aliases=myldap_get_values(entry,attmap_rpc_cn);
  if ((aliases==NULL)||(aliases[0]==NULL))
  {
    log_log(LOG_WARNING,"rpc entry %s does not contain %s value",
                        myldap_get_dn(entry),attmap_rpc_cn);
    return 0;
  }
  /* if the rpc name is not yet found, get the first entry */
  if (name==NULL)
    name=aliases[0];
  /* check case of returned rpc entry */
  if ((reqname!=NULL)&&(strcmp(reqname,name)!=0))
  {
    for (i=0;(aliases[i]!=NULL)&&(strcmp(reqname,aliases[i])!=0);i++)
      /* nothing here */ ;
    if (aliases[i]==NULL)
      return 0; /* neither the name nor any of the aliases matched */
  }
  /* get the rpc number */
  numbers=myldap_get_values(entry,attmap_rpc_oncRpcNumber);
  if ((numbers==NULL)||(numbers[0]==NULL))
  {
    log_log(LOG_WARNING,"rpc entry %s does not contain %s value",
                        myldap_get_dn(entry),attmap_rpc_oncRpcNumber);
    return 0;
  }
  else if (numbers[1]!=NULL)
  {
    log_log(LOG_WARNING,"rpc entry %s contains multiple %s values",
                        myldap_get_dn(entry),attmap_rpc_oncRpcNumber);
  }
  errno=0;
  number=(int)strtol(numbers[0],&tmp,0);
  if ((*(numbers[0])=='\0')||(*tmp!='\0'))
  {
    log_log(LOG_WARNING,"rpc entry %s contains non-numeric %s value",
                        myldap_get_dn(entry),attmap_rpc_oncRpcNumber);
    return 0;
  }
  else if (errno!=0)
  {
    log_log(LOG_WARNING,"rpc entry %s contains too large %s value",
                        myldap_get_dn(entry),attmap_rpc_oncRpcNumber);
    return 0;
  }
  /* write the entry */
  WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
  WRITE_STRING(fp,name);
  WRITE_STRINGLIST_EXCEPT(fp,aliases,name);
  WRITE_INT32(fp,number);
  return 0;
}

NSLCD_HANDLE(
  rpc,byname,
  char name[256];
  char filter[1024];
  READ_STRING(fp,name);,
  log_log(LOG_DEBUG,"nslcd_rpc_byname(%s)",name);,
  NSLCD_ACTION_RPC_BYNAME,
  mkfilter_rpc_byname(name,filter,sizeof(filter)),
  write_rpc(fp,entry,name)
)

NSLCD_HANDLE(
  rpc,bynumber,
  int number;
  char filter[1024];
  READ_INT32(fp,number);,
  log_log(LOG_DEBUG,"nslcd_rpc_bynumber(%d)",number);,
  NSLCD_ACTION_RPC_BYNUMBER,
  mkfilter_rpc_bynumber(number,filter,sizeof(filter)),
  write_rpc(fp,entry,NULL)
)

NSLCD_HANDLE(
  rpc,all,
  const char *filter;
  /* no parameters to read */,
  log_log(LOG_DEBUG,"nslcd_rpc_all()");,
  NSLCD_ACTION_RPC_ALL,
  (filter=rpc_filter,0),
  write_rpc(fp,entry,NULL)
)
