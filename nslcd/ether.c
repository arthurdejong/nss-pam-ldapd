/*
   ether.c - ethernet address entry lookup routines
   This file was part of the nss_ldap library (as ldap-ethers.c)
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
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
#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>
#endif
#ifdef HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif
#ifdef HAVE_NETINET_ETHER_H
#include <netinet/ether.h>
#endif

#include "ldap-nss.h"
#include "common.h"
#include "log.h"
#include "myldap.h"
#include "attmap.h"

#ifndef HAVE_STRUCT_ETHER_ADDR
struct ether_addr {
  u_int8_t ether_addr_octet[6];
};
#endif

struct ether
{
  char *e_name;
  struct ether_addr e_addr;
};

/* ( nisSchema.2.11 NAME 'ieee802Device' SUP top AUXILIARY
 *   DESC 'A device with a MAC address; device SHOULD be
 *         used as a structural class'
 *   MAY macAddress )
 */

/* the search base for searches */
const char *ether_base = NULL;

/* the search scope for searches */
int ether_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *ether_filter = "(objectClass=ieee802Device)";

/* the attributes to request with searches */
const char *attmap_ether_cn          = "cn";
const char *attmap_ether_macAddress  = "macAddress";

/* the attribute list to request with searches */
static const char *ether_attrs[3];

/* create a search filter for searching an ethernet address
   by name, return -1 on errors */
static int mkfilter_ether_byname(const char *name,
                                 char *buffer,size_t buflen)
{
  char buf2[1024];
  /* escape attribute */
  if(myldap_escape(name,buf2,sizeof(buf2)))
    return -1;
  /* build filter */
  return mysnprintf(buffer,buflen,
                   "(&%s(%s=%s))",
                   ether_filter,
                   attmap_ether_cn,buf2);
}

static int mkfilter_ether_byether(const struct ether_addr *addr,
                                  char *buffer,size_t buflen)
{
  char buf2[20];
  /* transform into string */
  if (ether_ntoa_r(addr,buf2)==NULL)
    return -1;
  /* FIXME: this has a bug when the directory has 01:00:0e:...
            and we're looking for 1:0:e:... (leading zeros) */
  /* there should be no characters that need escaping */
  /* build filter */
  return mysnprintf(buffer,buflen,
                   "(&%s(%s=%s))",
                   ether_filter,
                   attmap_ether_macAddress,buf2);
}

static void ether_init(void)
{
  /* set up base */
  if (ether_base==NULL)
    ether_base=nslcd_cfg->ldc_base;
  /* set up scope */
  if (ether_scope==LDAP_SCOPE_DEFAULT)
    ether_scope=nslcd_cfg->ldc_scope;
  /* set up attribute list */
  ether_attrs[0]=attmap_ether_cn;
  ether_attrs[1]=attmap_ether_macAddress;
  ether_attrs[2]=NULL;
}

static enum nss_status _nss_ldap_parse_ether(
        MYLDAP_ENTRY *entry,
        struct ether *ether,char *buffer,
        size_t buflen)
{
  char *saddr;
  enum nss_status stat;
  struct ether_addr *addr;
  stat=_nss_ldap_assign_attrval(entry,attmap_ether_cn,&ether->e_name,&buffer,&buflen);
  if (stat!=NSS_STATUS_SUCCESS)
    return stat;
  stat=_nss_ldap_assign_attrval(entry,attmap_ether_macAddress,&saddr,&buffer,&buflen);
  if ((stat!=NSS_STATUS_SUCCESS)||((addr=ether_aton(saddr))==NULL))
    return NSS_STATUS_NOTFOUND;
  memcpy(&ether->e_addr,addr,sizeof(*addr));
  return NSS_STATUS_SUCCESS;
}

/* macros for expanding the NSLCD_ETHER macro */
#define NSLCD_STRING(field)     WRITE_STRING(fp,field)
#define NSLCD_TYPE(field,type)  WRITE_TYPE(fp,field,type)
#define ETHER_NAME              result.e_name
#define ETHER_ADDR              result.e_addr

static int write_ether(TFILE *fp,MYLDAP_ENTRY *entry)
{
  int32_t tmpint32;
  struct ether result;
  char buffer[1024];
  if (_nss_ldap_parse_ether(entry,&result,buffer,sizeof(buffer))!=NSS_STATUS_SUCCESS)
    return 0;
  /* write the result code */
  WRITE_INT32(fp,NSLCD_RESULT_SUCCESS);
  /* write the entry */
  NSLCD_ETHER;
  return 0;
}

NSLCD_HANDLE(
  ether,byname,
  char name[256];
  char filter[1024];
  READ_STRING_BUF2(fp,name,sizeof(name));,
  log_log(LOG_DEBUG,"nslcd_ether_byname(%s)",name);,
  NSLCD_ACTION_ETHER_BYNAME,
  mkfilter_ether_byname(name,filter,sizeof(filter)),
  write_ether(fp,entry)
)

NSLCD_HANDLE(
  ether,byether,
  struct ether_addr addr;
  char filter[1024];
  READ_TYPE(fp,addr,u_int8_t[6]);,
  log_log(LOG_DEBUG,"nslcd_ether_byether(%s)",ether_ntoa(&addr));,
  NSLCD_ACTION_ETHER_BYETHER,
  mkfilter_ether_byether(&addr,filter,sizeof(filter)),
  write_ether(fp,entry)
)

NSLCD_HANDLE(
  ether,all,
  const char *filter;
  /* no parameters to read */,
  log_log(LOG_DEBUG,"nslcd_ether_all()");,
  NSLCD_ACTION_ETHER_ALL,
  (filter=ether_filter,0),
  write_ether(fp,entry)
)
