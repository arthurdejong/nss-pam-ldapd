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
#include "util.h"
#include "common.h"
#include "log.h"
#include "attmap.h"
#include "ldap-schema.h"

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

/* the attributes to request with searches */
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
                   "(&(%s=%s)(%s=%s))",
                   attmap_objectClass,attmap_ether_objectClass,
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
                   "(&(%s=%s)(%s=%s))",
                   attmap_objectClass,attmap_ether_objectClass,
                   attmap_ether_macAddress,buf2);
}

static int mkfilter_ether_all(char *buffer,size_t buflen)
{
  /* build filter */
  return mysnprintf(buffer,buflen,
                   "(%s=%s)",
                   attmap_objectClass,attmap_ether_objectClass);
}

static void ether_attrs_init(void)
{
  ether_attrs[0]=attmap_ether_cn;
  ether_attrs[1]=attmap_ether_macAddress;
  ether_attrs[2]=NULL;
}

static enum nss_status
_nss_ldap_parse_ether (LDAPMessage * e,
                       struct ldap_state UNUSED(*pvt),
                       void *result, char *buffer, size_t buflen)
{
  struct ether *ether = (struct ether *) result;
  char *saddr;
  enum nss_status stat;
  struct ether_addr *addr;

  stat = _nss_ldap_assign_attrval (e, attmap_ether_cn,
                                   &ether->e_name, &buffer, &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat = _nss_ldap_assign_attrval (e, attmap_ether_macAddress, &saddr,
                                   &buffer, &buflen);

  if (stat != NSS_STATUS_SUCCESS || ((addr = ether_aton (saddr)) == NULL))
    return NSS_STATUS_NOTFOUND;

  memcpy (&ether->e_addr, addr, sizeof (*addr));

  return NSS_STATUS_SUCCESS;
}

/* macros for expanding the NSLCD_ETHER macro */
#define NSLCD_STRING(field)     WRITE_STRING(fp,field)
#define NSLCD_TYPE(field,type)  WRITE_TYPE(fp,field,type)
#define ETHER_NAME            result.e_name
#define ETHER_ADDR            result.e_addr

int nslcd_ether_byname(TFILE *fp)
{
  int32_t tmpint32;
  char name[256];
  char filter[1024];
  /* these are here for now until we rewrite the LDAP code */
  struct ether result;
  char buffer[1024];
  int errnop;
  int retv;
  /* read request parameters */
  READ_STRING_BUF2(fp,name,sizeof(name));
  /* log call */
  log_log(LOG_DEBUG,"nslcd_ether_byname(%s)",name);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_ETHER_BYNAME);
  /* do the LDAP request */
  mkfilter_ether_byname(name,filter,sizeof(filter));
  ether_attrs_init();
  retv=_nss_ldap_getbyname(&result,buffer,1024,&errnop,LM_ETHERS,
                           NULL,filter,ether_attrs,_nss_ldap_parse_ether);
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
  {
    NSLCD_ETHER;
  }
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_ether_byether(TFILE *fp)
{
  int32_t tmpint32;
  struct ether_addr addr;
  char filter[1024];
  /* these are here for now until we rewrite the LDAP code */
  struct ether result;
  char buffer[1024];
  int errnop;
  int retv;
  /* read request parameters */
  READ_TYPE(fp,addr,u_int8_t[6]);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_ether_byether(%s)",ether_ntoa(&addr));
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_ETHER_BYETHER);
  /* do the LDAP request */
  mkfilter_ether_byether(&addr,filter,sizeof(filter));
  ether_attrs_init();
  retv=_nss_ldap_getbyname(&result,buffer,1024,&errnop,LM_ETHERS,
                           NULL,filter,ether_attrs,_nss_ldap_parse_ether);
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
  {
    NSLCD_ETHER;
  }
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_ether_all(TFILE *fp)
{
  int32_t tmpint32;
  static struct ent_context *ether_context;
  /* these are here for now until we rewrite the LDAP code */
  struct ether result;
  char buffer[1024];
  int errnop;
  int retv;
  /* log call */
  log_log(LOG_DEBUG,"nslcd_ether_all()");
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_ETHER_ALL);
  /* initialize context */
  if (_nss_ldap_ent_context_init(&ether_context)==NULL)
    return -1;
  /* loop over all results */
  ether_attrs_init();
  while ((retv=nss2nslcd(_nss_ldap_getent(&ether_context,&result,buffer,1024,&errnop,_nss_ldap_filt_getetherent,LM_ETHERS,ether_attrs,_nss_ldap_parse_ether)))==NSLCD_RESULT_SUCCESS)
  {
    /* write the result */
    WRITE_INT32(fp,retv);
    NSLCD_ETHER;
  }
  /* write the final result code */
  WRITE_INT32(fp,retv);
  WRITE_FLUSH(fp);
  /* FIXME: if a previous call returns what happens to the context? */
  _nss_ldap_enter();
  _nss_ldap_ent_context_release(ether_context);
  _nss_ldap_leave();
  /* we're done */
  return 0;
}
