/*
   ether.c - ethernet address entry lookup routines
   This file was part of the nss-ldap library (as ldap-ethers.c)
   which has been forked into the nss-ldapd library.

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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
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
#include "nslcd-server.h"
#include "common.h"
#include "log.h"

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

#ifdef NEW
static int write_ether(LDAPMessage *e,struct ldap_state *pvt,FILE *fp)
{
  int stat;
  char buffer[1024];
  /* write NSLCD_STRING(ETHER_NAME) */
  stat=_nss_ldap_write_attrval(fp,e,ATM(LM_ETHERS,cn));
  if (stat!=NSLCD_RESULT_SUCCESS)
    return stat;
  /* write NSLCD_TYPE(ETHER_ADDR,u_int8_t[6]) */
  stat=_nss_ldap_write_attrval_ether(fp,e,AT(macAddress));

  stat = _nss_ldap_assign_attrval (e, AT (macAddress), &saddr,
                                   &buffer, &buflen);
  if (stat != NSS_STATUS_SUCCESS || ((addr = ether_aton (saddr)) == NULL))
    return NSS_STATUS_NOTFOUND;
  memcpy (&ether->e_addr, addr, sizeof (*addr));
  return NSLCD_RESULT_SUCCESS;
}
#endif /* NEW */

static enum nss_status
_nss_ldap_parse_ether (LDAPMessage * e,
                       struct ldap_state * pvt,
                       void *result, char *buffer, size_t buflen)
{
  struct ether *ether = (struct ether *) result;
  char *saddr;
  enum nss_status stat;
  struct ether_addr *addr;

  stat = _nss_ldap_assign_attrval (e, ATM (LM_ETHERS, cn),
                                   &ether->e_name, &buffer, &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat = _nss_ldap_assign_attrval (e, AT (macAddress), &saddr,
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

int nslcd_ether_byname(FILE *fp)
{
  int32_t tmpint32;
  char *name;
  struct ldap_args a;
  /* these are here for now until we rewrite the LDAP code */
  struct ether result;
  char buffer[1024];
  int errnop;
  int retv;
  /* read request parameters */
  READ_STRING_ALLOC(fp,name);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_ether_byname(%s)",name);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_ETHER_BYNAME);
  /* do the LDAP request */
  LA_INIT(a);
  LA_STRING(a)=name;
  LA_TYPE(a)=LA_TYPE_STRING;
  retv=nss2nslcd(_nss_ldap_getbyname(&a,&result,buffer,1024,&errnop,_nss_ldap_filt_gethostton,LM_ETHERS,_nss_ldap_parse_ether));
  /* no more need for this string */
  free(name);
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

int nslcd_ether_byether(FILE *fp)
{
  int32_t tmpint32;
  struct ether_addr addr;
  struct ldap_args a;
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
  LA_INIT(a);
  /* FIXME: this has a bug when the directory has 01:00:0e:...
            and we're looking for 1:0:e:... (leading zeros) */
  LA_STRING(a)=ether_ntoa(&addr);
  LA_TYPE(a)=LA_TYPE_STRING;
  retv=nss2nslcd(_nss_ldap_getbyname(&a,&result,buffer,1024,&errnop,_nss_ldap_filt_getntohost,LM_ETHERS,_nss_ldap_parse_ether));
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

int nslcd_ether_all(FILE *fp)
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
  while ((retv=nss2nslcd(_nss_ldap_getent(&ether_context,&result,buffer,1024,&errnop,_nss_ldap_filt_getetherent,LM_ETHERS,_nss_ldap_parse_ether)))==NSLCD_RESULT_SUCCESS)
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
