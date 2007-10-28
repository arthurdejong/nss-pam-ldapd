/*
   service.c - service entry lookup routines
   This file was part of the nss_ldap library (as ldap-service.c)
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
#include <netinet/in.h>
#ifdef HAVE_SYS_BYTEORDER_H
#include <sys/byteorder.h>
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
#include "common.h"
#include "log.h"
#include "attmap.h"

/* ( nisSchema.2.3 NAME 'ipService' SUP top STRUCTURAL
 *   DESC 'Abstraction an Internet Protocol service.
 *         Maps an IP port and protocol (such as tcp or udp)
 *         to one or more names; the distinguished value of
 *         the cn attribute denotes the service's canonical
 *         name'
 *   MUST ( cn $ ipServicePort $ ipServiceProtocol )
 *   MAY ( description ) )
 */

/* the search base for searches */
const char *service_base = NULL;

/* the search scope for searches */
int service_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *service_filter = "(objectClass=ipService)";

/* the attributes to request with searches */
const char *attmap_service_cn                = "cn";
const char *attmap_service_ipServicePort     = "ipServicePort";
const char *attmap_service_ipServiceProtocol = "ipServiceProtocol";

/* the attribute list to request with searches */
static const char *service_attrs[4];

static int mkfilter_service_byname(const char *name,
                                   const char *protocol,
                                   char *buffer,size_t buflen)
{
  char buf2[1024],buf3[1024];
  /* escape attributes */
  if (myldap_escape(name,buf2,sizeof(buf2)))
    return -1;
  if (*protocol!='\0')
    if (myldap_escape(protocol,buf3,sizeof(buf3)))
      return -1;
  /* build filter */
  if (*protocol!='\0')
    return mysnprintf(buffer,buflen,
                      "(&%s(%s=%s)(%s=%s))",
                      service_filter,
                      attmap_service_cn,buf2,
                      attmap_service_ipServiceProtocol,buf3);
  else
    return mysnprintf(buffer,buflen,
                      "(&%s(%s=%s))",
                      service_filter,
                      attmap_service_cn,buf2);
}

static int mkfilter_service_bynumber(int number,
                                     const char *protocol,
                                     char *buffer,size_t buflen)
{
  char buf3[1024];
  /* escape attribute */
  if (*protocol!='\0')
    if (myldap_escape(protocol,buf3,sizeof(buf3)))
      return -1;
  /* build filter */
  if (*protocol!='\0')
    return mysnprintf(buffer,buflen,
                      "(&%s(%s=%d)(%s=%s))",
                      service_filter,
                      attmap_service_ipServicePort,number,
                      attmap_service_ipServiceProtocol,buf3);
  else
    return mysnprintf(buffer,buflen,
                      "(&%s(%s=%d))",
                      service_filter,
                      attmap_service_ipServicePort,number);
}

static void service_init(void)
{
  /* set up base */
  if (service_base==NULL)
    service_base=nslcd_cfg->ldc_base;
  /* set up scope */
  if (service_scope==LDAP_SCOPE_DEFAULT)
    service_scope=nslcd_cfg->ldc_scope;
  /* set up attribute list */
  service_attrs[0]=attmap_service_cn;
  service_attrs[1]=attmap_service_ipServicePort;
  service_attrs[2]=attmap_service_ipServiceProtocol;
  service_attrs[3]=NULL;
}

static enum nss_status _nss_ldap_parse_serv(
        MYLDAP_ENTRY *entry,const char *protocol,
        struct servent *service,char *buffer,size_t buflen)
{
  char *port;
  enum nss_status stat = NSS_STATUS_SUCCESS;

  /* this is complicated and ugly, because some git (me) specified that service
   * entries should expand to two entities (or more) if they have multi-valued
   * ipServiceProtocol fields.
   */

  if ((protocol!=NULL)&&(*protocol!='\0'))
    {
          register int len;
          len = strlen (protocol);
          if (buflen < (size_t) (len + 1))
            {
              return NSS_STATUS_TRYAGAIN;
            }
          strncpy (buffer, protocol, len);
          buffer[len] = '\0';
          service->s_proto = buffer;
          buffer += len + 1;
          buflen -= len + 1;
    }
  else
    {
      char **vals=myldap_get_values(entry,attmap_service_ipServiceProtocol);
      int len;
      if ((vals==NULL)||(vals[0]==NULL))
        return NSS_STATUS_NOTFOUND;
        /* FIXME: write an antry for each protocol */

          len = strlen (vals[0]);
          strncpy (buffer, vals[0], len);
          buffer[len] = '\0';
          service->s_proto = buffer;
          buffer += len + 1;
          buflen -= len + 1;

    }

  stat=_nss_ldap_getrdnvalue(entry,attmap_service_cn,&service->s_name,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    {
      return stat;
    }

  stat=_nss_ldap_assign_attrvals(entry,attmap_service_cn,service->s_name,&service->s_aliases,&buffer,&buflen,NULL);
  if (stat != NSS_STATUS_SUCCESS)
    {
      return stat;
    }

  stat=_nss_ldap_assign_attrval(entry,attmap_service_ipServicePort,&port,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    {
      return stat;
    }

  service->s_port = atoi(port);

  return NSS_STATUS_SUCCESS;
}

/* macros for expanding the NSLCD_SERVICE macro */
#define NSLCD_STRING(field)     WRITE_STRING(fp,field)
#define NSLCD_STRINGLIST(field) WRITE_STRINGLIST_NULLTERM(fp,field)
#define NSLCD_INT32(field)      WRITE_INT32(fp,field)
#define SERVICE_NAME            result.s_name
#define SERVICE_ALIASES         result.s_aliases
#define SERVICE_NUMBER          result.s_port
#define SERVICE_PROTOCOL        result.s_proto

static int write_service(TFILE *fp,MYLDAP_ENTRY *entry,const char *protocol)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  struct servent result;
  char buffer[1024];
  if (_nss_ldap_parse_serv(entry,protocol,&result,buffer,sizeof(buffer))!=NSS_STATUS_SUCCESS)
    return 0;
  /* write the result code */
  WRITE_INT32(fp,NSLCD_RESULT_SUCCESS);
  /* write the entry */
  NSLCD_SERVICE;
  return 0;
}

NSLCD_HANDLE(
  service,byname,
  char name[256];
  char protocol[256];
  char filter[1024];
  READ_STRING_BUF2(fp,name,sizeof(name));
  READ_STRING_BUF2(fp,protocol,sizeof(protocol));,
  log_log(LOG_DEBUG,"nslcd_service_byname(%s,%s)",name,protocol);,
  NSLCD_ACTION_SERVICE_BYNAME,
  mkfilter_service_byname(name,protocol,filter,sizeof(filter)),
  write_service(fp,entry,protocol)
)

NSLCD_HANDLE(
  service,bynumber,
  int number;
  char protocol[256];
  char filter[1024];
  READ_INT32(fp,number);
  READ_STRING_BUF2(fp,protocol,sizeof(protocol));,
  log_log(LOG_DEBUG,"nslcd_service_bynumber(%d,%s)",number,protocol);,
  NSLCD_ACTION_SERVICE_BYNUMBER,
  mkfilter_service_bynumber(number,protocol,filter,sizeof(filter)),
  write_service(fp,entry,protocol)
)

NSLCD_HANDLE(
  service,all,
  const char *filter;
  /* no parameters to read */,
  log_log(LOG_DEBUG,"nslcd_service_all()");,
  NSLCD_ACTION_SERVICE_ALL,
  (filter=service_filter,0),
  write_service(fp,entry,NULL)
)
