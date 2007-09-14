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
#include <errno.h>
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

/* macros for expanding the NSLCD_SERVICE macro */
#define NSLCD_STRING(field)     WRITE_STRING(fp,field)
#define NSLCD_STRINGLIST(field) WRITE_STRINGLIST_NULLTERM(fp,field)
#define NSLCD_INT32(field)      WRITE_INT32(fp,field)
#define SERVICE_NAME            result->s_name
#define SERVICE_ALIASES         result->s_aliases
#define SERVICE_NUMBER          htons(result->s_port)
#define SERVICE_PROTOCOL        result->s_proto

static int write_servent(TFILE *fp,struct servent *result)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  NSLCD_SERVICE;
  return 0;
}

static enum nss_status _nss_ldap_parse_serv(
        MYLDAP_SESSION *session,LDAPMessage *e,struct ldap_state *state,
        void *result,char *buffer,size_t buflen)
{
  struct servent *service = (struct servent *)result;
  char *port;
  enum nss_status stat = NSS_STATUS_SUCCESS;

  /* this is complicated and ugly, because some git (me) specified that service
   * entries should expand to two entities (or more) if they have multi-valued
   * ipServiceProtocol fields.
   */

  if (state->ls_type==LS_TYPE_KEY)
    {
      if (state->ls_info.ls_key == NULL)
        {
          /* non-deterministic behaviour is ok */
          stat=_nss_ldap_assign_attrval(session,e,attmap_service_ipServiceProtocol,&service->s_proto,&buffer,&buflen);
          if (stat != NSS_STATUS_SUCCESS)
            {
              return stat;
            }
        }
      else
        {
          register int len;
          len = strlen (state->ls_info.ls_key);
          if (buflen < (size_t) (len + 1))
            {
              return NSS_STATUS_TRYAGAIN;
            }
          strncpy (buffer, state->ls_info.ls_key, len);
          buffer[len] = '\0';
          service->s_proto = buffer;
          buffer += len + 1;
          buflen -= len + 1;
        }
    }
  else
    {
      char **vals=_nss_ldap_get_values(session,e,attmap_service_ipServiceProtocol);
      int len;
      if (vals == NULL)
        {
          state->ls_info.ls_index = -1;
          return NSS_STATUS_NOTFOUND;
        }

      switch (state->ls_info.ls_index)
        {
        case 0:
          /* last time. decrementing ls_index to -1 AND returning !NSS_STATUS_SUCCESS
             will force this entry to be discarded.
           */
          stat = NSS_STATUS_NOTFOUND;
          break;
        case -1:
          /* first time */
          state->ls_info.ls_index = ldap_count_values (vals);
          /* fall off to default ... */
        default:
          len = strlen (vals[state->ls_info.ls_index - 1]);
          if (buflen < (size_t) (len + 1))
            {
              return NSS_STATUS_TRYAGAIN;
            }
          strncpy (buffer, vals[state->ls_info.ls_index - 1], len);
          buffer[len] = '\0';
          service->s_proto = buffer;
          buffer += len + 1;
          buflen -= len + 1;
          stat = NSS_STATUS_SUCCESS;
        }

      ldap_value_free (vals);
      state->ls_info.ls_index--;
    }

  if (stat != NSS_STATUS_SUCCESS)
    {
      return stat;
    }

  stat=_nss_ldap_getrdnvalue(session,e,attmap_service_cn,&service->s_name,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    {
      return stat;
    }

  stat=_nss_ldap_assign_attrvals(session,e,attmap_service_cn,service->s_name,&service->s_aliases,&buffer,&buflen,NULL);
  if (stat != NSS_STATUS_SUCCESS)
    {
      return stat;
    }

  stat=_nss_ldap_assign_attrval(session,e,attmap_service_ipServicePort,&port,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    {
      return stat;
    }

  service->s_port = htons (atoi (port));

  return NSS_STATUS_SUCCESS;
}

int nslcd_service_byname(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  char name[256],protocol[256];
  char filter[1024];
  /* these are here for now until we rewrite the LDAP code */
  struct servent result;
  char buffer[1024];
  int errnop;
  int retv;
  /* read request parameters */
  READ_STRING_BUF2(fp,name,sizeof(name));
  READ_STRING_BUF2(fp,protocol,sizeof(protocol));
  /* log call */
  log_log(LOG_DEBUG,"nslcd_service_byname(%s,%s)",name,protocol);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_SERVICE_BYNAME);
  /* do the LDAP request */
  mkfilter_service_byname(name,protocol,filter,sizeof(filter));
  service_init();
  retv=_nss_ldap_getbyname(session,&result,buffer,1024,&errnop,
                           service_base,service_scope,filter,service_attrs,
                           _nss_ldap_parse_serv);
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
    if (write_servent(fp,&result))
      return -1;
  /* we're done */
  return 0;
}

int nslcd_service_bynumber(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  int number;
  char protocol[256];
  char filter[1024];
  /* these are here for now until we rewrite the LDAP code */
  struct servent result;
  char buffer[1024];
  int errnop;
  int retv;
  /* read request parameters */
  READ_INT32(fp,number);
  READ_STRING_BUF2(fp,protocol,sizeof(protocol));
  /* log call */
  log_log(LOG_DEBUG,"nslcd_service_bynumber(%d,%s)",number,protocol);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_SERVICE_BYNUMBER);
  /* do the LDAP request */
  mkfilter_service_bynumber(number,protocol,filter,sizeof(filter));
  service_init();
  retv=_nss_ldap_getbyname(session,&result,buffer,1024,&errnop,
                           service_base,service_scope,filter,service_attrs,
                           _nss_ldap_parse_serv);
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
    if (write_servent(fp,&result))
      return -1;
  /* we're done */
  return 0;
}

int nslcd_service_all(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  struct ent_context context;
  /* these are here for now until we rewrite the LDAP code */
  struct servent result;
  char buffer[1024];
  int errnop;
  int retv;
  /* log call */
  log_log(LOG_DEBUG,"nslcd_service_all()");
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_SERVICE_ALL);
  /* initialize context */
  _nss_ldap_ent_context_init(&context,session);
  /* loop over all results */
  service_init();
  while ((retv=_nss_ldap_getent(&context,&result,buffer,sizeof(buffer),&errnop,
                                service_base,service_scope,service_filter,service_attrs,
                                _nss_ldap_parse_serv))==NSLCD_RESULT_SUCCESS)
  {
    /* write the result code */
    WRITE_INT32(fp,retv);
    /* write the entry */
    if (write_servent(fp,&result))
      return -1;
  }
  /* write the final result code */
  WRITE_INT32(fp,retv);
  /* FIXME: if a previous call returns what happens to the context? */
  _nss_ldap_ent_context_cleanup(&context);
  /* we're done */
  return 0;
}
