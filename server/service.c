/*
   service.c - service entry lookup routines
   This file was part of the nss-ldap library (as ldap-service.c)
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
#include "util.h"
#include "nslcd-server.h"
#include "common.h"
#include "log.h"

/* macros for expanding the NSLCD_SERVICE macro */
#define NSLCD_STRING(field)     WRITE_STRING(fp,field)
#define NSLCD_STRINGLIST(field) WRITE_STRINGLIST_NULLTERM(fp,field)
#define NSLCD_INT32(field)      WRITE_INT32(fp,field)
#define SERVICE_NAME          result->s_name
#define SERVICE_ALIASES       result->s_aliases
#define SERVICE_NUMBER        htons(result->s_port)
#define SERVICE_PROTOCOL      result->s_proto

/* write a single host entry to the stream */
static int write_servent(FILE *fp,struct servent *result)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  NSLCD_SERVICE;
  return 0;
}

static enum nss_status _nss_ldap_parse_serv (LDAPMessage *e,
                      struct ldap_state *state,
                      void *result,char *buffer,size_t buflen)
{
  struct servent *service = (struct servent *)result;
  char *port;
  enum nss_status stat = NSS_STATUS_SUCCESS;

  /* this is complicated and ugly, because some git (me) specified that service
   * entries should expand to two entities (or more) if they have multi-valued
   * ipServiceProtocol fields.
   */

  if (state->ls_type == LS_TYPE_KEY)
    {
      if (state->ls_info.ls_key == NULL)
        {
          /* non-deterministic behaviour is ok */
          stat =
            _nss_ldap_assign_attrval (e, AT (ipServiceProtocol),
                                      &service->s_proto, &buffer, &buflen);
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
      char **vals = _nss_ldap_get_values (e, AT (ipServiceProtocol));
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

  stat =
    _nss_ldap_getrdnvalue (e, ATM (LM_SERVICES, cn), &service->s_name,
                           &buffer, &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    {
      return stat;
    }

  stat =
    _nss_ldap_assign_attrvals (e, ATM (LM_SERVICES, cn), service->s_name,
                               &service->s_aliases, &buffer, &buflen, NULL);
  if (stat != NSS_STATUS_SUCCESS)
    {
      return stat;
    }

  stat =
    _nss_ldap_assign_attrval (e, AT (ipServicePort), &port, &buffer,
                              &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    {
      return stat;
    }

  service->s_port = htons (atoi (port));

  return NSS_STATUS_SUCCESS;
}

int nslcd_service_byname(FILE *fp)
{
  int32_t tmpint32;
  char *name,*protocol;
  struct ldap_args a;
  /* these are here for now until we rewrite the LDAP code */
  struct servent result;
  char buffer[1024];
  int errnop;
  int retv;
  /* read request parameters */
  READ_STRING_ALLOC(fp,name);
  READ_STRING_ALLOC(fp,protocol);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_service_byname(%s,%s)",name,protocol);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_SERVICE_BYNAME);
  /* do the LDAP request */
  LA_INIT(a);
  LA_STRING(a)=name;
  LA_TYPE(a)=(strlen(protocol)==0)?LA_TYPE_STRING:LA_TYPE_STRING_AND_STRING;
  LA_STRING2(a)=protocol;
  retv=nss2nslcd(_nss_ldap_getbyname(&a,&result,buffer,1024,&errnop,
                 ((strlen(protocol)==0)?_nss_ldap_filt_getservbyname:_nss_ldap_filt_getservbynameproto),
                 LM_SERVICES,_nss_ldap_parse_serv));
  /* no more need for these strings */
  free(name);
  free(protocol);
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
    write_servent(fp,&result);
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_service_bynumber(FILE *fp)
{
  int32_t tmpint32;
  int number;
  char *protocol;
  struct ldap_args a;
  /* these are here for now until we rewrite the LDAP code */
  struct servent result;
  char buffer[1024];
  int errnop;
  int retv;
  /* read request parameters */
  READ_INT32(fp,number);
  READ_STRING_ALLOC(fp,protocol);
  /* log call */
  log_log(LOG_DEBUG,"nslcd_service_bynumber(%d,%s)",number,protocol);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_SERVICE_BYNUMBER);
  /* do the LDAP request */
  LA_INIT(a);
  LA_NUMBER(a)=number;
  LA_TYPE(a)=(strlen(protocol)==0)?LA_TYPE_NUMBER:LA_TYPE_NUMBER_AND_STRING;
  LA_STRING2(a)=protocol;
  retv=nss2nslcd(_nss_ldap_getbyname(&a,&result,buffer,1024,&errnop,
                 ((strlen(protocol)==0)?_nss_ldap_filt_getservbyport:_nss_ldap_filt_getservbyportproto),
                 LM_SERVICES,_nss_ldap_parse_serv));
  /* no more need for this string */
  free(protocol);
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
    write_servent(fp,&result);
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_service_all(FILE *fp)
{
  int32_t tmpint32;
  static struct ent_context *serv_context;
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
  if (_nss_ldap_ent_context_init(&serv_context)==NULL)
    return -1;
  /* loop over all results */
  while ((retv=nss2nslcd(_nss_ldap_getent(&serv_context,&result,buffer,1024,&errnop,_nss_ldap_filt_getservent,LM_SERVICES,_nss_ldap_parse_serv)))==NSLCD_RESULT_SUCCESS)
  {
    /* write the result code */
    WRITE_INT32(fp,retv);
    /* write the entry */
    write_servent(fp,&result);
  }
  /* write the final result code */
  WRITE_INT32(fp,retv);
  WRITE_FLUSH(fp);
  /* FIXME: if a previous call returns what happens to the context? */
  _nss_ldap_enter();
  _nss_ldap_ent_context_release(serv_context);
  _nss_ldap_leave();
  /* we're done */
  return 0;
}
