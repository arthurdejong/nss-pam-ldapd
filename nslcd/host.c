/*
   host.c - host name lookup routines
   This file was part of the nss_ldap library (as ldap-hosts.c)
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

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
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
#ifdef INET6
#include <resolv/mapv4v6addr.h>
#endif

#include "ldap-nss.h"
#include "util.h"
#include "common.h"
#include "log.h"
#include "attmap.h"
#include "ldap-schema.h"

#ifndef MAXALIASES
#define MAXALIASES 35
#endif

/* write a single host entry to the stream */
static int write_hostent(TFILE *fp,struct hostent *result)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  int numaddr,i;
  /* write the host entry */
  WRITE_STRING(fp,result->h_name);
  /* write the alias list */
  WRITE_STRINGLIST_NULLTERM(fp,result->h_aliases);
  /* write the number of addresses */
  for (numaddr=0;result->h_addr_list[numaddr]!=NULL;numaddr++)
    /*noting*/ ;
  WRITE_INT32(fp,numaddr);
  /* write the addresses */
  for (i=0;i<numaddr;i++)
  {
    WRITE_INT32(fp,result->h_addrtype);
    WRITE_INT32(fp,result->h_length);
    WRITE(fp,result->h_addr_list[i],result->h_length);
  }
  return 0;
}

static enum nss_status
_nss_ldap_parse_host (LDAPMessage * e,
                      struct ldap_state * pvt,
                      void *result, char *buffer, size_t buflen,
                      int af)
{
  /* this code needs reviewing. XXX */
  struct hostent *host = (struct hostent *) result;
  enum nss_status stat;
#ifdef INET6
  char addressbuf[sizeof ("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") *
                  MAXALIASES];
#else
  char addressbuf[sizeof ("255.255.255.255") * MAXALIASES];
#endif
  char *p_addressbuf = addressbuf;
  char **addresses = NULL;
  size_t addresslen = sizeof (addressbuf);
  size_t addresscount = 0;
  char **host_addresses = NULL;
  int i;

  *addressbuf = *buffer = '\0';

  stat = _nss_ldap_assign_attrval (e, attmap_host_cn, &host->h_name,
                                   &buffer, &buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrvals (e, attmap_host_cn, host->h_name,
                               &host->h_aliases, &buffer, &buflen, NULL);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrvals (e, attmap_host_ipHostNumber, NULL, &addresses,
                               &p_addressbuf, &addresslen, &addresscount);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;
  if (addresscount == 0)
    return NSS_STATUS_NOTFOUND;

#ifdef INET6
  if (af == AF_INET6)
    {
      if (bytesleft (buffer, buflen, char *) <
          (size_t) ((addresscount + 1) * IN6ADDRSZ))
          return NSS_STATUS_TRYAGAIN;
    }
  else
    {
      if (bytesleft (buffer, buflen, char *) <
          (size_t) ((addresscount + 1) * INADDRSZ))
          return NSS_STATUS_TRYAGAIN;
    }
#else
  if (bytesleft (buffer, buflen, char *) <
      (size_t) ((addresscount + 1) * INADDRSZ))
      return NSS_STATUS_TRYAGAIN;
#endif

  align (buffer, buflen, char *);
  host_addresses = (char **) buffer;
  host->h_addr_list = host_addresses;
  host_addresses[addresscount] = NULL;

  buffer += (addresscount + 1) * sizeof (char *);
  buflen -= (addresscount + 1) * sizeof (char *);
#ifdef INET6
  host->h_addrtype = 0;
  host->h_length = 0;
#else
  host->h_addrtype = AF_INET;
  host->h_length = INADDRSZ;
#endif

  for (i = 0; i < (int) addresscount; i++)
    {
#ifdef INET6
      char *addr = addresses[i];
      char entdata[16];
      /* from glibc NIS parser. Thanks, Uli. */

      if (af == AF_INET && inet_pton (AF_INET, addr, entdata) > 0)
        {
          if (_res.options & RES_USE_INET6)
            {
              map_v4v6_address ((char *) entdata,
                                (char *) entdata);
              host->h_addrtype = AF_INET6;
              host->h_length = IN6ADDRSZ;
            }
          else
            {
              host->h_addrtype = AF_INET;
              host->h_length = INADDRSZ;
            }
        }
      else if (af == AF_INET6
               && inet_pton (AF_INET6, addr, entdata) > 0)
        {
          host->h_addrtype = AF_INET6;
          host->h_length = IN6ADDRSZ;
        }
      else
        /* Illegal address: ignore line.  */
        continue;

#else
      in_addr_t haddr;
      haddr = inet_addr (addresses[i]);
#endif

      if (buflen < (size_t) host->h_length)
        return NSS_STATUS_TRYAGAIN;

#ifdef INET6
      memcpy (buffer, entdata, host->h_length);
      *host_addresses = buffer;
      buffer += host->h_length;
      buflen -= host->h_length;
#else
      memcpy (buffer, &haddr, INADDRSZ);
      *host_addresses = buffer;
      buffer += INADDRSZ;
      buflen -= INADDRSZ;
#endif

      host_addresses++;
      *host_addresses = NULL;
    }

#ifdef INET6
  /* if host->h_addrtype is not changed, this entry does not
     have the right IP address.  */
  if (host->h_addrtype == 0)
    return NSS_STATUS_NOTFOUND;
#endif

  return NSS_STATUS_SUCCESS;
}

static enum nss_status
_nss_ldap_parse_hostv4 (LDAPMessage * e,
                        struct ldap_state * pvt,
                        void *result, char *buffer, size_t buflen)
{
  return _nss_ldap_parse_host (e, pvt, result, buffer, buflen,
                               AF_INET);
}

#ifdef INET6
static enum nss_status
_nss_ldap_parse_hostv6 (LDAPMessage * e,
                        struct ldap_state * pvt,
                        void *result, char *buffer, size_t buflen)
{
  return _nss_ldap_parse_host (e, pvt, result, buffer, buflen,
                               AF_INET6);
}
#endif

int nslcd_host_byname(TFILE *fp)
{
  int32_t tmpint32;
  char name[256];
  struct ldap_args a;
  int retv;
  struct hostent result;
  char buffer[1024];
  int errnop;
  /* read request parameters */
  READ_STRING_BUF2(fp,name,sizeof(name));
  /* log call */
  log_log(LOG_DEBUG,"nslcd_host_byname(%s)",name);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_HOST_BYNAME);
  /* do the LDAP request */
  LA_INIT(a);
  LA_STRING(a)=name;
  LA_TYPE(a)=LA_TYPE_STRING;
  retv=nss2nslcd(_nss_ldap_getbyname(&a,&result,buffer,1024,&errnop,_nss_ldap_filt_gethostbyname,LM_HOSTS,
#ifdef INET6
                     (af == AF_INET6)?_nss_ldap_parse_hostv6:_nss_ldap_parse_hostv4));
#else
                     _nss_ldap_parse_hostv4));
#endif
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
    write_hostent(fp,&result);
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_host_byaddr(TFILE *fp)
{
  int32_t tmpint32;
  int af;
  int len;
  char addr[64],name[1024];
  struct ldap_args a;
  int retv;
  struct hostent result;
  char buffer[1024];
  int errnop;
  /* read address family */
  READ_INT32(fp,af);
  if ((af!=AF_INET)&&(af!=AF_INET6))
  {
    log_log(LOG_WARNING,"incorrect address family specified: %d",af);
    return -1;
  }
  /* read address length */
  READ_INT32(fp,len);
  if ((len>64)||(len<=0))
  {
    log_log(LOG_WARNING,"address length incorrect: %d",len);
    return -1;
  }
  /* read address */
  READ(fp,addr,len);
  /* translate the address to a string */
  if (inet_ntop(af,addr,name,1024)==NULL)
  {
    log_log(LOG_WARNING,"unable to convert address to string");
    return -1;
  }
  /* log call */
  log_log(LOG_DEBUG,"nslcd_host_byaddr(%s)",name);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_HOST_BYADDR);
  /* do the LDAP request */
  LA_INIT(a);
  LA_STRING(a)=name;
  LA_TYPE(a)=LA_TYPE_STRING;
  retv=nss2nslcd(_nss_ldap_getbyname(&a,&result,buffer,1024,&errnop,_nss_ldap_filt_gethostbyaddr,LM_HOSTS,
#ifdef INET6
                     (af == AF_INET6)?_nss_ldap_parse_hostv6:_nss_ldap_parse_hostv4));
#else
                     _nss_ldap_parse_hostv4));
#endif
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
    write_hostent(fp,&result);
  WRITE_FLUSH(fp);
  /* we're done */
  return 0;
}

int nslcd_host_all(TFILE *fp)
{
  int32_t tmpint32;
  static struct ent_context *host_context;
  /* these are here for now until we rewrite the LDAP code */
  struct hostent result;
  char buffer[1024];
  int errnop;
  int retv;
  /* log call */
  log_log(LOG_DEBUG,"nslcd_host_all()");
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_HOST_ALL);
  /* initialize context */
  if (_nss_ldap_ent_context_init(&host_context)==NULL)
    return -1;
  /* loop over all results */
  while ((retv=nss2nslcd(_nss_ldap_getent(&host_context,&result,buffer,1024,&errnop,_nss_ldap_filt_gethostent,LM_HOSTS,
#ifdef INET6
                             (_res.options&RES_USE_INET6)?_nss_ldap_parse_hostv6:_nss_ldap_parse_hostv4
#else
                             _nss_ldap_parse_hostv4
#endif
                             )))==NSLCD_RESULT_SUCCESS)
  {
    /* write the result */
    WRITE_INT32(fp,retv);
    if (write_hostent(fp,&result))
      return -1;
  }
  /* write the final result code */
  WRITE_INT32(fp,retv);
  WRITE_FLUSH(fp);
  /* FIXME: if a previous call returns what happens to the context? */
  _nss_ldap_enter();
  _nss_ldap_ent_context_release(host_context);
  _nss_ldap_leave();
  /* we're done */
  return 0;
}
