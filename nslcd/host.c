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
#include "common.h"
#include "log.h"
#include "attmap.h"

#ifndef MAXALIASES
#define MAXALIASES 35
#endif

/* ( nisSchema.2.6 NAME 'ipHost' SUP top AUXILIARY
 *   DESC 'Abstraction of a host, an IP device. The distinguished
 *         value of the cn attribute denotes the host's canonical
 *         name. Device SHOULD be used as a structural class'
 *   MUST ( cn $ ipHostNumber )
 *   MAY ( l $ description $ manager ) )
 */

/* the search base for searches */
const char *host_base = NULL;

/* the search scope for searches */
int host_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *host_filter = "(objectClass=ipHost)";

/* the attributes to request with searches */
const char *attmap_host_cn            = "cn";
const char *attmap_host_ipHostNumber  = "ipHostNumber";

/* the attribute list to request with searches */
static const char *host_attrs[3];

/* create a search filter for searching a host entry
   by name, return -1 on errors */
static int mkfilter_host_byname(const char *name,
                                char *buffer,size_t buflen)
{
  char buf2[1024];
  /* escape attribute */
  if (myldap_escape(name,buf2,sizeof(buf2)))
    return -1;
  /* build filter */
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%s))",
                    host_filter,
                    attmap_host_cn,buf2);
}

static int mkfilter_host_byaddr(const char *name,
                                char *buffer,size_t buflen)
{
  char buf2[1024];
  /* escape attribute */
  if (myldap_escape(name,buf2,sizeof(buf2)))
    return -1;
  /* build filter */
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%s))",
                    host_filter,
                    attmap_host_ipHostNumber,buf2);
}

static void host_init(void)
{
  /* set up base */
  if (host_base==NULL)
    host_base=nslcd_cfg->ldc_base;
  /* set up scope */
  if (host_scope==LDAP_SCOPE_DEFAULT)
    host_scope=nslcd_cfg->ldc_scope;
  /* set up attribute list */
  host_attrs[0]=attmap_host_cn;
  host_attrs[1]=attmap_host_ipHostNumber;
  host_attrs[2]=NULL;
}

static enum nss_status _nss_ldap_parse_host(
        MYLDAP_ENTRY *entry,
        struct hostent *host,char *buffer,size_t buflen)
{
  /* this code needs reviewing. XXX */
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

  stat=_nss_ldap_assign_attrval(entry,attmap_host_cn,&host->h_name,
                                &buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat=_nss_ldap_assign_attrvals(entry,attmap_host_cn,host->h_name,
                                 &host->h_aliases,&buffer,&buflen,NULL);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  stat=_nss_ldap_assign_attrvals(entry,attmap_host_ipHostNumber,NULL,&addresses,
                                 &p_addressbuf,&addresslen,&addresscount);
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

/* write a single host entry to the stream */
static int write_host(TFILE *fp,MYLDAP_ENTRY *entry)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  int numaddr,i;
  struct hostent result;
  char buffer[1024];
  if (_nss_ldap_parse_host(entry,&result,buffer,sizeof(buffer))!=NSS_STATUS_SUCCESS)
    return 0;
  /* write the result code */
  WRITE_INT32(fp,NSLCD_RESULT_SUCCESS);
  /* write the host entry */
  WRITE_STRING(fp,result.h_name);
  /* write the alias list */
  WRITE_STRINGLIST_NULLTERM(fp,result.h_aliases);
  /* write the number of addresses */
  for (numaddr=0;result.h_addr_list[numaddr]!=NULL;numaddr++)
    /*noting*/ ;
  WRITE_INT32(fp,numaddr);
  /* write the addresses */
  for (i=0;i<numaddr;i++)
  {
    WRITE_INT32(fp,result.h_addrtype);
    WRITE_INT32(fp,result.h_length);
    WRITE(fp,result.h_addr_list[i],result.h_length);
  }
  return 0;
}

static int read_address(TFILE *fp,char *addr,int *addrlen,int *af)
{
  int32_t tmpint32;
  int len;
  /* read address family */
  READ_INT32(fp,*af);
  if ((*af!=AF_INET)&&(*af!=AF_INET6))
  {
    log_log(LOG_WARNING,"incorrect address family specified: %d",*af);
    return -1;
  }
  /* read address length */
  READ_INT32(fp,len);
  if ((len>*addrlen)||(len<=0))
  {
    log_log(LOG_WARNING,"address length incorrect: %d",len);
    return -1;
  }
  *addrlen=len;
  /* read address */
  READ(fp,addr,len);
  /* we're done */
  return 0;
}

#define READ_ADDRESS(fp,addr,len,af) \
  len=(int)sizeof(addr); \
  if (read_address(fp,addr,&(len),&(af))) \
    return -1;

NSLCD_HANDLE(
  host,byname,
  char name[256];
  char filter[1024];
  READ_STRING_BUF2(fp,name,sizeof(name));,
  log_log(LOG_DEBUG,"nslcd_host_byname(%s)",name);,
  NSLCD_ACTION_HOST_BYNAME,
  mkfilter_host_byname(name,filter,sizeof(filter)),
  write_host(fp,entry)
)

NSLCD_HANDLE(
  host,byaddr,
  int af;
  char addr[64];
  int len=sizeof(addr);
  char name[1024];
  char filter[1024];
  READ_ADDRESS(fp,addr,len,af);
  /* translate the address to a string */
  if (inet_ntop(af,addr,name,sizeof(name))==NULL)
  {
    log_log(LOG_WARNING,"unable to convert address to string");
    return -1;
  },
  log_log(LOG_DEBUG,"nslcd_host_byaddr(%s)",name);,
  NSLCD_ACTION_HOST_BYADDR,
  mkfilter_host_byaddr(name,filter,sizeof(filter)),
  write_host(fp,entry)
)

NSLCD_HANDLE(
  host,all,
  const char *filter;
  /* no parameters to read */,
  log_log(LOG_DEBUG,"nslcd_host_all()");,
  NSLCD_ACTION_HOST_ALL,
  (filter=host_filter,0),
  write_host(fp,entry)
)
