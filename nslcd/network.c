/*
   network.c - network address entry lookup routines
   This file was part of the nss_ldap library (as ldap-network.c)
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <sys/socket.h>
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

#if defined(HAVE_USERSEC_H)
#define MAXALIASES 35
#define MAXADDRSIZE 4
#endif /* HAVE_USERSEC_H */

/* the search base for searches */
const char *network_base = NULL;

/* the search scope for searches */
int network_scope = LDAP_SCOPE_DEFAULT;

/* the basic search filter for searches */
const char *network_filter = "(objectClass=ipNetwork)";

/* the attributes used in searches
 * ( nisSchema.2.7 NAME 'ipNetwork' SUP top STRUCTURAL
 *   DESC 'Abstraction of a network. The distinguished value of
 *   MUST ( cn $ ipNetworkNumber )
 *   MAY ( ipNetmaskNumber $ l $ description $ manager ) )
 */
const char *attmap_network_cn              = "cn";
const char *attmap_network_ipNetworkNumber = "ipNetworkNumber";
/*const char *attmap_network_ipNetmaskNumber = "ipNetmaskNumber"; */

/* the attribute list to request with searches */
static const char *network_attrs[3];

/* create a search filter for searching a network entry
   by name, return -1 on errors */
static int mkfilter_network_byname(const char *name,
                                   char *buffer,size_t buflen)
{
  char buf2[1024];
  /* escape attribute */
  if (myldap_escape(name,buf2,sizeof(buf2)))
    return -1;
  /* build filter */
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%s))",
                    network_filter,
                    attmap_network_cn,buf2);
}

static int mkfilter_network_byaddr(const char *name,
                                   char *buffer,size_t buflen)
{
  char buf2[1024];
  /* escape attribute */
  if (myldap_escape(name,buf2,sizeof(buf2)))
    return -1;
  /* build filter */
  return mysnprintf(buffer,buflen,
                    "(&%s(%s=%s))",
                    network_filter,
                    attmap_network_ipNetworkNumber,buf2);
}

static void network_init(void)
{
  /* set up base */
  if (network_base==NULL)
    network_base=nslcd_cfg->ldc_base;
  /* set up scope */
  if (network_scope==LDAP_SCOPE_DEFAULT)
    network_scope=nslcd_cfg->ldc_scope;
  /* set up attribute list */
  network_attrs[0]=attmap_network_cn;
  network_attrs[1]=attmap_network_ipNetworkNumber;
  network_attrs[2]=NULL;
}

/* write a single network entry to the stream */
static int write_netent(TFILE *fp,struct netent *result)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  /* write the network name */
  WRITE_STRING(fp,result->n_name);
  /* write the alias list */
  WRITE_STRINGLIST_NULLTERM(fp,result->n_aliases);
  /* write the number of addresses */
  WRITE_INT32(fp,1);
  /* write the addresses in network byte order */
  WRITE_INT32(fp,result->n_addrtype);
  WRITE_INT32(fp,sizeof(unsigned long int));
  result->n_net=htonl(result->n_net);
  WRITE_INT32(fp,result->n_net);
  return 0;
}
static enum nss_status _nss_ldap_parse_net(
        MYLDAP_SESSION *session,LDAPMessage *e,struct ldap_state UNUSED(*state),
        void *result,char *buffer,size_t buflen)
{

  char *tmp;
  struct netent *network=(struct netent *)result;
  enum nss_status stat;

  /* IPv6 support ? XXX */
  network->n_addrtype = AF_INET;

  stat=_nss_ldap_assign_attrval(session,e,attmap_network_cn,&network->n_name,&buffer,&buflen);
  if (stat!=NSS_STATUS_SUCCESS)
    return stat;

  stat=_nss_ldap_assign_attrval(session,e,attmap_network_ipNetworkNumber,&tmp,&buffer,&buflen);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  network->n_net = inet_network (tmp);

  stat=_nss_ldap_assign_attrvals(session,e,attmap_network_cn,network->n_name,&network->n_aliases,&buffer,&buflen,NULL);
  if (stat != NSS_STATUS_SUCCESS)
    return stat;

  return NSS_STATUS_SUCCESS;
}

int nslcd_network_byname(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  char name[256];
  char filter[1024];
  int retv;
  struct netent result;
  char buffer[1024];
  /* read request parameters */
  READ_STRING_BUF2(fp,name,sizeof(name));
  /* log call */
  log_log(LOG_DEBUG,"nslcd_network_byname(%s)",name);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_NETWORK_BYNAME);
  /* do the LDAP request */
  mkfilter_network_byname(name,filter,sizeof(filter));
  network_init();
  retv=_nss_ldap_getbyname(session,&result,buffer,1024,
                           network_base,network_scope,filter,network_attrs,
                           _nss_ldap_parse_net);
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
    write_netent(fp,&result);
  /* we're done */
  return 0;
}

int nslcd_network_byaddr(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  int af;
  int len;
  char addr[64],name[1024];
  char filter[1024];
  int retv=456;
  struct netent result;
  char buffer[1024];
  /* read address family */
  READ_INT32(fp,af);
  if (af!=AF_INET)
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
  log_log(LOG_DEBUG,"nslcd_network_byaddr(%s)",name);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_NETWORK_BYADDR);
  /* do requests until we find a result */
  /* TODO: probably do more sofisticated queries */
  while (retv==456)
  {
    /* do the request */
    mkfilter_network_byaddr(name,filter,sizeof(filter));
    network_init();
    retv=_nss_ldap_getbyname(session,&result,buffer,1024,
                             network_base,network_scope,filter,network_attrs,
                             _nss_ldap_parse_net);
    /* if no entry was found, retry with .0 stripped from the end */
    if ((retv==NSLCD_RESULT_NOTFOUND) &&
        (strlen(name)>2) &&
        (strncmp(name+strlen(name)-2,".0",2)==0))
    {
      /* strip .0 and try again */
      name[strlen(name)-2]='\0';
      retv=456;
    }
  }
  /* write the response */
  WRITE_INT32(fp,retv);
  if (retv==NSLCD_RESULT_SUCCESS)
    if (write_netent(fp,&result))
      return -1;
  /* we're done */
  return 0;
}

int nslcd_network_all(TFILE *fp,MYLDAP_SESSION *session)
{
  int32_t tmpint32;
  struct ent_context context;
  /* these are here for now until we rewrite the LDAP code */
  struct netent result;
  char buffer[1024];
  int retv;
  /* log call */
  log_log(LOG_DEBUG,"nslcd_network_all()");
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_NETWORK_ALL);
  /* initialize context */
  _nss_ldap_ent_context_init(&context,session);
  /* loop over all results */
  network_init();
  while ((retv=_nss_ldap_getent(&context,&result,buffer,sizeof(buffer),
                                network_base,network_scope,network_filter,network_attrs,
                                _nss_ldap_parse_net))==NSLCD_RESULT_SUCCESS)
  {
    /* write the result */
    WRITE_INT32(fp,retv);
    if (write_netent(fp,&result))
      return -1;
  }
  /* write the final result code */
  WRITE_INT32(fp,retv);
  /* FIXME: if a previous call returns what happens to the context? */
  _nss_ldap_ent_context_cleanup(&context);
  /* we're done */
  return 0;
}
