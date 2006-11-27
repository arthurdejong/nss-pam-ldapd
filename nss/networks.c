/*
   networks.c - NSS lookup functions for networks database

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

#include <string.h>
#include <nss.h>
#include <errno.h>

#include "prototypes.h"
#include "common.h"

/* Redifine some ERROR_OUT macros as we also want to set h_errnop. */

#undef ERROR_OUT_BUFERROR
#define ERROR_OUT_BUFERROR(fp) \
  fclose(fp); \
  fp=NULL; \
  *errnop=ERANGE; \
  *h_errnop=TRY_AGAIN; \
  return NSS_STATUS_TRYAGAIN;

#undef ERROR_OUT_NOSUCCESS
#define ERROR_OUT_NOSUCCESS(fp,retv) \
  fclose(fp); \
  fp=NULL; \
  *errnop=ENOENT; \
  *h_errnop=HOST_NOT_FOUND; \
  return nslcd2nss(retv);

/* read a single host entry from the stream, ignoring entries
   that are not AF_INET (IPv4), result is stored in result */
static enum nss_status read_netent(
        FILE *fp,struct netent *result,
        char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  int32_t numaddr,i;
  int readaf;
  size_t bufptr=0;
  enum nss_status retv=NSS_STATUS_NOTFOUND;
  /* read the host entry */
  READ_STRING_BUF(fp,result->n_name);
  READ_STRINGLIST_NULLTERM(fp,result->n_aliases);
  result->n_addrtype=AF_INET;
  /* read number of addresses to follow */
  READ_TYPE(fp,numaddr,int32_t);
  /* go through the address list and filter on af */
  i=0;
  while (--numaddr>=0)
  {
    /* read address family and size */
    READ_INT32(fp,readaf);
    READ_INT32(fp,tmp2int32);
    if ((readaf==AF_INET)&&(tmp2int32==4))
    {
      /* read address */
      READ_INT32(fp,result->n_net);
      /* signal that we've read a proper entry */
      retv=NSS_STATUS_SUCCESS;
    }
    else
    {
      SKIP(fp,tmpint32);
    }
  }
  return retv;
}

enum nss_status _nss_ldap_getnetbyname_r(const char *name,struct netent *result,char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  FILE *fp;
  int32_t tmpint32;
  enum nss_status retv;
  /* set to NO_RECOVERY in case some error is caught */
  *h_errnop=NO_RECOVERY;
  /* open socket and write request */
  OPEN_SOCK(fp);
  WRITE_REQUEST(fp,NSLCD_ACTION_NETWORK_BYNAME);
  WRITE_STRING(fp,name);
  WRITE_FLUSH(fp);
  /* read response */
  READ_RESPONSEHEADER(fp,NSLCD_ACTION_NETWORK_BYNAME);
  READ_RESPONSE_CODE(fp);
  retv=read_netent(fp,result,buffer,buflen,errnop,h_errnop);
  /* check read result */
  if (retv==NSS_STATUS_NOTFOUND)
  {
    *h_errnop=NO_ADDRESS;
    fclose(fp);
    return NSS_STATUS_NOTFOUND;
  }
  else if (retv!=NSS_STATUS_SUCCESS)
    return retv;
  /* close socket and we're done */
  fclose(fp);
  return NSS_STATUS_SUCCESS;
}

/* Note: the af parameter is ignored and is assumed to be AF_INET */
enum nss_status _nss_ldap_getnetbyaddr_r(uint32_t addr,int af,struct netent *result,char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  FILE *fp;
  int32_t tmpint32;
  enum nss_status retv;
  /* set to NO_RECOVERY in case some error is caught */
  *h_errnop=NO_RECOVERY;
  /* open socket and write request */
  OPEN_SOCK(fp);
  WRITE_REQUEST(fp,NSLCD_ACTION_NETWORK_BYADDR);
  /* write the address */
  WRITE_INT32(fp,AF_INET);
  WRITE_INT32(fp,4);
  WRITE_INT32(fp,addr);
  WRITE_FLUSH(fp);
  /* read response */
  READ_RESPONSEHEADER(fp,NSLCD_ACTION_NETWORK_BYADDR);
  READ_RESPONSE_CODE(fp);
  retv=read_netent(fp,result,buffer,buflen,errnop,h_errnop);
  /* check read result */
  if (retv==NSS_STATUS_NOTFOUND)
  {
    *h_errnop=NO_ADDRESS;
    fclose(fp);
    return NSS_STATUS_NOTFOUND;
  }
  else if (retv!=NSS_STATUS_SUCCESS)
    return retv;
  /* close socket and we're done */
  fclose(fp);
  return NSS_STATUS_SUCCESS;
}

/* thread-local file pointer to an ongoing request */
static __thread FILE *netentfp;

enum nss_status _nss_ldap_setnetent(int stayopen)
{
  NSS_SETENT(netentfp,NSLCD_ACTION_NETWORK_ALL);
}

enum nss_status _nss_ldap_getnetent_r(struct netent *result,char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  int32_t tmpint32;
  enum nss_status retv=NSS_STATUS_NOTFOUND;
  /* check that we have a valid file descriptor */
  if (netentfp==NULL)
  {
    *errnop=ENOENT;
    return NSS_STATUS_UNAVAIL;
  }
  /* check until we read an non-empty entry */
  do
  {
    /* read a response */
    READ_RESPONSE_CODE(netentfp);
    retv=read_netent(netentfp,result,buffer,buflen,errnop,h_errnop);
    /* do another loop run if we read an empty address list */
  }
  while ((retv==NSS_STATUS_SUCCESS)||(retv==NSS_STATUS_NOTFOUND));
  return retv;
}

enum nss_status _nss_ldap_endnetent(void)
{
  NSS_ENDENT(netentfp);
}
