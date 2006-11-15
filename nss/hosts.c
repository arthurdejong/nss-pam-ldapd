/*
   hosts.c - NSS lookup functions for hosts database

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
#include "nslcd-client.h"
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

/* read a single host entry from the stream, filtering on the
   specified address family, result is stored in result 
   it will return NSS_STATUS_NOTFOUND if an empty entry was read
   (no addresses in the address family) */
static enum nss_status host_readhostent(
        FILE *fp,int af,struct hostent *result,
        char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  int32_t tmpint32,tmp2int32,tmp3int32;
  int32_t numaddr,i;
  int readaf;
  size_t bufptr=0;
  /* read the host entry */
  READ_STRING_BUF(fp,result->h_name);
  READ_STRINGLIST_NULLTERM(fp,result->h_aliases);
  result->h_addrtype=af;
  result->h_length=0;
  /* read number of addresses to follow */
  READ_TYPE(fp,numaddr,int32_t);
  /* allocate memory for array */
  /* Note: this may allocate too much memory (e.g. also for
           address records of other address families) but
           this is an easy way to do it */ 
  BUF_CHECK(fp,(numaddr+1)*sizeof(char *));
  result->h_addr_list=(char **)BUF_CUR;
  /* go through the address list and filter on af */
  i=0;
  while (--numaddr>=0)
  {
    /* read address family and size */
    READ_INT32(fp,readaf);
    READ_INT32(fp,tmp2int32);
    if (readaf==af)
    {
      result->h_length=tmp2int32;
      /* allocate room in buffer */
      BUF_CHECK(fp,tmp2int32);
      READ(fp,BUF_CUR,tmp2int32);
      result->h_addr_list[i++]=BUF_CUR;
      BUF_SKIP(tmp2int32);
    }
    else
    {
      SKIP(fp,tmpint32);
    }
  }
  /* null-terminate address list */
  result->h_addr_list[i]=NULL;
  /* check read result */
  if (result->h_addr_list[0]==NULL)
    return NSS_STATUS_NOTFOUND;
  return NSS_STATUS_SUCCESS;
}

/* this function looks up a single host entry and returns all the addresses
   associated with the host in a single address familiy
   name            - IN  - hostname to lookup 
   af              - IN  - address familty to present results for 
   result          - OUT - entry found
   buffer,buflen   - OUT - buffer to store allocated stuff on
   errnop,h_errnop - OUT - for reporting errors */
enum nss_status _nss_ldap_gethostbyname2_r(
        const char *name,int af,struct hostent *result,
        char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  FILE *fp;
  int32_t tmpint32;
  enum nss_status retv;
  /* set to NO_RECOVERY in case some error is caught */
  *h_errnop=NO_RECOVERY;
  /* open socket and write request */
  OPEN_SOCK(fp);
  WRITE_REQUEST(fp,NSLCD_ACTION_HOST_BYNAME);
  WRITE_STRING(fp,name);
  WRITE_FLUSH(fp);
  /* read response */
  READ_RESPONSEHEADER(fp,NSLCD_ACTION_HOST_BYNAME);
  READ_RESPONSE_CODE(fp);
  retv=host_readhostent(fp,af,result,buffer,buflen,errnop,h_errnop);
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

/* this function just calls the gethostbyname2() variant with the address
   familiy set */
enum nss_status _nss_ldap_gethostbyname_r(
        const char *name,struct hostent *result,
        char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  return _nss_ldap_gethostbyname2_r(name,AF_INET,result,buffer,buflen,errnop,h_errnop);
}


/* this function looks up a single host entry and returns all the addresses
   associated with the host in a single address familiy
   addr            - IN  - the address to look up
   len             - IN  - the size of the addr struct
   af              - IN  - address familty the address is specified as
   result          - OUT - entry found
   buffer,buflen   - OUT - buffer to store allocated stuff on
   errnop,h_errnop - OUT - for reporting errors */
enum nss_status _nss_ldap_gethostbyaddr_r(
        const void *addr,socklen_t len,int af,struct hostent *result,
        char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  FILE *fp;
  int32_t tmpint32;
  enum nss_status retv;
  /* set to NO_RECOVERY in case some error is caught */
  *h_errnop=NO_RECOVERY;
  /* open socket and write request */
  OPEN_SOCK(fp);
  WRITE_REQUEST(fp,NSLCD_ACTION_HOST_BYADDR);
  /* write the address */
  WRITE_INT32(fp,af);
  WRITE_INT32(fp,len);
  WRITE(fp,addr,len);
  WRITE_FLUSH(fp);
  /* read response */
  READ_RESPONSEHEADER(fp,NSLCD_ACTION_HOST_BYADDR);
  READ_RESPONSE_CODE(fp);
  retv=host_readhostent(fp,af,result,buffer,buflen,errnop,h_errnop);
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
static __thread FILE *hostentfp;
#define fp hostentfp

enum nss_status _nss_ldap_sethostent(int stayopen)
{
  NSS_SETENT(NSLCD_ACTION_HOST_ALL);
}

/* this function only returns addresses of the AF_INET address family */
enum nss_status _nss_ldap_gethostent_r(
        struct hostent *result,
        char *buffer,size_t buflen,int *errnop,int *h_errnop)
{
  int32_t tmpint32;
  enum nss_status retv=NSS_STATUS_NOTFOUND;
  /* check that we have a valid file descriptor */
  if (fp==NULL)
  {
    *errnop=ENOENT;
    return NSS_STATUS_UNAVAIL;
  }
  /* check until we read an non-empty entry */
  do
  {
    /* read a response */
    READ_RESPONSE_CODE(fp);
    retv=host_readhostent(fp,AF_INET,result,buffer,buflen,errnop,h_errnop);
    /* do another loop run if we read an ok address or */
  }
  while ((retv==NSS_STATUS_SUCCESS)||(retv==NSS_STATUS_NOTFOUND));
  return retv;
}

enum nss_status _nss_ldap_endhostent(void)
{
  NSS_ENDENT();
}
