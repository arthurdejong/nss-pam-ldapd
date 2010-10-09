/*
   ethers.c - NSS lookup functions for ethers database

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007, 2008, 2010 Arthur de Jong
   Copyright (C) 2010 Symas Corporation

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

#include <string.h>
#include <errno.h>

#include "prototypes.h"
#include "common.h"
#include "compat/attrs.h"

/* read an ethernet entry from the stream */
static nss_status_t read_etherent(
        TFILE *fp,struct etherent *result,
        char *buffer,size_t buflen,int *errnop)
{
  int32_t tmpint32;
  size_t bufptr=0;
  READ_BUF_STRING(fp,result->e_name);
  READ_TYPE(fp,result->e_addr,uint8_t[6]);
  return NSS_STATUS_SUCCESS;
}

#ifdef NSS_FLAVOUR_GLIBC

/* map a hostname to the corresponding ethernet address */
nss_status_t _nss_ldap_gethostton_r(
        const char *name,struct etherent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_ETHER_BYNAME,buffer,buflen,
             name,
             read_etherent(fp,result,buffer,buflen,errnop));
  return retv;
}

/* map an ethernet address to the corresponding hostname */
nss_status_t _nss_ldap_getntohost_r(
        const struct ether_addr *addr,struct etherent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYTYPE(NSLCD_ACTION_ETHER_BYETHER,buffer,buflen,
             *addr,uint8_t[6],
             read_etherent(fp,result,buffer,buflen,errnop));
  return retv;
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *etherentfp;

/* open a connection to read all ether entries */
nss_status_t _nss_ldap_setetherent(int UNUSED(stayopen))
{
  NSS_SETENT(etherentfp);
}

/* read a single ethernet entry from the stream */
nss_status_t _nss_ldap_getetherent_r(
        struct etherent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(etherentfp,NSLCD_ACTION_ETHER_ALL,buffer,buflen,
             read_etherent(etherentfp,result,buffer,buflen,errnop));
  return retv;
}

/* close the stream opened with setetherent() above */
nss_status_t _nss_ldap_endetherent(void)
{
  NSS_ENDENT(etherentfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

#ifndef NSS_BUFLEN_ETHERS
#define NSS_BUFLEN_ETHERS 1024
#endif /* NSS_BUFLEN_ETHERS */

#define errnop &errno

/* map a hostname to the corresponding ethernet address */
static nss_status_t _xnss_ldap_gethostton_r(nss_backend_t UNUSED(*be),void *args)
{
  struct etherent result;
  char buffer[NSS_BUFLEN_ETHERS];
  const char *name=(NSS_ARGS(args)->key.name);
  NSS_BYNAME(NSLCD_ACTION_ETHER_BYNAME,buffer,sizeof(buffer),
             name,
             read_etherent(fp,&result,buffer,sizeof(buffer),&errno));
  if (retv==NSS_STATUS_SUCCESS)
  {
    if (NSS_ARGS(args)->buf.result==NULL)
    {
      strcpy(NSS_ARGS(args)->buf.buffer,ether_ntoa(&result.e_addr));
      NSS_ARGS(args)->buf.buflen=strlen(NSS_ARGS(args)->buf.buffer);
      NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.buffer;
      NSS_ARGS(args)->returnlen=strlen(NSS_ARGS(args)->buf.buffer);
      return retv;
    }
    memcpy(NSS_ARGS(args)->buf.result,&result.e_addr,sizeof(result.e_addr));
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;
  }
  return retv;
}

/* map an ethernet address to the corresponding hostname */
static nss_status_t _xnss_ldap_getntohost_r(nss_backend_t UNUSED(*be),void *args)
{
  struct etherent result;
  struct ether_addr *addr=(struct ether_addr *)(NSS_ARGS(args)->key.ether);
  char buffer[NSS_BUFLEN_ETHERS];
  NSS_BYTYPE(NSLCD_ACTION_ETHER_BYETHER,buffer,sizeof(buffer),
             *addr,uint8_t[6],
             read_etherent(fp,&result,buffer,sizeof(buffer),&errno));
  if (retv==NSS_STATUS_SUCCESS)
  {
    if (NSS_ARGS(args)->buf.buffer!=NULL)
    {
      /* TODO: OpenSolaris expects "<macAddress> <host>" */
      /* This output is handled correctly by NSCD,but not */
      /* when NSCD is off. Not an issue with NSS_LDAP,but */
      /* with the frontend. */
      sprintf(NSS_ARGS(args)->buf.buffer,"%s %s",ether_ntoa(addr),result.e_name);
      NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.buffer;
      NSS_ARGS(args)->returnlen=strlen(NSS_ARGS(args)->buf.buffer);
      return retv;
    }
    memcpy(NSS_ARGS(args)->buf.buffer,result.e_name,strlen(result.e_name)+1);
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result=NSS_ARGS(args)->buf.buffer;
    NSS_ARGS(args)->buf.buflen=strlen(result.e_name); /* ?? */
  }
  else
  {
    NSS_ARGS(args)->returnval=NULL;
  }
  return retv;
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *etherentfp;

static nss_status_t _xnss_ldap_setetherent(nss_backend_t UNUSED(*be),void UNUSED(*args))
{
  NSS_SETENT(etherentfp);
}

static nss_status_t _xnss_ldap_getetherent_r(nss_backend_t UNUSED(*be),void *args)
{
  /* TODO: padl uses struct ether,verify */
  struct etherent result;
  char *buffer=NSS_ARGS(args)->buf.buffer;
  size_t buflen=NSS_ARGS(args)->buf.buflen;
  NSS_GETENT(etherentfp,NSLCD_ACTION_ETHER_ALL,buffer,buflen,
             read_etherent(etherentfp,&result,buffer,buflen,&errno));
  if (retv==NSS_STATUS_SUCCESS)
  {
    memcpy(NSS_ARGS(args)->buf.result,&result.e_addr,sizeof(result.e_addr));
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;
  }
  else
    NSS_ARGS(args)->returnval=NULL;
  return retv;
}

static nss_status_t _xnss_ldap_endetherent(nss_backend_t UNUSED(*be),void UNUSED(*args))
{
  NSS_ENDENT(etherentfp);
}

static nss_status_t _xnss_ldap_ethers_destr(nss_backend_t *be,void UNUSED(*args))
{
  free(be);
  return NSS_STATUS_SUCCESS;
}

static nss_backend_op_t ethers_ops[]={
  _xnss_ldap_ethers_destr,
  _xnss_ldap_gethostton_r,
  _xnss_ldap_getntohost_r
};

nss_backend_t *_nss_ldap_ethers_constr(const char UNUSED(*db_name),
      const char UNUSED(*src_name),const char UNUSED(*cfg_args))
{
  nss_backend_t *be;
  if (!(be=(nss_backend_t *)malloc(sizeof(*be))))
    return NULL;
  be->ops=ethers_ops;
  be->n_ops=sizeof(ethers_ops)/sizeof(nss_backend_op_t);
  return be;
}

#endif /* NSS_FLAVOUR_SOLARIS */
