/*
   ethers.c - NSS lookup functions for ethers database

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007, 2008, 2010, 2012 Arthur de Jong
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
  NSS_BYNAME(NSLCD_ACTION_ETHER_BYNAME,
             name,
             read_etherent(fp,result,buffer,buflen,errnop));
}

/* map an ethernet address to the corresponding hostname */
nss_status_t _nss_ldap_getntohost_r(
        const struct ether_addr *addr,struct etherent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYTYPE(NSLCD_ACTION_ETHER_BYETHER,
             *addr,uint8_t[6],
             read_etherent(fp,result,buffer,buflen,errnop));
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
  NSS_GETENT(etherentfp,NSLCD_ACTION_ETHER_ALL,
             read_etherent(etherentfp,result,buffer,buflen,errnop));
}

/* close the stream opened with setetherent() above */
nss_status_t _nss_ldap_endetherent(void)
{
  NSS_ENDENT(etherentfp);
}

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

/* we disable NSS_BUFCHECK because these functions do not use the buffer */
#undef NSS_BUFCHECK
#define NSS_BUFCHECK ;

/* provide a fallback definition */
#ifndef NSS_BUFLEN_ETHERS
#define NSS_BUFLEN_ETHERS HOST_NAME_MAX
#endif /* NSS_BUFLEN_ETHERS */

static nss_status_t read_result(TFILE *fp,void *args,int wantname)
{
  struct etherent result;
  char buffer[NSS_BUFLEN_ETHERS];
  nss_status_t retv;
  int res;
  /* read the result entry from the stream */
  retv=read_etherent(fp,&result,buffer,sizeof(buffer),&NSS_ARGS(args)->erange);
  if (retv!=NSS_STATUS_SUCCESS)
    return retv;
#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN
  /* try to return in string format if requested */
  if ((NSS_ARGS(args)->buf.buffer!=NULL)&&(NSS_ARGS(args)->buf.buflen>0))
  {
    res=snprintf(NSS_ARGS(args)->buf.buffer,NSS_ARGS(args)->buf.buflen,
                 "%s %s",ether_ntoa(&result.e_addr),result.e_name);
    if ((res<0)||(res>=NSS_ARGS(args)->buf.buflen))
      return NSS_STR_PARSE_PARSE;
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.buffer;
    NSS_ARGS(args)->returnlen=strlen(NSS_ARGS(args)->returnval);
    NSS_ARGS(args)->buf.result=NULL;
    return NSS_SUCCESS;
  }
#endif /* not HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */
  /* return the result entry */
  if (wantname)
  {
    strcpy(NSS_ARGS(args)->buf.buffer,result.e_name);
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result=NSS_ARGS(args)->buf.buffer;
    NSS_ARGS(args)->buf.buflen=strlen(NSS_ARGS(args)->returnval);
  }
  else /* address */
  {
    memcpy(NSS_ARGS(args)->buf.result,&result.e_addr,sizeof(result.e_addr));
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;
    NSS_ARGS(args)->buf.result=NULL;
  }
  return NSS_SUCCESS;
}

/* map a hostname to the corresponding ethernet address */
static nss_status_t ethers_gethostton(nss_backend_t UNUSED(*be),void *args)
{
  NSS_BYNAME(NSLCD_ACTION_ETHER_BYNAME,
             NSS_ARGS(args)->key.name,
             read_result(fp,args,0));
}

/* map an ethernet address to the corresponding hostname */
static nss_status_t ethers_getntohost(nss_backend_t UNUSED(*be),void *args)
{
  struct ether_addr *addr=(struct ether_addr *)(NSS_ARGS(args)->key.ether);
  NSS_BYTYPE(NSLCD_ACTION_ETHER_BYETHER,
             *addr,uint8_t[6],
             read_result(fp,args,1));
}

static nss_status_t ethers_destructor(nss_backend_t *be,void UNUSED(*args))
{
  free(be);
  return NSS_STATUS_SUCCESS;
}

static nss_backend_op_t ethers_ops[]={
  ethers_destructor,
  ethers_gethostton,
  ethers_getntohost
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
