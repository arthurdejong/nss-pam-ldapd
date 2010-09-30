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

/* map a hostname to the corresponding ethernet address */
#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_nslcd_gethostton_r(
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_gethostton_r(
#endif /* HAVE_NSSWITCH_H */
        const char *name,struct etherent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYNAME(NSLCD_ACTION_ETHER_BYNAME,
             name,
             read_etherent(fp,result,buffer,buflen,errnop));
}

/* map an ethernet address to the corresponding hostname */
#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_nslcd_getntohost_r(
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_getntohost_r(
#endif /* HAVE_NSSWITCH_H */
        const struct ether_addr *addr,struct etherent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_BYTYPE(NSLCD_ACTION_ETHER_BYETHER,
             *addr,uint8_t[6],
             read_etherent(fp,result,buffer,buflen,errnop));
}

/* thread-local file pointer to an ongoing request */
static __thread TFILE *etherentfp;

#ifdef HAVE_NSSWITCH_H
static nss_status_t _nss_ldap_setetherent(
        nss_backend_t *be,void *args)
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_setetherent(int UNUSED(stayopen))
#endif /* HAVE_NSSWITCH_H */
{
  NSS_SETENT(etherentfp);
}

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_nslcd_getetherent_r(
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_getetherent_r(
#endif /* HAVE_NSSWITCH_H */
        struct etherent *result,
        char *buffer,size_t buflen,int *errnop)
{
  NSS_GETENT(etherentfp,NSLCD_ACTION_ETHER_ALL,
             read_etherent(etherentfp,result,buffer,buflen,errnop));
}

#ifdef HAVE_NSSWITCH_H
nss_status_t _nss_ldap_endetherent(nss_backend_t *be,void *args)
#else /* not HAVE_NSSWITCH_H */
nss_status_t _nss_ldap_endetherent(void)
#endif /* HAVE_NSSWITCH_H */
{
  NSS_ENDENT(etherentfp);
}

#ifdef HAVE_NSSWITCH_H

/* Solaris wrapper around _nss_nslcd_gethsotton_r */
static nss_status_t _nss_ldap_gethostton_r(nss_backend_t *be,void *args)
{
  struct etherent result;
  char buffer[NSS_BUFLEN_ETHERS];
  nss_status_t status;
  char *name=(char *)(NSS_ARGS(args)->key.name);
  status=_nss_nslcd_gethostton_r(name,&result,buffer,sizeof(buffer),&errno);
  if (status==NSS_STATUS_SUCCESS)
  {
   /*  if (NSS_ARGS(args)->buf.buffer!=NULL) { */
    if (NSS_ARGS(args)->buf.result==NULL)
    {
      strcpy(NSS_ARGS(args)->buf.buffer,ether_ntoa(&result.e_addr));
      NSS_ARGS(args)->buf.buflen=strlen(NSS_ARGS(args)->buf.buffer);
      NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.buffer;
      NSS_ARGS(args)->returnlen=strlen(NSS_ARGS(args)->buf.buffer);
      return status;
    }
    memcpy(NSS_ARGS(args)->buf.result,&result.e_addr,sizeof(result.e_addr));
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;
  }
  return status;
}

/* Solaris wrapper around _nss_nslcd_getntohost_r */
static nss_status_t _nss_ldap_getntohost_r(nss_backend_t *be,void *args)
{
  struct etherent result;
  struct ether_addr *addr;
  char buffer[NSS_BUFLEN_ETHERS];
  size_t buflen=sizeof(buffer);
  nss_status_t status;
  addr=(struct ether_addr *)(NSS_ARGS(args)->key.ether);
  status=_nss_nslcd_getntohost_r(addr,&result,buffer,buflen,&errno);
  if (status==NSS_STATUS_SUCCESS)
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
      return status;
    }
    memcpy(NSS_ARGS(args)->buf.buffer,result.e_name,strlen(result.e_name)+1);
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result=NSS_ARGS(args)->buf.buffer;
    NSS_ARGS(args)->buf.buflen=strlen(result.e_name);
  }
  else
  {
    NSS_ARGS(args)->returnval=NULL;
  }
  return status;
}

static nss_status_t _nss_ldap_getetherent_r(nss_backend_t *be,void *args)
{
  /* TODO: cns3 uses struct ether,verify */
  struct etherent result;
  char *buffer;
  size_t buflen;
  int errnop;
  nss_status_t status;
  buffer=NSS_ARGS(args)->buf.buffer;
  buflen=NSS_ARGS(args)->buf.buflen;
  status=_nss_nslcd_getetherent_r(&result,buffer,buflen,&errnop);
  if (status==NSS_STATUS_SUCCESS)
  {
    memcpy(NSS_ARGS(args)->buf.result,&result.e_addr,sizeof(result.e_addr));
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result;
  }
  else
    NSS_ARGS(args)->returnval=NULL;
  return status;
}

static nss_status_t _nss_ldap_ethers_destr(nss_backend_t *ether_context,void *args)
{
  return _nss_ldap_default_destr(ether_context,args);
}

static nss_backend_op_t ethers_ops[]={
  _nss_ldap_ethers_destr,
  _nss_ldap_gethostton_r,
  _nss_ldap_getntohost_r
};

nss_backend_t *_nss_ldap_ethers_constr(const char *db_name,const char *src_name,const char *cfg_args)
{
  nss_ldap_backend_t *be;
  if (!(be=(nss_ldap_backend_t *)malloc(sizeof(*be))))
    return NULL;
  be->ops=ethers_ops;
  be->n_ops=sizeof(ethers_ops)/sizeof(nss_backend_op_t);
  if (_nss_ldap_default_constr(be)!=NSS_STATUS_SUCCESS)
    return NULL;
  return (nss_backend_t *)be;
}

#endif /* HAVE_NSSWITCH_H */
