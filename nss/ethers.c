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

#ifndef NSS_BUFLEN_ETHERS
#define NSS_BUFLEN_ETHERS 1024
#endif /* NSS_BUFLEN_ETHERS */

static nss_status_t read_etherstring(TFILE *fp,nss_XbyY_args_t *args)
{
  /* TODO: padl uses struct ether, verify */
  struct etherent result;
  nss_status_t retv;
  char *buffer;
  size_t buflen;
  /* read the etherent */
  retv=read_etherent(fp,&result,NSS_ARGS(args)->buf.buffer,args->buf.buflen,&errno);
  if (retv!=NSS_STATUS_SUCCESS)
    return retv;
  /* allocate a temporary buffer */
  buflen=args->buf.buflen;
  buffer=(char *)malloc(buflen);
  /* build the formatted string */
  /* FIXME: implement proper buffer size checking */
  /* TODO: OpenSolaris expects "<macAddress> <host>" */
  /* This output is handled correctly by NSCD,but not */
  /* when NSCD is off. Not an issue with NSS_LDAP,but */
  /* with the frontend. */
  sprintf(buffer,"%s %s",ether_ntoa(&result.e_addr),result.e_name);
  /* copy the result back to the result buffer and free the temporary one */
  strcpy(NSS_ARGS(args)->buf.buffer,buffer);
  free(buffer);
  NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.buffer;
  NSS_ARGS(args)->returnlen=strlen(NSS_ARGS(args)->buf.buffer);
  return NSS_STATUS_SUCCESS;
}

#define READ_RESULT(fp) \
  NSS_ARGS(args)->buf.result? \
    read_etherent(fp,(struct etherent *)NSS_ARGS(args)->buf.result,NSS_ARGS(args)->buf.buffer,NSS_ARGS(args)->buf.buflen,&errno): \
    read_etherstring(fp,args); \
  if (NSS_ARGS(args)->buf.result) \
    NSS_ARGS(args)->returnval=NSS_ARGS(args)->buf.result

/* map a hostname to the corresponding ethernet address */
static nss_status_t get_gethostton(nss_backend_t UNUSED(*be),void *args)
{
  NSS_BYNAME(NSLCD_ACTION_ETHER_BYNAME,
             NSS_ARGS(args)->key.name,
             READ_RESULT(fp));
}

/* map an ethernet address to the corresponding hostname */
static nss_status_t get_getntohost(nss_backend_t UNUSED(*be),void *args)
{
  struct ether_addr *addr=(struct ether_addr *)(NSS_ARGS(args)->key.ether);
  NSS_BYTYPE(NSLCD_ACTION_ETHER_BYETHER,
             *addr,uint8_t[6],
             READ_RESULT(fp));
}

static nss_status_t destructor(nss_backend_t *be,void UNUSED(*args))
{
  free(be);
  return NSS_STATUS_SUCCESS;
}

static nss_backend_op_t ethers_ops[]={
  destructor,
  get_gethostton,
  get_getntohost
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
