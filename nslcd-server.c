/*
   nslcd-server.c - server socket routines

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

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <malloc.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>

/* temp added for ldap requests */
#include <pwd.h>
#include <ldap.h>
#include "ldap-nss.h"

#include "nslcd-server.h"
#include "log.h"


/* returns a socket ready to answer requests from the client,
   return <0 on error */
int nslcd_server_open(void)
{
  int sock;
  /*int flag;*/
  struct sockaddr_un addr;

  /* create a socket */
  if ( (sock=socket(PF_UNIX,SOCK_STREAM,0))<0 )
  {
    log_log(LOG_ERR,"cannot create socket: %s",strerror(errno));
    exit(1);
  }

  /* create socket address structure */
  addr.sun_family=AF_UNIX;
  strcpy(addr.sun_path,NSLCD_SOCKET);
  
  /* unlink to socket */
  if (unlink(NSLCD_SOCKET)<0)
  {
    log_log(LOG_DEBUG,"unlink() of "NSLCD_SOCKET" failed (ignored): %s",
            strerror(errno));
  }

  /* bind to the socket */
  if (bind(sock,(struct sockaddr *)&addr,sizeof(struct sockaddr_un))<0)
  {
    log_log(LOG_ERR,"bind() to "NSLCD_SOCKET" failed: %s",
            strerror(errno));
    if (close(sock))
      log_log(LOG_WARNING,"problem closing socket: %s",strerror(errno));
    exit(1);
  }

#ifdef NONBLOCKING
  /* we are going to block for now and implement threading later on */
  /* do not block on accept() */
  if ((flag=fcntl(sock,F_GETFL,0))<0)
  {
    log_log(LOG_ERR,"fctnl(F_GETFL) failed: %s",strerror(errno));
    if (close(sock))
      log_log(LOG_WARNING,"problem closing socket: %s",strerror(errno));
    exit(1);
  }
  if (fcntl(sock,F_SETFL,flag|O_NONBLOCK)<0)
  {
    log_log(LOG_ERR,"fctnl(F_SETFL,O_NONBLOCK) failed: %s",strerror(errno));
    if (close(sock))
      log_log(LOG_WARNING,"problem closing socket: %s",strerror(errno));
    exit(1);
  }
#endif /* NONBLOCKING */

  /* close the file descriptor on exit */
  if (fcntl(sock,F_SETFD,FD_CLOEXEC)<0)
  {
    log_log(LOG_ERR,"fctnl(F_SETFL,O_NONBLOCK) failed: %s",strerror(errno));
    if (close(sock))
      log_log(LOG_WARNING,"problem closing socket: %s",strerror(errno));
    exit(1);
  }

#ifdef DONT_FOR_NOW
  /* Set permissions for the socket.  */
  chmod (_PATH_NSCDSOCKET, DEFFILEMODE);
#endif /* DONT_FOR_NOW */

  /* start listening for connections */
  if (listen(sock,SOMAXCONN)<0)
  {
    log_log(LOG_ERR,"listen() failed: %s",strerror(errno));
    if (close(sock))
      log_log(LOG_WARNING,"problem closing socket: %s",strerror(errno));
    exit(1);
  }

  /* we're done */
  return sock;
}

/* FIXME: the following write can fail with EINTR */

/* helper marco for writes, bails out on any write problems */
#define WRITE(sock, buf, count) \
  if (write(sock, buf, count) < (count)) \
    { close(sock); return -1; }

/* helper macro for writing 32-bit integer values, uses tmpint32 as
   temporary value (should be defined by caller) */
#define WRITE_INT32(sock, i) \
  tmpint32 = (int32_t)(i); \
  WRITE(sock, &tmpint32, sizeof(int32_t))

/* FIXME: the following read can fail with EINTR */

#define READ(sock, buf, count) \
  if (read(sock, buf, count) < (count)) \
    { close(sock); return -1; }

/* helper macro for writing 32-bit integer values, uses tmpint32 as
   temporary value (should be defined by caller) */
#define READ_INT32(sock, i) \
  READ(sock, &tmpint32, sizeof(int32_t)); \
  i = tmpint32;
  
 
/* temp decl here */
enum nss_status
_nss_ldap_parse_pw (LDAPMessage * e,
                    struct ldap_state * pvt,
                    void *result, char *buffer, size_t buflen);
 
 
 
/* handle a connection */
static int nslcd_server_handlerequest(int type, char *key)
{
  struct passwd result;
  enum nss_status s;
  char buffer[1024];
  int errnop;
  struct ldap_args args;

  printf("request id=%d key=%s\n", (int)type, key);  

  switch (type)
  {
    case NSLCD_RT_GETPWBYNAME:
      LA_INIT(args);
      LA_STRING(args) = key;
      LA_TYPE(args) = LA_TYPE_STRING;
      s=_nss_ldap_getbyname(&args,&result,buffer,1024,&errnop,_nss_ldap_filt_getpwnam,LM_PASSWD,_nss_ldap_parse_pw);
      /* TODO: print s, result and buffer */
      break;
    default:
      return -1;
  }
  
  return 0; /* success */
}

/* read a request message, returns <0 in case of errors,
   on errors, socket is closed by callee */
int nslcd_server_readrequest(int sock)
{
  int32_t tmpint32, tmp2, type;
  size_t count;
  char *key;
  READ_INT32(sock, tmp2);
  if (tmp2 != NSLCD_VERSION)
    return -1; /* FIXME: report protocol error */
  READ_INT32(sock, type);
  READ_INT32(sock, count);
  key = (char *)malloc(count+1);
  if (key == NULL)
    return -1; /* FIXME: report memory allocation errors */
  READ(sock, key, count);
  key[count]=0;
  READ_INT32(sock, tmp2);
  if (tmp2 != NSLCD_MAGIC)
    return -1; /* FIXME: report protocol error */  

  /* pass the request to the request handler */
  return nslcd_server_handlerequest(type, key);
}

/* read a response message */
int nslcd_client_writeresponse(int sock, void *buf)
{
  /* TODO: validate */
  return -1; /* not implemented */
}


/* probably use fwrite and fiends */
