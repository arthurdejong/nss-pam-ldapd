/*
   nslcd-client.c - request/response functions for nslcd communication

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

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include "nslcd-client.h"


/* returns a socket to the server or NULL on error (see errno),
   socket should be closed with fclose() */
FILE *nslcd_client_open()
{
  int sock;
  struct sockaddr_un addr;
  FILE *fp;
  /* create a socket */
  if ( (sock=socket(PF_UNIX,SOCK_STREAM,0))<0 )
    return NULL;
  /* create socket address structure */
  addr.sun_family=AF_UNIX;
  strcpy(addr.sun_path,NSLCD_SOCKET);
  /* connect to the socket */
  if (connect(sock,(struct sockaddr *)&addr,sizeof(struct sockaddr_un))<0)
  {
    close(sock);
    return NULL;
  }
  /* create a stream object */
  if ((fp=fdopen(sock,"w+"))==NULL)
  {
    close(sock);
    return NULL;
  }
  /* return the stream */
  return fp;
}


/* helper marco for writes, bails out on any write problems */
#define WRITE(socket, buf, count) \
  if (fwrite(buf, 1, count, socket) < (count)) \
    { return -1; }


/* helper macro for writing 32-bit integer values, uses tmpint32 as
   temporary value (should be defined by caller) */
#define WRITE_INT32(socket, i) \
  tmpint32 = (int32_t)(i); \
  WRITE(socket, &tmpint32, sizeof(int32_t))


/* write a request message, returns <0 in case of errors */
int nslcd_client_writerequest(FILE *sock,int type,const char *name,size_t count)
{
  int32_t tmpint32;
  /* see nslcd.h for protocol definition */
  WRITE_INT32(sock, NSLCD_VERSION);  
  WRITE_INT32(sock, type);
  WRITE_INT32(sock, count);
  WRITE(sock, name, count);
  WRITE_INT32(sock, NSLCD_MAGIC);
  if (fflush(sock)<0)
    return -1;
  return 0; /* success */
}


/* read a response message */
int nslcd_client_readresponse(FILE *sock,int type)
{




  /* see nslcd.h for protocol definition */
  /* TODO: validate */
  return -1; /* not implemented */
}
