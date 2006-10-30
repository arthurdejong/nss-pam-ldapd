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
#define WRITE(fp,buf,count) \
  if (fwrite(buf,1,count,fp)<1) \
    { return -1; }


/* helper macro for writing 32-bit integer values, uses tmpint32 as
   temporary value (should be defined by caller) */
#define WRITE_INT32(fp,i) \
  tmpint32=(int32_t)(i); \
  WRITE(fp,&tmpint32,sizeof(int32_t))


/* write a request message, returns <0 in case of errors */
int nslcd_client_writerequest(FILE *fp,int type,const char *name,size_t count)
{
  int32_t tmpint32;
  /* see nslcd.h for protocol definition */
  WRITE_INT32(fp,NSLCD_VERSION);  
  WRITE_INT32(fp,type);
  WRITE_INT32(fp,count);
  WRITE(fp,name,count);
  if (fflush(fp)<0)
    return -1;
  return 0; /* success */
}

/* read a response message, return a NSLCD_RS_* status,
   this function does not close stream on error,
   stream status is undetermined */
int nslcd_client_readresponse(FILE *fp,int type)
{
  int32_t tmp;
  /* read the protocol version */
  if (fread(&tmp,sizeof(int32_t),1,fp)<1)
    return -1;
  if (tmp != NSLCD_VERSION)
    return -1;
  /* read the original request type */
  if (fread(&tmp,sizeof(int32_t),1,fp)<1)
    return -1;
  if (tmp != type)
    return -1;
  /* read the response code */
  if (fread(&tmp,sizeof(int32_t),1,fp)<1)
    return -1;
  /* TODO: check that we have a valid code */
  return tmp;
}
