/*
   nslcd-prot.c - common functions for NSLCD lookups

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007, 2008 Arthur de Jong

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

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif /* HAVE_STDINT_H */
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

#include "nslcd.h"
#include "nslcd-prot.h"

/* buffer sizes for I/O */
#define READBUFFER_MINSIZE 1024
#define READBUFFER_MAXSIZE 2*1024*1024
#define WRITEBUFFER_MINSIZE 32
#define WRITEBUFFER_MAXSIZE 32

/* Note that the READBUFFER_MAXSIZE should be large enough to hold any single
   result entity as defined in nslcd.h because the get*ent() functions expect
   to be able to tio_reset() the stream to re-read the current entity.
   Since group entities can grow arbitrarily large, this setting limits the
   number of users that can be put in a group. */

/* returns a socket to the server or NULL on error (see errno),
   socket should be closed with fclose() */
TFILE *nslcd_client_open()
{
  int sock;
  struct sockaddr_un addr;
  struct timeval readtimeout,writetimeout;
  TFILE *fp;
  /* create a socket */
  if ( (sock=socket(PF_UNIX,SOCK_STREAM,0))<0 )
    return NULL;
  /* create socket address structure */
  memset(&addr,0,sizeof(struct sockaddr_un));
  addr.sun_family=AF_UNIX;
  strncpy(addr.sun_path,NSLCD_SOCKET,sizeof(addr.sun_path));
  addr.sun_path[sizeof(addr.sun_path)-1]='\0';
  /* connect to the socket */
  if (connect(sock,(struct sockaddr *)&addr,(socklen_t)sizeof(struct sockaddr_un))<0)
  {
    (void)close(sock);
    return NULL;
  }
  /* set the timeouts */
  readtimeout.tv_sec=60; /* looking up stuff may take some time */
  readtimeout.tv_usec=0;
  writetimeout.tv_sec=10; /* nslcd could be loaded with requests */
  writetimeout.tv_usec=0;
  /* create a stream object */
  if ((fp=tio_fdopen(sock,&readtimeout,&writetimeout,
                     READBUFFER_MINSIZE,READBUFFER_MAXSIZE,
                     WRITEBUFFER_MINSIZE,WRITEBUFFER_MAXSIZE))==NULL)
  {
    (void)close(sock);
    return NULL;
  }
  /* return the stream */
  return fp;
}
