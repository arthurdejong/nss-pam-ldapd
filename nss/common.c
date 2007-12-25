/*
   common.c - common functions for NSS lookups

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007 Arthur de Jong

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

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <nss.h>
#include <string.h>

#include "nslcd.h"
#include "common.h"
#include "common/tio.h"

/* translates a nsklcd return code (as defined in nslcd.h) to
   a nss code (as defined in nss.h) */
enum nss_status nslcd2nss(int32_t code)
{
  switch (code)
  {
    case NSLCD_RESULT_END: return NSS_STATUS_NOTFOUND;
    case NSLCD_RESULT_SUCCESS:  return NSS_STATUS_SUCCESS;
    default:                    return NSS_STATUS_UNAVAIL;
  }
}

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
  readtimeout.tv_sec=2; /* looking up stuff may take some time */
  readtimeout.tv_usec=0;
  writetimeout.tv_sec=1; /* nslcd could be loaded with requests */
  writetimeout.tv_usec=500000;
  /* create a stream object */
  if ((fp=tio_fdopen(sock,&readtimeout,&writetimeout))==NULL)
  {
    (void)close(sock);
    return NULL;
  }
  /* return the stream */
  return fp;
}
