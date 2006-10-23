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

#ifndef _NSLCD_CLIENT_H
#define _NSLCD_CLIENT_H 1

#include <stdio.h>

#include "nslcd.h"

/* returns a socket to the server or NULL on error (see errno),
   socket should be closed with fclose() */
FILE *nslcd_client_open(void);

/* write a request message, returns <0 in case of errors */
int nslcd_client_writerequest(FILE *sock,int type,char *name,size_t count);

/* read a response message */
int nslcd_client_readresponse(FILE *sock,void *buf,size_t bufsize);

#endif /* not _NSLCD_CLIENT_H */
