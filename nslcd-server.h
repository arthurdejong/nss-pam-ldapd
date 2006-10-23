/*
   nslcd-server.h - server socket routines

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

#include "nslcd.h"

/* returns a socket ready to answer requests from the client,
   return <0 on error */
int nslcd_server_open(void);

/* read a request message, returns <0 in case of errors,
   on errors, socket is closed by callee */
int nslcd_server_readrequest(int socket);

/* write a response message */
int nslcd_client_writeresponse(int socket, void *buf);
