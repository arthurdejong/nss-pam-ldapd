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

#ifndef _NSLCD_SERVER_H
#define _NSLCD_SERVER_H 1

#include "nslcd.h"
#include "nslcd-common.h"

/* returns a socket ready to answer requests from the client,
   return <0 on error */
int nslcd_server_open(void);

/* read a request message, returns <0 in case of errors,
   this function closes the socket */
void nslcd_server_handlerequest(int sock);

/* LDAP methods */
/* TODO: these definitions should probably be moved */

/* the caller should take care of opening and closing the stream */
int nslcd_passwd_byname(FILE *fp);

/* the caller should take care of opening and closing the stream */
int nslcd_passwd_byuid(FILE *fp);

/* the caller should take care of opening and closing the stream */
int nslcd_passwd_all(FILE *fp);

int nslcd_alias_byname(FILE *fp);

int nslcd_alias_all(FILE *fp);

#endif /* not _NSLCD_SERVER_H */
