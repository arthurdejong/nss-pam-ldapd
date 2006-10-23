/*
   nslcd.h - file describing client/server protocol 

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

#ifndef _NSLCD_H
#define _NSLCD_H 1

/*
   A request messages basically looks like:
     int32 NSLCD_VERSION
     int32 NSLCD_RT_*
     int32 length(name)
     ...   name
     int32 NSLCD_MAGIC
   (any messages not fitting this should be ignored
    closing the connection)
   A response looks like:
     int32 NSLCD_VERSION
     int32 NSLCD_RT_* (the original request type)
     int32 length(result)
     ... result
     int32 NSLCD_MAGIC
*/

/* TODO: generate this file from a .in file */

/* The location of the socket used for communicating. */
#define NSLCD_SOCKET "/tmp/nslcd.socket"

/* The location of the pidfile used for checking availability of the nslcd. */
#define NSLCD_PIDFILE "/tmp/nslcd.pid"

/* The current version of the protocol. */
#define NSLCD_VERSION 1

/* The magic number passed back and forth. This is to reducte the change of
   handling non-valid requests (e.g. some random data). */
#define NSLCD_MAGIC 0x8642

/* Request types. */
#define NSLCD_RT_GETPWBYNAME  	    	1
#define NSLCD_RT_GETPWBYUID		2
#define NSLCD_RT_GETGRBYNAME		3
#define NSLCD_RT_GETGRBYGID		4
#define NSLCD_RT_GETHOSTBYNAME		5
#define NSLCD_RT_GETHOSTBYNAMEv6	7
#define NSLCD_RT_GETHOSTBYADDR		8
#define NSLCD_RT_GETHOSTBYADDRv6	9
#define NSLCD_RT_LASTDBREQ           	NSLCD_RT_GETHOSTBYADDRv6

/* Request result. */
#define NSLCD_RS_TRYAGAIN               1
#define NSLCD_RS_UNAVAIL                2
#define NSLCD_RS_NOTFOUND               3
#define NSLCD_RS_SUCCESS                0
#define NSLCD_RS_RETURN                 4

#endif /* not _NSLCD_H */
