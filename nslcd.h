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
   The protocol used between the nslcd client and server
   is a simple binary protocol. It is request/response based
   where the client initiates a connection, does a single request
   and closes the connection again. Any mangled messages will be
   silently ignored by the server.

   A request looks like:
     int32 NSLCD_VERSION
     int32 NSLCD_RT_*
     [request parameters if any]
   A response looks like:
     int32 NSLCD_VERSION
     int32 NSLCD_RT_* (the original request type)
     int32 NSLCD_RS_* (response code)
     [result value(s)]
   If a response would return multiple values (e.g. for the
   NSLCD_RT_GETPWDALL function) each return value will be preceded
   by a NSLCD_RS_* value.

   These are the available data types:
     INT32  - 32-bit integer value
     TYPE   - a typed field that is transferred using sizeof()
     STRING - a string length (32bit) followed by the string value
              (not null-terminted)
     LOOP   - a 32-bit number noting the number of entries followed
              by the entries one at a time

   Compound datatypes (such as PASSWD) are defined below as a
   combination of the above types. They are defined as macros so
   they can be expanded to code later on.

   The protocol is described in this generic fashion (instead of just
   transferring the allocated memory) because pointers will not
   be valid between transfers and this also makes the server
   independant of the NSS implementation.
*/

/* used for transferring struct alias information */
#define LDF_ALIAS \
  LDF_STRING(ALIAS_NAME) \
  LDF_LOOP( \
    LDF_STRING(ALIAS_RCPT) \
  )

/* AUTOMOUNT - TBD */

/* used for transferring mac addresses */
#define LDF_ETHER \
  LDF_TYPE(ETHER_ADDR,u_int8_t[6])

/* a group entry from /etc/group (struct group) */
#define LDF_GROUP \
  LDF_STRING(GROUP_NAME) \
  LDF_STRING(GROUP_PASSWD) \
  LDF_TYPE(GROUP_GID,gid_t) \
  LDF_LOOP( \
    LDF_STRING(GROUP_MEMBER) \
  )

/* HOSTS - TBD - gethostbyname - struct hostent - gethostbyaddr - struct in_addr */

/* NETGROUP - TBD */

/* NETWORKS - TBD - struct netent */

/* used for transferring struct passwd information */
#define LDF_PASSWD \
  LDF_STRING(PASSWD_NAME) \
  LDF_STRING(PASSWD_PASSWD) \
  LDF_TYPE(PASSWD_UID,uid_t) \
  LDF_TYPE(PASSWD_GID,gid_t) \
  LDF_STRING(PASSWD_GECOS) \
  LDF_STRING(PASSWD_DIR) \
  LDF_STRING(PASSWD_SHELL)

/* PROTOCOLS - TBD - getprotobyname - struct protoent */

/* for transferring struct rpcent structs */
#define LDF_RPC \
  LDF_STRING(RPC_NAME) \
  LDF_LOOP( \
    LDF_STRING(RPC_ALIAS) \
  ) \
  LDF_TYPE(RPC_NUMBER,int32_t)

/* SERVICES - TBD - getservbyname - struct servent */

/* SHADOW - TBD - getspnam - struct spwd */

/* The location of the socket used for communicating. */
#define NSLCD_SOCKET "/tmp/nslcd.socket"

/* The location of the pidfile used for checking availability of the nslcd. */
#define NSLCD_PIDFILE "/tmp/nslcd.pid"

/* The current version of the protocol. */
#define NSLCD_VERSION 1

/* Request types. */
#define NSLCD_RT_ALIAS_BYNAME           4001
#define NSLCD_RT_GETPWBYNAME            1001
#define NSLCD_RT_GETPWBYUID             1002
#define NSLCD_RT_GETPWALL               1004
#define NSLCD_RT_GETGRBYNAME            2003
#define NSLCD_RT_GETGRBYGID             2004
#define NSLCD_RT_GETHOSTBYNAME          3005
#define NSLCD_RT_GETHOSTBYADDR          3008
#define NSLCD_ACTION_GROUP_BYNAME       5001
#define NSLCD_ACTION_GROUP_BYGID        5002
#define NSLCD_ACTION_GROUP_ALL          5003

/* Request result. */
#define NSLCD_RS_UNAVAIL                2 /* sevice unavailable */
#define NSLCD_RS_NOTFOUND               3 /* key was not found */
#define NSLCD_RS_SUCCESS                0 /* everything ok */

#endif /* not _NSLCD_H */
