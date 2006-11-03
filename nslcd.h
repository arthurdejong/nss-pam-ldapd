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
   The protocol used between the nslcd client and server is a simple binary
   protocol. It is request/response based where the client initiates a
   connection, does a single request and closes the connection again. Any
   mangled or not understood messages will be silently ignored by the server.

   A request looks like:
     int32 NSLCD_VERSION
     int32 NSLCD_ACTION_*
     [request parameters if any]
   A response looks like:
     int32 NSLCD_VERSION
     int32 NSLCD_ACTION_* (the original request type)
     int32 NSLCD_RESULT_* (response code)
     [result value(s)]
   If a response would return multiple values (e.g. for NSLCD_ACTION_*_ALL
   functions) each return value will be preceded by a NSLCD_RESULT_* value.

   These are the available data types:
     INT32  - 32-bit integer value
     TYPE   - a typed field that is transferred using sizeof()
     STRING - a string length (32bit) followed by the string value (not
              null-terminted)
     STRINGLIST - a 32-bit number noting the number of strings followed by the
                  strings one at a time

   Compound datatypes (such as PASSWD) are defined below as a combination of
   the above types. They are defined as macros so they can be expanded to code
   later on.

   The protocol is described in this generic fashion (instead of just
   transferring the allocated memory) because pointers will not be valid
   between transfers and this also makes the server independant of the NSS
   implementation.
*/

/* used for transferring alias information */
#define LDF_ALIAS \
  LDF_STRING(ALIAS_NAME) \
  LDF_STRINGLIST(ALIAS_RCPTS)

/* AUTOMOUNT - TBD */

/* used for transferring mac addresses */
#define LDF_ETHER \
  LDF_TYPE(ETHER_ADDR,u_int8_t[6])

/* used for transferring group and membership information */
#define LDF_GROUP \
  LDF_STRING(GROUP_NAME) \
  LDF_STRING(GROUP_PASSWD) \
  LDF_TYPE(GROUP_GID,gid_t) \
  LDF_STRINGLIST(GROUP_MEMBERS)

/* used for storing address information for the host database */
/* Note: this marcos is not expanded to code, check manually */
#define LDF_ADDRESS \
  LDF_INT32(ADDRESS_TYPE) /* type of address: e.g. AF_INET or AF_INET6 */ \
  LDF_INT32(ADDRESS_LEN)  /* length of the address to follow */ \
  LDF_BUF(ADDRESS_ADDR)   /* the address itself in network byte order */  

/* used for transferring host (/etc/hosts) information */
/* Note: this marcos is not expanded to code, check manually */
#define LDF_HOST \
  LDF_STRING(HOST_NAME) \
  LDF_STRINGLIST(HOST_ALIASES) \
  LDF_ADDRESSLIST(HOST_ADDRS)

/* NETGROUP - TBD */

/* NETWORKS - TBD - struct netent */

/* used for transferring user (/etc/passwd) information */
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
  LDF_STRINGLIST(RPC_ALIASES) \
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
#define NSLCD_ACTION_ALIAS_BYNAME       4001
#define NSLCD_ACTION_ALIAS_ALL          4002
#define NSLCD_ACTION_GROUP_BYNAME       5001
#define NSLCD_ACTION_GROUP_BYGID        5002
#define NSLCD_ACTION_GROUP_BYMEMBER     5003
#define NSLCD_ACTION_GROUP_ALL          5004
#define NSLCD_ACTION_HOST_BYNAME        6001
#define NSLCD_ACTION_HOST_BYADDR        6002
#define NSLCD_ACTION_HOST_ALL           6005
#define NSLCD_ACTION_PASSWD_BYNAME      1001
#define NSLCD_ACTION_PASSWD_BYUID       1002
#define NSLCD_ACTION_PASSWD_ALL         1004

/* Request result codes. */
#define NSLCD_RESULT_NOTFOUND              3 /* key was not found */
#define NSLCD_RESULT_SUCCESS               0 /* everything ok */

/* We need this for now, get rid of it later. */
#define NSLCD_RESULT_UNAVAIL               2 /* sevice unavailable */

#endif /* not _NSLCD_H */
