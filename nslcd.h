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
              null-terminted) the string itself is assumed to be UTF-8
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
#define LDF_AUTOMOUNT \
  LDF_STRING(AUTOMOUNT_KEY) \
  LDF_STRING(AUTOMOUNT_INFO)

/* used for transferring mac addresses */
#define LDF_ETHER \
  LDF_STRING(ETHER_NAME) \
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
/* Note: this marco is not expanded to code, check manually */
#define LDF_HOST \
  LDF_STRING(HOST_NAME) \
  LDF_STRINGLIST(HOST_ALIASES) \
  LDF_ADDRESSLIST(HOST_ADDRS)

/* used for transferring netgroup entries one at a time */
#define LDF_NETGROUP \
  LDF_STRING(NETGROUP_HOST) \
  LDF_STRING(NETGROUP_USER) \
  LDF_STRING(NETGROUP_DOMAIN)

/* user for transferring network (/etc/networks) information */
/* Note: this marco is not expanded to code, check manually */
#define LDF_NETWORK \
  LDF_STRING(NETWORK_NAME) \
  LDF_STRINGLIST(NETWORK_ALIASES) \
  LDF_ADDRESSLIST(NETWORK_ADDRS)

/* used for transferring user (/etc/passwd) information */
#define LDF_PASSWD \
  LDF_STRING(PASSWD_NAME) \
  LDF_STRING(PASSWD_PASSWD) \
  LDF_TYPE(PASSWD_UID,uid_t) \
  LDF_TYPE(PASSWD_GID,gid_t) \
  LDF_STRING(PASSWD_GECOS) \
  LDF_STRING(PASSWD_DIR) \
  LDF_STRING(PASSWD_SHELL)

/* used for transferring protocol information */
#define LDF_PROTOCOL \
  LDF_STRING(PROTOCOL_NAME) \
  LDF_STRINGLIST(PROTOCOL_ALIASES) \
  LDF_INT32(PROTOCOL_NUMBER)

/* for transferring struct rpcent structs */
#define LDF_RPC \
  LDF_STRING(RPC_NAME) \
  LDF_STRINGLIST(RPC_ALIASES) \
  LDF_INT32(RPC_NUMBER)

/* for transferring struct servent informatio */
#define LDF_SERVICE \
  LDF_STRING(SERVICE_NAME) \
  LDF_STRINGLIST(SERVICE_ALIASES) \
  LDF_INT32(SERVICE_NUMBER) \
  LDF_STRING(SERVICE_PROTOCOL)

/* used for transferring account (/etc/shadow) information */
#define LDF_SHADOW \
  LDF_STRING(SHADOW_NAME) \
  LDF_STRING(SHADOW_PASSWD) \
  LDF_INT32(SHADOW_LASTCHANGE) \
  LDF_INT32(SHADOW_MINDAYS) \
  LDF_INT32(SHADOW_MAXDAYS) \
  LDF_INT32(SHADOW_WARN) \
  LDF_INT32(SHADOW_INACT) \
  LDF_INT32(SHADOW_EXPIRE) \
  LDF_INT32(SHADOW_FLAG)

/* The location of the socket used for communicating. */
#define NSLCD_SOCKET "/tmp/nslcd.socket"

/* The location of the pidfile used for checking availability of the nslcd. */
#define NSLCD_PIDFILE "/tmp/nslcd.pid"

/* The current version of the protocol. */
#define NSLCD_VERSION 1

/* Request types. */
#define NSLCD_ACTION_ALIAS_BYNAME       4001
#define NSLCD_ACTION_ALIAS_ALL          4002
#define NSLCD_ACTION_AUTOMOUNT_BYNAME   7001
#define NSLCD_ACTION_AUTOMOUNT_ALL      7005
#define NSLCD_ACTION_ETHER_BYNAME       3001
#define NSLCD_ACTION_ETHER_BYETHER      3002
#define NSLCD_ACTION_ETHER_ALL          3005
#define NSLCD_ACTION_GROUP_BYNAME       5001
#define NSLCD_ACTION_GROUP_BYGID        5002
#define NSLCD_ACTION_GROUP_BYMEMBER     5003
#define NSLCD_ACTION_GROUP_ALL          5004
#define NSLCD_ACTION_HOST_BYNAME        6001
#define NSLCD_ACTION_HOST_BYADDR        6002
#define NSLCD_ACTION_HOST_ALL           6005
#define NSLCD_NETGROUP_BYNAME          12001
#define NSLCD_ACTION_NETWORK_BYNAME     8001
#define NSLCD_ACTION_NETWORK_BYADDR     8002
#define NSLCD_ACTION_NETWORK_ALL        8005
#define NSLCD_ACTION_PASSWD_BYNAME      1001
#define NSLCD_ACTION_PASSWD_BYUID       1002
#define NSLCD_ACTION_PASSWD_ALL         1004
#define NSLCD_ACTION_PROTOCOL_BYNAME    9001
#define NSLCD_ACTION_PROTOCOL_BYNUMBER  9002
#define NSLCD_ACTION_PROTOCOL_ALL       9003
#define NSLCD_ACTION_RPC_BYNAME        10001
#define NSLCD_ACTION_RPC_BYNUMBER      10002
#define NSLCD_ACTION_RPC_ALL           10003
#define NSLCD_ACTION_SERVICE_BYNAME    11001
#define NSLCD_ACTION_SERVICE_BYNUMBER  11002
#define NSLCD_ACTION_SERVICE_ALL       11005
#define NSLCD_ACTION_SHADOW_BYNAME      2001
#define NSLCD_ACTION_SHADOW_ALL         2005

/* Request result codes. */
#define NSLCD_RESULT_NOTFOUND              3 /* key was not found */
#define NSLCD_RESULT_SUCCESS               0 /* everything ok */

/* We need this for now, get rid of it later. */
#define NSLCD_RESULT_UNAVAIL               2 /* sevice unavailable */

#endif /* not _NSLCD_H */
