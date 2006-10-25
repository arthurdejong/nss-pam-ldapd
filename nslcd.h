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
     int32 NSLCD_RS_* (response code)
   Followed by the data for the response (if call was sucessful)
     int32 NSLCD_DT_BUF (data type)
     int32 length(result)
     ... result
*/

/*
  These are the data types that can be transferred in the protocol.
  They are defined as macros so they can be expanded to code
  later on.

  LDF_STRING:
    int32 length
    ...   length bytes
  LDF_TYPE:
    sizeof(type)  value
  LDF_LOOP:
    int32 number
      number times the containing thing(s)
*/

#define LDF_ALIAS \
  LDF_STRING(ALIAS_NAME) \
  LDF_LOOP( \
    LDF_STRING(ALIAS_RCPT) \
  )

/* AUTOMOUNT - TBD */

#define LDF_ETHER \
  LDF_TYPE(ETHER_ADDR,"123456")

#define LDF_GROUP \
  LDF_STRING(GROUP_NAME) \
  LDF_STRING(GROUP_PASSWD) \
  LDF_TYPE(GROUP_GIF,gid_t) \
  LDF_LOOP( \
    LDF_STRING(GROUP_MEMBER) \
  )

/* HOSTS - TBD - gethostbyname - struct hostent - gethostbyaddr - struct in_addr */

/* NETGROUP - TBD */

/* NETWORKS - TBD - struct netent */

#define LDF_PASSWD \
  LDF_STRING(PASSWD_NAME) \
  LDF_STRING(PASSWD_PASSWD) \
  LDF_TYPE(PASSWD_UID,uid_t) \
  LDF_TYPE(PASSWD_GID,gid_t) \
  LDF_STRING(PASSWD_GECOS) \
  LDF_STRING(PASSWD_DIR) \
  LDF_STRING(PASSWD_SHELL)

/* PROTOCOLS - TBD - getprotobyname - struct protoent */

#define LDF_RPC \
  LDF_STRING(RPC_NAME) \
  LDF_LOOP( \
    LDF_STRING(RPC_ALIAS) \
  ) \
  LDF_TYPE(RPC_NUMBER,int32_t)

/* SERVICES - TBD - getservbyname - struct servent */

/* SHADOW - TBD - getspnam - struct spwd */
/*
   Data units:

functions for
read_str(FILE *fp, buf, ptr, &result, size):
  - read string length from stream
  - check if there is enough room in buffer:
    - no: fail (maybe do some rollback)
  - read string in buffer
  - increment prt with string size
  - store pointer in &result or NULL on error
read_int(FILE *fp, int*i)
  - read int32
  - store in &i

code like:

  strcut foobar
  foobar.field=0
  return read_str(fp..,&foobar.field,...) ||
         read_int(...)

return NSLCD_RS_*


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
#define NSLCD_RT_GETPWBYNAME            1001
#define NSLCD_RT_GETPWBYUID             1002
#define NSLCD_RT_GETGRBYNAME            2003
#define NSLCD_RT_GETGRBYGID             2004
#define NSLCD_RT_GETHOSTBYNAME          3005
#define NSLCD_RT_GETHOSTBYADDR          3008

/* Response data types */
#define NSLCD_DT_BUF                    1000 /* any data, blob */
#define NSLCD_DT_HEADER                 2001 /* initial response header */
#define NSLCD_DT_PASSWD                 3001 /* struct passwd */

/* Request result. */
#define NSLCD_RS_UNAVAIL                2 /* sevice unavailable */
#define NSLCD_RS_NOTFOUND               3 /* key was not found */
#define NSLCD_RS_SUCCESS                0 /* everything ok */

#endif /* not _NSLCD_H */
