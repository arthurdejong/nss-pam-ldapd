/*
   nss_compat.h - compatibility definitions for NSS functions

   Copyright (C) 2010, 2012 Arthur de Jong
   Copyright (C) 2010 Symas Corporation

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

#ifndef COMPAT__NSS_H
#define COMPAT__NSS_H 1

#ifdef HAVE_NSS_H
#include <nss.h>
#endif /* HAVE_NSS_H */
#ifdef HAVE_NSS_COMMON_H
#include <nss_common.h>
#endif /* HAVE_NSS_COMMON_H */
#ifdef HAVE_ALIASES_H
#include <aliases.h>
#endif
#include <sys/socket.h>
#include <sys/types.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#ifdef HAVE_SHADOW_H
#include <shadow.h>
#endif /* HAVE_SHADOW_H */
#ifdef HAVE_RPC_RPCENT_H
#include <rpc/rpcent.h>
#endif /* HAVE_RPC_RPCENT_H */
#ifdef HAVE_NSS_DBDEFS_H
#include <nss_dbdefs.h>
#endif /* HAVE_NSS_DBDEFS_H */
#ifdef HAVE_NSSWITCH_H
#include <nsswitch.h>
#endif /* HAVE_NSSWITCH_H */

#include "compat/ether.h"

/* define missing status codes */
#ifndef HAVE_ENUM_NSS_STATUS

/* NetBSD flavour */
#ifdef NS_SUCCESS
enum nss_status {
        NSS_STATUS_SUCCESS = NS_SUCCESS,
        NSS_STATUS_NOTFOUND = NS_NOTFOUND,
        NSS_STATUS_UNAVAIL = NS_UNAVAIL,
        NSS_STATUS_TRYAGAIN = NS_TRYAGAIN,
        NSS_STATUS_RETURN = NS_RETURN,
};
#endif

/* FreeBSD flavour */
#ifdef NSS_SUCCESS
enum nss_status {
        NSS_STATUS_SUCCESS = NSS_SUCCESS,
        NSS_STATUS_NOTFOUND = NSS_NOTFOUND,
        NSS_STATUS_UNAVAIL = NSS_UNAVAIL,
        NSS_STATUS_TRYAGAIN = NS_TRYAGAIN,
        NSS_STATUS_RETURN = NSS_RETURN,
};
#endif
#endif /* not HAVE_ENUM_NSS_STATUS */

/* define nss_status_t */
typedef enum nss_status nss_status_t;

/* Define an aliasent if it was not found on the system. */
#ifndef HAVE_STRUCT_ALIASENT
struct aliasent {
  char *alias_name;
  size_t alias_members_len;
  char **alias_members;
  int alias_local;
};
#endif /* not HAVE_STRUCT_ALIASENT */

/* Define an rpcent if it was not found on the system */
#ifndef HAVE_STRUCT_RPCENT
struct rpcent {
  char *r_name;
  char **r_aliases;
  int r_number;
};
#endif /* not HAVE_STRUCT_RPCENT */

/* We define struct etherent here because it does not seem to
   be defined in any publicly available header file exposed
   by glibc. This is taken from include/netinet/ether.h
   of the glibc (2.3.6) source tarball. */
#ifndef HAVE_STRUCT_ETHERENT
struct etherent {
  const char *e_name;
  struct ether_addr e_addr;
};
#endif /* not HAVE_STRUCT_ETHERENT */

/* We also define struct __netgrent because its definition is
   not publicly available. This is taken from inet/netgroup.h
   of the glibc (2.3.6) source tarball.
   The first part of the struct is the only part that is modified
   by our getnetgrent() function, all the other fields are not
   touched at all. */
struct __netgrent {
  enum { triple_val, group_val } type;
  union {
    struct {
      const char *host;
      const char *user;
      const char *domain;
    } triple;
    const char *group;
  } val;
  /* the following stuff is used by some NSS services
     but not by ours (it's not completely clear how these
     are shared between different services) or is used
     by our caller */
  char *data;
  size_t data_size;
  union {
    char *cursor;
    unsigned long int position;
  } insertedname; /* added name to union to avoid warning */
  int first;
  struct name_list *known_groups;
  struct name_list *needed_groups;
  void *nip; /* changed from `service_user *nip' */
};

/* Define struct spwd if it was not found on the system. */
#ifndef HAVE_STRUCT_SPWD
struct spwd {
  char *sp_namp;
  char *sp_pwdp;
  long sp_lstchg;
  long sp_min;
  long sp_max;
  long sp_warn;
  long sp_inact;
  long sp_expire;
  unsigned long sp_flag;
};
#endif /* not HAVE_STRUCT_SPWD */

/* Define NETDB_INTERNAL h_errno return code if it is missing */
#ifndef NETDB_INTERNAL
#define NETDB_INTERNAL -1
#endif

#endif /* not COMPAT__NSS_H */
