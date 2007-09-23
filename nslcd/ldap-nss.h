/*
   ldap-nss.c - main file for NSS interface
   This file was part of the nss_ldap library which has been
   forked into the nss-ldapd library.

   Copyright (C) 1997-2005 Luke Howard
   Copyright (C) 2006, 2007 West Consulting
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

#ifndef _LDAP_NSS_LDAP_LDAP_NSS_H
#define _LDAP_NSS_LDAP_LDAP_NSS_H

#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/in.h>
#include <nss.h>
#include <ldap.h>

#include "cfg.h"

#ifdef __GNUC__
#define alignof(ptr) __alignof__(ptr)
#elif defined(HAVE_ALIGNOF_H)
#include <alignof.h>
#else
#define alignof(ptr) (sizeof(char *))
#endif /* __GNUC__ */

#define align(ptr, blen, TYPE)\
  { \
      char *qtr = ptr; \
      ptr += alignof(TYPE) - 1; \
      ptr -= ((ptr - (char *)NULL) % alignof(TYPE)); \
      blen -= (ptr - qtr); \
  }

/* worst case */
#define bytesleft(ptr, blen, TYPE) \
  ( (blen < alignof(TYPE)) ? 0 : (blen - alignof(TYPE) + 1))

/* This a a generic session handle. */
typedef struct ldap_session MYLDAP_SESSION;

/*
 * the state consists of the desired attribute value or an offset into a list of
 * values for the desired attribute. This is necessary to support services.
 *
 * Be aware of the arbitary distinction between state and context. Context is
 * the enumeration state of a lookup subsystem (which may be per-subsystem,
 * or per-subsystem/per-thread, depending on the OS). State is the state
 * of a particular lookup, and is only concerned with resolving and enumerating
 * services. State is represented as instances of struct ldap_state; context as
 * instances of struct ent_context. The context contains the state.
 */
struct ldap_state
{
  int ls_type;
  int ls_retry;
#define LS_TYPE_KEY     (0)
#define LS_TYPE_INDEX   (1)
  union
  {
    /* ls_key is the requested attribute value.
       ls_index is the desired offset into the value list.
     */
    const char *ls_key;
    int ls_index;
  }
  ls_info;
};

/*
 * thread specific context: result chain, and state data
 */
struct ent_context
{
  MYLDAP_SESSION *session;           /* the connection to the LDAP server */
  struct ldap_state ec_state;        /* eg. for services */
  int ec_msgid;                      /* message ID */
  LDAPMessage *ec_res;               /* result chain */
  struct berval *ec_cookie;          /* cookie for paged searches */
};

/* create a new session, this does not yet connect to the LDAP server */
MUST_USE MYLDAP_SESSION *myldap_create_session(void);

/* this a a parser function for LDAP results */
typedef enum nss_status (*parser_t)(MYLDAP_SESSION *session,LDAPMessage *e,
                                    struct ldap_state *state,void *result,
                                    char *buffer,size_t buflen);

/*
 * _nss_ldap_ent_context_init() is called for each getXXent() call
 */
void _nss_ldap_ent_context_init(struct ent_context *context,MYLDAP_SESSION *session);

/*
 * _nss_ldap_ent_context_cleanup() is used to manually free a context
 */
void _nss_ldap_ent_context_cleanup(struct ent_context *context);

/*
 * common enumeration routine; uses asynchronous API.
 */
int _nss_ldap_getent(
        struct ent_context *context, /* IN/OUT */
        void *result,      /* IN/OUT */
        char *buffer,      /* IN */
        size_t buflen,     /* IN */
        const char *base,  /* IN */
        int scope,         /* IN */
        const char *filter, /* IN */
        const char **attrs, /* IN */
        parser_t parser /* IN */ );

/*
 * common lookup routine; uses synchronous API.
 */
int _nss_ldap_getbyname(
        MYLDAP_SESSION *session,void *result, char *buffer, size_t buflen,
        const char *base,int scope,const char *filter,const char **attrs,
        parser_t parser);

/* parsing utility functions */

char **_nss_ldap_get_values(MYLDAP_SESSION *session,LDAPMessage *e,const char *attr);

enum nss_status _nss_ldap_assign_attrvals (
        MYLDAP_SESSION *session,
        LDAPMessage *e,     /* IN */
        const char *attr, /* IN */
        const char *omitvalue,    /* IN */
        char ***valptr,   /* OUT */
        char **pbuffer,    /* IN/OUT */
        size_t * pbuflen,  /* IN/OUT */
        size_t * pvalcount /* OUT */ );

enum nss_status _nss_ldap_assign_attrval(
        MYLDAP_SESSION *session,
        LDAPMessage *e,      /* IN */
        const char *attr,  /* IN */
        char **valptr,     /* OUT */
        char **buffer,     /* IN/OUT */
        size_t * buflen /* IN/OUT */ );

enum nss_status _nss_ldap_assign_userpassword(
        MYLDAP_SESSION *session,
        LDAPMessage *e,       /* IN */
        const char *attr,     /* IN */
        char **valptr,        /* OUT */
        char **buffer,        /* IN/OUT */
        size_t * buflen);     /* IN/OUT */

/* check that the entry has the specified objectclass
   return 0 for false, not-0 for true */
int has_objectclass(MYLDAP_SESSION *session,LDAPMessage *entry,const char *objectclass);

/*
 * get the RDN's value: eg. if the RDN was cn=lukeh, getrdnvalue(entry)
 * would return lukeh.
 */
enum nss_status _nss_ldap_getrdnvalue(
        MYLDAP_SESSION *session,LDAPMessage *entry,const char *rdntype,
        char **rval,char **buffer,size_t * buflen);

/*
 * Escape '*' in a string for use as a filter
 */
MUST_USE int myldap_escape(const char *src,char *buffer,size_t buflen);

#endif /* _LDAP_NSS_LDAP_LDAP_NSS_H */
