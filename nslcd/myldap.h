/*
   myldap.h - simple interface to do LDAP requests
   This file is part of the nss-ldapd library.

   Copyright (C) 2007 Arthur de Jong

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

#ifndef _MYLDAP_H
#define _MYLDAP_H

/* for size_t: */
#include <stdlib.h>
/* for LDAP_SCOPE_*: */
#include <ldap.h>

#include "compat/attrs.h"

/* This a a generic session handle. */
typedef struct ldap_session MYLDAP_SESSION;

/* Note that this session handle may be used within one thread only. No
   locking is performed to prevent concurrent modifications. Most LDAP
   libraries also are not thread-safe in that a single connection may
   be shared by multiple threads. It seems however that OpenLDAP at least
   does not have any problems with an LDAP *ld per thread.
   (TODO: find references for this) */

/* A result set as returned by myldap_search(). */
typedef struct myldap_search MYLDAP_SEARCH;

/* A single entry from the LDAP database as returned by
   myldap_get_entry(). */
typedef struct myldap_entry MYLDAP_ENTRY;

/* Create a new session, this does not yet connect to the LDAP server.
   The connection to the server is made on-demand when a search is
   performed. */
MUST_USE MYLDAP_SESSION *myldap_create_session(void);

/* Closes all pending searches and deallocates any memory that is
   allocated with these searches. This does not close the session. */
void myldap_session_cleanup(MYLDAP_SESSION *session);

/* Do an LDAP search and returns a reference to the results
   (returns NULL on error).
   This function uses paging, and does reconnects to the configured
   URLs transparently. */
MUST_USE MYLDAP_SEARCH *myldap_search(
        MYLDAP_SESSION *session,
        const char *base,int scope,const char *filter,const char **attrs);

/* Close the specified search. This frees all the memory that was
   allocated for the search and its results. */
void myldap_search_close(MYLDAP_SEARCH *search);

/* Get an entry from the result set, going over all results
   (returns NULL if no more entries are available).
   Note that any memory allocated to return information
   about the entry (e.g. with myldap_get_values()) is freed
   with this call. */
MUST_USE MYLDAP_ENTRY *myldap_get_entry(MYLDAP_SEARCH *search);

/* Get the DN from the entry. This function does not return
   NULL (on error "unknown" is returned). */
MUST_USE const char *myldap_get_dn(MYLDAP_ENTRY *entry);

/* Get the attribute values from a ceirtain entry as
   a NULL terminated list. */
MUST_USE const char **myldap_get_values(MYLDAP_ENTRY *entry,const char *attr);

/* Return the number of elements in the array returned by
   by myldap_get_values(). */
MUST_USE int myldap_count_values(const char **vals);

/* Checks to see if the entry has the specified object class. */
MUST_USE int myldap_has_objectclass(MYLDAP_ENTRY *entry,const char *objectclass);

/* Get the RDN's value: eg. if the RDN was cn=lukeh, getrdnvalue(entry,cn)
   would return lukeh. If the attribute was not found in the DN or on other
   errors NULL is returned. This method may be used to get the "most authorative"
   value for an attribute. */
MUST_USE const char *myldap_get_rdn_value(MYLDAP_ENTRY *entry,const char *attr);

/* Escapes characters in a string for use in a filter. */
MUST_USE int myldap_escape(const char *src,char *buffer,size_t buflen);

#endif /* not _MYLDAP_H */
