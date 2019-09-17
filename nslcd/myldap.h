/*
   myldap.h - simple interface to do LDAP requests
   This file is part of the nss-pam-ldapd library.

   Copyright (C) 2007-2017 Arthur de Jong

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

/*
   This file describes the API of the myldap module which takes the complexity
   out of using the OpenLDAP library. Memory management, paging, reconnect
   logic, idle timeout of connections, etc is taken care of by the module.

   Use of this module is very straightforward. You first have to create a
   session (with myldap_create_session()), with this session you can start
   searches (with myldap_search()), from a search you can get entries (with
   myldap_get_entry()) from the LDAP database and from these entries you can
   get attribute values (with myldap_get_values()).
*/

#ifndef NSLCD__MYLDAP_H
#define NSLCD__MYLDAP_H

/* for size_t */
#include <stdlib.h>
/* for LDAP_SCOPE_* */
#include <lber.h>
#include <ldap.h>

#include "compat/attrs.h"

#ifndef LDAP_SCOPE_DEFAULT
#define LDAP_SCOPE_DEFAULT LDAP_SCOPE_SUBTREE
#endif /* not LDAP_SCOPE_DEFAULT */

/* This a a generic session handle. */
typedef struct ldap_session MYLDAP_SESSION;

/* Note that this session handle may be used within one thread only. No
   locking is performed to prevent concurrent modifications. Most LDAP
   libraries also are not thread-safe in that a single connection may be
   shared by multiple threads. It seems however that OpenLDAP at least does
   not have any problems with an LDAP *ld per thread.
   http://www.openldap.org/lists/openldap-software/200606/msg00252.html */

/* A result set as returned by myldap_search(). */
typedef struct myldap_search MYLDAP_SEARCH;

/* A single entry from the LDAP database as returned by myldap_get_entry(). */
typedef struct myldap_entry MYLDAP_ENTRY;

/* Create a new session, this does not yet connect to the LDAP server. The
   connection to the server is made on-demand when a search is performed. This
   uses the configuration to find the URLs to attempt connections to. */
MUST_USE MYLDAP_SESSION *myldap_create_session(void);

/* Perform a simple bind operation and return the ppolicy results.
   This function returns an LDAP status code while response is an NSLCD_PAM_*
   code with accompanying message. */
MUST_USE int myldap_bind(MYLDAP_SESSION *session, const char *dn,
                         const char *password,
                         int *response, const char **message);

/* Closes all pending searches and deallocates any memory that is allocated
   with these searches. This does not close the session. */
void myldap_session_cleanup(MYLDAP_SESSION *session);

/* This checks the timeout value of the session and closes the connection
   to the LDAP server if the timeout has expired and there are no pending
   searches. */
void myldap_session_check(MYLDAP_SESSION *session);

/* Close the session and free all the resources allocated for the session.
   After a call to this function the referenced handle is invalid. */
void myldap_session_close(MYLDAP_SESSION *session);

/* Mark all failing LDAP servers as needing quick retries. This ensures that the
   reconnect_sleeptime and reconnect_retrytime sleeping period is cut short. */
void myldap_immediate_reconnect(void);

/* Do an LDAP search and return a reference to the results (returns NULL on
   error). This function uses paging, and does reconnects to the configured
   URLs transparently. The function returns an LDAP status code in the
   location pointed to by rcp if it is non-NULL. */
MUST_USE MYLDAP_SEARCH *myldap_search(MYLDAP_SESSION *session,
                                      const char *base, int scope,
                                      const char *filter, const char **attrs,
                                      int *rcp);

/* Close the specified search. This frees all the memory that was allocated
   for the search and its results. */
void myldap_search_close(MYLDAP_SEARCH *search);

/* Get an entry from the result set, going over all results (returns NULL if
   no more entries are available). Note that any memory allocated to return
   information about the previous entry (e.g. with myldap_get_values()) is
   freed with this call. The search is automatically closed when no more
   results are available. The function returns an LDAP status code in the
   location pointed to by rcp if it is non-NULL. */
MUST_USE MYLDAP_ENTRY *myldap_get_entry(MYLDAP_SEARCH *search, int *rcp);

/* Get the DN from the entry. This function does not return NULL (on error
   "unknown" is returned). */
MUST_USE const char *myldap_get_dn(MYLDAP_ENTRY *entry);

/* Just like myldap_get_dn() but copies the result into the buffer. */
char *myldap_cpy_dn(MYLDAP_ENTRY *entry, char *buf, size_t buflen);

/* Get the attribute values from a certain entry as a NULL terminated list.
   May return NULL or an empty array. */
MUST_USE const char **myldap_get_values(MYLDAP_ENTRY *entry, const char *attr);

/* Get the attribute values from a certain entry as a NULL terminated list.
   May return NULL or an empty array. */
MUST_USE const char **myldap_get_values_len(MYLDAP_ENTRY *entry, const char *attr);

/* Checks to see if the entry has the specified object class. */
MUST_USE int myldap_has_objectclass(MYLDAP_ENTRY *entry, const char *objectclass);

/* See if the entry has any deref controls attached to it and deref attr
   derefattr to get the getattr values. Will return two lists of attribute
   values. One list of deref'ed attribute values and one list of original
   attribute values that could not be deref'ed. */
MUST_USE const char ***myldap_get_deref_values(MYLDAP_ENTRY *entry,
                const char *derefattr, const char *getattr);

/* Get the RDN's value: eg. if the DN was cn=lukeh, ou=People, dc=example,
   dc=com getrdnvalue(entry, cn) would return lukeh. If the attribute was not
   found in the DN or if some error occurs NULL is returned. This method may
   be used to get the "most authoritative" value for an attribute. */
MUST_USE const char *myldap_get_rdn_value(MYLDAP_ENTRY *entry, const char *attr);

/* Just like myldap_get_rdn_value() but use the supplied character sequence
   and copies the result into the buffer.
   Returns a pointer to the start of the string on success and NULL on
   failure. */
MUST_USE const char *myldap_cpy_rdn_value(const char *dn, const char *attr,
                                          char *buf, size_t buflen);

/* Escapes characters in a string for use in a search filter. */
MUST_USE int myldap_escape(const char *src, char *buffer, size_t buflen);

/* Set the debug level globally. Returns an LDAP status code. */
int myldap_set_debuglevel(int level);

/* Perform an EXOP password modification call. Returns an LDAP status code. */
int myldap_passwd(MYLDAP_SESSION *session,
                  const char *userdn, const char *oldpassword,
                  const char *newpasswd);

/* Perform an LDAP modification request. Returns an LDAP status code. */
int myldap_modify(MYLDAP_SESSION *session, const char *dn, LDAPMod * mods[]);

/* Get an LDAP error message from the supplied rc and optionally any extra
   information in the connection. */
int myldap_error_message(MYLDAP_SESSION *session, int rc,
                         char *buffer, size_t buflen);

#endif /* not NSLCD__MYLDAP_H */
