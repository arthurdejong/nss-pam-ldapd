/* Copyright (C) 1997-2006 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@padl.com>, 2006.

   The nss_ldap library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The nss_ldap library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the nss_ldap library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   $Id: ldap-sldap.h,v 2.4 2006/01/12 13:06:23 lukeh Exp $
 */

#ifndef _LDAP_NSS_LDAP_LDAP_SLDAP_H
#define _LDAP_NSS_LDAP_LDAP_SLDAP_H

#define	NS_LDAP_VERSION		NS_LDAP_VERSION_2
#define	NS_LDAP_VERSION_1	"1.0"
#define	NS_LDAP_VERSION_2	"2.0"

typedef enum {
	NS_LDAP_FILE_VERSION_P = 0
} ParamIndexType;

typedef enum {
	NS_LDAP_SUCCESS	= 0,
	NS_LDAP_OP_FAILED,
	NS_LDAP_NOTFOUND,
	NS_LDAP_MEMORY,
	NS_LDAP_CONFIG,
	NS_LDAP_PARTIAL,
	NS_LDAP_INTERNAL,
	NS_LDAP_INVALID_PARAM,
	NS_LDAP_SUCCESS_WITH_INFO
} ns_ldap_return_code;

typedef struct ns_ldap_search_desc {
	char *basedn;
	int scope;
	char *filter;
} ns_ldap_search_desc_t;

typedef struct ns_ldap_attribute_map {
	char *origAttr;
	char **mappedAttr;
} ns_ldap_attribute_map_t;

typedef struct ns_ldap_objectclass_map {
	char *origOC;
	char *mappedOC;
} ns_ldap_objectclass_map_t;

typedef struct ns_ldap_passwd_mgmt {
	int pad[2];
} ns_ldap_passwd_mgmt_t;

typedef struct ns_ldap_error {
	int status;
	char *message;
	ns_ldap_passwd_mgmt_t pwd_mgmt;
} ns_ldap_error_t;

typedef struct ns_ldap_attr {
	char *attrname;
	unsigned int value_count;
	char **attrvalue;
} ns_ldap_attr_t;

typedef struct ns_ldap_entry {
	unsigned int attr_count;
	ns_ldap_attr_t **attr_pair;
	struct ns_ldap_entry *next;
} ns_ldap_entry_t;

typedef struct ns_ldap_result {
	unsigned int entries_count;
	ns_ldap_entry_t *entry;
} ns_ldap_result_t;

#define NS_LDAP_HARD		0x001
#define NS_LDAP_ALL_RES		0x002
#define NS_LDAP_FOLLOWREF 	0x004
#define NS_LDAP_NOREF		0x008
#define NS_LDAP_SCOPE_BASE	0x010
#define NS_LDAP_SCOPE_ONELEVEL	0x020
#define NS_LDAP_SCOPE_SUBTREE	0x040
#define NS_LDAP_KEEP_CONN	0x080
#define NS_LDAP_NEW_CONN	0x400
#define NS_LDAP_NOMAP		0x800

#define	NS_LDAP_CB_NEXT	0
#define	NS_LDAP_CB_DONE	1

typedef struct ns_ldap_cookie {
	char *map;
	char *filter;
	char **attribute;
	int flags;

	int (*init_filter_cb)(const ns_ldap_search_desc_t *desc, char **realfilter, const void *userdata);
	int (*callback)(const ns_ldap_entry_t *entry, const void *userdata);
	const void *userdata;

	char *mapped_filter;
	const char **mapped_attribute;

	int ret;
	int cb_ret;
	int erange;
	ldap_map_selector_t sel;
	ent_context_t *state;
	ldap_automount_context_t *am_state;

	ns_ldap_result_t *result;
	ns_ldap_entry_t *entry;
} ns_ldap_cookie_t;

char **__ns_ldap_getMappedAttributes(const char *service, const char *attribute);
char **__ns_ldap_getMappedObjectClass(const char *service, const char *attribute);

ns_ldap_return_code __ns_ldap_getParam(const ParamIndexType type, void ***data, ns_ldap_error_t **errorp);
ns_ldap_return_code __ns_ldap_freeError(ns_ldap_error_t **errorp);
ns_ldap_return_code __ns_ldap_freeEntry(ns_ldap_entry_t **pentry);
ns_ldap_return_code __ns_ldap_freeResult(ns_ldap_result_t **result);

typedef void ns_cred_t;

ns_ldap_return_code __ns_ldap_firstEntry(const char *service,
	const char *filter,
	int (*init_filter_cb)(const ns_ldap_search_desc_t *desc,
			char **realfilter, const void *userdata),
	const char * const *attribute,
	const ns_cred_t *cred,
	const int flags,
	void **cookie,
	ns_ldap_result_t ** result,
	ns_ldap_error_t **errorp,
	const void *userdata);

ns_ldap_return_code  __ns_ldap_nextEntry(
	void *cookie,
	ns_ldap_result_t ** result,
	ns_ldap_error_t **errorp);

ns_ldap_return_code  __ns_ldap_endEntry(
	void **cookie,
	ns_ldap_error_t **errorp);

ns_ldap_return_code __ns_ldap_list(
	const char *service,
	const char *filter,
	int (*init_filter_cb)(const ns_ldap_search_desc_t *desc, char **realfilter, const void *userdata),
	const char * const *attribute,
	const ns_cred_t *cred,
	const int flags,
	ns_ldap_result_t **result,
	ns_ldap_error_t **errorp,
	int (*callback)(const ns_ldap_entry_t *entry, const void *userdata),
	const void *userdata);

ns_ldap_return_code __ns_ldap_err2str(ns_ldap_return_code err, char **strmsg);

#endif /* _LDAP_NSS_LDAP_LDAP_SLDAP_H */
