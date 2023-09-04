/*
   attmap.h - attribute mapping variables
   This file is part of the nss-pam-ldapd library.

   Copyright (C) 2007, 2008, 2009, 2010, 2012 Arthur de Jong

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

#ifndef NSLCD__ATTMAP_H
#define NSLCD__ATTMAP_H 1

#include "cfg.h"
#include "myldap.h"
#include "common/set.h"

/* these are the attribute names per database */
extern const char *attmap_alias_cn;
extern const char *attmap_alias_rfc822MailMember;
extern const char *attmap_ether_cn;
extern const char *attmap_ether_macAddress;
extern const char *attmap_group_cn;
extern const char *attmap_group_userPassword;
extern const char *attmap_group_gidNumber;
extern const char *attmap_group_memberUid;
extern const char *attmap_group_member;
extern const char *attmap_host_cn;
extern const char *attmap_host_ipHostNumber;
extern const char *attmap_netgroup_cn;
extern const char *attmap_netgroup_nisNetgroupTriple;
extern const char *attmap_netgroup_memberNisNetgroup;
extern const char *attmap_network_cn;
extern const char *attmap_network_ipNetworkNumber;
extern const char *attmap_passwd_uid;
extern const char *attmap_passwd_userPassword;
extern const char *attmap_passwd_uidNumber;
extern const char *attmap_passwd_gidNumber;
extern const char *attmap_passwd_gecos;
extern const char *attmap_passwd_homeDirectory;
extern const char *attmap_passwd_loginShell;
extern const char *attmap_passwd_class;
extern const char *attmap_protocol_cn;
extern const char *attmap_protocol_ipProtocolNumber;
extern const char *attmap_rpc_cn;
extern const char *attmap_rpc_oncRpcNumber;
extern const char *attmap_service_cn;
extern const char *attmap_service_ipServicePort;
extern const char *attmap_service_ipServiceProtocol;
extern const char *attmap_shadow_uid;
extern const char *attmap_shadow_userPassword;
extern const char *attmap_shadow_shadowLastChange;
extern const char *attmap_shadow_shadowMin;
extern const char *attmap_shadow_shadowMax;
extern const char *attmap_shadow_shadowWarning;
extern const char *attmap_shadow_shadowInactive;
extern const char *attmap_shadow_shadowExpire;
extern const char *attmap_shadow_shadowFlag;

/* return a reference to the map specific base variable */
const char **base_get_var(enum ldap_map_selector map);

/* return a reference to the map specific scope variable */
int *scope_get_var(enum ldap_map_selector map);

/* return a reference to the map specific filter variable */
const char **filter_get_var(enum ldap_map_selector map);

/* return a reference to the attribute mapping variable for the specified name
   the name is the name after the attmap_... variables above with the
   underscore replaced by a dot (e.g passwd.homeDirectory) */
const char **attmap_get_var(enum ldap_map_selector map, const char *name);

/* Set the attribute mapping of the variable to the value specified.
   Returns the new value on success. */
MUST_USE const char *attmap_set_mapping(const char **var, const char *value);

/* Return a value for the attribute, handling the case where attr
   is an expression. On error (e.g. problem parsing expression, attribute
   value not found) it returns NULL and the buffer is made empty. */
const char *attmap_get_value(MYLDAP_ENTRY *entry, const char *attr,
                             char *buffer, size_t buflen);

/* Add the attributes from attr to the set. The attr argument
   can either be an attribute or an attribute expression. */
SET *attmap_add_attributes(SET *set, const char *attr);

#endif /* not NSLCD__ATTMAP_H */
