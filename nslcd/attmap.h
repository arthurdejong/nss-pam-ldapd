/*
   attmap.h - attribute mapping variables
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

#ifndef _ATTMAP_H
#define _ATTMAP_H 1

#include "ldap-nss.h"

/* These are the filters that are defined per database. */

/* TODO: move these to a per-database header file */
extern const char *alias_filter;
extern const char *ether_filter;
extern const char *group_filter;
extern const char *host_filter;
extern const char *netgroup_filter;
extern const char *network_filter;
extern const char *passwd_filter;
extern const char *protocol_filter;
extern const char *rpc_filter;
extern const char *service_filter;
extern const char *shadow_filter;

/* What follows is a list of attribute names per database. */

/* TODO: replace the objectClass name mapping with filter definitions */

extern const char *attmap_objectClass;

/**
 * Vendor-specific attributes and object classes.
 * (Mainly from Sun.)
 * ( 1.3.6.1.4.1.42.2.27.1.2.5 NAME 'nisMailAlias' SUP top STRUCTURAL
 *   DESC 'NIS mail alias'
 *   MUST cn
 *   MAY rfc822MailMember )
 */
extern const char *attmap_alias_cn;
extern const char *attmap_alias_rfc822MailMember;

/*
 * ( nisSchema.2.11 NAME 'ieee802Device' SUP top AUXILIARY
 *   DESC 'A device with a MAC address; device SHOULD be
 *         used as a structural class'
 *   MAY macAddress )
 */
extern const char *attmap_ether_cn;
extern const char *attmap_ether_macAddress;

/*
 * ( nisSchema.2.2 NAME 'posixGroup' SUP top STRUCTURAL
 *   DESC 'Abstraction of a group of accounts'
 *   MUST ( cn $ gidNumber )
 *   MAY ( userPassword $ uidMember $ description ) )
 */
extern const char *attmap_group_cn;
extern const char *attmap_group_userPassword;
extern const char *attmap_group_gidNumber;
extern const char *attmap_group_memberUid;
extern const char *attmap_group_uniqueMember;
extern const char *attmap_group_memberOf;

/*
 * ( nisSchema.2.6 NAME 'ipHost' SUP top AUXILIARY
 *   DESC 'Abstraction of a host,An IP device. The distinguished
 *         value of the cn attribute denotes the host's canonical
 *         name. Device SHOULD be used as a structural class'
 *   MUST ( cn $ ipHostNumber )
 *   MAY ( l $ description $ manager ) )
 */
extern const char *attmap_host_cn;
extern const char *attmap_host_ipHostNumber;

/*
 * ( nisSchema.2.8 NAME 'nisNetgroup' SUP top STRUCTURAL
 *   DESC 'Abstraction of a netgroup. May refer to other netgroups'
 *   MUST cn
 *   MAY ( nisNetgroupTriple $ memberNisNetgroup $ description ) )
 */
extern const char *attmap_netgroup_cn;
extern const char *attmap_netgroup_nisNetgroupTriple;
extern const char *attmap_netgroup_memberNisNetgroup;

/*
 * ( nisSchema.2.7 NAME 'ipNetwork' SUP top STRUCTURAL
 *   DESC 'Abstraction of a network. The distinguished value of
 *   MUST ( cn $ ipNetworkNumber )
 *   MAY ( ipNetmaskNumber $ l $ description $ manager ) )
 */
extern const char *attmap_network_cn;
extern const char *attmap_network_ipNetworkNumber;
/*extern const char *attmap_network_ipNetmaskNumber; */

/*
 * ( nisSchema.2.0 NAME 'posixAccount' SUP top AUXILIARY
 *   DESC 'Abstraction of an account with POSIX attributes'
 *   MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory )
 *   MAY ( userPassword $ loginShell $ gecos $ description ) )
 */
extern const char *attmap_passwd_uid;
extern const char *attmap_passwd_userPassword;
extern const char *attmap_passwd_uidNumber;
extern const char *attmap_passwd_gidNumber;
extern const char *attmap_passwd_gecos;
extern const char *attmap_passwd_cn;
extern const char *attmap_passwd_homeDirectory;
extern const char *attmap_passwd_loginShell;

/*
 * ( nisSchema.2.4 NAME 'ipProtocol' SUP top STRUCTURAL
 *   DESC 'Abstraction of an IP protocol. Maps a protocol number
 *         to one or more names. The distinguished value of the cn
 *         attribute denotes the protocol's canonical name'
 *   MUST ( cn $ ipProtocolNumber )
 *    MAY description )
 */
extern const char *attmap_protocol_cn;
extern const char *attmap_protocol_ipProtocolNumber;

/*
 * ( nisSchema.2.5 NAME 'oncRpc' SUP top STRUCTURAL
 *   DESC 'Abstraction of an Open Network Computing (ONC)
 *         [RFC1057] Remote Procedure Call (RPC) binding.
 *         This class maps an ONC RPC number to a name.
 *         The distinguished value of the cn attribute denotes
 *         the RPC service's canonical name'
 *   MUST ( cn $ oncRpcNumber )
 *   MAY description )
 */
extern const char *attmap_rpc_cn;
extern const char *attmap_rpc_oncRpcNumber;

/*
 * ( nisSchema.2.3 NAME 'ipService' SUP top STRUCTURAL
 *   DESC 'Abstraction an Internet Protocol service.
 *         Maps an IP port and protocol (such as tcp or udp)
 *         to one or more names; the distinguished value of
 *         the cn attribute denotes the service's canonical
 *         name'
 *   MUST ( cn $ ipServicePort $ ipServiceProtocol )
 *   MAY ( description ) )
 */
extern const char *attmap_service_cn;
extern const char *attmap_service_ipServicePort;
extern const char *attmap_service_ipServiceProtocol;

/*
 * ( nisSchema.2.1 NAME 'shadowAccount' SUP top AUXILIARY
 *   DESC 'Additional attributes for shadow passwords'
 *   MUST uid
 *   MAY ( userPassword $ shadowLastChange $ shadowMin
 *         shadowMax $ shadowWarning $ shadowInactive $
 *         shadowExpire $ shadowFlag $ description ) )
 */
extern const char *attmap_shadow_uid;
extern const char *attmap_shadow_userPassword;
extern const char *attmap_shadow_shadowLastChange;
extern const char *attmap_shadow_shadowMin;
extern const char *attmap_shadow_shadowMax;
extern const char *attmap_shadow_shadowWarning;
extern const char *attmap_shadow_shadowInactive;
extern const char *attmap_shadow_shadowExpire;
extern const char *attmap_shadow_shadowFlag;

/* return a reference to the map specific filter variable */
const char **filter_get_var(enum ldap_map_selector map);

/* return a reference to the attribute mapping variable for the specified name
   the name is the name after the attmap_... variables above with the
   underscode replaced by a dot (e.g passwd.homeDirectory) */
const char **attmap_get_var(enum ldap_map_selector map,const char *name);

#endif /* not _ATTMAP_H */
