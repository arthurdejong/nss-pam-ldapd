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


/* What follows is a list of attribute names per database. */

#include <ldap-schema.h>

#define attmap_objectClass             _nss_ldap_map_at(LM_NONE,AT_objectClass)

#define attmap_alias_objectClass       _nss_ldap_map_oc(LM_NONE,OC_nisMailAlias)
#define attmap_alias_cn                _nss_ldap_map_at(LM_ALIASES,AT_cn)
#define attmap_alias_rfc822MailMember  _nss_ldap_map_at(LM_NONE,AT_rfc822MailMember)

#define attmap_ether_objectClass       _nss_ldap_map_oc(LM_NONE,OC_ieee802Device)
#define attmap_ether_cn                _nss_ldap_map_at(LM_ETHERS,AT_cn)
#define attmap_ether_macAddress        _nss_ldap_map_at(LM_NONE,AT_macAddress)

#define attmap_group_objectClass       _nss_ldap_map_oc(LM_NONE,OC_posixGroup)
#define attmap_group_cn                _nss_ldap_map_at(LM_GROUP,AT_cn)
#define attmap_group_userPassword      _nss_ldap_map_at(LM_GROUP,AT_userPassword)
#define attmap_group_gidNumber         _nss_ldap_map_at(LM_GROUP,AT_gidNumber)
#define attmap_group_memberUid         _nss_ldap_map_at(LM_GROUP,AT_memberUid)
#define attmap_group_uniqueMember      _nss_ldap_map_at(LM_GROUP,AT_uniqueMember)
#define attmap_group_memberOf          _nss_ldap_map_at(LM_GROUP,AT_memberOf)

#define attmap_host_objectClass        _nss_ldap_map_oc(LM_NONE,OC_ipHost)
#define attmap_host_cn                 _nss_ldap_map_at(LM_HOSTS,AT_cn)
#define attmap_host_ipHostNumber       _nss_ldap_map_at(LM_NONE,AT_ipHostNumber)

#define attmap_netgroup_objectClass       _nss_ldap_map_oc(LM_NONE,OC_nisNetgroup)
#define attmap_netgroup_cn                _nss_ldap_map_at(LM_NETGROUP,AT_cn)
#define attmap_netgroup_nisNetgroupTriple _nss_ldap_map_at(LM_NONE,AT_nisNetgroupTriple)
#define attmap_netgroup_memberNisNetgroup _nss_ldap_map_at(LM_NONE,AT_memberNisNetgroup)

#define attmap_network_objectClass     _nss_ldap_map_oc(LM_NONE,OC_ipNetwork)
#define attmap_network_cn              _nss_ldap_map_at(LM_NETWORKS,AT_cn)
#define attmap_network_ipNetworkNumber _nss_ldap_map_at(LM_NONE,AT_ipNetworkNumber)

#define attmap_passwd_objectClass      _nss_ldap_map_oc(LM_NONE,OC_posixAccount) 
#define attmap_passwd_uid              _nss_ldap_map_at(LM_PASSWD,AT_uid)
#define attmap_passwd_userPassword     _nss_ldap_map_at(LM_PASSWD,AT_userPassword)
#define attmap_passwd_uidNumber        _nss_ldap_map_at(LM_NONE,AT_uidNumber)
#define attmap_passwd_gidNumber        _nss_ldap_map_at(LM_PASSWD,AT_gidNumber)
#define attmap_passwd_gecos            _nss_ldap_map_at(LM_NONE,AT_gecos)
#define attmap_passwd_cn               _nss_ldap_map_at(LM_PASSWD,AT_cn)
#define attmap_passwd_homeDirectory    _nss_ldap_map_at(LM_NONE,AT_homeDirectory)
#define attmap_passwd_loginShell       _nss_ldap_map_at(LM_NONE,AT_loginShell)

#define attmap_protocol_objectClass      _nss_ldap_map_oc(LM_NONE,OC_ipProtocol)
#define attmap_protocol_cn               _nss_ldap_map_at(LM_PROTOCOLS,AT_cn)
#define attmap_protocol_ipProtocolNumber _nss_ldap_map_at(LM_NONE,AT_ipProtocolNumber)

#define attmap_rpc_objectClass         _nss_ldap_map_oc(LM_NONE,OC_oncRpc)
#define attmap_rpc_cn                  _nss_ldap_map_at(LM_RPC,AT_cn)
#define attmap_rpc_oncRpcNumber        _nss_ldap_map_at(LM_NONE,AT_oncRpcNumber)

#define attmap_service_objectClass       _nss_ldap_map_oc(LM_NONE,OC_ipService)
#define attmap_service_cn                _nss_ldap_map_at(LM_SERVICES,AT_cn)
#define attmap_service_ipServicePort     _nss_ldap_map_at(LM_NONE,AT_ipServicePort)
#define attmap_service_ipServiceProtocol _nss_ldap_map_at(LM_NONE,AT_ipServiceProtocol)

#define attmap_shadow_objectClass      _nss_ldap_map_oc(LM_NONE,OC_shadowAccount)
#define attmap_shadow_uid              _nss_ldap_map_at(LM_SHADOW,AT_uid)
#define attmap_shadow_userPassword     _nss_ldap_map_at(LM_SHADOW,AT_userPassword)
#define attmap_shadow_shadowLastChange _nss_ldap_map_at(LM_NONE,AT_shadowLastChange)
#define attmap_shadow_shadowMin        _nss_ldap_map_at(LM_NONE,AT_shadowMin)
#define attmap_shadow_shadowMax        _nss_ldap_map_at(LM_NONE,AT_shadowMax)
#define attmap_shadow_shadowWarning    _nss_ldap_map_at(LM_NONE,AT_shadowWarning)
#define attmap_shadow_shadowInactive   _nss_ldap_map_at(LM_NONE,AT_shadowInactive)
#define attmap_shadow_shadowExpire     _nss_ldap_map_at(LM_NONE,AT_shadowExpire)
#define attmap_shadow_shadowFlag       _nss_ldap_map_at(LM_NONE,AT_shadowFlag)


#ifdef NEW_DISABLED_FOR_NOW

/* This is new code to be put in place as new attribute mapping stuff.
   This will just use strings that may be replaced elsewhere. */

/**
 * Vendor-specific attributes and object classes.
 * (Mainly from Sun.)
 * ( 1.3.6.1.4.1.42.2.27.1.2.5 NAME 'nisMailAlias' SUP top STRUCTURAL
 *   DESC 'NIS mail alias'
 *   MUST cn
 *   MAY rfc822MailMember )
 */
extern const char *attmap_alias_objectClass;
extern const char *attmap_alias_cn;
extern const char *attmap_alias_rfc822MailMember;

/*
 * ( nisSchema.2.11 NAME 'ieee802Device' SUP top AUXILIARY
 *   DESC 'A device with a MAC address; device SHOULD be
 *         used as a structural class'
 *   MAY macAddress )
 */
extern const char *attmap_ether_objectClass;
extern const char *attmap_ether_cn;
extern const char *attmap_ether_macAddress;

/*
 * ( nisSchema.2.2 NAME 'posixGroup' SUP top STRUCTURAL
 *   DESC 'Abstraction of a group of accounts'
 *   MUST ( cn $ gidNumber )
 *   MAY ( userPassword $ uidMember $ description ) )
 */
extern const char *attmap_group_objectClass;
extern const char *attmap_group_cn;
extern const char *attmap_group_userPassword;
extern const char *attmap_group_gidNumber;
extern const char *attmap_group_memberUid;
/* probably also support uniqueMember and memberOf attributes */

/*
 * ( nisSchema.2.6 NAME 'ipHost' SUP top AUXILIARY
 *   DESC 'Abstraction of a host,An IP device. The distinguished
 *         value of the cn attribute denotes the host's canonical
 *         name. Device SHOULD be used as a structural class'
 *   MUST ( cn $ ipHostNumber )
 *   MAY ( l $ description $ manager ) )
 */
extern const char *attmap_host_objectClass;
extern const char *attmap_host_cn;
extern const char *attmap_host_ipHostNumber;

/*
 * ( nisSchema.2.8 NAME 'nisNetgroup' SUP top STRUCTURAL
 *   DESC 'Abstraction of a netgroup. May refer to other netgroups'
 *   MUST cn
 *   MAY ( nisNetgroupTriple $ memberNisNetgroup $ description ) )
 */
extern const char *attmap_netgroup_objectClass;
/*extern const char *attmap_netgroup_cn;*/
extern const char *attmap_netgroup_nisNetgroupTriple;
extern const char *attmap_netgroup_memberNisNetgroup;

/*
 * ( nisSchema.2.7 NAME 'ipNetwork' SUP top STRUCTURAL
 *   DESC 'Abstraction of a network. The distinguished value of
 *   MUST ( cn $ ipNetworkNumber )
 *   MAY ( ipNetmaskNumber $ l $ description $ manager ) )
 */
extern const char *attmap_network_objectClass;
extern const char *attmap_network_cn;
extern const char *attmap_network_ipNetworkNumber;
/*extern const char *attmap_network_ipNetmaskNumber; */

/*
 * ( nisSchema.2.0 NAME 'posixAccount' SUP top AUXILIARY
 *   DESC 'Abstraction of an account with POSIX attributes'
 *   MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory )
 *   MAY ( userPassword $ loginShell $ gecos $ description ) )
 */
extern const char *attmap_passwd_objectClass;
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
extern const char *attmap_protocol_objectClass;
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
extern const char *attmap_rpc_objectClass;
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
extern const char *attmap_service_objectClass;
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
extern const char *attmap_shadow_objectClass;
extern const char *attmap_shadow_uid;
extern const char *attmap_shadow_userPassword;
extern const char *attmap_shadow_shadowLastChange;
extern const char *attmap_shadow_shadowMin;
extern const char *attmap_shadow_shadowMax;
extern const char *attmap_shadow_shadowWarning;
extern const char *attmap_shadow_shadowInactive;
extern const char *attmap_shadow_shadowExpire;
extern const char *attmap_shadow_shadowFlag;

#endif /* NEW_DISABLED_FOR_NOW */

#endif /* not _ATTMAP_H */
