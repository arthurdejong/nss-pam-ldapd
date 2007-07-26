/*
   attmap.c - attribute mapping values and functions
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

#include "config.h"

#include <stdlib.h>
#include <strings.h>

#include "attmap.h"


const char *attmap_objectClass           = "objectClass";


/**
 * Vendor-specific attributes and object classes.
 * (Mainly from Sun.)
 * ( 1.3.6.1.4.1.42.2.27.1.2.5 NAME 'nisMailAlias' SUP top STRUCTURAL
 *   DESC 'NIS mail alias'
 *   MUST cn
 *   MAY rfc822MailMember )
 */
const char *attmap_alias_objectClass      = "nisMailAlias";
const char *attmap_alias_cn               = "cn";
const char *attmap_alias_rfc822MailMember = "rfc822MailMember";

/*
 * ( nisSchema.2.11 NAME 'ieee802Device' SUP top AUXILIARY
 *   DESC 'A device with a MAC address; device SHOULD be
 *         used as a structural class'
 *   MAY macAddress )
 */
const char *attmap_ether_objectClass = "ieee802Device";
const char *attmap_ether_cn          = "cn";
const char *attmap_ether_macAddress  = "macAddress";

/*
 * ( nisSchema.2.2 NAME 'posixGroup' SUP top STRUCTURAL
 *   DESC 'Abstraction of a group of accounts'
 *   MUST ( cn $ gidNumber )
 *   MAY ( userPassword $ uidMember $ description ) )
 */
const char *attmap_group_objectClass   = "posixGroup";
const char *attmap_group_cn            = "cn";
const char *attmap_group_userPassword  = "userPassword";
const char *attmap_group_gidNumber     = "gidNumber";
const char *attmap_group_memberUid     = "memberUid";
const char *attmap_group_uniqueMember  = "uniqueMember";
const char *attmap_group_memberOf      = "memberOf";

/*
 * ( nisSchema.2.6 NAME 'ipHost' SUP top AUXILIARY
 *   DESC 'Abstraction of a host, an IP device. The distinguished
 *         value of the cn attribute denotes the host's canonical
 *         name. Device SHOULD be used as a structural class'
 *   MUST ( cn $ ipHostNumber )
 *   MAY ( l $ description $ manager ) )
 */
const char *attmap_host_objectClass   = "ipHost";
const char *attmap_host_cn            = "cn";
const char *attmap_host_ipHostNumber  = "ipHostNumber";

/*
 * ( nisSchema.2.8 NAME 'nisNetgroup' SUP top STRUCTURAL
 *   DESC 'Abstraction of a netgroup. May refer to other netgroups'
 *   MUST cn
 *   MAY ( nisNetgroupTriple $ memberNisNetgroup $ description ) )
 */
const char *attmap_netgroup_objectClass     = "nisNetgroup";
const char *attmap_netgroup_cn              = "cn";
const char *attmap_netgroup_nisNetgroupTriple = "nisNetgroupTriple";
const char *attmap_netgroup_memberNisNetgroup = "memberNisNetgroup";

/*
 * ( nisSchema.2.7 NAME 'ipNetwork' SUP top STRUCTURAL
 *   DESC 'Abstraction of a network. The distinguished value of
 *   MUST ( cn $ ipNetworkNumber )
 *   MAY ( ipNetmaskNumber $ l $ description $ manager ) )
 */
const char *attmap_network_objectClass     = "ipNetwork";
const char *attmap_network_cn              = "cn";
const char *attmap_network_ipNetworkNumber = "ipNetworkNumber";
/*const char *attmap_network_ipNetmaskNumber = "ipNetmaskNumber"; */

/*
 * ( nisSchema.2.0 NAME 'posixAccount' SUP top AUXILIARY
 *   DESC 'Abstraction of an account with POSIX attributes'
 *   MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory )
 *   MAY ( userPassword $ loginShell $ gecos $ description ) )
 */
const char *attmap_passwd_objectClass   = "posixAccount";
const char *attmap_passwd_uid           = "uid";
const char *attmap_passwd_userPassword  = "userPassword";
const char *attmap_passwd_uidNumber     = "uidNumber";
const char *attmap_passwd_gidNumber     = "gidNumber";
const char *attmap_passwd_gecos         = "gecos";
const char *attmap_passwd_cn            = "cn";
const char *attmap_passwd_homeDirectory = "homeDirectory";
const char *attmap_passwd_loginShell    = "loginShell";

/*
 * ( nisSchema.2.4 NAME 'ipProtocol' SUP top STRUCTURAL
 *   DESC 'Abstraction of an IP protocol. Maps a protocol number
 *         to one or more names. The distinguished value of the cn
 *         attribute denotes the protocol's canonical name'
 *   MUST ( cn $ ipProtocolNumber )
 *    MAY description )
 */
const char *attmap_protocol_objectClass      = "ipProtocol";
const char *attmap_protocol_cn               = "cn";
const char *attmap_protocol_ipProtocolNumber = "ipProtocolNumber";

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
const char *attmap_rpc_objectClass      = "oncRpc";
const char *attmap_rpc_cn               = "cn";
const char *attmap_rpc_oncRpcNumber     = "oncRpcNumber";

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
const char *attmap_service_objectClass       = "ipService";
const char *attmap_service_cn                = "cn";
const char *attmap_service_ipServicePort     = "ipServicePort";
const char *attmap_service_ipServiceProtocol = "ipServiceProtocol";

/*
 * ( nisSchema.2.1 NAME 'shadowAccount' SUP top AUXILIARY
 *   DESC 'Additional attributes for shadow passwords'
 *   MUST uid
 *   MAY ( userPassword $ shadowLastChange $ shadowMin
 *         shadowMax $ shadowWarning $ shadowInactive $
 *         shadowExpire $ shadowFlag $ description ) )
 */
const char *attmap_shadow_objectClass      = "shadowAccount";
const char *attmap_shadow_uid              = "uid";
const char *attmap_shadow_userPassword     = "userPassword";
const char *attmap_shadow_shadowLastChange = "shadowLastChange";
const char *attmap_shadow_shadowMin        = "shadowMin";
const char *attmap_shadow_shadowMax        = "shadowMax";
const char *attmap_shadow_shadowWarning    = "shadowWarning";
const char *attmap_shadow_shadowInactive   = "shadowInactive";
const char *attmap_shadow_shadowExpire     = "shadowExpire";
const char *attmap_shadow_shadowFlag       = "shadowFlag";

const char **attmap_get_var(const char *name)
{
  if (strncasecmp(name,"alias.",6)==0)
  {
    if (strcasecmp(name+6,"objectClass")==0)       return &attmap_alias_objectClass;
    if (strcasecmp(name+6,"cn")==0)                return &attmap_alias_cn;
    if (strcasecmp(name+6,"rfc822MailMember")==0)  return &attmap_alias_rfc822MailMember;
  }
  else if (strncasecmp(name,"ether.",6)==0)
  {
    if (strcasecmp(name+6,"objectClass")==0)       return &attmap_ether_objectClass;
    if (strcasecmp(name+6,"cn")==0)                return &attmap_ether_cn;
    if (strcasecmp(name+6,"macAddress")==0)        return &attmap_ether_macAddress;
  }
  else if (strncasecmp(name,"group.",6)==0)
  {
    if (strcasecmp(name+6,"objectClass")==0)       return &attmap_group_objectClass;
    if (strcasecmp(name+6,"cn")==0)                return &attmap_group_cn;
    if (strcasecmp(name+6,"userPassword")==0)      return &attmap_group_userPassword;
    if (strcasecmp(name+6,"gidNumber")==0)         return &attmap_group_gidNumber;
    if (strcasecmp(name+6,"memberUid")==0)         return &attmap_group_memberUid;
    if (strcasecmp(name+6,"uniqueMember")==0)      return &attmap_group_uniqueMember;
    if (strcasecmp(name+6,"memberOf")==0)          return &attmap_group_memberOf;
  }
  else if (strncasecmp(name,"host.",5)==0)
  {
    if (strcasecmp(name+5,"objectClass")==0)       return &attmap_host_objectClass;
    if (strcasecmp(name+5,"cn")==0)                return &attmap_host_cn;
    if (strcasecmp(name+5,"ipHostNumber")==0)      return &attmap_host_ipHostNumber;
  }
  else if (strncasecmp(name,"netgroup.",9)==0)
  {
    if (strcasecmp(name+9,"objectClass")==0)       return &attmap_netgroup_objectClass;
    if (strcasecmp(name+9,"cn")==0)                return &attmap_netgroup_cn;
    if (strcasecmp(name+9,"nisNetgroupTriple")==0) return &attmap_netgroup_nisNetgroupTriple;
    if (strcasecmp(name+9,"memberNisNetgroup")==0) return &attmap_netgroup_memberNisNetgroup;
  }
  else if (strncasecmp(name,"network.",8)==0)
  {
    if (strcasecmp(name+8,"objectClass")==0)       return &attmap_network_objectClass;
    if (strcasecmp(name+8,"cn")==0)                return &attmap_network_cn;
    if (strcasecmp(name+8,"ipNetworkNumber")==0)   return &attmap_network_ipNetworkNumber;
  }
  else if (strncasecmp(name,"passwd.",7)==0)
  {
    if (strcasecmp(name+7,"objectClass")==0)       return &attmap_passwd_objectClass;
    if (strcasecmp(name+7,"uid")==0)               return &attmap_passwd_uid;
    if (strcasecmp(name+7,"userPassword")==0)      return &attmap_passwd_userPassword;
    if (strcasecmp(name+7,"uidNumber")==0)         return &attmap_passwd_uidNumber;
    if (strcasecmp(name+7,"gidNumber")==0)         return &attmap_passwd_gidNumber;
    if (strcasecmp(name+7,"gecos")==0)             return &attmap_passwd_gecos;
    if (strcasecmp(name+7,"cn")==0)                return &attmap_passwd_cn;
    if (strcasecmp(name+7,"homeDirectory")==0)     return &attmap_passwd_homeDirectory;
    if (strcasecmp(name+7,"loginShell")==0)        return &attmap_passwd_loginShell;
  }
  else if (strncasecmp(name,"protocol.",9)==0)
  {
    if (strcasecmp(name+9,"objectClass")==0)       return &attmap_protocol_objectClass;
    if (strcasecmp(name+9,"cn")==0)                return &attmap_protocol_cn;
    if (strcasecmp(name+9,"ipProtocolNumber")==0)  return &attmap_protocol_ipProtocolNumber;
  }
  else if (strncasecmp(name,"rpc.",4)==0)
  {
    if (strcasecmp(name+9,"objectClass")==0)       return &attmap_rpc_objectClass;
    if (strcasecmp(name+9,"cn")==0)                return &attmap_rpc_cn;
    if (strcasecmp(name+9,"oncRpcNumber")==0)      return &attmap_rpc_oncRpcNumber;
  }
  else if (strncasecmp(name,"service.",8)==0)
  {
    if (strcasecmp(name+8,"objectClass")==0)       return &attmap_service_objectClass;
    if (strcasecmp(name+8,"cn")==0)                return &attmap_service_cn;
    if (strcasecmp(name+8,"ipServicePort")==0)     return &attmap_service_ipServicePort;
    if (strcasecmp(name+8,"ipServiceProtocol")==0) return &attmap_service_ipServiceProtocol;
  }
  else if (strncasecmp(name,"shadow.",7)==0)
  {
    if (strcasecmp(name+7,"objectClass")==0)       return &attmap_shadow_objectClass;
    if (strcasecmp(name+7,"uid")==0)               return &attmap_shadow_uid;
    if (strcasecmp(name+7,"userPassword")==0)      return &attmap_shadow_userPassword;
    if (strcasecmp(name+7,"shadowLastChange")==0)  return &attmap_shadow_shadowLastChange;
    if (strcasecmp(name+7,"shadowMin")==0)         return &attmap_shadow_shadowMin;
    if (strcasecmp(name+7,"shadowMax")==0)         return &attmap_shadow_shadowMax;
    if (strcasecmp(name+7,"shadowWarning")==0)     return &attmap_shadow_shadowWarning;
    if (strcasecmp(name+7,"shadowInactive")==0)    return &attmap_shadow_shadowInactive;
    if (strcasecmp(name+7,"shadowExpire")==0)      return &attmap_shadow_shadowExpire;
    if (strcasecmp(name+7,"shadowFlag")==0)        return &attmap_shadow_shadowFlag;
  }
  return NULL;
}
