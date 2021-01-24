/*
   attmap.c - attribute mapping values and functions
   This file is part of the nss-pam-ldapd library.

   Copyright (C) 2007-2014 Arthur de Jong

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
#include "log.h"
#include "common/expr.h"

/* these are the bases that are defined per database */
extern const char *alias_bases[];
extern const char *ether_bases[];
extern const char *group_bases[];
extern const char *host_bases[];
extern const char *netgroup_bases[];
extern const char *network_bases[];
extern const char *passwd_bases[];
extern const char *protocol_bases[];
extern const char *rpc_bases[];
extern const char *service_bases[];
extern const char *shadow_bases[];

const char **base_get_var(enum ldap_map_selector map)
{
  switch (map)
  {
    case LM_ALIASES:   return alias_bases;
    case LM_ETHERS:    return ether_bases;
    case LM_GROUP:     return group_bases;
    case LM_HOSTS:     return host_bases;
    case LM_NETGROUP:  return netgroup_bases;
    case LM_NETWORKS:  return network_bases;
    case LM_PASSWD:    return passwd_bases;
    case LM_PROTOCOLS: return protocol_bases;
    case LM_RPC:       return rpc_bases;
    case LM_SERVICES:  return service_bases;
    case LM_SHADOW:    return shadow_bases;
    case LM_NFSIDMAP:
    case LM_NONE:
    default:           return NULL;
  }
}

/* these are the scopes that are defined per database */
extern int alias_scope;
extern int ether_scope;
extern int group_scope;
extern int host_scope;
extern int netgroup_scope;
extern int network_scope;
extern int passwd_scope;
extern int protocol_scope;
extern int rpc_scope;
extern int service_scope;
extern int shadow_scope;

int *scope_get_var(enum ldap_map_selector map)
{
  switch (map)
  {
    case LM_ALIASES:   return &alias_scope;
    case LM_ETHERS:    return &ether_scope;
    case LM_GROUP:     return &group_scope;
    case LM_HOSTS:     return &host_scope;
    case LM_NETGROUP:  return &netgroup_scope;
    case LM_NETWORKS:  return &network_scope;
    case LM_PASSWD:    return &passwd_scope;
    case LM_PROTOCOLS: return &protocol_scope;
    case LM_RPC:       return &rpc_scope;
    case LM_SERVICES:  return &service_scope;
    case LM_SHADOW:    return &shadow_scope;
    case LM_NFSIDMAP:
    case LM_NONE:
    default:           return NULL;
  }
}

/* these are the filters that are defined per database */
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

const char **filter_get_var(enum ldap_map_selector map)
{
  switch (map)
  {
    case LM_ALIASES:   return &alias_filter;
    case LM_ETHERS:    return &ether_filter;
    case LM_GROUP:     return &group_filter;
    case LM_HOSTS:     return &host_filter;
    case LM_NETGROUP:  return &netgroup_filter;
    case LM_NETWORKS:  return &network_filter;
    case LM_PASSWD:    return &passwd_filter;
    case LM_PROTOCOLS: return &protocol_filter;
    case LM_RPC:       return &rpc_filter;
    case LM_SERVICES:  return &service_filter;
    case LM_SHADOW:    return &shadow_filter;
    case LM_NFSIDMAP:
    case LM_NONE:
    default:           return NULL;
  }
}

const char **attmap_get_var(enum ldap_map_selector map, const char *name)
{
  if (map == LM_ALIASES)
  {
    if (strcasecmp(name, "cn") == 0)                return &attmap_alias_cn;
    if (strcasecmp(name, "rfc822MailMember") == 0)  return &attmap_alias_rfc822MailMember;
  }
  else if (map == LM_ETHERS)
  {
    if (strcasecmp(name, "cn") == 0)                return &attmap_ether_cn;
    if (strcasecmp(name, "macAddress") == 0)        return &attmap_ether_macAddress;
  }
  else if (map == LM_GROUP)
  {
    if (strcasecmp(name, "cn") == 0)                return &attmap_group_cn;
    if (strcasecmp(name, "userPassword") == 0)      return &attmap_group_userPassword;
    if (strcasecmp(name, "gidNumber") == 0)         return &attmap_group_gidNumber;
    if (strcasecmp(name, "memberUid") == 0)         return &attmap_group_memberUid;
    if (strcasecmp(name, "member") == 0)            return &attmap_group_member;
  }
  else if (map == LM_HOSTS)
  {
    if (strcasecmp(name, "cn") == 0)                return &attmap_host_cn;
    if (strcasecmp(name, "ipHostNumber") == 0)      return &attmap_host_ipHostNumber;
  }
  else if (map == LM_NETGROUP)
  {
    if (strcasecmp(name, "cn") == 0)                return &attmap_netgroup_cn;
    if (strcasecmp(name, "nisNetgroupTriple") == 0) return &attmap_netgroup_nisNetgroupTriple;
    if (strcasecmp(name, "memberNisNetgroup") == 0) return &attmap_netgroup_memberNisNetgroup;
  }
  else if (map == LM_NETWORKS)
  {
    if (strcasecmp(name, "cn") == 0)                return &attmap_network_cn;
    if (strcasecmp(name, "ipNetworkNumber") == 0)   return &attmap_network_ipNetworkNumber;
  }
  else if (map == LM_PASSWD)
  {
    if (strcasecmp(name, "uid") == 0)               return &attmap_passwd_uid;
    if (strcasecmp(name, "userPassword") == 0)      return &attmap_passwd_userPassword;
    if (strcasecmp(name, "uidNumber") == 0)         return &attmap_passwd_uidNumber;
    if (strcasecmp(name, "gidNumber") == 0)         return &attmap_passwd_gidNumber;
    if (strcasecmp(name, "gecos") == 0)             return &attmap_passwd_gecos;
    if (strcasecmp(name, "homeDirectory") == 0)     return &attmap_passwd_homeDirectory;
    if (strcasecmp(name, "loginShell") == 0)        return &attmap_passwd_loginShell;
    if (strcasecmp(name, "class") == 0)             return &attmap_passwd_class;
  }
  else if (map == LM_PROTOCOLS)
  {
    if (strcasecmp(name, "cn") == 0)                return &attmap_protocol_cn;
    if (strcasecmp(name, "ipProtocolNumber") == 0)  return &attmap_protocol_ipProtocolNumber;
  }
  else if (map == LM_RPC)
  {
    if (strcasecmp(name, "cn") == 0)                return &attmap_rpc_cn;
    if (strcasecmp(name, "oncRpcNumber") == 0)      return &attmap_rpc_oncRpcNumber;
  }
  else if (map == LM_SERVICES)
  {
    if (strcasecmp(name, "cn") == 0)                return &attmap_service_cn;
    if (strcasecmp(name, "ipServicePort") == 0)     return &attmap_service_ipServicePort;
    if (strcasecmp(name, "ipServiceProtocol") == 0) return &attmap_service_ipServiceProtocol;
  }
  else if (map == LM_SHADOW)
  {
    if (strcasecmp(name, "uid") == 0)               return &attmap_shadow_uid;
    if (strcasecmp(name, "userPassword") == 0)      return &attmap_shadow_userPassword;
    if (strcasecmp(name, "shadowLastChange") == 0)  return &attmap_shadow_shadowLastChange;
    if (strcasecmp(name, "shadowMin") == 0)         return &attmap_shadow_shadowMin;
    if (strcasecmp(name, "shadowMax") == 0)         return &attmap_shadow_shadowMax;
    if (strcasecmp(name, "shadowWarning") == 0)     return &attmap_shadow_shadowWarning;
    if (strcasecmp(name, "shadowInactive") == 0)    return &attmap_shadow_shadowInactive;
    if (strcasecmp(name, "shadowExpire") == 0)      return &attmap_shadow_shadowExpire;
    if (strcasecmp(name, "shadowFlag") == 0)        return &attmap_shadow_shadowFlag;
  }
  return NULL;
}

const char *attmap_set_mapping(const char **var, const char *value)
{
  /* check if we are setting an expression */
  if (value[0] == '"')
  {
    /* these attributes may contain an expression
       (note that this needs to match the functionality in the specific
       lookup module) */
    if ((var != &attmap_group_userPassword) &&
        (var != &attmap_group_member) &&
        (var != &attmap_passwd_userPassword) &&
        (var != &attmap_passwd_gidNumber) &&
        (var != &attmap_passwd_gecos) &&
        (var != &attmap_passwd_homeDirectory) &&
        (var != &attmap_passwd_loginShell) &&
        (var != &attmap_passwd_class) &&
        (var != &attmap_shadow_userPassword) &&
        (var != &attmap_shadow_shadowLastChange) &&
        (var != &attmap_shadow_shadowMin) &&
        (var != &attmap_shadow_shadowMax) &&
        (var != &attmap_shadow_shadowWarning) &&
        (var != &attmap_shadow_shadowInactive) &&
        (var != &attmap_shadow_shadowExpire) &&
        (var != &attmap_shadow_shadowFlag))
      return NULL;
    /* the member attribute may only be set to an empty string */
    if ((var == &attmap_group_member) && (strcmp(value, "\"\"") != 0))
      return NULL;
  }
  /* check if the value will be changed */
  if ((*var == NULL) || (strcmp(*var, value) != 0))
    *var = strdup(value);
  return *var;
}

static const char *entry_expand(const char *name, void *expander_attr)
{
  MYLDAP_ENTRY *entry = (MYLDAP_ENTRY *)expander_attr;
  const char **values;
  if (strcasecmp(name, "dn") == 0)
    return myldap_get_dn(entry);
  values = myldap_get_values(entry, name);
  if (values == NULL)
    return "";
  /* TODO: handle userPassword attribute specially */
  if ((values[0] != NULL) && (values[1] != NULL))
  {
    log_log(LOG_WARNING, "%s: %s: multiple values",
            myldap_get_dn(entry), name);
  }
  return values[0];
}

const char *attmap_get_value(MYLDAP_ENTRY *entry, const char *attr,
                             char *buffer, size_t buflen)
{
  const char **values;
  /* check and clear buffer */
  if ((buffer == NULL) || (buflen <= 0))
    return NULL;
  buffer[0] = '\0';
  /* for simple values just return the attribute */
  if (attr[0] != '"')
  {
    values = myldap_get_values(entry, attr);
    if ((values == NULL) || (values[0] == NULL))
      return NULL;
    if (strlen(values[0]) >= buflen)
    {
      log_log(LOG_ERR, "attmap_get_value(): buffer too small (%lu required)",
              (unsigned long) strlen(values[0]));
      return NULL;
    }
    strncpy(buffer, values[0], buflen);
    buffer[buflen - 1] = '\0';
    return buffer;
    /* TODO: maybe warn when multiple values are found */
  }
  /* we have an expression, try to parse */
  if ((attr[strlen(attr) - 1] != '"') ||
      (expr_parse(attr + 1, buffer, buflen, entry_expand, (void *)entry) == NULL))
  {
    log_log(LOG_ERR, "attribute mapping %s is invalid", attr);
    buffer[0] = '\0';
    return NULL;
  }
  /* strip trailing " */
  if (buffer[strlen(buffer) - 1] == '"')
    buffer[strlen(buffer) - 1] = '\0';
  return buffer;
}

SET *attmap_add_attributes(SET *set, const char *attr)
{
  if (attr[0] != '\"')
    set_add(set, attr);
  else
    expr_vars(attr, set);
  return set;
}
