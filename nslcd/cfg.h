/*
   cfg.h - definition of configuration information
   This file contains parts that were part of the nss_ldap
   library which has been forked into the nss-pam-ldapd library.

   Copyright (C) 1997-2005 Luke Howard
   Copyright (C) 2007 West Consulting
   Copyright (C) 2007, 2008, 2009, 2010, 2011, 2012, 2013 Arthur de Jong

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

#ifndef NSLCD__CFG_H
#define NSLCD__CFG_H

#include <unistd.h>
#include <sys/types.h>
#include <lber.h>
#include <ldap.h>
#include <regex.h>

#include "compat/attrs.h"
#include "common/set.h"

/* values for uid and gid */
#define NOUID ((gid_t)-1)
#define NOGID ((gid_t)-1)

/* maximum number of URIs */
#define NSS_LDAP_CONFIG_URI_MAX 31

/* maximum number of search bases */
#define NSS_LDAP_CONFIG_MAX_BASES 7

/* maximum number of pam_authz_search options */
#define NSS_LDAP_CONFIG_MAX_AUTHZ_SEARCHES 8

enum ldap_ssl_options
{
  SSL_OFF,
  SSL_LDAPS,
  SSL_START_TLS
};

/* selectors for different maps */
enum ldap_map_selector
{
  LM_PASSWD,
  LM_SHADOW,
  LM_GROUP,
  LM_HOSTS,
  LM_SERVICES,
  LM_NETWORKS,
  LM_PROTOCOLS,
  LM_RPC,
  LM_ETHERS,
  LM_ALIASES,
  LM_NETGROUP,
  LM_NONE
};

struct myldap_uri
{
  char *uri;
  /* time of first failed operation */
  time_t firstfail;
  /* time of last failed operation */
  time_t lastfail;
};

struct ldap_config
{
  /* the number of threads to start */
  int ldc_threads;
  /* the user name specified in the uid option */
  char *ldc_uidname;
  /* the user id nslcd should be run as */
  uid_t ldc_uid;
  /* the group id nslcd should be run as */
  gid_t ldc_gid;
  /* whether or not case should be ignored in lookups */
  int ldc_ignorecase;
  /* NULL terminated list of URIs */
  struct myldap_uri ldc_uris[NSS_LDAP_CONFIG_URI_MAX+1];
  /* protocol version */
  int ldc_version;
  /* bind DN */
  char *ldc_binddn;
  /* bind cred */
  char *ldc_bindpw;
  /* bind DN for password modification by administrator */
  char *ldc_rootpwmoddn;
  /* bind password for password modification by root */
  char *ldc_rootpwmodpw;
  /* sasl mech */
  char *ldc_sasl_mech;
  /* sasl realm */
  char *ldc_sasl_realm;
  /* sasl authentication id */
  char *ldc_sasl_authcid;
  /* sasl authorization id */
  char *ldc_sasl_authzid;
  /* sasl security */
  char *ldc_sasl_secprops;
#ifdef LDAP_OPT_X_SASL_NOCANON
  /* whether host name should be canonicalised */
  int ldc_sasl_canonicalize;
#endif /* LDAP_OPT_X_SASL_NOCANON */
  /* base DN, eg. dc=gnu,dc=org */
  const char *ldc_bases[NSS_LDAP_CONFIG_MAX_BASES];
  /* scope for searches */
  int ldc_scope;
  /* dereference aliases/links */
  int ldc_deref;
  /* chase referrals */
  int ldc_referrals;
  /* bind timelimit */
  int ldc_bind_timelimit;
  /* search timelimit */
  int ldc_timelimit;
  /* idle timeout */
  int ldc_idle_timelimit;
  /* seconds to sleep; doubled until max */
  int ldc_reconnect_sleeptime;
  /* maximum seconds to sleep */
  int ldc_reconnect_retrytime;
#ifdef LDAP_OPT_X_TLS
  /* SSL enabled */
  enum ldap_ssl_options ldc_ssl_on;
#endif /* LDAP_OPT_X_TLS */
  /* whether the LDAP library should restart the select(2) system call when interrupted */
  int ldc_restart;
  /* set to a greater than 0 to enable handling of paged results with the specified size */
  int ldc_pagesize;
  /* the users for which no initgroups() searches should be done */
  SET *ldc_nss_initgroups_ignoreusers;
  /* the searches that should be performed to do autorisation checks */
  char *ldc_pam_authz_search[NSS_LDAP_CONFIG_MAX_AUTHZ_SEARCHES];
  /* minimum uid for users retrieved from LDAP */
  uid_t ldc_nss_min_uid;
  /* the regular expression to determine valid names */
  regex_t validnames;
  /* whether password changing should be denied and user prompted with
     this message */
  char *pam_password_prohibit_message;
};

/* this is a pointer to the global configuration, it should be available
   once cfg_init() was called */
extern struct ldap_config *nslcd_cfg;

/* Initialize the configuration in nslcd_cfg. This method
   will read the default configuration file and call exit()
   if an error occurs. */
void cfg_init(const char *fname);

#endif /* NSLCD__CFG_H */
