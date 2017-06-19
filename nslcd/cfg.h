/*
   cfg.h - definition of configuration information
   This file contains parts that were part of the nss_ldap
   library which has been forked into the nss-pam-ldapd library.

   Copyright (C) 1997-2005 Luke Howard
   Copyright (C) 2007 West Consulting
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

#ifndef NSLCD__CFG_H
#define NSLCD__CFG_H

#include <unistd.h>
#include <sys/types.h>
#include <lber.h>
#include <ldap.h>
#include <regex.h>
#include <time.h>

#include "compat/attrs.h"
#include "common/set.h"

/* values for uid and gid */
#define NOUID ((gid_t)-1)
#define NOGID ((gid_t)-1)

/* maximum number of URIs */
#define NSS_LDAP_CONFIG_MAX_URIS 31

/* maximum number of search bases */
#define NSS_LDAP_CONFIG_MAX_BASES 31

/* maximum number of pam_authz_search options */
#define NSS_LDAP_CONFIG_MAX_AUTHZ_SEARCHES 8

enum ldap_ssl_options {
  SSL_OFF,
  SSL_LDAPS,
  SSL_START_TLS
};

/* selectors for different maps */
enum ldap_map_selector {
  LM_ALIASES,
  LM_ETHERS,
  LM_GROUP,
  LM_HOSTS,
  LM_NETGROUP,
  LM_NETWORKS,
  LM_PASSWD,
  LM_PROTOCOLS,
  LM_RPC,
  LM_SERVICES,
  LM_SHADOW,
  LM_NFSIDMAP, /* only used for cache invalidation */
  LM_NONE
};

struct myldap_uri {
  char *uri;
  /* time of first failed operation */
  time_t firstfail;
  /* time of last failed operation */
  time_t lastfail;
};

struct ldap_config {
  int threads;    /* the number of threads to start */
  char *uidname;  /* the user name specified in the uid option */
  uid_t uid;      /* the user id nslcd should be run as */
  gid_t gid;      /* the group id nslcd should be run as */

  struct myldap_uri uris[NSS_LDAP_CONFIG_MAX_URIS + 1]; /* NULL terminated list of URIs */
  int ldap_version;   /* LDAP protocol version */
  char *binddn;       /* bind DN */
  char *bindpw;       /* bind cred */
  char *rootpwmoddn;  /* bind DN for password modification by root */
  char *rootpwmodpw;  /* bind password for password modification by root */

  char *sasl_mech;      /* SASL mechanism */
  char *sasl_realm;     /* SASL realm */
  char *sasl_authcid;   /* SASL authentication identity */
  char *sasl_authzid;   /* SASL authorization identity */
  char *sasl_secprops;  /* SASL security properties */
#ifdef LDAP_OPT_X_SASL_NOCANON
  int sasl_canonicalize; /* whether host name should be canonicalised */
#endif /* LDAP_OPT_X_SASL_NOCANON */

  const char *bases[NSS_LDAP_CONFIG_MAX_BASES]; /* search bases */
  int scope;      /* scope for searches */
  int deref;      /* dereference aliases/links */
  int referrals;  /* chase referrals */

#if defined(HAVE_LDAP_SASL_BIND) && defined(LDAP_SASL_SIMPLE)
  int pam_authc_ppolicy;    /* whether to send password policy controls on bind */
#endif
  int bind_timelimit;       /* bind timelimit */
  int timelimit;            /* search timelimit */
  int idle_timelimit;       /* idle timeout */
  int reconnect_sleeptime;  /* seconds to sleep; doubled until max */
  int reconnect_retrytime;  /* maximum seconds to sleep */

#ifdef LDAP_OPT_X_TLS
  /* SSL enabled */
  enum ldap_ssl_options ssl;
#endif /* LDAP_OPT_X_TLS */

  int pagesize; /* set to a greater than 0 to enable handling of paged results with the specified size */
  SET *nss_initgroups_ignoreusers;  /* the users for which no initgroups() searches should be done */
  uid_t nss_min_uid;  /* minimum uid for users retrieved from LDAP */
  uid_t nss_uid_offset; /* offset for uids retrieved from LDAP to avoid local uid clashes */
  gid_t nss_gid_offset; /* offset for gids retrieved from LDAP to avoid local gid clashes */
  int nss_nested_groups; /* whether to expand nested groups */
  int nss_getgrent_skipmembers;  /* whether to skip member lookups */
  int nss_disable_enumeration;  /* enumeration turned on or off */
  regex_t validnames; /* the regular expression to determine valid names */
  char *validnames_str; /* string version of validnames regexp */
  int ignorecase; /* whether or not case should be ignored in lookups */
  char *pam_authc_search; /* the search that should be performed post-authentication */
  char *pam_authz_searches[NSS_LDAP_CONFIG_MAX_AUTHZ_SEARCHES]; /* the searches that should be performed to do autorisation checks */
  char *pam_password_prohibit_message;   /* whether password changing should be denied and user prompted with this message */
  char reconnect_invalidate[LM_NONE];  /* set to 1 if the corresponding map should be invalidated */

  time_t cache_dn2uid_positive;
  time_t cache_dn2uid_negative;
};

/* this is a pointer to the global configuration, it should be available
   and populated after cfg_init() is called */
extern struct ldap_config *nslcd_cfg;

/* Initialize the configuration in nslcd_cfg. This method will read the
   default configuration file and call exit() if an error occurs. */
void cfg_init(const char *fname);

#endif /* NSLCD__CFG_H */
