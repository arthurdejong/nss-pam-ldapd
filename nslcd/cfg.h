/*
   cfg.h - definition of configuration information
   This file contains parts that were part of the nss-ldap
   library which has been forked into the nss-ldapd library.

   Copyright (C) 1997-2005 Luke Howard
   Copyright (C) 2007 West Consulting
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

#ifndef _CFG_H
#define _CFG_H

#include "ldap-nss.h"
#include "common/dict.h"
#include "compat/attrs.h"

/* maximum number of URIs */
#define NSS_LDAP_CONFIG_URI_MAX         31

enum ldap_ssl_options
{
  SSL_OFF,
  SSL_LDAPS,
  SSL_START_TLS
};

enum ldap_reconnect_policy
{
  LP_RECONNECT_HARD_INIT,
  LP_RECONNECT_HARD_OPEN,
  LP_RECONNECT_SOFT
};

struct ldap_config
{
  /* NULL terminated list of URIs */
  char *ldc_uris[NSS_LDAP_CONFIG_URI_MAX + 1];
  /* default port, if not specified in URI */
  int ldc_port;
  /* base DN, eg. dc=gnu,dc=org */
  char *ldc_base;
  /* scope for searches */
  int ldc_scope;
  /* dereference aliases/links */
  int ldc_deref;
  /* bind DN */
  char *ldc_binddn;
  /* bind cred */
  char *ldc_bindpw;
  /* do we use sasl when binding? */
  int ldc_usesasl;
  /* sasl auth id */
  char *ldc_saslid;
  /* shadow bind DN */
  char *ldc_rootbinddn;
  /* shadow bind cred */
  char *ldc_rootbindpw;
  /* do we use sasl for root? */
  int ldc_rootusesasl;
  /* shadow sasl auth id */
  char *ldc_rootsaslid;
  /* protocol version */
  int ldc_version;
  /* search timelimit */
  int ldc_timelimit;
  /* bind timelimit */
  int ldc_bind_timelimit;
  /* SSL enabled */
  enum ldap_ssl_options ldc_ssl_on;
  /* SSL certificate path */
  char *ldc_sslpath;
  /* Chase referrals */
  int ldc_referrals;
  int ldc_restart;
  /* naming contexts */
  struct ldap_service_search_descriptor *ldc_sds[LM_NONE];
  /* tls check peer */
  int ldc_tls_checkpeer;
  /* tls ca certificate file */
  char *ldc_tls_cacertfile;
  /* tls ca certificate dir */
  char *ldc_tls_cacertdir;
  /* tls ciphersuite */
  char *ldc_tls_ciphers;
  /* tls certificate */
  char *ldc_tls_cert;
  /* tls key */
  char *ldc_tls_key;
  /* tls randfile */
  char *ldc_tls_randfile;
  /* idle timeout */
  time_t ldc_idle_timelimit;
  /* reconnect policy */
  enum ldap_reconnect_policy ldc_reconnect_pol;
  int ldc_reconnect_tries;
  int ldc_reconnect_sleeptime;
  int ldc_reconnect_maxsleeptime;
  int ldc_reconnect_maxconntries;
  /* sasl security */
  char *ldc_sasl_secprops;
  /* directory for debug files */
  char *ldc_logdir;
  /* LDAP debug level */
  int ldc_debug;
  int ldc_pagesize;
#ifdef CONFIGURE_KRB5_CCNAME
  /* krb5 ccache name */
  char *ldc_krb5_ccname;
#endif /* CONFIGURE_KRB5_CCNAME */
  /* attribute/objectclass maps relative to this config */
  DICT *ldc_maps[LM_NONE + 1][6]; /* must match MAP_MAX */
  /* is userPassword "userPassword" or not? ie. do we need {crypt} to be stripped */
  enum ldap_userpassword_selector ldc_password_type;
  /* Use active directory time offsets? */
  enum ldap_shadow_selector ldc_shadow_type;
  /* attribute table for ldap search requensts */
  const char **ldc_attrtab[LM_NONE + 1];
  unsigned int ldc_flags;
  /* last modification time */
  time_t ldc_mtime;
  char **ldc_initgroups_ignoreusers;
};

extern struct ldap_config *nslcd_cfg;

/*
 * There are a number of means of obtaining configuration information.
 *
 * (a) DHCP (Cf draft-hedstrom-dhc-ldap-00.txt)
 * (b) a configuration file (/etc/ldap.conf) **
 * (c) a coldstart file & subsequent referrals from the LDAP server
 * (d) a custom LDAP bind protocol
 * (e) DNS **
 *
 * This should be opaque to the rest of the library.
 * ** implemented
 */

/*
 * Flags that are exposed via _nss_ldap_test_config_flag()
 */
#define NSS_LDAP_FLAGS_INITGROUPS_BACKLINK      0x0001
#define NSS_LDAP_FLAGS_PAGED_RESULTS            0x0002
#define NSS_LDAP_FLAGS_RFC2307BIS               0x0004
#define NSS_LDAP_FLAGS_CONNECT_POLICY_ONESHOT   0x0008

int _nss_ldap_test_config_flag(unsigned int flag)
  MUST_USE;

int cfg_init(void)
  MUST_USE;

#endif /* _CFG_H */
