/*
   cfg.c - functions for configuration information
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

#include "config.h"

#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

#include "ldap-nss.h"
#include "util.h"
#include "log.h"
#include "ldap-schema.h"
#include "cfg.h"
#include "attmap.h"

struct ldap_config *nslcd_cfg=NULL;

/*
 * Timeouts for reconnecting code. Similar to rebind
 * logic in Darwin NetInfo. Some may find sleeping
 * unacceptable, in which case you may wish to adjust
 * the constants below.
 */
#define LDAP_NSS_TRIES           5      /* number of sleeping reconnect attempts */
#define LDAP_NSS_SLEEPTIME       4      /* seconds to sleep; doubled until max */
#define LDAP_NSS_MAXSLEEPTIME    64     /* maximum seconds to sleep */
#define LDAP_NSS_MAXCONNTRIES    2      /* reconnect attempts before sleeping */

#define NSS_LDAP_KEY_MAP                "map"
#define NSS_LDAP_KEY_SCOPE              "scope"
#define NSS_LDAP_KEY_BASE               "base"
#define NSS_LDAP_KEY_BINDDN             "binddn"
#define NSS_LDAP_KEY_BINDPW             "bindpw"
#define NSS_LDAP_KEY_USESASL            "use_sasl"
#define NSS_LDAP_KEY_SASLID             "sasl_auth_id"
#define NSS_LDAP_KEY_DEREF              "deref"
#define NSS_LDAP_KEY_ROOTBINDDN         "rootbinddn"
#define NSS_LDAP_KEY_ROOTUSESASL        "rootuse_sasl"
#define NSS_LDAP_KEY_ROOTSASLID         "rootsasl_auth_id"
#define NSS_LDAP_KEY_LDAP_VERSION       "ldap_version"
#define NSS_LDAP_KEY_TIMELIMIT          "timelimit"
#define NSS_LDAP_KEY_BIND_TIMELIMIT     "bind_timelimit"
#define NSS_LDAP_KEY_SSL                "ssl"
#define NSS_LDAP_KEY_SSLPATH            "sslpath"
#define NSS_LDAP_KEY_REFERRALS          "referrals"
#define NSS_LDAP_KEY_RESTART            "restart"
#define NSS_LDAP_KEY_URI                "uri"
#define NSS_LDAP_KEY_IDLE_TIMELIMIT     "idle_timelimit"
#define NSS_LDAP_KEY_RECONNECT_POLICY   "bind_policy"
#define NSS_LDAP_KEY_SASL_SECPROPS      "sasl_secprops"
#ifdef CONFIGURE_KRB5_CCNAME
#define NSS_LDAP_KEY_KRB5_CCNAME        "krb5_ccname"
#endif /* CONFIGURE_KRB5_CCNAME */
#define NSS_LDAP_KEY_DEBUG              "debug"
#define NSS_LDAP_KEY_PAGESIZE           "pagesize"

/* more reconnect policy fine-tuning */
#define NSS_LDAP_KEY_RECONNECT_TRIES            "nss_reconnect_tries"
#define NSS_LDAP_KEY_RECONNECT_SLEEPTIME        "nss_reconnect_sleeptime"
#define NSS_LDAP_KEY_RECONNECT_MAXSLEEPTIME     "nss_reconnect_maxsleeptime"
#define NSS_LDAP_KEY_RECONNECT_MAXCONNTRIES     "nss_reconnect_maxconntries"

#define NSS_LDAP_KEY_SCHEMA             "nss_schema"
#define NSS_LDAP_KEY_CONNECT_POLICY     "nss_connect_policy"

/*
 * support separate naming contexts for each map
 * eventually this will support the syntax defined in
 * the DUAConfigProfile searchDescriptor attribute
 */
#define NSS_LDAP_KEY_NSS_BASE_PREFIX            "nss_base_"
#define NSS_LDAP_KEY_NSS_BASE_PREFIX_LEN        ( sizeof(NSS_LDAP_KEY_NSS_BASE_PREFIX) - 1 )

#define NSS_LDAP_CONFIG_BUFSIZ          4096

int _nss_ldap_test_config_flag(unsigned int flag)
{
  return nslcd_cfg != NULL &&
         (nslcd_cfg->ldc_flags&flag);
}

static void _nss_ldap_init_config(struct ldap_config *result)
{

  memset (result, 0, sizeof (*result));

  result->ldc_scope = LDAP_SCOPE_SUBTREE;
  result->ldc_deref = LDAP_DEREF_NEVER;
  result->ldc_base = NULL;
  result->ldc_binddn = NULL;
  result->ldc_bindpw = NULL;
  result->ldc_saslid = NULL;
  result->ldc_usesasl = 0;
  result->ldc_rootbinddn = NULL;
  result->ldc_rootbindpw = NULL;
  result->ldc_rootsaslid = NULL;
  result->ldc_rootusesasl = 0;
#ifdef LDAP_VERSION3
  result->ldc_version = LDAP_VERSION3;
#else /* LDAP_VERSION3 */
  result->ldc_version = LDAP_VERSION2;
#endif /* not LDAP_VERSION3 */
  result->ldc_timelimit = LDAP_NO_LIMIT;
  result->ldc_bind_timelimit = 30;
  result->ldc_ssl_on = SSL_OFF;
  result->ldc_sslpath = NULL;
  result->ldc_referrals = 1;
  result->ldc_restart = 1;
  result->ldc_tls_checkpeer = -1;
  result->ldc_tls_cacertfile = NULL;
  result->ldc_tls_cacertdir = NULL;
  result->ldc_tls_ciphers = NULL;
  result->ldc_tls_cert = NULL;
  result->ldc_tls_key = NULL;
  result->ldc_tls_randfile = NULL;
  result->ldc_idle_timelimit = 0;
  result->ldc_reconnect_pol = LP_RECONNECT_HARD_OPEN;
  result->ldc_sasl_secprops = NULL;
  result->ldc_debug = 0;
  result->ldc_pagesize = 0;
#ifdef CONFIGURE_KRB5_CCNAME
  result->ldc_krb5_ccname = NULL;
#endif /* CONFIGURE_KRB5_CCNAME */
  result->ldc_flags = 0;
#ifdef RFC2307BIS
  result->ldc_flags |= NSS_LDAP_FLAGS_RFC2307BIS;
#endif /* RFC2307BIS */
  result->ldc_reconnect_tries = LDAP_NSS_TRIES;
  result->ldc_reconnect_sleeptime = LDAP_NSS_SLEEPTIME;
  result->ldc_reconnect_maxsleeptime = LDAP_NSS_MAXSLEEPTIME;
  result->ldc_reconnect_maxconntries = LDAP_NSS_MAXCONNTRIES;
}

static enum nss_status
_nss_ldap_add_uri (struct ldap_config *result, const char *uri,
                   char **buffer, size_t *buflen)
{
  /* add a single URI to the list of URIs in the configuration */
  int i;
  size_t uri_len;

  log_log(LOG_DEBUG,"==> _nss_ldap_add_uri");

  for (i = 0; result->ldc_uris[i] != NULL; i++)
    ;

  if (i == NSS_LDAP_CONFIG_URI_MAX)
    {
      log_log(LOG_DEBUG,"<== _nss_ldap_add_uri: maximum number of URIs exceeded");
      return NSS_STATUS_UNAVAIL;
    }

  assert (i < NSS_LDAP_CONFIG_URI_MAX);

  uri_len = strlen (uri);

  if (*buflen < uri_len + 1)
    return NSS_STATUS_TRYAGAIN;

  memcpy (*buffer, uri, uri_len + 1);

  result->ldc_uris[i] = *buffer;
  result->ldc_uris[i + 1] = NULL;

  *buffer += uri_len + 1;
  *buflen -= uri_len + 1;

  log_log(LOG_DEBUG,"<== _nss_ldap_add_uri: added URI %s", uri);

  return NSS_STATUS_SUCCESS;
}

static enum nss_status
do_add_uris (struct ldap_config *result, char *uris,
             char **buffer, size_t *buflen)
{
  /* Add a space separated list of URIs */
  char *p;
  enum nss_status status = NSS_STATUS_SUCCESS;

  for (p = uris; p != NULL; )
    {
      char *q = strchr (p, ' ');
      if (q != NULL)
        *q = '\0';

      status = _nss_ldap_add_uri (result, p, buffer, buflen);

      p = (q != NULL) ? ++q : NULL;

      if (status != NSS_STATUS_SUCCESS)
        break;
    }

  return status;
}

static enum ldap_map_selector _nss_ldap_str2selector(const char *key)
{
  enum ldap_map_selector sel;

  if (!strcasecmp (key, MP_passwd))
    sel = LM_PASSWD;
  else if (!strcasecmp (key, MP_shadow))
    sel = LM_SHADOW;
  else if (!strcasecmp (key, MP_group))
    sel = LM_GROUP;
  else if (!strcasecmp (key, MP_hosts))
    sel = LM_HOSTS;
  else if (!strcasecmp (key, MP_services))
    sel = LM_SERVICES;
  else if (!strcasecmp (key, MP_networks))
    sel = LM_NETWORKS;
  else if (!strcasecmp (key, MP_protocols))
    sel = LM_PROTOCOLS;
  else if (!strcasecmp (key, MP_rpc))
    sel = LM_RPC;
  else if (!strcasecmp (key, MP_ethers))
    sel = LM_ETHERS;
  else if (!strcasecmp (key, MP_aliases))
    sel = LM_ALIASES;
  else if (!strcasecmp (key, MP_netgroup))
    sel = LM_NETGROUP;
  else
    sel = LM_NONE;
  return sel;
}

/* this function modifies the statement argument passed */
static enum nss_status do_parse_map_statement(
                struct ldap_config *cfg,char *statement)
{
  char *key,*val;
  const char **var;
  key=(char *)statement;
  val=key;
  /* search for the end of the key */
  while (*val!=' '&&*val!='\t')
    val++;
  *(val++)='\0';
  /* search for the end of the value */
  while (*val==' '||*val=='\t')
    val++;
  /* special handling for some attribute mappings */
  if (strcasecmp(key,"passwd.userPassword")==0)
  {
    if (strcasecmp(val,"userPassword")==0)
      cfg->ldc_password_type=LU_RFC2307_USERPASSWORD;
    else if (strcasecmp (val,"authPassword")==0)
      cfg->ldc_password_type=LU_RFC3112_AUTHPASSWORD;
    else
      cfg->ldc_password_type=LU_OTHER_PASSWORD;
  }
  else if (strcasecmp(key,"shadow.shadowLastChange")==0)
  {
    if (strcasecmp(val,"shadowLastChange")==0)
      cfg->ldc_shadow_type=LS_RFC2307_SHADOW;
    else if (strcasecmp (val,"pwdLastSet")==0)
      cfg->ldc_shadow_type=LS_AD_SHADOW;
  }
  var=attmap_get_var(key);
  if (var==NULL)
    /* the used mapping key was unknown */
    return NSS_STATUS_NOTFOUND;
  /* check if the value actually changed */
  if (strcmp(*var,val)!=0)
  {
    /* Note: we have a memory leak here if a single mapping is changed
             multiple times in one config (deemed not a problem) */
    *var=strdup(val);
    if (*var==NULL)
      /* memory allocation failed */
      return NSS_STATUS_TRYAGAIN;
  }
  return NSS_STATUS_SUCCESS;
}

static enum nss_status
do_searchdescriptorconfig (const char *key, const char *value, size_t len,
                           struct ldap_service_search_descriptor ** result,
                           char **buffer, size_t * buflen)
{
  struct ldap_service_search_descriptor **t, *cur;
  char *base;
  char *filter, *s;
  int scope;
  enum ldap_map_selector sel;

  t = NULL;
  filter = NULL;
  scope = -1;

  if (strncasecmp (key, NSS_LDAP_KEY_NSS_BASE_PREFIX,
                   NSS_LDAP_KEY_NSS_BASE_PREFIX_LEN) != 0)
    return NSS_STATUS_SUCCESS;

  sel = _nss_ldap_str2selector (&key[NSS_LDAP_KEY_NSS_BASE_PREFIX_LEN]);
  t = (sel < LM_NONE) ? &result[sel] : NULL;

  if (t == NULL)
    return NSS_STATUS_SUCCESS;

  /* we have already checked for room for the value */
  /* len is set to the length of value */
  base = *buffer;
  strncpy (base, value, len);
  base[len] = '\0';

  *buffer += len + 1;
  *buflen -= len + 1;

  /* probably is some funky escaping needed here. later... */
  s = strchr (base, '?');
  if (s != NULL)
    {
      *s = '\0';
      s++;
      if (!strcasecmp (s, "sub"))
        scope = LDAP_SCOPE_SUBTREE;
      else if (!strcasecmp (s, "one"))
        scope = LDAP_SCOPE_ONELEVEL;
      else if (!strcasecmp (s, "base"))
        scope = LDAP_SCOPE_BASE;
      filter = strchr (s, '?');
      if (filter != NULL)
        {
          *filter = '\0';
          filter++;
        }
    }

  if (bytesleft (*buffer, *buflen, struct ldap_service_search_descriptor) <
      sizeof (struct ldap_service_search_descriptor))
    return NSS_STATUS_UNAVAIL;

  align (*buffer, *buflen, struct ldap_service_search_descriptor);

  for (cur = *t; cur && cur->lsd_next; cur = cur->lsd_next)
    ;
  if (!cur)
    {
      *t = (struct ldap_service_search_descriptor *) * buffer;
      cur = *t;
    }
  else
    {
      cur->lsd_next = (struct ldap_service_search_descriptor *) * buffer;
      cur = cur->lsd_next;
    }

  cur->lsd_base = base;
  cur->lsd_scope = scope;
  cur->lsd_filter = filter;
  cur->lsd_next = NULL;

  *buffer += sizeof (struct ldap_service_search_descriptor);
  *buflen -= sizeof (struct ldap_service_search_descriptor);

  return NSS_STATUS_SUCCESS;
}

static enum nss_status _nss_ldap_readconfig(struct ldap_config ** presult, char **buffer, size_t *buflen)
{
  FILE *fp;
  char b[NSS_LDAP_CONFIG_BUFSIZ];
  enum nss_status status = NSS_STATUS_SUCCESS;
  struct ldap_config *result;

  if (bytesleft (*buffer, *buflen, struct ldap_config *) < sizeof (struct ldap_config))
  {
    return NSS_STATUS_TRYAGAIN;
  }
  align (*buffer, *buflen, struct ldap_config *);
  result = *presult = (struct ldap_config *) *buffer;
  *buffer += sizeof (struct ldap_config);
  *buflen -= sizeof (struct ldap_config);

  _nss_ldap_init_config(result);

  fp = fopen (NSS_LDAP_PATH_CONF, "r");
  if (fp == NULL)
    {
      return NSS_STATUS_UNAVAIL;
    }

  while (fgets (b, sizeof (b), fp) != NULL)
    {
      char *k, *v;
      int len;
      char **t = NULL;

      if (*b == '\n' || *b == '\r' || *b == '#')
        continue;

      k = b;
      v = k;

      /* skip past all characters in keyword */
      while (*v != '\0' && *v != ' ' && *v != '\t')
        v++;

      if (*v == '\0')
        continue;

      /* terminate keyword */
      *(v++) = '\0';

      /* skip empty lines with more than 3 spaces at the start of the line */
      /* rds.oliver@samera.com.py 01-set-2004                              */
      if (*v == '\n')
        continue;

      /* skip all whitespaces between keyword and value */
      /* Lars Oergel <lars.oergel@innominate.de>, 05.10.2000 */
      while (*v == ' ' || *v == '\t')
        v++;

      /* kick off all whitespaces and newline at the end of value */
      /* Bob Guo <bob@mail.ied.ac.cn>, 08.10.2001 */

      /* Also remove \r (CR) to be able to handle files in DOS format (lines
       * terminated in CR LF).  Alejandro Forero Cuervo
       * <azul@freaks-unidos.net>, 10-may-2005 */

      len = strlen (v) - 1;
      while (v[len] == ' ' || v[len] == '\t' || v[len] == '\n' || v[len] == '\r')
        --len;
      v[++len] = '\0';

      if (*buflen < (size_t) (len + 1))
        {
          status = NSS_STATUS_TRYAGAIN;
          break;
        }

      else if (!strcasecmp (k, NSS_LDAP_KEY_URI))
        {
          status = do_add_uris (result, v, buffer, buflen);
          if (status != NSS_STATUS_SUCCESS)
            break;
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_BASE))
        {
          t = &result->ldc_base;
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_BINDDN))
        {
          t = &result->ldc_binddn;
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_BINDPW))
        {
          t = &result->ldc_bindpw;
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_USESASL))
        {
          result->ldc_usesasl = (!strcasecmp (v, "on")
                                 || !strcasecmp (v, "yes")
                                 || !strcasecmp (v, "true"));
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_SASLID))
        {
          t = &result->ldc_saslid;
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_ROOTBINDDN))
        {
          t = &result->ldc_rootbinddn;
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_ROOTUSESASL))
        {
          result->ldc_rootusesasl = (!strcasecmp (v, "on")
                                     || !strcasecmp (v, "yes")
                                     || !strcasecmp (v, "true"));
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_ROOTSASLID))
        {
          t = &result->ldc_rootsaslid;
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_SSLPATH))
        {
          t = &result->ldc_sslpath;
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_SCOPE))
        {
          if (!strcasecmp (v, "sub"))
            {
              result->ldc_scope = LDAP_SCOPE_SUBTREE;
            }
          else if (!strcasecmp (v, "one"))
            {
              result->ldc_scope = LDAP_SCOPE_ONELEVEL;
            }
          else if (!strcasecmp (v, "base"))
            {
              result->ldc_scope = LDAP_SCOPE_BASE;
            }
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_DEREF))
        {
          if (!strcasecmp (v, "never"))
            {
              result->ldc_deref = LDAP_DEREF_NEVER;
            }
          else if (!strcasecmp (v, "searching"))
            {
              result->ldc_deref = LDAP_DEREF_SEARCHING;
            }
          else if (!strcasecmp (v, "finding"))
            {
              result->ldc_deref = LDAP_DEREF_FINDING;
            }
          else if (!strcasecmp (v, "always"))
            {
              result->ldc_deref = LDAP_DEREF_ALWAYS;
            }
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_SSL))
        {
          if (!strcasecmp (v, "on") || !strcasecmp (v, "yes")
              || !strcasecmp (v, "true"))
            {
              result->ldc_ssl_on = SSL_LDAPS;
            }
          else if (!strcasecmp (v, "start_tls"))
            {
              result->ldc_ssl_on = SSL_START_TLS;
            }
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_REFERRALS))
        {
          result->ldc_referrals = (!strcasecmp (v, "on")
                                   || !strcasecmp (v, "yes")
                                   || !strcasecmp (v, "true"));
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_RESTART))
        {
          result->ldc_restart = (!strcasecmp (v, "on")
                                 || !strcasecmp (v, "yes")
                                 || !strcasecmp (v, "true"));
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_LDAP_VERSION))
        {
          result->ldc_version = atoi (v);
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_TIMELIMIT))
        {
          result->ldc_timelimit = atoi (v);
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_BIND_TIMELIMIT))
        {
          result->ldc_bind_timelimit = atoi (v);
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_IDLE_TIMELIMIT))
        {
          result->ldc_idle_timelimit = atoi (v);
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_RECONNECT_POLICY))
        {
          if (!strcasecmp (v, "hard") ||
              !strcasecmp (v, "hard_open"))
            {
              result->ldc_reconnect_pol = LP_RECONNECT_HARD_OPEN;
            }
          else if (!strcasecmp (v, "hard_init"))
            {
              result->ldc_reconnect_pol = LP_RECONNECT_HARD_INIT;
            }
          else if (!strcasecmp (v, "soft"))
            {
              result->ldc_reconnect_pol = LP_RECONNECT_SOFT;
            }
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_RECONNECT_TRIES))
        {
          result->ldc_reconnect_tries = atoi (v);
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_RECONNECT_SLEEPTIME))
        {
          result->ldc_reconnect_sleeptime = atoi (v);
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_RECONNECT_MAXSLEEPTIME))
        {
          result->ldc_reconnect_maxsleeptime = atoi (v);
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_RECONNECT_MAXCONNTRIES))
        {
          result->ldc_reconnect_maxconntries = atoi (v);
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_SASL_SECPROPS))
        {
          t = &result->ldc_sasl_secprops;
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_DEBUG))
        {
          result->ldc_debug = atoi (v);
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_PAGESIZE))
        {
          result->ldc_pagesize = atoi (v);
        }
#ifdef CONFIGURE_KRB5_CCNAME
      else if (!strcasecmp (k, NSS_LDAP_KEY_KRB5_CCNAME))
        {
          t = &result->ldc_krb5_ccname;
        }
#endif /* CONFIGURE_KRB5_CCNAME */
      else if (!strcasecmp (k, "tls_checkpeer"))
        {
          if (!strcasecmp (v, "on") || !strcasecmp (v, "yes")
              || !strcasecmp (v, "true"))
            {
              result->ldc_tls_checkpeer = 1;
            }
          else if (!strcasecmp (v, "off") || !strcasecmp (v, "no")
                   || !strcasecmp (v, "false"))
            {
              result->ldc_tls_checkpeer = 0;
            }
        }
      else if (!strcasecmp (k, "tls_cacertfile"))
        {
          t = &result->ldc_tls_cacertfile;
        }
      else if (!strcasecmp (k, "tls_cacertdir"))
        {
          t = &result->ldc_tls_cacertdir;
        }
      else if (!strcasecmp (k, "tls_ciphers"))
        {
          t = &result->ldc_tls_ciphers;
        }
      else if (!strcasecmp (k, "tls_cert"))
        {
          t = &result->ldc_tls_cert;
        }
      else if (!strcasecmp (k, "tls_key"))
        {
          t = &result->ldc_tls_key;
        }
      else if (!strcasecmp (k, "tls_randfile"))
        {
          t = &result->ldc_tls_randfile;
        }
      else if (!strncasecmp (k, NSS_LDAP_KEY_MAP,
                             strlen (NSS_LDAP_KEY_MAP)))
        {
          do_parse_map_statement (result, v);
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_SCHEMA))
        {
          if (!strcasecmp (v, "rfc2307bis"))
            {
              result->ldc_flags |= NSS_LDAP_FLAGS_RFC2307BIS;
            }
          else if (!strcasecmp (v, "rfc2307"))
            {
              result->ldc_flags &= ~(NSS_LDAP_FLAGS_RFC2307BIS);
            }
        }
      else if (!strcasecmp (k, NSS_LDAP_KEY_CONNECT_POLICY))
        {
          if (!strcasecmp (v, "oneshot"))
            {
              result->ldc_flags |= NSS_LDAP_FLAGS_CONNECT_POLICY_ONESHOT;
            }
          else if (!strcasecmp (v, "persist"))
            {
              result->ldc_flags &= ~(NSS_LDAP_FLAGS_CONNECT_POLICY_ONESHOT);
            }
        }
      else
        {
          /*
           * check whether the key is a naming context key
           * if yes, parse; otherwise just return NSS_STATUS_SUCCESS
           * so we can ignore keys we don't understand.
           */
          status =
            do_searchdescriptorconfig (k, v, len, result->ldc_sds,
                                       buffer, buflen);
          if (status == NSS_STATUS_UNAVAIL)
            {
              break;
            }
        }

      if (t != NULL)
        {
          strncpy (*buffer, v, len);
          (*buffer)[len] = '\0';
          *t = *buffer;
          *buffer += len + 1;
          *buflen -= len + 1;
        }
    }

  fclose (fp);

  if (status != NSS_STATUS_SUCCESS)
    {
      return status;
    }

  if (result->ldc_rootbinddn != NULL)
    {
      fp = fopen (NSS_LDAP_PATH_ROOTPASSWD, "r");
      if (fp)
        {
          if (fgets (b, sizeof (b), fp) != NULL)
            {
              int len;

              len = strlen (b);
              /* BUG#138: check for newline before removing */
              if (len > 0 && b[len - 1] == '\n')
                len--;

              if (*buflen < (size_t) (len + 1))
                {
                  return NSS_STATUS_UNAVAIL;
                }

              strncpy (*buffer, b, len);
              (*buffer)[len] = '\0';
              result->ldc_rootbindpw = *buffer;
              *buffer += len + 1;
              *buflen -= len + 1;
            }
          fclose (fp);
        }
      else if (!result->ldc_rootusesasl)
        {
          result->ldc_rootbinddn = NULL;
        }
    }

  if (result->ldc_uris[0] == NULL)
    {
      status = NSS_STATUS_NOTFOUND;
    }

  return status;
}

int cfg_init(void)
{
  static char configbuf[NSS_LDAP_CONFIG_BUFSIZ];
  char *configbufp;
  size_t configbuflen;
  enum nss_status retv;
  if (nslcd_cfg==NULL)
  {
    configbufp=configbuf;
    configbuflen=sizeof(configbuf);
    retv=_nss_ldap_readconfig(&nslcd_cfg,&configbufp,&configbuflen);
    if (retv!=NSS_STATUS_SUCCESS)
    {
      log_log(LOG_DEBUG,"cfg_init() failed to read config");
      return -1;
    }
  }
  return 0;
}
