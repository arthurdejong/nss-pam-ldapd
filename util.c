/* Copyright (C) 1997-2005 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@padl.com>, 1997.
   (The author maintains a non-exclusive licence to distribute this file
   under their own conditions.)

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
 */

#include "config.h"

#if defined(HAVE_THREAD_H) && !defined(_AIX)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include <stdio.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <stdlib.h>

#include <sys/param.h>
#include <sys/stat.h>

#include <netdb.h>
#include <syslog.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#ifndef HAVE_SNPRINTF
#include "snprintf.h"
#endif

#include "ldap-nss.h"
#include "util.h"

static char rcsId[] = "$Id$";

static NSS_STATUS do_getrdnvalue (const char *dn,
				  const char *rdntype,
				  char **rval, char **buffer,
				  size_t * buflen);


static NSS_STATUS do_parse_map_statement (ldap_config_t * cfg,
					  const char *statement,
					  ldap_map_type_t type);

static NSS_STATUS do_searchdescriptorconfig (const char *key,
					     const char *value,
					     size_t valueLength,
					     ldap_service_search_descriptor_t
					     ** result, char **buffer,
					     size_t * buflen);

#include <fcntl.h>
static void *__cache = NULL;

NSS_LDAP_DEFINE_LOCK (__cache_lock);

#define cache_lock()     NSS_LDAP_LOCK(__cache_lock)
#define cache_unlock()   NSS_LDAP_UNLOCK(__cache_lock)

static NSS_STATUS
dn2uid_cache_put (const char *dn, const char *uid)
{
  NSS_STATUS stat;
  ldap_datum_t key, val;

  cache_lock ();

  if (__cache == NULL)
    {
      __cache = _nss_ldap_db_open ();
      if (__cache == NULL)
	{
	  cache_unlock ();
	  return NSS_TRYAGAIN;
	}
    }

  key.data = (void *) dn;
  key.size = strlen (dn);
  val.data = (void *) uid;
  val.size = strlen (uid);

  stat = _nss_ldap_db_put (__cache, 0, &key, &val);

  cache_unlock ();

  return stat;
}

static NSS_STATUS
dn2uid_cache_get (const char *dn, char **uid, char **buffer, size_t * buflen)
{
  ldap_datum_t key, val;
  NSS_STATUS stat;

  cache_lock ();

  if (__cache == NULL)
    {
      cache_unlock ();
      return NSS_NOTFOUND;
    }

  key.data = (void *) dn;
  key.size = strlen (dn);

  stat = _nss_ldap_db_get (__cache, 0, &key, &val);
  if (stat != NSS_SUCCESS)
    {
      cache_unlock ();
      return stat;
    }

  if (*buflen <= val.size)
    {
      cache_unlock ();
      return NSS_TRYAGAIN;
    }

  *uid = *buffer;
  memcpy (*uid, (char *) val.data, val.size);
  (*uid)[val.size] = '\0';
  *buffer += val.size + 1;
  *buflen -= val.size + 1;

  cache_unlock ();
  return NSS_SUCCESS;
}

#ifdef HPUX
static int lock_inited = 0;
#endif

NSS_STATUS
_nss_ldap_dn2uid (const char *dn, char **uid, char **buffer, size_t * buflen,
		  int *pIsNestedGroup, LDAPMessage ** pRes)
{
  NSS_STATUS stat;

  debug ("==> _nss_ldap_dn2uid");

  *pIsNestedGroup = 0;

#ifdef HPUX
  /* XXX this is not thread-safe */
  if (!lock_inited)
    {
      __thread_mutex_init (&__cache_lock, NULL);
      lock_inited = 1;
    }
#endif

  stat = dn2uid_cache_get (dn, uid, buffer, buflen);
  if (stat == NSS_NOTFOUND)
    {
      const char *attrs[4];
      LDAPMessage *res;

      attrs[0] = ATM (LM_PASSWD, uid);
      attrs[1] = ATM (LM_GROUP, uniqueMember);
      attrs[2] = AT (objectClass);
      attrs[3] = NULL;

      if (_nss_ldap_read (dn, attrs, &res) == NSS_SUCCESS)
	{
	  LDAPMessage *e = _nss_ldap_first_entry (res);
	  if (e != NULL)
	    {
	      if (_nss_ldap_oc_check (e, OC (posixGroup)) == NSS_SUCCESS)
		{
		  *pIsNestedGroup = 1;
		  *pRes = res;
		  debug ("<== _nss_ldap_dn2uid (nested group)");
		  return NSS_SUCCESS;
		}

	      stat =
		_nss_ldap_assign_attrval (e, ATM (LM_PASSWD, uid), uid,
					  buffer, buflen);
	      if (stat == NSS_SUCCESS)
		dn2uid_cache_put (dn, *uid);
	    }
	}
      ldap_msgfree (res);
    }

  debug ("<== _nss_ldap_dn2uid");

  return stat;
}

NSS_STATUS
_nss_ldap_getrdnvalue (LDAPMessage * entry,
		       const char *rdntype,
		       char **rval, char **buffer, size_t * buflen)
{
  char *dn;
  NSS_STATUS status;

  dn = _nss_ldap_get_dn (entry);
  if (dn == NULL)
    {
      return NSS_NOTFOUND;
    }

  status = do_getrdnvalue (dn, rdntype, rval, buffer, buflen);
#ifdef HAVE_LDAP_MEMFREE
  ldap_memfree (dn);
#else
  free (dn);
#endif /* HAVE_LDAP_MEMFREE */

  /*
   * If examining the DN failed, then pick the nominal first
   * value of cn as the canonical name (recall that attributes
   * are sets, not sequences)
   */
  if (status == NSS_NOTFOUND)
    {
      char **vals;

      vals = _nss_ldap_get_values (entry, rdntype);

      if (vals != NULL)
	{
	  int rdnlen = strlen (*vals);
	  if (*buflen > rdnlen)
	    {
	      char *rdnvalue = *buffer;
	      strncpy (rdnvalue, *vals, rdnlen);
	      rdnvalue[rdnlen] = '\0';
	      *buffer += rdnlen + 1;
	      *buflen -= rdnlen + 1;
	      *rval = rdnvalue;
	      status = NSS_SUCCESS;
	    }
	  else
	    {
	      status = NSS_TRYAGAIN;
	    }
	  ldap_value_free (vals);
	}
    }

  return status;
}

static NSS_STATUS
do_getrdnvalue (const char *dn,
		const char *rdntype,
		char **rval, char **buffer, size_t * buflen)
{
  char **exploded_dn;
  char *rdnvalue = NULL;
  char rdnava[64];
  int rdnlen = 0, rdnavalen;

  snprintf (rdnava, sizeof rdnava, "%s=", rdntype);
  rdnavalen = strlen (rdnava);

  exploded_dn = ldap_explode_dn (dn, 0);

  if (exploded_dn != NULL)
    {
      /*
       * attempt to get the naming attribute's principal
       * value by parsing the RDN. We need to support
       * multivalued RDNs (as they're essentially mandated
       * for services)
       */
#ifdef HAVE_LDAP_EXPLODE_RDN
      /*
       * use ldap_explode_rdn() API, as it's cleaner than
       * strtok(). This code has not been tested!
       */
      char **p, **exploded_rdn;

      exploded_rdn = ldap_explode_rdn (*exploded_dn, 0);
      if (exploded_rdn != NULL)
	{
	  for (p = exploded_rdn; *p != NULL; p++)
	    {
	      if (strncasecmp (*p, rdnava, rdnavalen) == 0)
		{
		  char *r = *p + rdnavalen;

		  rdnlen = strlen (r);
		  if (*buflen <= rdnlen)
		    {
		      ldap_value_free (exploded_rdn);
		      ldap_value_free (exploded_dn);
		      return NSS_TRYAGAIN;
		    }
		  rdnvalue = *buffer;
		  strncpy (rdnvalue, r, rdnlen);
		  break;
		}
	    }
	  ldap_value_free (exploded_rdn);
	}
#else
      /*
       * we don't have Netscape's ldap_explode_rdn() API,
       * so we fudge it with strtok(). Note that this will
       * not handle escaping properly.
       */
      char *p, *r = *exploded_dn;
#ifdef HAVE_STRTOK_R
      char *st = NULL;
#endif

#ifndef HAVE_STRTOK_R
      for (p = strtok (r, "+");
#else
      for (p = strtok_r (r, "+", &st);
#endif
	   p != NULL;
#ifndef HAVE_STRTOK_R
	   p = strtok (NULL, "+"))
#else
	   p = strtok_r (NULL, "+", &st))
#endif
      {
	if (strncasecmp (p, rdnava, rdnavalen) == 0)
	  {
	    p += rdnavalen;
	    rdnlen = strlen (p);
	    if (*buflen <= rdnlen)
	      {
		ldap_value_free (exploded_dn);
		return NSS_TRYAGAIN;
	      }
	    rdnvalue = *buffer;
	    strncpy (rdnvalue, p, rdnlen);
	    break;
	  }
	if (r != NULL)
	  r = NULL;
      }
#endif /* HAVE_LDAP_EXPLODE_RDN */
    }

  if (exploded_dn != NULL)
    {
      ldap_value_free (exploded_dn);
    }

  if (rdnvalue != NULL)
    {
      rdnvalue[rdnlen] = '\0';
      *buffer += rdnlen + 1;
      *buflen -= rdnlen + 1;
      *rval = rdnvalue;
      return NSS_SUCCESS;
    }

  return NSS_NOTFOUND;
}

static NSS_STATUS
do_parse_map_statement (ldap_config_t * cfg,
			const char *statement, ldap_map_type_t type)
{
  char *key, *val;
  ldap_map_selector_t sel = LM_NONE;

  key = (char *) statement;
  val = key;
  while (*val != ' ' && *val != '\t')
    val++;
  *(val++) = '\0';

  while (*val == ' ' || *val == '\t')
    val++;

  {
    char *p = strchr (key, ':');

    if (p != NULL)
      {
	*p = '\0';
	sel = _nss_ldap_str2selector (key);
	key = ++p;
      }
  }

  return _nss_ldap_map_put (cfg, sel, type, key, val);
}

/* parse a comma-separated list */
static NSS_STATUS
do_parse_list (char *values, char ***valptr,
	       char **pbuffer, size_t *pbuflen)
{
  char *s, **p;
#ifdef HAVE_STRTOK_R
  char *tok_r;
#endif
  int valcount;

  int buflen = *pbuflen;
  char *buffer = *pbuffer;

  /* comma separated list of values to ignore on initgroups() */
  for (valcount = 1, s = values; *s != '\0'; s++)
    {
      if (*s == ',')
	valcount++;
    }

  if (bytesleft (buffer, buflen, char *) < (valcount + 1) * sizeof (char *))
    {
      return NSS_UNAVAIL;
    }

  align (buffer, buflen, char *);
  p = *valptr = (char **) buffer;

  buffer += (valcount + 1) * sizeof (char *);
  buflen -= (valcount + 1) * sizeof (char *);

#ifdef HAVE_STRTOK_R
  for (s = strtok_r(values, ",", &tok_r); s != NULL;
       s = strtok_r(NULL, ",", &tok_r))
#else
  for (s = strtok(values, ","); s != NULL; s = strtok(NULL, ","))
#endif
    {
      int vallen;
      char *elt = NULL;

      vallen = strlen (s);
      if (buflen < (size_t) (vallen + 1))
        {
	  return NSS_UNAVAIL;
	}

      /* copy this value into the next block of buffer space */
      elt = buffer;
      buffer += vallen + 1;
      buflen -= vallen + 1;

      strncpy (elt, s, vallen);
      elt[vallen] = '\0';
      *p++ = elt;
    }

  *p = NULL;
  *pbuffer = buffer;
  *pbuflen = buflen;

  return NSS_SUCCESS;
}

ldap_map_selector_t
_nss_ldap_str2selector (const char *key)
{
  ldap_map_selector_t sel;

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
  else if (!strcasecmp (key, MP_netmasks))
    sel = LM_NETMASKS;
  else if (!strcasecmp (key, MP_bootparams))
    sel = LM_BOOTPARAMS;
  else if (!strcasecmp (key, MP_aliases))
    sel = LM_ALIASES;
  else if (!strcasecmp (key, MP_netgroup))
    sel = LM_NETGROUP;
  else if (!strcasecmp (key, MP_automount))
    sel = LM_AUTOMOUNT;
  else
    sel = LM_NONE;

  return sel;
}

static NSS_STATUS
do_searchdescriptorconfig (const char *key, const char *value, size_t len,
			   ldap_service_search_descriptor_t ** result,
			   char **buffer, size_t * buflen)
{
  ldap_service_search_descriptor_t **t, *cur;
  char *base;
  char *filter, *s;
  int scope;
  ldap_map_selector_t sel;

  t = NULL;
  filter = NULL;
  scope = -1;

  if (strncasecmp (key, NSS_LDAP_KEY_NSS_BASE_PREFIX,
		   NSS_LDAP_KEY_NSS_BASE_PREFIX_LEN) != 0)
    return NSS_SUCCESS;

  sel = _nss_ldap_str2selector (&key[NSS_LDAP_KEY_NSS_BASE_PREFIX_LEN]);
  t = (sel < LM_NONE) ? &result[sel] : NULL;

  if (t == NULL)
    return NSS_SUCCESS;

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

  if (bytesleft (*buffer, *buflen, ldap_service_search_descriptor_t) <
      sizeof (ldap_service_search_descriptor_t))
    return NSS_UNAVAIL;

  align (*buffer, *buflen, ldap_service_search_descriptor_t);

  for (cur = *t; cur && cur->lsd_next; cur = cur->lsd_next)
    ;
  if (!cur)
    {
      *t = (ldap_service_search_descriptor_t *) * buffer;
      cur = *t;
    }
  else
    {
      cur->lsd_next = (ldap_service_search_descriptor_t *) * buffer;
      cur = cur->lsd_next;
    }

  cur->lsd_base = base;
  cur->lsd_scope = scope;
  cur->lsd_filter = filter;
  cur->lsd_next = NULL;

  *buffer += sizeof (ldap_service_search_descriptor_t);
  *buflen -= sizeof (ldap_service_search_descriptor_t);

  return NSS_SUCCESS;
}

NSS_STATUS _nss_ldap_init_config (ldap_config_t * result)
{
  int i, j;

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
#else
  result->ldc_version = LDAP_VERSION2;
#endif /* LDAP_VERSION3 */
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
  result->ldc_srv_domain = NULL;
  result->ldc_logdir = NULL;
  result->ldc_debug = 0;
  result->ldc_pagesize = LDAP_PAGESIZE;
#ifdef CONFIGURE_KRB5_CCNAME
  result->ldc_krb5_ccname = NULL;
#endif /* CONFIGURE_KRB5_CCNAME */
  result->ldc_flags = 0;
#ifdef RFC2307BIS
  result->ldc_flags |= NSS_LDAP_FLAGS_RFC2307BIS;
#endif
#ifdef PAGE_RESULTS
  result->ldc_flags |= NSS_LDAP_FLAGS_PAGED_RESULTS;
#endif
  result->ldc_reconnect_tries = LDAP_NSS_TRIES;
  result->ldc_reconnect_sleeptime = LDAP_NSS_SLEEPTIME;
  result->ldc_reconnect_maxsleeptime = LDAP_NSS_MAXSLEEPTIME;
  result->ldc_reconnect_maxconntries = LDAP_NSS_MAXCONNTRIES;
  result->ldc_initgroups_ignoreusers = NULL;

  for (i = 0; i <= LM_NONE; i++)
    {
      for (j = 0; j <= MAP_MAX; j++)
	{
	  result->ldc_maps[i][j] = _nss_ldap_db_open ();
	  if (result->ldc_maps[i][j] == NULL)
	    return NSS_UNAVAIL;
	}
    }

  return NSS_SUCCESS;
}

NSS_STATUS
_nss_ldap_add_uri (ldap_config_t *result, const char *uri,
		   char **buffer, size_t *buflen)
{
  /* add a single URI to the list of URIs in the configuration */
  int i;
  size_t uri_len;

  debug ("==> _nss_ldap_add_uri");

  for (i = 0; result->ldc_uris[i] != NULL; i++)
    ;

  if (i == NSS_LDAP_CONFIG_URI_MAX)
    {
      debug ("<== _nss_ldap_add_uri: maximum number of URIs exceeded");
      return NSS_UNAVAIL;
    }

  assert (i < NSS_LDAP_CONFIG_URI_MAX);

  uri_len = strlen (uri);

  if (*buflen < uri_len + 1)
    return NSS_TRYAGAIN;

  memcpy (*buffer, uri, uri_len + 1);

  result->ldc_uris[i] = *buffer;
  result->ldc_uris[i + 1] = NULL;

  *buffer += uri_len + 1;
  *buflen -= uri_len + 1;

  debug ("<== _nss_ldap_add_uri: added URI %s", uri);

  return NSS_SUCCESS;
}

static NSS_STATUS
do_add_uris (ldap_config_t *result, char *uris,
	     char **buffer, size_t *buflen)
{
  /* Add a space separated list of URIs */
  char *p;
  NSS_STATUS stat = NSS_SUCCESS;

  for (p = uris; p != NULL; )
    {
      char *q = strchr (p, ' ');
      if (q != NULL)
	*q = '\0';

      stat = _nss_ldap_add_uri (result, p, buffer, buflen);

      p = (q != NULL) ? ++q : NULL;

      if (stat != NSS_SUCCESS)
	break;
    }

  return stat;
}

static NSS_STATUS
do_add_hosts (ldap_config_t *result, char *hosts,
	      char **buffer, size_t *buflen)
{
  /* Add a space separated list of hosts */
  char *p;
  NSS_STATUS stat = NSS_SUCCESS;

  for (p = hosts; p != NULL; )
    {
      char b[NSS_LDAP_CONFIG_BUFSIZ];
      char *q = strchr (p, ' ');

      if (q != NULL)
	*q = '\0';

      snprintf (b, sizeof(b), "ldap://%s", p);

      stat = _nss_ldap_add_uri (result, b, buffer, buflen);

      p = (q != NULL) ? ++q : NULL;

      if (stat != NSS_SUCCESS)
	break;
    }

  return stat;
}

NSS_STATUS
_nss_ldap_readconfig (ldap_config_t ** presult, char **buffer, size_t *buflen)
{
  FILE *fp;
  char b[NSS_LDAP_CONFIG_BUFSIZ];
  NSS_STATUS stat = NSS_SUCCESS;
  ldap_config_t *result;
  struct stat statbuf;

  if (bytesleft (*buffer, *buflen, ldap_config_t *) < sizeof (ldap_config_t))
    {
      return NSS_TRYAGAIN;
    }
  align (*buffer, *buflen, ldap_config_t *);
  result = *presult = (ldap_config_t *) *buffer;
  *buffer += sizeof (ldap_config_t);
  *buflen -= sizeof (ldap_config_t);

  stat = _nss_ldap_init_config (result);
  if (stat != NSS_SUCCESS)
    {
      return NSS_SUCCESS;
    }

  fp = fopen (NSS_LDAP_PATH_CONF, "r");
  if (fp == NULL)
    {
      return NSS_UNAVAIL;
    }

  if (fstat (fileno (fp), &statbuf) == 0)
      result->ldc_mtime = statbuf.st_mtime;
  else
      result->ldc_mtime = 0;

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
	  stat = NSS_TRYAGAIN;
	  break;
	}

      if (!strcasecmp (k, NSS_LDAP_KEY_HOST))
	{
	  stat = do_add_hosts (result, v, buffer, buflen);
	  if (stat != NSS_SUCCESS)
	    break;
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_URI))
	{
	  stat = do_add_uris (result, v, buffer, buflen);
	  if (stat != NSS_SUCCESS)
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
      else if (!strcasecmp (k, NSS_LDAP_KEY_PORT))
	{
	  result->ldc_port = atoi (v);
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
      else if (!strcasecmp (k, NSS_LDAP_KEY_LOGDIR))
	{
	  t = &result->ldc_logdir;
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
      else if (!strncasecmp (k, NSS_LDAP_KEY_MAP_ATTRIBUTE,
			     strlen (NSS_LDAP_KEY_MAP_ATTRIBUTE)))
	{
	  do_parse_map_statement (result, v, MAP_ATTRIBUTE);
	}
      else if (!strncasecmp (k, NSS_LDAP_KEY_MAP_OBJECTCLASS,
			     strlen (NSS_LDAP_KEY_MAP_OBJECTCLASS)))
	{
	  do_parse_map_statement (result, v, MAP_OBJECTCLASS);
	}
      else if (!strncasecmp (k, NSS_LDAP_KEY_SET_OVERRIDE,
			     strlen (NSS_LDAP_KEY_SET_OVERRIDE)))
	{
	  do_parse_map_statement (result, v, MAP_OVERRIDE);
	}
      else if (!strncasecmp (k, NSS_LDAP_KEY_SET_DEFAULT,
			     strlen (NSS_LDAP_KEY_SET_DEFAULT)))
	{
	  do_parse_map_statement (result, v, MAP_DEFAULT);
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_INITGROUPS))
	{
	  if (!strcasecmp (v, "backlink"))
	    {
	      result->ldc_flags |= NSS_LDAP_FLAGS_INITGROUPS_BACKLINK;
	    }
	  else
	    {
	      result->ldc_flags &= ~(NSS_LDAP_FLAGS_INITGROUPS_BACKLINK);
	    }
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
      else if (!strcasecmp (k, NSS_LDAP_KEY_PAGED_RESULTS))
	{
	  if (!strcasecmp (v, "on")
	      || !strcasecmp (v, "yes")
	      || !strcasecmp (v, "true"))
	    {
	      result->ldc_flags |= NSS_LDAP_FLAGS_PAGED_RESULTS;
	    }
	  else
	    {
	      result->ldc_flags &= ~(NSS_LDAP_FLAGS_PAGED_RESULTS);
	    }
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_INITGROUPS_IGNOREUSERS))
	{
	  stat = do_parse_list (v, &result->ldc_initgroups_ignoreusers,
				buffer, buflen);
	  if (stat == NSS_UNAVAIL)
	    {
	      break;
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
      else if (!strcasecmp (k, NSS_LDAP_KEY_SRV_DOMAIN))
	{
	  t = &result->ldc_srv_domain;
	}
      else
	{
	  /*
	   * check whether the key is a naming context key
	   * if yes, parse; otherwise just return NSS_SUCCESS
	   * so we can ignore keys we don't understand.
	   */
	  stat =
	    do_searchdescriptorconfig (k, v, len, result->ldc_sds,
				       buffer, buflen);
	  if (stat == NSS_UNAVAIL)
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

  if (stat != NSS_SUCCESS)
    {
      return stat;
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
		  return NSS_UNAVAIL;
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

  if (result->ldc_port == 0)
    {
      if (result->ldc_ssl_on == SSL_LDAPS)
	{
	  result->ldc_port = LDAPS_PORT;
	}
      else
	{
	  result->ldc_port = LDAP_PORT;
	}
    }

  if (result->ldc_uris[0] == NULL)
    {
      stat = NSS_NOTFOUND;
    }

  return stat;
}

NSS_STATUS
_nss_ldap_escape_string (const char *str, char *buf, size_t buflen)
{
  int ret = NSS_TRYAGAIN;
  char *p = buf;
  char *limit = p + buflen - 3;
  const char *s = str;

  while (p < limit && *s)
    {
      switch (*s)
	{
	case '*':
	  strcpy (p, "\\2a");
	  p += 3;
	  break;
	case '(':
	  strcpy (p, "\\28");
	  p += 3;
	  break;
	case ')':
	  strcpy (p, "\\29");
	  p += 3;
	  break;
	case '\\':
	  strcpy (p, "\\5c");
	  p += 3;
	  break;
	default:
	  *p++ = *s;
	  break;
	}
      s++;
    }

  if (*s == '\0')
    {
      /* got to end */
      *p = '\0';
      ret = NSS_SUCCESS;
    }

  return ret;
}

/* XXX just a linked list for now */

struct ldap_dictionary
{
  ldap_datum_t key;
  ldap_datum_t value;
  struct ldap_dictionary *next;
};

static struct ldap_dictionary *
do_alloc_dictionary (void)
{
  struct ldap_dictionary *dict;

  dict = malloc (sizeof (*dict));
  if (dict == NULL)
    {
      return NULL;
    }
  NSS_LDAP_DATUM_ZERO (&dict->key);
  NSS_LDAP_DATUM_ZERO (&dict->value);
  dict->next = NULL;

  return dict;
}

static void
do_free_datum (ldap_datum_t * datum)
{
  if (datum->data != NULL)
    {
      free (datum->data);
      datum->data = NULL;
    }
  datum->size = 0;
}

static struct ldap_dictionary *
do_find_last (struct ldap_dictionary *dict)
{
  struct ldap_dictionary *p;

  for (p = dict; p->next != NULL; p = p->next)
    ;

  return p;
}

static void
do_free_dictionary (struct ldap_dictionary *dict)
{
  do_free_datum (&dict->key);
  do_free_datum (&dict->value);
  free (dict);
}

static NSS_STATUS
do_dup_datum (unsigned flags, ldap_datum_t * dst, const ldap_datum_t * src)
{
  dst->data = malloc (src->size);
  if (dst->data == NULL)
    return NSS_TRYAGAIN;

  memcpy (dst->data, src->data, src->size);
  dst->size = src->size;

  return NSS_SUCCESS;
}

void *
_nss_ldap_db_open (void)
{
  return (void *) do_alloc_dictionary ();
}

void
_nss_ldap_db_close (void *db)
{
  struct ldap_dictionary *dict;

  dict = (struct ldap_dictionary *) db;

  while (dict != NULL)
    {
      struct ldap_dictionary *next = dict->next;

      do_free_dictionary (dict);

      dict = next;
    }
}

NSS_STATUS
_nss_ldap_db_get (void *db,
		  unsigned flags,
		  const ldap_datum_t * key,
		  ldap_datum_t * value)
{
  struct ldap_dictionary *dict = (struct ldap_dictionary *) db;
  struct ldap_dictionary *p;

  for (p = dict; p != NULL; p = p->next)
    {
      int cmp;

      if (p->key.size != key->size)
	continue;

      if (flags & NSS_LDAP_DB_NORMALIZE_CASE)
	cmp = strncasecmp ((char *)p->key.data, (char *)key->data, key->size);
      else
	cmp = memcmp (p->key.data, key->data, key->size);

      if (cmp == 0)
	{
	  value->data = p->value.data;
	  value->size = p->value.size;

	  return NSS_SUCCESS;
	}
    }

  return NSS_NOTFOUND;
}

NSS_STATUS
_nss_ldap_db_put (void *db,
		  unsigned flags,
		  const ldap_datum_t * key,
		  const ldap_datum_t * value)
{
  struct ldap_dictionary *dict = (struct ldap_dictionary *) db;
  struct ldap_dictionary *p, *q;

  assert (key != NULL);
  assert (key->data != NULL);

  if (dict->key.data == NULL)
    {
      /* uninitialized */
      q = dict;
      p = NULL;
    }
  else
    {
      p = do_find_last (dict);
      assert (p != NULL);
      assert (p->next == NULL);
      q = do_alloc_dictionary ();
      if (q == NULL)
	return NSS_TRYAGAIN;
    }

  if (do_dup_datum (flags, &q->key, key) != NSS_SUCCESS)
    {
      do_free_dictionary (q);
      return NSS_TRYAGAIN;
    }

  if (do_dup_datum (flags, &q->value, value) != NSS_SUCCESS)
    {
      do_free_dictionary (q);
      return NSS_TRYAGAIN;
    }

  if (p != NULL)
    p->next = q;

  return NSS_SUCCESS;
}

/*
 * Add a nested netgroup or group to the namelist
 */
NSS_STATUS
_nss_ldap_namelist_push (struct name_list **head, const char *name)
{
  struct name_list *nl;

  debug ("==> _nss_ldap_namelist_push (%s)", name);

  nl = (struct name_list *) malloc (sizeof (*nl));
  if (nl == NULL)
    {
      debug ("<== _nss_ldap_namelist_push");
      return NSS_TRYAGAIN;
    }

  nl->name = strdup (name);
  if (nl->name == NULL)
    {
      debug ("<== _nss_ldap_namelist_push");
      free (nl);
      return NSS_TRYAGAIN;
    }

  nl->next = *head;

  *head = nl;

  debug ("<== _nss_ldap_namelist_push");

  return NSS_SUCCESS;
}

/*
 * Remove last nested netgroup or group from the namelist
 */
void
_nss_ldap_namelist_pop (struct name_list **head)
{
  struct name_list *nl;

  debug ("==> _nss_ldap_namelist_pop");

  assert (*head != NULL);
  nl = *head;

  *head = nl->next;

  assert (nl->name != NULL);
  free (nl->name);
  free (nl);

  debug ("<== _nss_ldap_namelist_pop");
}

/*
 * Cleanup nested netgroup or group namelist.
 */
void
_nss_ldap_namelist_destroy (struct name_list **head)
{
  struct name_list *p, *next;

  debug ("==> _nss_ldap_namelist_destroy");

  for (p = *head; p != NULL; p = next)
    {
      next = p->next;

      if (p->name != NULL)
	free (p->name);
      free (p);
    }

  *head = NULL;

  debug ("<== _nss_ldap_namelist_destroy");
}

/*
 * Check whether we have already seen a netgroup or group,
 * to avoid loops in nested netgroup traversal
 */
int
_nss_ldap_namelist_find (struct name_list *head, const char *netgroup)
{
  struct name_list *p;
  int found = 0;

  debug ("==> _nss_ldap_namelist_find");

  for (p = head; p != NULL; p = p->next)
    {
      if (strcasecmp (p->name, netgroup) == 0)
	{
	  found++;
	  break;
	}
    }

  debug ("<== _nss_ldap_namelist_find");

  return found;
}

NSS_STATUS _nss_ldap_validateconfig (ldap_config_t *config)
{
  struct stat statbuf;

  if (config == NULL)
    {
      return NSS_UNAVAIL;
    }

  if (config->ldc_mtime == 0)
    {
      return NSS_SUCCESS;
    }

  if (stat (NSS_LDAP_PATH_CONF, &statbuf) == 0)
    {
      return (statbuf.st_mtime > config->ldc_mtime) ? NSS_TRYAGAIN : NSS_SUCCESS;
    }

  return NSS_SUCCESS;
}

