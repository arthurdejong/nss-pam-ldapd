/*
   cfg.c - functions for configuration information
   This file contains parts that were part of the nss_ldap
   library which has been forked into the nss-pam-ldapd library.

   Copyright (C) 1997-2005 Luke Howard
   Copyright (C) 2007 West Consulting
   Copyright (C) 2007-2021 Arthur de Jong

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#ifdef HAVE_GSSAPI_H
#include <gssapi.h>
#endif /* HAVE_GSSAPI_H */
#ifdef HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#endif /* HAVE_GSSAPI_GSSAPI_H */
#ifdef HAVE_GSSAPI_GSSAPI_KRB5_H
#include <gssapi/gssapi_krb5.h>
#endif /* HAVE_GSSAPI_GSSAPI_KRB5_H */
#ifdef HAVE_GSSAPI_GSSAPI_GENERIC_H
#include <gssapi/gssapi_generic.h>
#endif /* HAVE_GSSAPI_GSSAPI_GENERIC_H */
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include "common.h"
#include "log.h"
#include "cfg.h"
#include "attmap.h"
#include "common/expr.h"

struct ldap_config *nslcd_cfg = NULL;

/* the maximum line length in the configuration file */
#define MAX_LINE_LENGTH          4096

/* the delimiters of tokens */
#define TOKEN_DELIM " \t\n\r"

/* convenient wrapper macro for ldap_set_option() */
#define LDAP_SET_OPTION(ld, option, invalue)                                \
  rc = ldap_set_option(ld, option, invalue);                                \
  if (rc != LDAP_SUCCESS)                                                   \
  {                                                                         \
    log_log(LOG_ERR, "ldap_set_option(" #option ") failed: %s",             \
            ldap_err2string(rc));                                           \
    exit(EXIT_FAILURE);                                                     \
  }

/* simple strdup wrapper */
static char *xstrdup(const char *s)
{
  char *tmp;
  if (s == NULL)
  {
    log_log(LOG_CRIT, "xstrdup() called with NULL");
    exit(EXIT_FAILURE);
  }
  tmp = strdup(s);
  if (tmp == NULL)
  {
    log_log(LOG_CRIT, "strdup() failed to allocate memory");
    exit(EXIT_FAILURE);
  }
  return tmp;
}

/* check that the condition is true and otherwise log an error
   and bail out */
static inline void check_argumentcount(const char *filename, int lnr,
                                       const char *keyword, int condition)
{
  if (!condition)
  {
    log_log(LOG_ERR, "%s:%d: %s: wrong number of arguments",
            filename, lnr, keyword);
    exit(EXIT_FAILURE);
  }
}

/* This function works like strtok() except that the original string is
   not modified and a pointer within str to where the next token begins
   is returned (this can be used to pass to the function on the next
   iteration). If no more tokens are found or the token will not fit in
   the buffer, NULL is returned. */
static char *get_token(char **line, char *buf, size_t buflen)
{
  size_t len;
  if ((line == NULL) || (*line == NULL) || (**line == '\0') || (buf == NULL))
    return NULL;
  /* find the beginning and length of the token */
  *line += strspn(*line, TOKEN_DELIM);
  len = strcspn(*line, TOKEN_DELIM);
  /* check if there is a token */
  if (len == 0)
  {
    *line = NULL;
    return NULL;
  }
  /* limit the token length */
  if (len >= buflen)
    len = buflen - 1;
  /* copy the token */
  strncpy(buf, *line, len);
  buf[len] = '\0';
  /* skip to the next token */
  *line += len;
  *line += strspn(*line, TOKEN_DELIM);
  /* return the token */
  return buf;
}

static char *get_strdup(const char *filename, int lnr,
                        const char *keyword, char **line)
{
  char token[MAX_LINE_LENGTH];
  check_argumentcount(filename, lnr, keyword,
                      get_token(line, token, sizeof(token)) != NULL);
  return xstrdup(token);
}

static char *get_linedup(const char *filename, int lnr,
                         const char *keyword, char **line)
{
  char *var;
  check_argumentcount(filename, lnr, keyword, (*line != NULL) && (**line != '\0'));
  var = xstrdup(*line);
  /* mark that we are at the end of the line */
  *line = NULL;
  return var;
}

static void get_eol(const char *filename, int lnr,
                    const char *keyword, char **line)
{
  if ((line != NULL) && (*line != NULL) && (**line != '\0'))
  {
    log_log(LOG_ERR, "%s:%d: %s: too many arguments", filename, lnr, keyword);
    exit(EXIT_FAILURE);
  }
}

static int get_int(const char *filename, int lnr,
                   const char *keyword, char **line)
{
  char token[32];
  check_argumentcount(filename, lnr, keyword,
                      get_token(line, token, sizeof(token)) != NULL);
  /* TODO: replace with correct numeric parse */
  return atoi(token);
}

static int parse_boolean(const char *filename, int lnr, const char *value)
{
  if ((strcasecmp(value, "on") == 0) ||
      (strcasecmp(value, "yes") == 0) ||
      (strcasecmp(value, "true") == 0) || (strcasecmp(value, "1") == 0))
    return 1;
  else if ((strcasecmp(value, "off") == 0) ||
           (strcasecmp(value, "no") == 0) ||
           (strcasecmp(value, "false") == 0) || (strcasecmp(value, "0") == 0))
    return 0;
  else
  {
    log_log(LOG_ERR, "%s:%d: not a boolean argument: '%s'",
            filename, lnr, value);
    exit(EXIT_FAILURE);
  }
}

static int get_boolean(const char *filename, int lnr,
                       const char *keyword, char **line)
{
  char token[32];
  check_argumentcount(filename, lnr, keyword,
                      get_token(line, token, sizeof(token)) != NULL);
  return parse_boolean(filename, lnr, token);
}

static const char *print_boolean(int bool)
{
  if (bool) return "yes";
  else      return "no";
}

#define TIME_MINUTES 60
#define TIME_HOURS (60 * 60)
#define TIME_DAYS (60 * 60 * 24)

static time_t parse_time(const char *filename, int lnr, const char *value)
{
  time_t t;
  char *tmp = NULL;
  if (strcasecmp(value, "off") == 0)
    return 0;
  errno = 0;
  t = strtol(value, &tmp, 10);
  if (errno != 0)
  {
    log_log(LOG_ERR, "%s:%d: value out of range: '%s'",
            filename, lnr, value);
    exit(EXIT_FAILURE);
  }
  if ((strcasecmp(tmp, "") == 0) || (strcasecmp(tmp, "s") == 0))
    return t;
  else if (strcasecmp(tmp, "m") == 0)
    return t * TIME_MINUTES;
  else if (strcasecmp(tmp, "h") == 0)
    return t * TIME_HOURS;
  else if (strcasecmp(tmp, "d") == 0)
    return t * TIME_DAYS;
  else
  {
    log_log(LOG_ERR, "%s:%d: invalid time value: '%s'",
            filename, lnr, value);
    exit(EXIT_FAILURE);
  }
}

static time_t get_time(const char *filename, int lnr,
                       const char *keyword, char **line)
{
  char token[32];
  check_argumentcount(filename, lnr, keyword,
                      get_token(line, token, sizeof(token)) != NULL);
  return parse_time(filename, lnr, token);
}

static void print_time(time_t t, char *buffer, size_t buflen)
{
  if (t == 0)
    mysnprintf(buffer, buflen, "off");
  else if ((t % TIME_DAYS) == 0)
    mysnprintf(buffer, buflen, "%ldd", (long)(t / TIME_DAYS));
  else if ((t % TIME_HOURS) == 0)
    mysnprintf(buffer, buflen, "%ldh", (long)(t / TIME_HOURS));
  else if ((t % TIME_MINUTES) == 0)
    mysnprintf(buffer, buflen, "%ldm", (long)(t / TIME_MINUTES));
  else
    mysnprintf(buffer, buflen, "%lds", (long)t);
}

static void handle_uid(const char *filename, int lnr,
                       const char *keyword, char *line,
                       struct ldap_config *cfg)
{
  char token[32];
  struct passwd *pwent;
  char *tmp;
  check_argumentcount(filename, lnr, keyword,
                      get_token(&line, token, sizeof(token)) != NULL);
  get_eol(filename, lnr, keyword, &line);
  /* check if it is a valid numerical uid */
  errno = 0;
  cfg->uid = strtouid(token, &tmp, 10);
  if ((*token != '\0') && (*tmp == '\0') && (errno == 0) && (strchr(token, '-') == NULL))
  {
    /* get the name and gid from the passwd database */
    pwent = getpwuid(cfg->uid);
    if (pwent != NULL)
    {
      if (cfg->gid == NOGID)
        cfg->gid = pwent->pw_gid;
      cfg->uidname = strdup(pwent->pw_name);
      return;
    }
  }
  /* find by name */
  pwent = getpwnam(token);
  if (pwent != NULL)
  {
    cfg->uid = pwent->pw_uid;
    if (cfg->gid == NOGID)
      cfg->gid = pwent->pw_gid;
    cfg->uidname = strdup(token);
    return;
  }
  /* log an error */
  log_log(LOG_ERR, "%s:%d: %s: not a valid uid: '%s'",
          filename, lnr, keyword, token);
  exit(EXIT_FAILURE);
}

static void handle_gid(const char *filename, int lnr,
                       const char *keyword, char *line,
                       gid_t *gid)
{
  char token[32];
  struct group *grent;
  char *tmp;
  check_argumentcount(filename, lnr, keyword,
                      get_token(&line, token, sizeof(token)) != NULL);
  get_eol(filename, lnr, keyword, &line);
  /* check if it is a valid numerical gid */
  errno = 0;
  *gid = strtogid(token, &tmp, 10);
  if ((*token != '\0') && (*tmp == '\0') && (errno == 0) && (strchr(token, '-') == NULL))
    return;
  /* find by name */
  grent = getgrnam(token);
  if (grent != NULL)
  {
    *gid = grent->gr_gid;
    return;
  }
  /* log an error */
  log_log(LOG_ERR, "%s:%d: %s: not a valid gid: '%s'",
          filename, lnr, keyword, token);
  exit(EXIT_FAILURE);
}

static int parse_loglevel(const char *filename, int lnr, const char *value)
{
  if (strcasecmp(value, "crit") == 0)
    return LOG_CRIT;
  else if ((strcasecmp(value, "error") == 0) || (strcasecmp(value, "err") == 0))
    return LOG_ERR;
  else if (strcasecmp(value, "warning")==0)
    return LOG_WARNING;
  else if (strcasecmp(value, "notice")==0)
    return LOG_NOTICE;
  else if (strcasecmp(value, "info")==0)
    return LOG_INFO;
  else if (strcasecmp(value, "debug")==0)
    return LOG_DEBUG;
  else
  {
    log_log(LOG_ERR, "%s:%d: not a log level '%s'",
            filename, lnr, value);
    exit(EXIT_FAILURE);
  }
}

static void handle_log(const char *filename, int lnr,
                       const char *keyword, char *line)
{
  int level = LOG_INFO;
  char scheme[64];
  char loglevel[32];
  check_argumentcount(filename, lnr, keyword,
                      get_token(&line, scheme, sizeof(scheme)) != NULL);
  if (get_token(&line, loglevel, sizeof(loglevel)) != NULL)
    level = parse_loglevel(filename, lnr, loglevel);
  get_eol(filename, lnr, keyword, &line);
  if (strcasecmp(scheme, "none") == 0)
    log_addlogging_none();
  else if (strcasecmp(scheme, "syslog") == 0)
    log_addlogging_syslog(level);
  else if (scheme[0] == '/')
    log_addlogging_file(level, scheme);
  else
  {
    log_log(LOG_ERR, "%s:%d: %s: invalid argument '%s'",
            filename, lnr, keyword, scheme);
    exit(EXIT_FAILURE);
  }
}

/* add a single URI to the list of URIs in the configuration */
static void add_uri(const char *filename, int lnr,
                    struct ldap_config *cfg, const char *uri)
{
  int i;
  /* find the place where to insert the URI */
  for (i = 0; cfg->uris[i].uri != NULL; i++)
    /* nothing */ ;
  /* check for room */
  if (i >= NSS_LDAP_CONFIG_MAX_URIS)
  {
    log_log(LOG_ERR, "%s:%d: maximum number of URIs exceeded",
            filename, lnr);
    exit(EXIT_FAILURE);
  }
  /* append URI to list */
  cfg->uris[i].uri = xstrdup(uri);
}

#ifdef HAVE_LDAP_DOMAIN2HOSTLIST
/* return the domain name of the current host
   the returned string must be freed by caller */
static const char *cfg_getdomainname(const char *filename, int lnr)
{
  const char *fqdn, *domain;
  fqdn = getfqdn();
  if ((fqdn != NULL) && ((domain = strchr(fqdn, '.')) != NULL) && (domain[1] != '\0'))
    return domain + 1;
  log_log(LOG_ERR, "%s:%d: unable to determinate a domain name",
          filename, lnr);
  exit(EXIT_FAILURE);
}

/* add URIs by doing DNS queries for SRV records */
static void add_uris_from_dns(const char *filename, int lnr,
                              struct ldap_config *cfg, const char *domain,
                              int force_ldaps)
{
  int rc;
  char *hostlist = NULL, *nxt;
  char buf[BUFLEN_HOSTNAME + sizeof("ldaps://")];
  log_log(LOG_DEBUG, "query %s for SRV records", domain);
  rc = ldap_domain2hostlist(domain, &hostlist);
  if (rc != LDAP_SUCCESS)
  {
    log_log(LOG_ERR, "%s:%d: no servers found in DNS zone %s: %s",
            filename, lnr, domain, ldap_err2string(rc));
    exit(EXIT_FAILURE);
  }
  if ((hostlist == NULL) || (*hostlist == '\0'))
  {
    log_log(LOG_ERR, "%s:%d: no servers found in DNS zone %s",
            filename, lnr, domain);
    exit(EXIT_FAILURE);
  }
  /* hostlist is a space-separated list of host names that we use to build
     URIs */
  while (hostlist != NULL)
  {
    /* find the next space and split the string there */
    nxt = strchr(hostlist, ' ');
    if (nxt != NULL)
    {
      *nxt = '\0';
      nxt++;
    }
    /* if port is 636, use ldaps:// URI */
    if ((strlen(hostlist) > 4) && (strcmp(hostlist + strlen(hostlist) - 4, ":636") == 0))
    {
      hostlist[strlen(hostlist) - 4] = '\0';
      if (mysnprintf(buf, sizeof(buf), "ldaps://%s", hostlist))
      {
        log_log(LOG_ERR, "add_uris_from_dns(): buf buffer too small (%lu required)",
                (unsigned long) strlen(hostlist) + 8);
        exit(EXIT_FAILURE);
      }
    }
    else
    {
      /* strip default port number */
      if ((strlen(hostlist) > 4) && (strcmp(hostlist + strlen(hostlist) - 4, ":389") == 0))
        hostlist[strlen(hostlist) - 4] = '\0';
      if (mysnprintf(buf, sizeof(buf), "ldap%s://%s", force_ldaps ? "s" : "", hostlist))
      {
        log_log(LOG_ERR, "add_uris_from_dns(): buf buffer too small (%lu required)",
                (unsigned long) strlen(hostlist) + 7);
        exit(EXIT_FAILURE);
      }
    }
    log_log(LOG_DEBUG, "add_uris_from_dns(): found uri: %s", buf);
    add_uri(filename, lnr, cfg, buf);
    /* get next entry from list */
    hostlist = nxt;
  }
}
#endif /* HAVE_LDAP_DOMAIN2HOSTLIST */

/* check that the file is not world readable */
static void check_permissions(const char *filename, const char *keyword)
{
  struct stat sb;
  /* get file status */
  if (stat(filename, &sb))
  {
    log_log(LOG_ERR, "cannot stat() %s: %s", filename, strerror(errno));
    exit(EXIT_FAILURE);
  }
  /* check permissions */
  if ((sb.st_mode & 0007) != 0)
  {
    if (keyword != NULL)
      log_log(LOG_ERR, "%s: file should not be world readable if %s is set",
              filename, keyword);
    else
      log_log(LOG_ERR, "%s: file should not be world readable", filename);
    exit(EXIT_FAILURE);
  }
}

/* check whether the specified path is readable */
static void check_readable(const char *filename, int lnr,
                       const char *keyword, const char *path)
{
  if (access(path, R_OK) != 0)
  {
    log_log(LOG_ERR, "%s:%d: %s: error accessing %s: %s",
            filename, lnr, keyword, path, strerror(errno));
    exit(EXIT_FAILURE);
  }
}

/* check whether the specified path is a directory */
static void check_dir(const char *filename, int lnr,
                      const char *keyword, const char *path)
{
  struct stat sb;
  if (stat(path, &sb))
  {
    log_log(LOG_ERR, "%s:%d: %s: cannot stat() %s: %s",
            filename, lnr, keyword, path, strerror(errno));
    exit(EXIT_FAILURE);
  }
  if (!S_ISDIR(sb.st_mode))
  {
    log_log(LOG_ERR, "%s:%d: %s: %s is not a directory",
            filename, lnr, keyword, path);
    exit(EXIT_FAILURE);
  }
}

static void handle_krb5_ccname(const char *filename, int lnr,
                               const char *keyword, char *line)
{
  char token[80];
  const char *ccname;
  const char *ccfile;
  size_t ccenvlen;
  char *ccenv;
#ifdef HAVE_GSS_KRB5_CCACHE_NAME
  OM_uint32 minor_status;
#endif /* HAVE_GSS_KRB5_CCACHE_NAME */
  /* get token */
  check_argumentcount(filename, lnr, keyword,
                      (get_token(&line, token, sizeof(token)) != NULL));
  get_eol(filename, lnr, keyword, &line);
  /* set default kerberos ticket cache for SASL-GSSAPI */
  ccname = token;
  /* check that cache exists and is readable if it is a file */
  if ((strncasecmp(ccname, "FILE:", sizeof("FILE:") - 1) == 0) ||
      (strncasecmp(ccname, "WRFILE:", sizeof("WRFILE:") - 1) == 0))
  {
    ccfile = strchr(ccname, ':') + 1;
    check_readable(filename, lnr, keyword, ccfile);
  }
  /* set the environment variable (we have a memory leak if this option
     is set multiple times) */
  ccenvlen = strlen(ccname) + sizeof("KRB5CCNAME=");
  ccenv = (char *)malloc(ccenvlen);
  if (ccenv == NULL)
  {
    log_log(LOG_CRIT, "malloc() failed to allocate memory");
    exit(EXIT_FAILURE);
  }
  mysnprintf(ccenv, ccenvlen, "KRB5CCNAME=%s", ccname);
  putenv(ccenv);
#ifdef HAVE_GSS_KRB5_CCACHE_NAME
  /* set the name with gss_krb5_ccache_name() */
  if (gss_krb5_ccache_name(&minor_status, ccname, NULL) != GSS_S_COMPLETE)
  {
    log_log(LOG_ERR, "%s:%d: unable to set default credential cache: %s",
            filename, lnr, ccname);
    exit(EXIT_FAILURE);
  }
#endif /* HAVE_GSS_KRB5_CCACHE_NAME */
}

static enum ldap_map_selector parse_map(const char *value)
{
  if ((strcasecmp(value, "alias") == 0) || (strcasecmp(value, "aliases") == 0))
    return LM_ALIASES;
  else if ((strcasecmp(value, "ether") == 0) || (strcasecmp(value, "ethers") == 0))
    return LM_ETHERS;
  else if (strcasecmp(value, "group") == 0)
    return LM_GROUP;
  else if ((strcasecmp(value, "host") == 0) || (strcasecmp(value, "hosts") == 0))
    return LM_HOSTS;
  else if (strcasecmp(value, "netgroup") == 0)
    return LM_NETGROUP;
  else if ((strcasecmp(value, "network") == 0) || (strcasecmp(value, "networks") == 0))
    return LM_NETWORKS;
  else if (strcasecmp(value, "passwd") == 0)
    return LM_PASSWD;
  else if ((strcasecmp(value, "protocol") == 0) || (strcasecmp(value, "protocols") == 0))
    return LM_PROTOCOLS;
  else if (strcasecmp(value, "rpc") == 0)
    return LM_RPC;
  else if ((strcasecmp(value, "service") == 0) || (strcasecmp(value, "services") == 0))
    return LM_SERVICES;
  else if (strcasecmp(value, "shadow") == 0)
    return LM_SHADOW;
  else if (strcasecmp(value, "nfsidmap") == 0)
    return LM_NFSIDMAP;
  /* unknown map */
  return LM_NONE;
}

/* check to see if the line begins with a named map */
static enum ldap_map_selector get_map(char **line)
{
  char token[32];
  char *old;
  enum ldap_map_selector map;
  /* get the token */
  old = *line;
  if (get_token(line, token, sizeof(token)) == NULL)
    return LM_NONE;
  /* see if we found a map */
  map = parse_map(token);
  /* unknown map, return to the previous state */
  if (map == LM_NONE)
    *line = old;
  return map;
}

static const char *print_map(enum ldap_map_selector map)
{
  switch (map)
  {
    case LM_ALIASES:   return "aliases";
    case LM_ETHERS:    return "ethers";
    case LM_GROUP:     return "group";
    case LM_HOSTS:     return "hosts";
    case LM_NETGROUP:  return "netgroup";
    case LM_NETWORKS:  return "networks";
    case LM_PASSWD:    return "passwd";
    case LM_PROTOCOLS: return "protocols";
    case LM_RPC:       return "rpc";
    case LM_SERVICES:  return "services";
    case LM_SHADOW:    return "shadow";
    case LM_NFSIDMAP:  return "nfsidmap";
    case LM_NONE:
    default:           return "???";
  }
}

static void handle_base(const char *filename, int lnr,
                        const char *keyword, char *line,
                        struct ldap_config *cfg)
{
  const char **bases;
  int i;
  char *value;
#ifdef HAVE_LDAP_DOMAIN2DN
  const char *domain = NULL;
  char *domaindn = NULL;
#endif /* HAVE_LDAP_DOMAIN2DN */
  /* get the list of bases to update */
  bases = base_get_var(get_map(&line));
  if (bases == NULL)
    bases = cfg->bases;
  /* rest of the line is the value */
  value = get_linedup(filename, lnr, keyword, &line);
  /* if the base is "DOMAIN" use the domain name */
  if (strcasecmp(value, "domain") == 0)
  {
#ifdef HAVE_LDAP_DOMAIN2DN
    free(value);
    domain = cfg_getdomainname(filename, lnr);
    ldap_domain2dn(domain, &domaindn);
    log_log(LOG_DEBUG, "set_base(): setting base to %s from domain",
            domaindn);
    value = xstrdup(domaindn);
#else /* not HAVE_LDAP_DOMAIN2DN */
    log_log(LOG_ERR, "%s:%d: value %s not supported on platform",
            filename, lnr, value);
    exit(EXIT_FAILURE);
#endif /* not HAVE_LDAP_DOMAIN2DN */
  }
  if (strcasecmp(value, "\"\"") == 0)
    value = "";
  /* find the spot in the list of bases */
  for (i = 0; i < NSS_LDAP_CONFIG_MAX_BASES; i++)
    if (bases[i] == NULL)
    {
      bases[i] = value;
      return;
    }
  /* no free spot found */
  log_log(LOG_ERR, "%s:%d: maximum number of base options per map (%d) exceeded",
          filename, lnr, NSS_LDAP_CONFIG_MAX_BASES);
  exit(EXIT_FAILURE);
}

static void handle_scope(const char *filename, int lnr,
                         const char *keyword, char *line,
                         struct ldap_config *cfg)
{
  char token[32];
  int *var;
  var = scope_get_var(get_map(&line));
  check_argumentcount(filename, lnr, keyword,
                      get_token(&line, token, sizeof(token)) != NULL);
  get_eol(filename, lnr, keyword, &line);
  if (var == NULL)
    var = &cfg->scope;
  if ((strcasecmp(token, "sub") == 0) || (strcasecmp(token, "subtree") == 0))
    *var = LDAP_SCOPE_SUBTREE;
  else if ((strcasecmp(token, "one") == 0) || (strcasecmp(token, "onelevel") == 0))
    *var = LDAP_SCOPE_ONELEVEL;
  else if (strcasecmp(token, "base") == 0)
    *var = LDAP_SCOPE_BASE;
#ifdef LDAP_SCOPE_CHILDREN
  else if (strcasecmp(token, "children") == 0)
    *var = LDAP_SCOPE_CHILDREN;
#endif /* LDAP_SCOPE_CHILDREN */
  else
  {
    log_log(LOG_ERR, "%s:%d: not a scope argument: '%s'",
            filename, lnr, token);
    exit(EXIT_FAILURE);
  }
}

static const char *print_scope(int scope)
{
  switch (scope)
  {
    case LDAP_SCOPE_SUBTREE:  return "sub";
    case LDAP_SCOPE_ONELEVEL: return "one";
    case LDAP_SCOPE_BASE:     return "base";
#ifdef LDAP_SCOPE_CHILDREN
    case LDAP_SCOPE_CHILDREN: return "children";
#endif /* LDAP_SCOPE_CHILDREN */
    default:                  return "???";
  }
}

static void handle_deref(const char *filename, int lnr,
                         const char *keyword, char *line,
                         struct ldap_config *cfg)
{
  char token[32];
  check_argumentcount(filename, lnr, keyword,
                      get_token(&line, token, sizeof(token)) != NULL);
  get_eol(filename, lnr, keyword, &line);
  if (strcasecmp(token, "never") == 0)
    cfg->deref = LDAP_DEREF_NEVER;
  else if (strcasecmp(token, "searching") == 0)
    cfg->deref = LDAP_DEREF_SEARCHING;
  else if (strcasecmp(token, "finding") == 0)
    cfg->deref = LDAP_DEREF_FINDING;
  else if (strcasecmp(token, "always") == 0)
    cfg->deref = LDAP_DEREF_ALWAYS;
  else
  {
    log_log(LOG_ERR, "%s:%d: wrong argument: '%s'", filename, lnr, token);
    exit(EXIT_FAILURE);
  }
}

static const char *print_deref(int deref)
{
  switch (deref)
  {
    case LDAP_DEREF_NEVER:     return "never";
    case LDAP_DEREF_SEARCHING: return "searching";
    case LDAP_DEREF_FINDING:   return "finding";
    case LDAP_DEREF_ALWAYS:    return "always";
    default:                   return "???";
  }
}

static void handle_filter(const char *filename, int lnr,
                          const char *keyword, char *line)
{
  const char **var;
  const char *map = line;
  var = filter_get_var(get_map(&line));
  if (var == NULL)
  {
    log_log(LOG_ERR, "%s:%d: unknown map: '%s'", filename, lnr, map);
    exit(EXIT_FAILURE);
  }
  check_argumentcount(filename, lnr, keyword, (line != NULL) && (*line != '\0'));
  /* check if the value will be changed */
  if (strcmp(*var, line) != 0)
  {
    /* Note: we have a memory leak here if a single mapping is changed
       multiple times in one config (deemed not a problem) */
    *var = xstrdup(line);
  }
}

/* this function modifies the statement argument passed */
static void handle_map(const char *filename, int lnr,
                       const char *keyword, char *line)
{
  enum ldap_map_selector map;
  const char **var;
  char oldatt[32], *newatt;
  /* get the map */
  if ((map = get_map(&line)) == LM_NONE)
  {
    log_log(LOG_ERR, "%s:%d: unknown map: '%s'", filename, lnr, line);
    exit(EXIT_FAILURE);
  }
  /* read the other tokens */
  check_argumentcount(filename, lnr, keyword,
                      (get_token(&line, oldatt, sizeof(oldatt)) != NULL));
  newatt = get_linedup(filename, lnr, keyword, &line);
  /* change attribute mapping */
  var = attmap_get_var(map, oldatt);
  if (var == NULL)
  {
    log_log(LOG_ERR, "%s:%d: unknown attribute to map: '%s'",
            filename, lnr, oldatt);
    exit(EXIT_FAILURE);
  }
  if (attmap_set_mapping(var, newatt) == NULL)
  {
    log_log(LOG_ERR, "%s:%d: attribute %s cannot be an expression",
            filename, lnr, oldatt);
    exit(EXIT_FAILURE);
  }
  free(newatt);
}

#ifdef LDAP_OPT_X_TLS
static const char *print_ssl(int ssl)
{
  switch (ssl)
  {
    case SSL_OFF:       return "off";
    case SSL_START_TLS: return "start_tls";
    case SSL_LDAPS:     return "on";
    default:            return "???";
  }
}

static int get_tls_reqcert(const char *filename, int lnr,
                           const char *keyword, char **line)
{
  char token[16];
  check_argumentcount(filename, lnr, keyword,
                      get_token(line, token, sizeof(token)) != NULL);
  /* check if it is a valid value for tls_reqcert option */
  if ((strcasecmp(token, "never") == 0) || (strcasecmp(token, "no") == 0))
    return LDAP_OPT_X_TLS_NEVER;
  else if (strcasecmp(token, "allow") == 0)
    return LDAP_OPT_X_TLS_ALLOW;
  else if (strcasecmp(token, "try") == 0)
    return LDAP_OPT_X_TLS_TRY;
  else if ((strcasecmp(token, "demand") == 0) ||
           (strcasecmp(token, "yes") == 0))
    return LDAP_OPT_X_TLS_DEMAND;
  else if (strcasecmp(token, "hard") == 0)
    return LDAP_OPT_X_TLS_HARD;
  else
  {
    log_log(LOG_ERR, "%s:%d: %s: invalid argument: '%s'",
            filename, lnr, keyword, token);
    exit(EXIT_FAILURE);
  }
}

static const char *print_tls_reqcert(int value)
{
  switch (value)
  {
    case LDAP_OPT_X_TLS_NEVER:  return "never";
    case LDAP_OPT_X_TLS_ALLOW:  return "allow";
    case LDAP_OPT_X_TLS_TRY:    return "try";
    case LDAP_OPT_X_TLS_DEMAND: return "demand";
    case LDAP_OPT_X_TLS_HARD:   return "hard";
    default:                    return "???";
  }
}

static void handle_tls_reqcert(const char *filename, int lnr,
                               const char *keyword, char *line)
{
  int value, rc;
  value = get_tls_reqcert(filename, lnr, keyword, &line);
  get_eol(filename, lnr, keyword, &line);
  log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_X_TLS_REQUIRE_CERT,%s)",
          print_tls_reqcert(value));
  LDAP_SET_OPTION(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &value);
}

#ifdef LDAP_OPT_X_TLS_REQUIRE_SAN
static void handle_tls_reqsan(const char *filename, int lnr,
                                   const char *keyword, char *line)
{
  int value, rc;
  value = get_tls_reqcert(filename, lnr, keyword, &line);
  get_eol(filename, lnr, keyword, &line);
  log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_X_TLS_REQUIRE_SAN,%s)",
          print_tls_reqcert(value));
  LDAP_SET_OPTION(NULL, LDAP_OPT_X_TLS_REQUIRE_SAN, &value);
}
#endif /* LDAP_OPT_X_TLS_REQUIRE_SAN */

#ifdef LDAP_OPT_X_TLS_CRLCHECK
static void handle_tls_crlcheck(const char *filename, int lnr,
                               const char *keyword, char *line)
{
  char token[16];
  int value, rc;
  /* get token */
  check_argumentcount(filename, lnr, keyword,
                      get_token(&line, token, sizeof(token)) != NULL);
  get_eol(filename, lnr, keyword, &line);
  /* check if it is a valid value for tls_crlcheck option */
  if (strcasecmp(token, "none") == 0)
    value = LDAP_OPT_X_TLS_CRL_NONE;
  else if (strcasecmp(token, "peer") == 0)
    value = LDAP_OPT_X_TLS_CRL_PEER;
  else if (strcasecmp(token, "all") == 0)
    value = LDAP_OPT_X_TLS_CRL_ALL;
  else
  {
    log_log(LOG_ERR, "%s:%d: %s: invalid argument: '%s'",
            filename, lnr, keyword, token);
    exit(EXIT_FAILURE);
  }
  log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_X_TLS_CRLCHECK,%s)", token);
  LDAP_SET_OPTION(NULL, LDAP_OPT_X_TLS_CRLCHECK, &value);
}

static const char *print_tls_crlcheck(int value)
{
  switch (value)
  {
    case LDAP_OPT_X_TLS_CRL_NONE:  return "none";
    case LDAP_OPT_X_TLS_CRL_PEER:  return "peer";
    case LDAP_OPT_X_TLS_CRL_ALL:   return "all";
    default:                       return "???";
  }
}
#endif /* LDAP_OPT_X_TLS_CRLCHECK */
#endif /* LDAP_OPT_X_TLS */

/* this function modifies the line argument passed */
static void handle_nss_initgroups_ignoreusers(
                const char *filename, int lnr,
                const char *keyword, char *line, struct ldap_config *cfg)
{
  char token[MAX_LINE_LENGTH];
  char *username, *next;
  struct passwd *pwent;
  check_argumentcount(filename, lnr, keyword, (line != NULL) && (*line != '\0'));
  if (cfg->nss_initgroups_ignoreusers == NULL)
    cfg->nss_initgroups_ignoreusers = set_new();
  while (get_token(&line, token, sizeof(token)) != NULL)
  {
    if (strcasecmp(token, "alllocal") == 0)
    {
      /* go over all users (this will work because nslcd is not yet running) */
      setpwent();
      while ((pwent = getpwent()) != NULL)
        set_add(cfg->nss_initgroups_ignoreusers, pwent->pw_name);
      endpwent();
    }
    else
    {
      next = token;
      while (*next != '\0')
      {
        username = next;
        /* find the end of the current username */
        while ((*next != '\0') && (*next != ','))
          next++;
        if (*next == ',')
        {
          *next = '\0';
          next++;
        }
        /* check if user exists (but add anyway) */
        pwent = getpwnam(username);
        if (pwent == NULL)
          log_log(LOG_ERR, "%s:%d: user '%s' does not exist",
                  filename, lnr, username);
        set_add(cfg->nss_initgroups_ignoreusers, username);
      }
    }
  }
}

static void handle_validnames(const char *filename, int lnr,
                              const char *keyword, char *line,
                              struct ldap_config *cfg)
{
  char *value;
  int i, l;
  int flags = REG_EXTENDED | REG_NOSUB;
  /* the rest of the line should be a regular expression */
  value = get_linedup(filename, lnr, keyword, &line);
  if (cfg->validnames_str != NULL)
  {
    free(cfg->validnames_str);
    regfree(&cfg->validnames);
  }
  cfg->validnames_str = strdup(value);
  /* check formatting and update flags */
  if (value[0] != '/')
  {
    log_log(LOG_ERR, "%s:%d: regular expression incorrectly delimited",
            filename, lnr);
    exit(EXIT_FAILURE);
  }
  l = strlen(value);
  if (value[l - 1] == 'i')
  {
    value[l - 1] = '\0';
    l--;
    flags |= REG_ICASE;
  }
  if (value[l - 1] != '/')
  {
    log_log(LOG_ERR, "%s:%d: regular expression incorrectly delimited",
            filename, lnr);
    exit(EXIT_FAILURE);
  }
  value[l - 1] = '\0';
  /* compile the regular expression */
  if ((i = regcomp(&cfg->validnames, value + 1, flags)) != 0)
  {
    /* get the error message */
    l = regerror(i, &cfg->validnames, NULL, 0);
    value = malloc(l);
    if (value == NULL)
      log_log(LOG_ERR, "%s:%d: invalid regular expression", filename, lnr);
    else
    {
      regerror(i, &cfg->validnames, value, l);
      log_log(LOG_ERR, "%s:%d: invalid regular expression: %s",
              filename, lnr, value);
    }
    exit(EXIT_FAILURE);
  }
  free(value);
}

static void check_search_variables(
                const char *filename, int lnr,
                const char *expression)
{
  SET *set;
  const char **list;
  int i;
  set = expr_vars(expression, NULL);
  list = set_tolist(set);
  if (list == NULL)
  {
    log_log(LOG_CRIT,
            "check_search_variables(): malloc() failed to allocate memory");
    exit(EXIT_FAILURE);
  }
  for (i = 0; list[i] != NULL; i++)
  {
    if ((strcmp(list[i], "username") != 0) &&
        (strcmp(list[i], "service") != 0) &&
        (strcmp(list[i], "ruser") != 0) &&
        (strcmp(list[i], "rhost") != 0) &&
        (strcmp(list[i], "tty") != 0) &&
        (strcmp(list[i], "hostname") != 0) &&
        (strcmp(list[i], "fqdn") != 0) &&
        (strcmp(list[i], "domain") != 0) &&
        (strcmp(list[i], "dn") != 0) &&
        (strcmp(list[i], "uid") != 0))
    {
      log_log(LOG_ERR, "%s:%d: unknown variable $%s", filename, lnr, list[i]);
      exit(EXIT_FAILURE);
    }
  }
  /* free memory */
  set_free(set);
  free(list);
}

static void handle_pam_authc_search(
                const char *filename, int lnr,
                const char *keyword, char *line, struct ldap_config *cfg)
{
  check_argumentcount(filename, lnr, keyword, (line != NULL) && (*line != '\0'));
  cfg->pam_authc_search = xstrdup(line);
  /* check the variables used in the expression */
  check_search_variables(filename, lnr, cfg->pam_authc_search);
}

static void handle_pam_authz_search(
                const char *filename, int lnr,
                const char *keyword, char *line, struct ldap_config *cfg)
{
  int i;
  check_argumentcount(filename, lnr, keyword, (line != NULL) && (*line != '\0'));
  /* find free spot for search filter */
  for (i = 0; (i < NSS_LDAP_CONFIG_MAX_AUTHZ_SEARCHES) && (cfg->pam_authz_searches[i] != NULL);
       i++)
    /* nothing */ ;
  if (i >= NSS_LDAP_CONFIG_MAX_AUTHZ_SEARCHES)
  {
    log_log(LOG_ERR, "%s:%d: maximum number of pam_authz_search options (%d) exceeded",
            filename, lnr, NSS_LDAP_CONFIG_MAX_AUTHZ_SEARCHES);
    exit(EXIT_FAILURE);
  }
  cfg->pam_authz_searches[i] = xstrdup(line);
  /* check the variables used in the expression */
  check_search_variables(filename, lnr, cfg->pam_authz_searches[i]);
}

static void handle_pam_password_prohibit_message(
                const char *filename, int lnr,
                const char *keyword, char *line, struct ldap_config *cfg)
{
  char *value;
  int l;
  /* the rest of the line should be a message */
  value = get_linedup(filename, lnr, keyword, &line);
  /* strip quotes if they are present */
  l = strlen(value);
  if ((value[0] == '\"') && (value[l - 1] == '\"'))
  {
    value[l - 1] = '\0';
    value++;
  }
  cfg->pam_password_prohibit_message = value;
}

static void handle_reconnect_invalidate(
                const char *filename, int lnr,
                const char *keyword, char *line, struct ldap_config *cfg)
{
  char token[MAX_LINE_LENGTH];
  char *name, *next;
  enum ldap_map_selector map;
  check_argumentcount(filename, lnr, keyword, (line != NULL) && (*line != '\0'));
  while (get_token(&line, token, sizeof(token)) != NULL)
  {
    next = token;
    while (*next != '\0')
    {
      name = next;
      /* find the end of the current map name */
      while ((*next != '\0') && (*next != ','))
        next++;
      if (*next == ',')
      {
        *next = '\0';
        next++;
      }
      /* check if map name exists */
      map = parse_map(name);
      if (map == LM_NONE)
      {
        log_log(LOG_ERR, "%s:%d: unknown map: '%s'", filename, lnr, name);
        exit(EXIT_FAILURE);
      }
      cfg->reconnect_invalidate[map] = 1;
    }
  }
}

static void handle_cache(const char *filename, int lnr,
                         const char *keyword, char *line,
                         struct ldap_config *cfg)
{
  char cache[16];
  time_t value1, value2;
  /* get cache map and values */
  check_argumentcount(filename, lnr, keyword,
                      get_token(&line, cache, sizeof(cache)) != NULL);
  value1 = get_time(filename, lnr, keyword, &line);
  if ((line != NULL) && (*line != '\0'))
    value2 = get_time(filename, lnr, keyword, &line);
  else
    value2 = value1;
  get_eol(filename, lnr, keyword, &line);
  /* check the cache */
  if (strcasecmp(cache, "dn2uid") == 0)
  {
    cfg->cache_dn2uid_positive = value1;
    cfg->cache_dn2uid_negative = value2;
  }
  else
  {
    log_log(LOG_ERR, "%s:%d: unknown cache: '%s'", filename, lnr, cache);
    exit(EXIT_FAILURE);
  }
}

/* This function tries to get the LDAP search base from the LDAP server.
   Note that this returns a string that has been allocated with strdup().
   For this to work the myldap module needs enough configuration information
   to make an LDAP connection. */
static MUST_USE char *get_base_from_rootdse(void)
{
  MYLDAP_SESSION *session;
  MYLDAP_SEARCH *search;
  MYLDAP_ENTRY *entry;
  const char *attrs[] = { "+", NULL };
  int i;
  int rc;
  const char **values;
  char *base = NULL;
  /* initialize session */
  session = myldap_create_session();
  assert(session != NULL);
  /* perform search */
  search = myldap_search(session, "", LDAP_SCOPE_BASE, "(objectClass=*)",
                         attrs, NULL);
  if (search == NULL)
  {
    myldap_session_close(session);
    return NULL;
  }
  /* go over results */
  for (i = 0; (entry = myldap_get_entry(search, &rc)) != NULL; i++)
  {
    /* get defaultNamingContext */
    values = myldap_get_values(entry, "defaultNamingContext");
    if ((values != NULL) && (values[0] != NULL))
    {
      base = xstrdup(values[0]);
      log_log(LOG_DEBUG, "get_basedn_from_rootdse(): found attribute defaultNamingContext with value %s",
              values[0]);
      break;
    }
    /* get namingContexts */
    values = myldap_get_values(entry, "namingContexts");
    if ((values != NULL) && (values[0] != NULL))
    {
      base = xstrdup(values[0]);
      log_log(LOG_DEBUG, "get_basedn_from_rootdse(): found attribute namingContexts with value %s",
              values[0]);
      break;
    }
  }
  /* clean up */
  myldap_session_close(session);
  return base;
}

/* set the configuration information to the defaults */
static void cfg_defaults(struct ldap_config *cfg)
{
  int i;
  memset(cfg, 0, sizeof(struct ldap_config));
  cfg->threads = 5;
  cfg->uidname = NULL;
  cfg->uid = NOUID;
  cfg->gid = NOGID;
  for (i = 0; i < (NSS_LDAP_CONFIG_MAX_URIS + 1); i++)
  {
    cfg->uris[i].uri = NULL;
    cfg->uris[i].firstfail = 0;
    cfg->uris[i].lastfail = 0;
  }
#ifdef LDAP_VERSION3
  cfg->ldap_version = LDAP_VERSION3;
#else /* LDAP_VERSION3 */
  cfg->ldap_version = LDAP_VERSION2;
#endif /* not LDAP_VERSION3 */
  cfg->binddn = NULL;
  cfg->bindpw = NULL;
  cfg->rootpwmoddn = NULL;
  cfg->rootpwmodpw = NULL;
  cfg->sasl_mech = NULL;
  cfg->sasl_realm = NULL;
  cfg->sasl_authcid = NULL;
  cfg->sasl_authzid = NULL;
  cfg->sasl_secprops = NULL;
#ifdef LDAP_OPT_X_SASL_NOCANON
  cfg->sasl_canonicalize = -1;
#endif /* LDAP_OPT_X_SASL_NOCANON */
  for (i = 0; i < NSS_LDAP_CONFIG_MAX_BASES; i++)
    cfg->bases[i] = NULL;
  cfg->scope = LDAP_SCOPE_SUBTREE;
  cfg->deref = LDAP_DEREF_NEVER;
  cfg->referrals = 1;
#if defined(HAVE_LDAP_SASL_BIND) && defined(LDAP_SASL_SIMPLE)
  cfg->pam_authc_ppolicy = 1;
#endif
  cfg->bind_timelimit = 10;
  cfg->timelimit = LDAP_NO_LIMIT;
  cfg->idle_timelimit = 0;
  cfg->reconnect_sleeptime = 1;
  cfg->reconnect_retrytime = 10;
#ifdef LDAP_OPT_X_TLS
  cfg->ssl = SSL_OFF;
#endif /* LDAP_OPT_X_TLS */
  cfg->pagesize = 0;
  cfg->nss_initgroups_ignoreusers = NULL;
  cfg->nss_min_uid = 0;
  cfg->nss_uid_offset = 0;
  cfg->nss_gid_offset = 0;
  cfg->nss_nested_groups = 0;
  cfg->nss_getgrent_skipmembers = 0;
  cfg->nss_disable_enumeration = 0;
  cfg->validnames_str = NULL;
  handle_validnames(__FILE__, __LINE__, "",
                    "/^[a-z0-9._@$()]([a-z0-9._@$() \\~-]*[a-z0-9._@$()~-])?$/i",
                    cfg);
  cfg->ignorecase = 0;
  cfg->pam_authc_search = "BASE";
  for (i = 0; i < NSS_LDAP_CONFIG_MAX_AUTHZ_SEARCHES; i++)
    cfg->pam_authz_searches[i] = NULL;
  cfg->pam_password_prohibit_message = NULL;
  for (i = 0; i < LM_NONE; i++)
    cfg->reconnect_invalidate[i] = 0;
  cfg->cache_dn2uid_positive = 15 * TIME_MINUTES;
  cfg->cache_dn2uid_negative = 15 * TIME_MINUTES;
}

static void cfg_read(const char *filename, struct ldap_config *cfg)
{
  FILE *fp;
  int lnr = 0;
  char linebuf[MAX_LINE_LENGTH];
  char *line;
  char keyword[32];
  char token[256];
  int i;
#ifdef LDAP_OPT_X_TLS
  int rc;
  char *value;
#endif
  /* open config file */
  if ((fp = fopen(filename, "r")) == NULL)
  {
    log_log(LOG_ERR, "cannot open config file (%s): %s",
            filename, strerror(errno));
    exit(EXIT_FAILURE);
  }
  /* read file and parse lines */
  while (fgets(linebuf, sizeof(linebuf), fp) != NULL)
  {
    lnr++;
    line = linebuf;
    /* strip newline */
    i = (int)strlen(line);
    if ((i <= 0) || (line[i - 1] != '\n'))
    {
      log_log(LOG_ERR, "%s:%d: line too long or last line missing newline",
              filename, lnr);
      exit(EXIT_FAILURE);
    }
    line[i - 1] = '\0';
    /* ignore comment lines */
    if (line[0] == '#')
      continue;
    /* strip trailing spaces */
    for (i--; (i > 0) && isspace(line[i - 1]); i--)
      line[i - 1] = '\0';
    /* get keyword from line and ignore empty lines */
    if (get_token(&line, keyword, sizeof(keyword)) == NULL)
      continue;
    /* runtime options */
    if (strcasecmp(keyword, "threads") == 0)
    {
      cfg->threads = get_int(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "uid") == 0)
    {
      handle_uid(filename, lnr, keyword, line, cfg);
    }
    else if (strcasecmp(keyword, "gid") == 0)
    {
      handle_gid(filename, lnr, keyword, line, &cfg->gid);
    }
    else if (strcasecmp(keyword, "log") == 0)
    {
      handle_log(filename, lnr, keyword, line);
    }
    /* general connection options */
    else if (strcasecmp(keyword, "uri") == 0)
    {
      check_argumentcount(filename, lnr, keyword, (line != NULL) && (*line != '\0'));
      while (get_token(&line, token, sizeof(token)) != NULL)
      {
        if (strcasecmp(token, "dns") == 0)
        {
#ifdef HAVE_LDAP_DOMAIN2HOSTLIST
          add_uris_from_dns(filename, lnr, cfg, cfg_getdomainname(filename, lnr), 0);
#else /* not HAVE_LDAP_DOMAIN2HOSTLIST */
          log_log(LOG_ERR, "%s:%d: value %s not supported on platform",
                  filename, lnr, token);
          exit(EXIT_FAILURE);
#endif /* not HAVE_LDAP_DOMAIN2HOSTLIST */
        }
        else if (strncasecmp(token, "dns:", 4) == 0)
        {
#ifdef HAVE_LDAP_DOMAIN2HOSTLIST
          add_uris_from_dns(filename, lnr, cfg, strdup(token + 4), 0);
#else /* not HAVE_LDAP_DOMAIN2HOSTLIST */
          log_log(LOG_ERR, "%s:%d: value %s not supported on platform",
                  filename, lnr, token);
          exit(EXIT_FAILURE);
#endif /* not HAVE_LDAP_DOMAIN2HOSTLIST */
        }
        else if (strcasecmp(token, "dnsldaps") == 0)
        {
#ifdef HAVE_LDAP_DOMAIN2HOSTLIST
          add_uris_from_dns(filename, lnr, cfg, cfg_getdomainname(filename, lnr), 1);
#else /* not HAVE_LDAP_DOMAIN2HOSTLIST */
          log_log(LOG_ERR, "%s:%d: value %s not supported on platform",
                  filename, lnr, token);
          exit(EXIT_FAILURE);
#endif /* not HAVE_LDAP_DOMAIN2HOSTLIST */
        }
        else if (strncasecmp(token, "dnsldaps:", 9) == 0)
        {
#ifdef HAVE_LDAP_DOMAIN2HOSTLIST
          add_uris_from_dns(filename, lnr, cfg, strdup(token + 9), 1);
#else /* not HAVE_LDAP_DOMAIN2HOSTLIST */
          log_log(LOG_ERR, "%s:%d: value %s not supported on platform",
                  filename, lnr, token);
          exit(EXIT_FAILURE);
#endif /* not HAVE_LDAP_DOMAIN2HOSTLIST */
        }
        else
          add_uri(filename, lnr, cfg, token);
      }
    }
    else if (strcasecmp(keyword, "ldap_version") == 0)
    {
      cfg->ldap_version = get_int(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "binddn") == 0)
    {
      cfg->binddn = get_linedup(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "bindpw") == 0)
    {
      check_permissions(filename, keyword);
      cfg->bindpw = get_linedup(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "rootpwmoddn") == 0)
    {
      cfg->rootpwmoddn = get_linedup(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "rootpwmodpw") == 0)
    {
      check_permissions(filename, keyword);
      cfg->rootpwmodpw = get_linedup(filename, lnr, keyword, &line);
    }
    /* SASL authentication options */
    else if (strcasecmp(keyword, "sasl_mech") == 0)
    {
      cfg->sasl_mech = get_strdup(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "sasl_realm") == 0)
    {
      cfg->sasl_realm = get_strdup(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "sasl_authcid") == 0)
    {
      cfg->sasl_authcid = get_strdup(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "sasl_authzid") == 0)
    {
      cfg->sasl_authzid = get_strdup(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "sasl_secprops") == 0)
    {
      cfg->sasl_secprops = get_strdup(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
#ifdef LDAP_OPT_X_SASL_NOCANON
    else if ((strcasecmp(keyword, "sasl_canonicalize") == 0) ||
             (strcasecmp(keyword, "sasl_canonicalise") == 0) ||
             (strcasecmp(keyword, "ldap_sasl_canonicalize") == 0) ||
             (strcasecmp(keyword, "sasl_canon") == 0))
    {
      cfg->sasl_canonicalize = get_boolean(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "sasl_nocanon") == 0)
    {
      cfg->sasl_canonicalize = get_boolean(filename, lnr, keyword, &line);
      cfg->sasl_canonicalize = !cfg->sasl_canonicalize;
      get_eol(filename, lnr, keyword, &line);
    }
#endif /* LDAP_OPT_X_SASL_NOCANON */
    /* Kerberos authentication options */
    else if (strcasecmp(keyword, "krb5_ccname") == 0)
    {
      handle_krb5_ccname(filename, lnr, keyword, line);
    }
    /* search/mapping options */
    else if (strcasecmp(keyword, "base") == 0)
    {
      handle_base(filename, lnr, keyword, line, cfg);
    }
    else if (strcasecmp(keyword, "scope") == 0)
    {
      handle_scope(filename, lnr, keyword, line, cfg);
    }
    else if (strcasecmp(keyword, "deref") == 0)
    {
      handle_deref(filename, lnr, keyword, line, cfg);
    }
    else if (strcasecmp(keyword, "referrals") == 0)
    {
      cfg->referrals = get_boolean(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "filter") == 0)
    {
      handle_filter(filename, lnr, keyword, line);
    }
    else if (strcasecmp(keyword, "map") == 0)
    {
      handle_map(filename, lnr, keyword, line);
    }
    else if (strcasecmp(keyword, "pam_authc_ppolicy") == 0)
    {
#if defined(HAVE_LDAP_SASL_BIND) && defined(LDAP_SASL_SIMPLE)
      cfg->pam_authc_ppolicy = get_boolean(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
#else
      log_log(LOG_ERR, "%s:%d: value %s not supported on platform",
              filename, lnr, value);
      exit(EXIT_FAILURE);
#endif
    }
    /* timing/reconnect options */
    else if (strcasecmp(keyword, "bind_timelimit") == 0)
    {
      cfg->bind_timelimit = get_int(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "timelimit") == 0)
    {
      cfg->timelimit = get_int(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "idle_timelimit") == 0)
    {
      cfg->idle_timelimit = get_int(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (!strcasecmp(keyword, "reconnect_sleeptime"))
    {
      cfg->reconnect_sleeptime = get_int(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "reconnect_retrytime") == 0)
    {
      cfg->reconnect_retrytime = get_int(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
#ifdef LDAP_OPT_X_TLS
    /* SSL/TLS options */
    else if (strcasecmp(keyword, "ssl") == 0)
    {
      check_argumentcount(filename, lnr, keyword,
                          (get_token(&line, token, sizeof(token)) != NULL));
      if ((strcasecmp(token, "start_tls") == 0) ||
          (strcasecmp(token, "starttls") == 0))
        cfg->ssl = SSL_START_TLS;
      else if (parse_boolean(filename, lnr, token))
        cfg->ssl = SSL_LDAPS;
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "tls_reqcert") == 0)
    {
      handle_tls_reqcert(filename, lnr, keyword, line);
    }
    else if (strcasecmp(keyword, "tls_cacertdir") == 0)
    {
      value = get_strdup(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
      check_dir(filename, lnr, token, value);
      log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_X_TLS_CACERTDIR,\"%s\")",
              value);
      LDAP_SET_OPTION(NULL, LDAP_OPT_X_TLS_CACERTDIR, value);
      free(value);
    }
    else if ((strcasecmp(keyword, "tls_cacertfile") == 0) ||
             (strcasecmp(keyword, "tls_cacert") == 0))
    {
      value = get_strdup(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
      check_readable(filename, lnr, keyword, value);
      log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_X_TLS_CACERTFILE,\"%s\")",
              value);
      LDAP_SET_OPTION(NULL, LDAP_OPT_X_TLS_CACERTFILE, value);
      free(value);
    }
    else if (strcasecmp(keyword, "tls_randfile") == 0)
    {
      value = get_strdup(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
      check_readable(filename, lnr, keyword, value);
      log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_X_TLS_RANDOM_FILE,\"%s\")",
              value);
      LDAP_SET_OPTION(NULL, LDAP_OPT_X_TLS_RANDOM_FILE, value);
      free(value);
    }
    else if (strcasecmp(keyword, "tls_ciphers") == 0)
    {
      value = get_linedup(filename, lnr, keyword, &line);
      log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_X_TLS_CIPHER_SUITE,\"%s\")",
              value);
      LDAP_SET_OPTION(NULL, LDAP_OPT_X_TLS_CIPHER_SUITE, value);
      free(value);
    }
    else if (strcasecmp(keyword, "tls_cert") == 0)
    {
      value = get_strdup(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
      check_readable(filename, lnr, keyword, value);
      log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_X_TLS_CERTFILE,\"%s\")",
              value);
      LDAP_SET_OPTION(NULL, LDAP_OPT_X_TLS_CERTFILE, value);
      free(value);
    }
    else if (strcasecmp(keyword, "tls_key") == 0)
    {
      value = get_strdup(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
      check_readable(filename, lnr, keyword, value);
      log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_X_TLS_KEYFILE,\"%s\")",
              value);
      LDAP_SET_OPTION(NULL, LDAP_OPT_X_TLS_KEYFILE, value);
      free(value);
    }
    else if (strcasecmp(keyword, "tls_reqsan") == 0)
    {
#ifdef LDAP_OPT_X_TLS_REQUIRE_SAN
      handle_tls_reqsan(filename, lnr, keyword, line);
#else /* not LDAP_OPT_X_TLS_REQUIRE_SAN */
      log_log(LOG_ERR, "%s:%d: option %s not supported on platform",
              filename, lnr, keyword);
      exit(EXIT_FAILURE);
#endif /* LDAP_OPT_X_TLS_REQUIRE_SAN */
    }
    else if (strcasecmp(keyword, "tls_crlcheck") == 0)
    {
#ifdef LDAP_OPT_X_TLS_CRLCHECK
      handle_tls_crlcheck(filename, lnr, keyword, line);
#else /* not LDAP_OPT_X_TLS_CRLCHECK */
      log_log(LOG_ERR, "%s:%d: option %s not supported on platform",
              filename, lnr, keyword);
      exit(EXIT_FAILURE);
#endif /* LDAP_OPT_X_TLS_CRLCHECK */
    }
    else if (strcasecmp(keyword, "tls_crlfile") == 0)
    {
#ifdef LDAP_OPT_X_TLS_CRLFILE
      value = get_strdup(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
      check_readable(filename, lnr, keyword, value);
      log_log(LOG_DEBUG, "ldap_set_option(LDAP_OPT_X_TLS_CRLFILE,\"%s\")",
              value);
      LDAP_SET_OPTION(NULL, LDAP_OPT_X_TLS_CRLFILE, value);
      free(value);
#else /* not LDAP_OPT_X_TLS_CRLFILE */
      log_log(LOG_ERR, "%s:%d: option %s not supported on platform",
              filename, lnr, keyword);
      exit(EXIT_FAILURE);
#endif /* LDAP_OPT_X_TLS_CRLFILE */
    }
#endif /* LDAP_OPT_X_TLS */
    /* other options */
    else if (strcasecmp(keyword, "pagesize") == 0)
    {
      cfg->pagesize = get_int(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "nss_initgroups_ignoreusers") == 0)
    {
      handle_nss_initgroups_ignoreusers(filename, lnr, keyword, line,
                                                 cfg);
    }
    else if (strcasecmp(keyword, "nss_min_uid") == 0)
    {
      cfg->nss_min_uid = get_int(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "nss_uid_offset") == 0)
    {
      cfg->nss_uid_offset = get_int(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "nss_gid_offset") == 0)
    {
      cfg->nss_gid_offset = get_int(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "nss_nested_groups") == 0)
    {
      cfg->nss_nested_groups = get_boolean(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "nss_getgrent_skipmembers") == 0)
    {
      cfg->nss_getgrent_skipmembers = get_boolean(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "nss_disable_enumeration") == 0)
    {
      cfg->nss_disable_enumeration = get_boolean(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "validnames") == 0)
    {
      handle_validnames(filename, lnr, keyword, line, cfg);
    }
    else if (strcasecmp(keyword, "ignorecase") == 0)
    {
      cfg->ignorecase = get_boolean(filename, lnr, keyword, &line);
      get_eol(filename, lnr, keyword, &line);
    }
    else if (strcasecmp(keyword, "pam_authc_search") == 0)
    {
      handle_pam_authc_search(filename, lnr, keyword, line, cfg);
    }
    else if (strcasecmp(keyword, "pam_authz_search") == 0)
    {
      handle_pam_authz_search(filename, lnr, keyword, line, cfg);
    }
    else if (strcasecmp(keyword, "pam_password_prohibit_message") == 0)
    {
      handle_pam_password_prohibit_message(filename, lnr, keyword, line, cfg);
    }
    else if (strcasecmp(keyword, "reconnect_invalidate") == 0)
    {
      handle_reconnect_invalidate(filename, lnr, keyword, line, cfg);
    }
    else if (strcasecmp(keyword, "cache") == 0)
    {
      handle_cache(filename, lnr, keyword, line, cfg);
    }
#ifdef ENABLE_CONFIGFILE_CHECKING
    /* fallthrough */
    else
    {
      log_log(LOG_ERR, "%s:%d: unknown keyword: '%s'", filename, lnr, keyword);
      exit(EXIT_FAILURE);
    }
#endif
  }
  /* we're done reading file, close */
  fclose(fp);
}

#ifdef NSLCD_BINDPW_PATH
static void bindpw_read(const char *filename, struct ldap_config *cfg)
{
  FILE *fp;
  char linebuf[MAX_LINE_LENGTH];
  int i;
  /* open config file */
  errno = 0;
  if ((fp = fopen(filename, "r")) == NULL)
  {
    if (errno == ENOENT)
    {
      log_log(LOG_DEBUG, "no bindpw file (%s)", filename);
      return; /* ignore */
    }
    else
    {
      log_log(LOG_ERR, "cannot open bindpw file (%s): %s",
              filename, strerror(errno));
      exit(EXIT_FAILURE);
    }
  }
  /* check permissions */
  check_permissions(filename, NULL);
  /* read the first line */
  if (fgets(linebuf, sizeof(linebuf), fp) == NULL)
  {
    log_log(LOG_ERR, "%s: error reading first line", filename);
    exit(EXIT_FAILURE);
  }
  /* chop the last char off and save the rest as bindpw */
  i = (int)strlen(linebuf);
  if ((i <= 0) || (linebuf[i - 1] != '\n'))
  {
    log_log(LOG_ERR, "%s:1: line too long or missing newline", filename);
    exit(EXIT_FAILURE);
  }
  linebuf[i - 1] = '\0';
  if (strlen(linebuf) == 0)
  {
    log_log(LOG_ERR, "%s:1: the password is empty", filename);
    exit(EXIT_FAILURE);
  }
  cfg->bindpw = strdup(linebuf);
  /* check if there is no more data in the file */
  if (fgets(linebuf, sizeof(linebuf), fp) != NULL)
  {
    log_log(LOG_ERR, "%s:2: there is more than one line in the bindpw file",
            filename);
    exit(EXIT_FAILURE);
  }
  fclose(fp);
}
#endif /* NSLCD_BINDPW_PATH */

/* dump configuration */
static void cfg_dump(void)
{
  int i;
#ifdef LDAP_OPT_X_TLS
  int rc;
#endif /* LDAP_OPT_X_TLS */
  enum ldap_map_selector map;
  char *str;
  const char **strp;
  char buffer[1024];
  int *scopep;
  log_log(LOG_DEBUG, "CFG: threads %d", nslcd_cfg->threads);
  if (nslcd_cfg->uidname != NULL)
    log_log(LOG_DEBUG, "CFG: uid %s", nslcd_cfg->uidname);
  else if (nslcd_cfg->uid != NOUID)
    log_log(LOG_DEBUG, "CFG: uid %lu", (unsigned long int)nslcd_cfg->uid);
  else
    log_log(LOG_DEBUG, "CFG: # uid not set");
  if (nslcd_cfg->gid != NOGID)
    log_log(LOG_DEBUG, "CFG: gid %lu", (unsigned long int)nslcd_cfg->gid);
  else
    log_log(LOG_DEBUG, "CFG: # gid not set");
  log_log_config();
  for (i = 0; i < (NSS_LDAP_CONFIG_MAX_URIS + 1); i++)
    if (nslcd_cfg->uris[i].uri != NULL)
      log_log(LOG_DEBUG, "CFG: uri %s", nslcd_cfg->uris[i].uri);
  log_log(LOG_DEBUG, "CFG: ldap_version %d", nslcd_cfg->ldap_version);
  if (nslcd_cfg->binddn != NULL)
    log_log(LOG_DEBUG, "CFG: binddn %s", nslcd_cfg->binddn);
  if (nslcd_cfg->bindpw != NULL)
    log_log(LOG_DEBUG, "CFG: bindpw ***");
  if (nslcd_cfg->rootpwmoddn != NULL)
    log_log(LOG_DEBUG, "CFG: rootpwmoddn %s", nslcd_cfg->rootpwmoddn);
  if (nslcd_cfg->rootpwmodpw != NULL)
    log_log(LOG_DEBUG, "CFG: rootpwmodpw ***");
  if (nslcd_cfg->sasl_mech != NULL)
    log_log(LOG_DEBUG, "CFG: sasl_mech %s", nslcd_cfg->sasl_mech);
  if (nslcd_cfg->sasl_realm != NULL)
    log_log(LOG_DEBUG, "CFG: sasl_realm %s", nslcd_cfg->sasl_realm);
  if (nslcd_cfg->sasl_authcid != NULL)
    log_log(LOG_DEBUG, "CFG: sasl_authcid %s", nslcd_cfg->sasl_authcid);
  if (nslcd_cfg->sasl_authzid != NULL)
    log_log(LOG_DEBUG, "CFG: sasl_authzid %s", nslcd_cfg->sasl_authzid);
  if (nslcd_cfg->sasl_secprops != NULL)
    log_log(LOG_DEBUG, "CFG: sasl_secprops %s", nslcd_cfg->sasl_secprops);
#ifdef LDAP_OPT_X_SASL_NOCANON
  if (nslcd_cfg->sasl_canonicalize >= 0)
    log_log(LOG_DEBUG, "CFG: sasl_canonicalize %s", print_boolean(nslcd_cfg->sasl_canonicalize));
#endif /* LDAP_OPT_X_SASL_NOCANON */
  str = getenv("KRB5CCNAME");
  if (str != NULL)
    log_log(LOG_DEBUG, "CFG: krb5_ccname %s", str);
  for (i = 0; i < NSS_LDAP_CONFIG_MAX_BASES; i++)
    if (nslcd_cfg->bases[i] != NULL)
      log_log(LOG_DEBUG, "CFG: base %s", nslcd_cfg->bases[i][0] == '\0' ? "\"\"" : nslcd_cfg->bases[i]);
  for (map = LM_ALIASES; map < LM_NONE; map++)
  {
    strp = base_get_var(map);
    if (strp != NULL)
      for (i = 0; i < NSS_LDAP_CONFIG_MAX_BASES; i++)
        if (strp[i] != NULL)
          log_log(LOG_DEBUG, "CFG: base %s %s", print_map(map), strp[i][0] == '\0' ? "\"\"" : strp[i]);
  }
  log_log(LOG_DEBUG, "CFG: scope %s", print_scope(nslcd_cfg->scope));
  for (map = LM_ALIASES; map < LM_NONE; map++)
  {
    scopep = scope_get_var(map);
    if ((scopep != NULL) && (*scopep != LDAP_SCOPE_DEFAULT))
      log_log(LOG_DEBUG, "CFG: scope %s %s", print_map(map), print_scope(*scopep));
  }
  log_log(LOG_DEBUG, "CFG: deref %s", print_deref(nslcd_cfg->deref));
  log_log(LOG_DEBUG, "CFG: referrals %s", print_boolean(nslcd_cfg->referrals));
  for (map = LM_ALIASES; map < LM_NONE; map++)
  {
    strp = filter_get_var(map);
    if ((strp != NULL) && (*strp != NULL))
      log_log(LOG_DEBUG, "CFG: filter %s %s", print_map(map), *strp);
  }
#define LOG_ATTMAP(map, mapl, att)                                          \
  if (strcmp(attmap_##mapl##_##att, __STRING(att)) != 0)                    \
    log_log(LOG_DEBUG, "CFG: map %s %s %s",                                 \
            print_map(map), __STRING(att), attmap_##mapl##_##att);
  LOG_ATTMAP(LM_ALIASES, alias, cn);
  LOG_ATTMAP(LM_ALIASES, alias, rfc822MailMember);
  LOG_ATTMAP(LM_ETHERS, ether, cn);
  LOG_ATTMAP(LM_ETHERS, ether, macAddress);
  LOG_ATTMAP(LM_GROUP, group, cn);
  LOG_ATTMAP(LM_GROUP, group, userPassword);
  LOG_ATTMAP(LM_GROUP, group, gidNumber);
  LOG_ATTMAP(LM_GROUP, group, memberUid);
  LOG_ATTMAP(LM_GROUP, group, member);
  LOG_ATTMAP(LM_HOSTS, host, cn);
  LOG_ATTMAP(LM_HOSTS, host, ipHostNumber);
  LOG_ATTMAP(LM_NETGROUP, netgroup, cn);
  LOG_ATTMAP(LM_NETGROUP, netgroup, nisNetgroupTriple);
  LOG_ATTMAP(LM_NETGROUP, netgroup, memberNisNetgroup);
  LOG_ATTMAP(LM_NETWORKS, network, cn);
  LOG_ATTMAP(LM_NETWORKS, network, ipNetworkNumber);
  LOG_ATTMAP(LM_PASSWD, passwd, uid);
  LOG_ATTMAP(LM_PASSWD, passwd, userPassword);
  LOG_ATTMAP(LM_PASSWD, passwd, uidNumber);
  LOG_ATTMAP(LM_PASSWD, passwd, gidNumber);
  LOG_ATTMAP(LM_PASSWD, passwd, gecos);
  LOG_ATTMAP(LM_PASSWD, passwd, homeDirectory);
  LOG_ATTMAP(LM_PASSWD, passwd, loginShell);
  LOG_ATTMAP(LM_PASSWD, passwd, class);
  LOG_ATTMAP(LM_PROTOCOLS, protocol, cn);
  LOG_ATTMAP(LM_PROTOCOLS, protocol, ipProtocolNumber);
  LOG_ATTMAP(LM_RPC, rpc, cn);
  LOG_ATTMAP(LM_RPC, rpc, oncRpcNumber);
  LOG_ATTMAP(LM_SERVICES, service, cn);
  LOG_ATTMAP(LM_SERVICES, service, ipServicePort);
  LOG_ATTMAP(LM_SERVICES, service, ipServiceProtocol);
  LOG_ATTMAP(LM_SHADOW, shadow, uid);
  LOG_ATTMAP(LM_SHADOW, shadow, userPassword);
  LOG_ATTMAP(LM_SHADOW, shadow, shadowLastChange);
  LOG_ATTMAP(LM_SHADOW, shadow, shadowMin);
  LOG_ATTMAP(LM_SHADOW, shadow, shadowMax);
  LOG_ATTMAP(LM_SHADOW, shadow, shadowWarning);
  LOG_ATTMAP(LM_SHADOW, shadow, shadowInactive);
  LOG_ATTMAP(LM_SHADOW, shadow, shadowExpire);
  LOG_ATTMAP(LM_SHADOW, shadow, shadowFlag);
#if defined(HAVE_LDAP_SASL_BIND) && defined(LDAP_SASL_SIMPLE)
  log_log(LOG_DEBUG, "CFG: pam_authc_ppolicy %s", print_boolean(nslcd_cfg->pam_authc_ppolicy));
#endif
  log_log(LOG_DEBUG, "CFG: bind_timelimit %d", nslcd_cfg->bind_timelimit);
  log_log(LOG_DEBUG, "CFG: timelimit %d", nslcd_cfg->timelimit);
  log_log(LOG_DEBUG, "CFG: idle_timelimit %d", nslcd_cfg->idle_timelimit);
  log_log(LOG_DEBUG, "CFG: reconnect_sleeptime %d", nslcd_cfg->reconnect_sleeptime);
  log_log(LOG_DEBUG, "CFG: reconnect_retrytime %d", nslcd_cfg->reconnect_retrytime);
#ifdef LDAP_OPT_X_TLS
  log_log(LOG_DEBUG, "CFG: ssl %s", print_ssl(nslcd_cfg->ssl));
  rc = ldap_get_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &i);
  if (rc != LDAP_SUCCESS)
    log_log(LOG_DEBUG, "CFG: # tls_reqcert ERROR: %s", ldap_err2string(rc));
  else
    log_log(LOG_DEBUG, "CFG: tls_reqcert %s", print_tls_reqcert(i));
  #define LOG_LDAP_OPT_STRING(cfg, option)                                  \
    str = NULL;                                                             \
    rc = ldap_get_option(NULL, option, &str);                               \
    if (rc != LDAP_SUCCESS)                                                 \
      log_log(LOG_DEBUG, "CFG: # %s ERROR: %s", cfg, ldap_err2string(rc));  \
    else if ((str != NULL) && (*str != '\0'))                               \
      log_log(LOG_DEBUG, "CFG: %s %s", cfg, str);                           \
    if (str != NULL)                                                        \
      ldap_memfree(str);
  LOG_LDAP_OPT_STRING("tls_cacertdir", LDAP_OPT_X_TLS_CACERTDIR);
  LOG_LDAP_OPT_STRING("tls_cacertfile", LDAP_OPT_X_TLS_CACERTFILE);
  LOG_LDAP_OPT_STRING("tls_randfile", LDAP_OPT_X_TLS_RANDOM_FILE);
  LOG_LDAP_OPT_STRING("tls_ciphers", LDAP_OPT_X_TLS_CIPHER_SUITE);
  LOG_LDAP_OPT_STRING("tls_cert", LDAP_OPT_X_TLS_CERTFILE);
  LOG_LDAP_OPT_STRING("tls_key", LDAP_OPT_X_TLS_KEYFILE);
#ifdef LDAP_OPT_X_TLS_REQUIRE_SAN
  rc = ldap_get_option(NULL, LDAP_OPT_X_TLS_REQUIRE_SAN, &i);
  if (rc != LDAP_SUCCESS)
    log_log(LOG_DEBUG, "CFG: # tls_reqsan ERROR: %s", ldap_err2string(rc));
  else
    log_log(LOG_DEBUG, "CFG: tls_reqsan %s", print_tls_reqcert(i));
#endif /* LDAP_OPT_X_TLS_REQUIRE_SAN */
#ifdef LDAP_OPT_X_TLS_CRLCHECK
  rc = ldap_get_option(NULL, LDAP_OPT_X_TLS_CRLCHECK, &i);
  if (rc != LDAP_SUCCESS)
    log_log(LOG_DEBUG, "CFG: # tls_crlcheck ERROR: %s", ldap_err2string(rc));
  else
    log_log(LOG_DEBUG, "CFG: tls_crlcheck %s", print_tls_crlcheck(i));
#endif /* LDAP_OPT_X_TLS_CRLCHECK */
#endif /* LDAP_OPT_X_TLS */
  log_log(LOG_DEBUG, "CFG: pagesize %d", nslcd_cfg->pagesize);
  if (nslcd_cfg->nss_initgroups_ignoreusers != NULL)
  {
    /* allocate memory for a comma-separated list */
    strp = set_tolist(nslcd_cfg->nss_initgroups_ignoreusers);
    if (strp == NULL)
    {
      log_log(LOG_CRIT, "malloc() failed to allocate memory");
      exit(EXIT_FAILURE);
    }
    /* turn the set into a comma-separated list */
    buffer[0] = '\0';
    for (i = 0; strp[i] != NULL; i++)
    {
      if (i > 0)
        strncat(buffer, ",", sizeof(buffer) - 1 - strlen(buffer));
      strncat(buffer, strp[i], sizeof(buffer) - 1 - strlen(buffer));
    }
    free(strp);
    if (strlen(buffer) >= (sizeof(buffer) - 4))
      strcpy(buffer + sizeof(buffer) - 4, "...");
    log_log(LOG_DEBUG, "CFG: nss_initgroups_ignoreusers %s", buffer);
  }
  log_log(LOG_DEBUG, "CFG: nss_min_uid %lu", (unsigned long int)nslcd_cfg->nss_min_uid);
  log_log(LOG_DEBUG, "CFG: nss_uid_offset %lu", (unsigned long int)nslcd_cfg->nss_uid_offset);
  log_log(LOG_DEBUG, "CFG: nss_gid_offset %lu", (unsigned long int)nslcd_cfg->nss_gid_offset);
  log_log(LOG_DEBUG, "CFG: nss_nested_groups %s", print_boolean(nslcd_cfg->nss_nested_groups));
  log_log(LOG_DEBUG, "CFG: nss_getgrent_skipmembers %s", print_boolean(nslcd_cfg->nss_getgrent_skipmembers));
  log_log(LOG_DEBUG, "CFG: nss_disable_enumeration %s", print_boolean(nslcd_cfg->nss_disable_enumeration));
  log_log(LOG_DEBUG, "CFG: validnames %s", nslcd_cfg->validnames_str);
  log_log(LOG_DEBUG, "CFG: ignorecase %s", print_boolean(nslcd_cfg->ignorecase));
  log_log(LOG_DEBUG, "CFG: pam_authc_search %s", nslcd_cfg->pam_authc_search);
  for (i = 0; i < NSS_LDAP_CONFIG_MAX_AUTHZ_SEARCHES; i++)
    if (nslcd_cfg->pam_authz_searches[i] != NULL)
      log_log(LOG_DEBUG, "CFG: pam_authz_search %s", nslcd_cfg->pam_authz_searches[i]);
  if (nslcd_cfg->pam_password_prohibit_message != NULL)
    log_log(LOG_DEBUG, "CFG: pam_password_prohibit_message \"%s\"", nslcd_cfg->pam_password_prohibit_message);
  /* build a comma-separated list */
  buffer[0] = '\0';
  for (i = 0; i < LM_NONE ; i++)
    if (nslcd_cfg->reconnect_invalidate[i])
    {
      if (buffer[0] != '\0')
        strncat(buffer, ",", sizeof(buffer) - 1 - strlen(buffer));
      strncat(buffer, print_map(i), sizeof(buffer) - 1 - strlen(buffer));
    }
  if (buffer[0] != '\0')
    log_log(LOG_DEBUG, "CFG: reconnect_invalidate %s", buffer);
  print_time(nslcd_cfg->cache_dn2uid_positive, buffer, sizeof(buffer) / 2);
  print_time(nslcd_cfg->cache_dn2uid_positive, buffer + (sizeof(buffer) / 2), sizeof(buffer) / 2);
  log_log(LOG_DEBUG, "CFG: cache dn2uid %s %s", buffer, buffer + (sizeof(buffer) / 2));
}

void cfg_init(const char *fname)
{
#ifdef LDAP_OPT_X_TLS
  int i;
#endif /* LDAP_OPT_X_TLS */
  /* check if we were called before */
  if (nslcd_cfg != NULL)
  {
    log_log(LOG_CRIT, "cfg_init() may only be called once");
    exit(EXIT_FAILURE);
  }
  /* allocate the memory (this memory is not freed anywhere) */
  nslcd_cfg = (struct ldap_config *)malloc(sizeof(struct ldap_config));
  if (nslcd_cfg == NULL)
  {
    log_log(LOG_CRIT, "malloc() failed to allocate memory");
    exit(EXIT_FAILURE);
  }
  /* clear configuration */
  cfg_defaults(nslcd_cfg);
  /* read configfile */
  cfg_read(fname, nslcd_cfg);
#ifdef NSLCD_BINDPW_PATH
  bindpw_read(NSLCD_BINDPW_PATH, nslcd_cfg);
#endif /* NSLCD_BINDPW_PATH */
  /* do some sanity checks */
  if (nslcd_cfg->uris[0].uri == NULL)
  {
    log_log(LOG_ERR, "no URIs defined in config");
    exit(EXIT_FAILURE);
  }
  /* if ssl is on each URI should start with ldaps */
#ifdef LDAP_OPT_X_TLS
  if (nslcd_cfg->ssl == SSL_LDAPS)
  {
    for (i = 0; nslcd_cfg->uris[i].uri != NULL; i++)
    {
      if (strncasecmp(nslcd_cfg->uris[i].uri, "ldaps://", 8) != 0)
        log_log(LOG_WARNING, "%s doesn't start with ldaps:// and \"ssl on\" is specified",
                nslcd_cfg->uris[i].uri);
    }
  }
  /* TODO: check that if some tls options are set the ssl option should be set to on (just warn) */
#endif /* LDAP_OPT_X_TLS */
  /* if basedn is not yet set,  get if from the rootDSE */
  if (nslcd_cfg->bases[0] == NULL)
    nslcd_cfg->bases[0] = get_base_from_rootdse();
  /* TODO: handle the case gracefully when no LDAP server is available yet */
  /* dump configuration */
  cfg_dump();
  /* initialise all database modules */
  alias_init();
  ether_init();
  group_init();
  host_init();
  netgroup_init();
  network_init();
  passwd_init();
  protocol_init();
  rpc_init();
  service_init();
  shadow_init();
}
