/*
   cfg.c - functions for configuration information
   This file contains parts that were part of the nss_ldap
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#ifdef HAVE_GSSAPI_GSSAPI_KRB5_H
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#endif /* HAVE_GSSAPI_GSSAPI_KRB5_H */

#include "common.h"
#include "log.h"
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
#define LDAP_NSS_SLEEPTIME       1      /* seconds to sleep; doubled until max */
#define LDAP_NSS_MAXSLEEPTIME    32     /* maximum seconds to sleep */
#define LDAP_NSS_MAXCONNTRIES    2      /* reconnect attempts before sleeping */

/* the maximum line length in the configuration file */
#define MAX_LINE_LENGTH          4096

/* the maximum number of keywords/options on the line */
#define MAX_LINE_OPTIONS         10

/* clear the configuration information back to the defaults */
static void cfg_defaults(struct ldap_config *cfg)
{
  int i;
  memset(cfg,0,sizeof(struct ldap_config));
  for (i=0;i<(NSS_LDAP_CONFIG_URI_MAX+1);i++)
    cfg->ldc_uris[i]=NULL;
#ifdef LDAP_VERSION3
  cfg->ldc_version=LDAP_VERSION3;
#else /* LDAP_VERSION3 */
  cfg->ldc_version=LDAP_VERSION2;
#endif /* not LDAP_VERSION3 */
  cfg->ldc_binddn=NULL;
  cfg->ldc_bindpw=NULL;
  cfg->ldc_rootbinddn=NULL;
  cfg->ldc_rootbindpw=NULL;
  cfg->ldc_saslid=NULL;
  cfg->ldc_rootsaslid=NULL;
  cfg->ldc_sasl_secprops=NULL;
  cfg->ldc_usesasl=0;
  cfg->ldc_rootusesasl=0;
  cfg->ldc_base=NULL;
  cfg->ldc_scope=LDAP_SCOPE_SUBTREE;
  cfg->ldc_deref=LDAP_DEREF_NEVER;
  cfg->ldc_referrals=1;
  cfg->ldc_timelimit=LDAP_NO_LIMIT;
  cfg->ldc_bind_timelimit=30;
  cfg->ldc_reconnect_pol=LP_RECONNECT_HARD_OPEN;
  cfg->ldc_flags=0;
  cfg->ldc_idle_timelimit=0;
  cfg->ldc_ssl_on=SSL_OFF;
  cfg->ldc_sslpath=NULL;
  cfg->ldc_tls_checkpeer=-1;
  cfg->ldc_tls_cacertdir=NULL;
  cfg->ldc_tls_cacertfile=NULL;
  cfg->ldc_tls_randfile=NULL;
  cfg->ldc_tls_ciphers=NULL;
  cfg->ldc_tls_cert=NULL;
  cfg->ldc_tls_key=NULL;
  cfg->ldc_restart=1;
  cfg->ldc_pagesize=0;
  cfg->ldc_reconnect_tries=LDAP_NSS_TRIES;
  cfg->ldc_reconnect_sleeptime=LDAP_NSS_SLEEPTIME;
  cfg->ldc_reconnect_maxsleeptime=LDAP_NSS_MAXSLEEPTIME;
  cfg->ldc_debug=0;
  cfg->ldc_password_type=LU_RFC2307_USERPASSWORD;
  cfg->ldc_shadow_type=LS_RFC2307_SHADOW;
}

/* simple strdup wrapper */
static char *xstrdup(const char *s)
{
  char *tmp;
  if (s==NULL)
  {
    log_log(LOG_CRIT,"xstrdup() called with NULL");
    exit(EXIT_FAILURE);
  }
  tmp=strdup(s);
  if (tmp==NULL)
  {
    log_log(LOG_CRIT,"strdup() failed to allocate memory");
    exit(EXIT_FAILURE);
  }
  return tmp;
}

/* add a single URI to the list of URIs in the configuration */
static void add_uri(const char *filename,int lnr,
                    struct ldap_config *cfg,const char *uri)
{
  int i;
  log_log(LOG_DEBUG,"add_uri(%s)",uri);
  /* find the place where to insert the URI */
  for (i=0;cfg->ldc_uris[i]!=NULL;i++)
    ;
  /* check for room */
  if (i>=NSS_LDAP_CONFIG_URI_MAX)
  {
    log_log(LOG_ERR,"%s:%d: maximum number of URIs exceeded",filename,lnr);
    exit(EXIT_FAILURE);
  }
  /* append URI to list */
  cfg->ldc_uris[i]=xstrdup(uri);
  cfg->ldc_uris[i+1]=NULL;
}

/* return the domain name of the current host
   we return part of the structure that is retured by gethostbyname()
   so there should be no need to free() this entry, however we should
   use the value before any other call to gethostbyname() */
static const char *cfg_getdomainname(const char *filename,int lnr)
{
  char hostname[HOST_NAME_MAX],*domain;
  struct hostent *host;
  /* lookup the hostname and with that the fqdn to extract the domain */
  if (gethostname(hostname,sizeof(hostname))<0)
  {
    log_log(LOG_ERR,"%s:%d: gethostname(): %s",filename,lnr,strerror(errno));
    exit(EXIT_FAILURE);
  }
  if ((host=gethostbyname(hostname))==NULL)
  {
    log_log(LOG_ERR,"%s:%d: gethostbyname(%s): %s",filename,lnr,hostname,hstrerror(h_errno));
    exit(EXIT_FAILURE);
  }
  /* TODO: this may fail if the fqdn is in h_aliases */
  if ((domain=strchr(host->h_name,'.'))==NULL)
  {
    log_log(LOG_ERR,"%s:%d: host name %s is not in fqdn form",filename,lnr,host->h_name);
    exit(EXIT_FAILURE);
  }
  /* we're done */
  return domain+1;
}

/* add URIs by doing DNS queries for SRV records */
static void add_uris_from_dns(const char *filename,int lnr,
                        struct ldap_config *cfg)
{
  int ret=0;
  const char *domain;
  char *hostlist=NULL,*nxt;
  char buf[HOST_NAME_MAX+sizeof("ldap://")];
  domain=cfg_getdomainname(filename,lnr);
  ret=ldap_domain2hostlist(domain,&hostlist);
  /* FIXME: have better error handling */
  if ((hostlist==NULL)||(*hostlist=='\0'))
  {
    log_log(LOG_ERR,"%s:%d: no servers found in DNS zone %s",filename,lnr,domain);
    exit(EXIT_FAILURE);
  }
  /* hostlist is a space-separated list of host names that we use to build
     URIs */
  while(hostlist!=NULL)
  {
    /* find the next space and split the string there */
    nxt=strchr(hostlist,' ');
    if (nxt!=NULL)
    {
      *nxt='\0';
      nxt++;
    }
    /* add the URI */
    mysnprintf(buf,sizeof(buf),"ldap://%s",hostlist);
    log_log(LOG_DEBUG,"add_uris_from_dns(): found uri: %s",buf);
    add_uri(filename,lnr,cfg,buf);
    /* get next entry from list */
    hostlist=nxt;
  }
}

static int parse_boolean(const char *filename,int lnr,const char *value)
{
  if ( (strcasecmp(value,"on")==0) ||
       (strcasecmp(value,"yes")==0) ||
       (strcasecmp(value,"true")==0) ||
       (strcasecmp(value,"1")==0) )
    return 1;
  else if ( (strcasecmp(value,"off")==0) ||
            (strcasecmp(value,"no")==0) ||
            (strcasecmp(value,"false")==0) ||
            (strcasecmp(value,"0")==0) )
    return 0;
  else
  {
    log_log(LOG_ERR,"%s:%d: not a boolean argument: '%s'",filename,lnr,value);
    exit(EXIT_FAILURE);
  }
}

static int parse_scope(const char *filename,int lnr,const char *value)
{
  if ( (strcasecmp(value,"sub")==0) || (strcasecmp(value,"subtree")==0) )
    return LDAP_SCOPE_SUBTREE;
  else if ( (strcasecmp(value,"one")==0) || (strcasecmp(value,"onelevel")==0) )
    return LDAP_SCOPE_ONELEVEL;
  else if (strcasecmp(value,"base")==0)
    return LDAP_SCOPE_BASE;
  else
  {
    log_log(LOG_ERR,"%s:%d: not a scope argument: '%s'",filename,lnr,value);
    exit(EXIT_FAILURE);
  }
}

static enum ldap_map_selector parse_map(const char *filename,int lnr,const char *value)
{
  if ( (strcasecmp(value,"alias")==0) || (strcasecmp(value,"aliases")==0) )
    return LM_ALIASES;
  else if ( (strcasecmp(value,"ether")==0) || (strcasecmp(value,"ethers")==0) )
    return LM_ETHERS;
  else if (strcasecmp(value,"group")==0)
    return LM_GROUP;
  else if ( (strcasecmp(value,"host")==0) || (strcasecmp(value,"hosts")==0) )
    return LM_HOSTS;
  else if (strcasecmp(value,"netgroup")==0)
    return LM_NETGROUP;
  else if ( (strcasecmp(value,"network")==0) || (strcasecmp(value,"networks")==0) )
    return LM_NETWORKS;
  else if (strcasecmp(value,"passwd")==0)
    return LM_PASSWD;
  else if ( (strcasecmp(value,"protocol")==0) || (strcasecmp(value,"protocols")==0) )
    return LM_PROTOCOLS;
  else if (strcasecmp(value,"rpc")==0)
    return LM_RPC;
  else if ( (strcasecmp(value,"service")==0) || (strcasecmp(value,"services")==0) )
    return LM_SERVICES;
  else if (strcasecmp(value,"shadow")==0)
    return LM_SHADOW;
  else
  {
    log_log(LOG_ERR,"%s:%d: unknown mapping: '%s'",filename,lnr,value);
    exit(EXIT_FAILURE);
  }
}

/* check that the condition is true and otherwise log an error
   and bail out */
static inline void check_argumentcount(const char *filename,int lnr,
                                       const char *keyword,int condition)
{
  if (!condition)
  {
    log_log(LOG_ERR,"%s:%d: %s: wrong number of arguments",filename,lnr,keyword);
    exit(EXIT_FAILURE);
  }
}

static void parse_krb5_ccname_statement(const char *filename,int lnr,
                                        const char **opts,int nopts)
{
  const char *ccname;
  const char *ccfile;
  size_t ccenvlen;
  char *ccenv;
  OM_uint32 minor_status;
  /* set default kerberos ticket cache for SASL-GSSAPI */
  log_log(LOG_WARNING,"%s:%d: option %s is currently untested (please report any successes)",filename,lnr,opts[0]);
  check_argumentcount(filename,lnr,opts[0],nopts==2);
  ccname=opts[1];
  /* check that cache exists and is readable if it is a file */
  if ( (strncasecmp(ccname,"FILE:",sizeof("FILE:")-1)==0) ||
       (strncasecmp(ccname,"WRFILE:",sizeof("WRFILE:")-1)==0))
  {
    ccfile=strchr(ccname,':')+1;
    if (access(ccfile,R_OK)!=0)
    {
      log_log(LOG_ERR,"%s:%d: error accessing %s: %s",filename,lnr,ccfile,strerror(errno));
      exit(EXIT_FAILURE);
    }
  }
  /* set the environment variable (we have a memory leak if this option
     is set multiple times) */
  ccenvlen=strlen(ccname)+sizeof("KRB5CCNAME=");
  ccenv=(char *)malloc(ccenvlen);
  if (ccenv==NULL)
  {
    log_log(LOG_CRIT,"malloc() failed to allocate memory");
    exit(EXIT_FAILURE);
  }
  mysnprintf(ccenv,ccenvlen,"KRB5CCNAME=%s",ccname);
  putenv(ccenv);
#ifdef HAVE_GSS_KRB5_CCACHE_NAME
  /* set the name with gss_krb5_ccache_name() */
  if (gss_krb5_ccache_name(&minor_status,ccname,NULL)!=GSS_S_COMPLETE)
  {
    log_log(LOG_ERR,"%s:%d: unable to set default credential cache: %s",filename,lnr,ccname);
    exit(EXIT_FAILURE);
  }
# endif /* HAVE_GSS_KRB5_CCACHE_NAME */
}

/* assigns the base to the specified variable doing domain expansion
   and a simple check to avoid overwriting duplicate values */
static void set_base(const char *filename,int lnr,
                     const char *value,const char **var)
{
  char *domaindn=NULL;
  /* if the base is "DOMAIN" use the domain name */
  if (strcasecmp(value,"domain")==0)
  {
    ldap_domain2dn(cfg_getdomainname(filename,lnr),&domaindn);
    log_log(LOG_DEBUG,"set_base(): setting base to %s from domain",domaindn);
    value=domaindn;
  }
  /* check if the value will be changed */
  if ((*var==NULL)||(strcmp(*var,value)!=0))
  {
    /* Note: we have a memory leak here if a single mapping is changed
             multiple times in one config (deemed not a problem) */
    *var=xstrdup(value);
  }
}

static void parse_base_statement(const char *filename,int lnr,
                                 const char **opts,int nopts,
                                 struct ldap_config *cfg)
{
  enum ldap_map_selector map;
  const char **var;
  if (nopts==2)
    set_base(filename,lnr,opts[1],(const char **)&(cfg->ldc_base));
  else if (nopts==3)
  {
    /* get the map */
    map=parse_map(filename,lnr,opts[1]);
    /* get the base variable to set */
    var=base_get_var(map);
    if (var==NULL)
    {
      log_log(LOG_ERR,"%s:%d: unknown map: '%s'",filename,lnr,opts[1]);
      exit(EXIT_FAILURE);
    }
    set_base(filename,lnr,opts[2],var);
  }
  else
    check_argumentcount(filename,lnr,opts[0],0);
}

static void parse_scope_statement(const char *filename,int lnr,
                                  const char **opts,int nopts,
                                  struct ldap_config *cfg)
{
  enum ldap_map_selector map;
  int *var;
  if (nopts==2)
    cfg->ldc_scope=parse_scope(filename,lnr,opts[1]);
  else if (nopts==3)
  {
    /* get the map */
    map=parse_map(filename,lnr,opts[1]);
    /* get the scope variable to set */
    var=scope_get_var(map);
    if (var==NULL)
    {
      log_log(LOG_ERR,"%s:%d: unknown map: '%s'",filename,lnr,opts[1]);
      exit(EXIT_FAILURE);
    }
    /* set the scope */
    *var=parse_scope(filename,lnr,opts[2]);
  }
  else
    check_argumentcount(filename,lnr,opts[0],0);
}

static void parse_filter_statement(const char *filename,int lnr,
                                   const char **opts,int nopts)
{
  enum ldap_map_selector map;
  const char **var;
  check_argumentcount(filename,lnr,opts[0],nopts==3);
  /* get the map */
  map=parse_map(filename,lnr,opts[1]);
  /* get the filter variable to set */
  var=filter_get_var(map);
  if (var==NULL)
  {
    log_log(LOG_ERR,"%s:%d: unknown map: '%s'",filename,lnr,opts[1]);
    exit(EXIT_FAILURE);
  }
  /* check if the value will be changed */
  if (strcmp(*var,opts[2])!=0)
  {
    /* Note: we have a memory leak here if a single mapping is changed
             multiple times in one config (deemed not a problem) */
    *var=xstrdup(opts[2]);
  }
}

/* this function modifies the statement argument passed */
static void parse_map_statement(const char *filename,int lnr,
                                const char **opts,int nopts,
                                struct ldap_config *cfg)
{
  enum ldap_map_selector map;
  const char **var;
  check_argumentcount(filename,lnr,opts[0],nopts==4);
  /* get the map */
  map=parse_map(filename,lnr,opts[1]);
  /* special handling for some attribute mappings */
  /* TODO: move this stuff to passwd.c or shadow.c or wherever it's used */
  if ((map==LM_PASSWD)&&(strcasecmp(opts[2],"userPassword")==0))
  {
    if (strcasecmp(opts[3],"userPassword")==0)
      cfg->ldc_password_type=LU_RFC2307_USERPASSWORD;
    else if (strcasecmp(opts[3],"authPassword")==0)
      cfg->ldc_password_type=LU_RFC3112_AUTHPASSWORD;
    else
      cfg->ldc_password_type=LU_OTHER_PASSWORD;
  }
  else if ((map==LM_SHADOW)&&(strcasecmp(opts[2],"shadowLastChange")==0))
  {
    if (strcasecmp(opts[3],"shadowLastChange")==0)
      cfg->ldc_shadow_type=LS_RFC2307_SHADOW;
    else if (strcasecmp(opts[3],"pwdLastSet")==0)
      cfg->ldc_shadow_type=LS_AD_SHADOW;
  }
  /* get the attribute variable to set */
  var=attmap_get_var(map,opts[2]);
  if (var==NULL)
  {
    log_log(LOG_ERR,"%s:%d: unknown attribute to map: '%s'",filename,lnr,opts[2]);
    exit(EXIT_FAILURE);
  }
  /* check if the value will be changed */
  if (strcmp(*var,opts[3])!=0)
  {
    /* Note: we have a memory leak here if a single mapping is changed
             multiple times in one config (deemed not a problem) */
    *var=xstrdup(opts[3]);
  }
}

/* split a line from the configuration file
   note that this code is not thread safe since a pointer to the same
   storage will be returned with each call
   the line string is modified */
static const char **tokenize(const char *filename,int lnr,char *line,int *nopt)
{
  static const char *retv[MAX_LINE_OPTIONS];
  int opt;
  for (opt=0;opt<MAX_LINE_OPTIONS;opt++)
  {
    /* skip beginning spaces */
    while ((*line==' ')||(*line=='\t'))
      line++;
    /* check for end of line or comment */
    if ((*line=='\0')||(*line=='#'))
      break; /* we're done */
    /* we have a new keyword */
    retv[opt]=line;
    if (*line=='"')
    {
      line++;
      /* find end quote */
      while ((*line!='"')&&(*line!='\0'))
        line++;
      if (*line!='"')
      {
        log_log(LOG_ERR,"%s:%d: quoted value not terminated",filename,lnr);
        exit(EXIT_FAILURE);
      }
      line++;
    }
    else
    {
      /* find the end of the token */
      while ((*line!=' ')&&(*line!='\t')&&(*line!='\0'))
        line++;
    }
    /* mark the end of the token */
    if (*line!='\0')
      *line++='\0';
  }
  *nopt=opt;
  return retv;
}

static void cfg_read(const char *filename,struct ldap_config *cfg)
{
  FILE *fp;
  int lnr=0;
  char line[MAX_LINE_LENGTH];
  int i;
  const char **opts;
  int nopts;

  /* open config file */
  if ((fp=fopen(filename,"r"))==NULL)
  {
    log_log(LOG_ERR,"cannot open config file (%s): %s",filename,strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* read file and parse lines */
  while (fgets(line,MAX_LINE_LENGTH,fp)!=NULL)
  {
    lnr++;
    /* strip newline */
    i=(int)strlen(line);
    if ((i<=0)||(line[i-1]!='\n'))
    {
      log_log(LOG_ERR,"%s:%d: line too long or last line missing newline",filename,lnr);
      exit(EXIT_FAILURE);
    }
    line[i-1]='\0';
    /* split the line in tokens */
    opts=tokenize(filename,lnr,line,&nopts);

    /* ignore empty lines */
    if (nopts==0)
      continue;

    /* TODO: replace atoi() calls with proper parser routine with checks */

    /* general connection options */
    if (strcasecmp(opts[0],"uri")==0)
    {
      check_argumentcount(filename,lnr,opts[0],nopts>1);
      for (i=1;i<nopts;i++)
      {
        if (strcasecmp(opts[i],"dns")==0)
          add_uris_from_dns(filename,lnr,cfg);
        else
          add_uri(filename,lnr,cfg,opts[i]);
      }
    }
    else if (strcasecmp(opts[0],"ldap_version")==0)
    {
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_version=atoi(opts[1]);
    }
    else if (strcasecmp(opts[0],"binddn")==0)
    {
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_binddn=xstrdup(opts[1]);
    }
    else if (strcasecmp(opts[0],"bindpw")==0)
    {
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_bindpw=xstrdup(opts[1]);
    }
    else if (strcasecmp(opts[0],"rootbinddn")==0)
    {
      log_log(LOG_ERR,"%s:%d: option %s is currently unsupported",filename,lnr,opts[0]);
      exit(EXIT_FAILURE);
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_rootbinddn=xstrdup(opts[1]);
    }
    else if (strcasecmp(opts[0],"rootbindpw")==0)
    {
      log_log(LOG_ERR,"%s:%d: option %s is currently unsupported",filename,lnr,opts[0]);
      exit(EXIT_FAILURE);
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_rootbindpw=xstrdup(opts[1]);
    }
    /* SASL authentication options */
    else if (strcasecmp(opts[0], "sasl_authid")==0)
    {
      log_log(LOG_WARNING,"%s:%d: option %s is currently untested (please report any successes)",filename,lnr,opts[0]);
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_saslid=xstrdup(opts[1]);
    }
    else if (strcasecmp(opts[0],"rootsasl_authid")==0)
    {
      log_log(LOG_ERR,"%s:%d: option %s is currently unsupported",filename,lnr,opts[0]);
      exit(EXIT_FAILURE);
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_rootsaslid=xstrdup(opts[1]);
    }
    else if (strcasecmp(opts[0],"sasl_secprops")==0)
    {
      log_log(LOG_WARNING,"%s:%d: option %s is currently untested (please report any successes)",filename,lnr,opts[0]);
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_sasl_secprops=xstrdup(opts[1]);
    }
    else if (strcasecmp(opts[0],"use_sasl")==0)
    {
      log_log(LOG_WARNING,"%s:%d: option %s is currently untested (please report any successes)",filename,lnr,opts[0]);
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_usesasl=parse_boolean(filename,lnr,opts[1]);
    }
    else if (strcasecmp(opts[0],"rootuse_sasl")==0)
    {
      log_log(LOG_ERR,"%s:%d: option %s is currently unsupported",filename,lnr,opts[0]);
      exit(EXIT_FAILURE);
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_rootusesasl=parse_boolean(filename,lnr,opts[1]);
    }
    /* Kerberos authentication options */
    else if (strcasecmp(opts[0],"krb5_ccname")==0)
    {
      parse_krb5_ccname_statement(filename,lnr,opts,nopts);
    }
    /* search/mapping options */
    else if (strcasecmp(opts[0],"base")==0)
    {
      parse_base_statement(filename,lnr,opts,nopts,cfg);
    }
    else if (strcasecmp(opts[0],"scope")==0)
    {
      parse_scope_statement(filename,lnr,opts,nopts,cfg);
    }
    else if (strcasecmp(opts[0],"deref")==0)
    {
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      if (strcasecmp(opts[1],"never")==0)
        cfg->ldc_deref=LDAP_DEREF_NEVER;
      else if (strcasecmp(opts[1],"searching")==0)
        cfg->ldc_deref=LDAP_DEREF_SEARCHING;
      else if (strcasecmp(opts[1],"finding")==0)
        cfg->ldc_deref=LDAP_DEREF_FINDING;
      else if (strcasecmp(opts[1],"always")==0)
        cfg->ldc_deref=LDAP_DEREF_ALWAYS;
      else
      {
        log_log(LOG_ERR,"%s:%d: wrong argument: '%s'",filename,lnr,opts[1]);
        exit(EXIT_FAILURE);
      }
    }
    else if (strcasecmp(opts[0],"referrals")==0)
    {
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_referrals=parse_boolean(filename,lnr,opts[1]);
    }
    else if (strcasecmp(opts[0],"filter")==0)
    {
      parse_filter_statement(filename,lnr,opts,nopts);
    }
    else if (strcasecmp(opts[0],"map")==0)
    {
      parse_map_statement(filename,lnr,opts,nopts,cfg);
    }
    /* timing/reconnect options */
    else if (strcasecmp(opts[0],"timelimit")==0)
    {
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_timelimit=atoi(opts[1]);
    }
    else if (strcasecmp(opts[0],"bind_timelimit")==0)
    {
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_bind_timelimit=atoi(opts[1]);
    }
    else if (strcasecmp(opts[0],"bind_policy")==0)
    {
      log_log(LOG_WARNING,"%s:%d: option %s is currently untested (and may be removed in an upcoming release)",filename,lnr,opts[0]);
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      if ( (strcasecmp(opts[1],"hard")==0) ||
           (strcasecmp(opts[1],"hard_open")==0) )
        cfg->ldc_reconnect_pol=LP_RECONNECT_HARD_OPEN;
      else if (strcasecmp(opts[1],"hard_init")==0)
        cfg->ldc_reconnect_pol=LP_RECONNECT_HARD_INIT;
      else if (strcasecmp(opts[1],"soft")==0)
        cfg->ldc_reconnect_pol=LP_RECONNECT_SOFT;
    }
    else if (strcasecmp(opts[0],"idle_timelimit")==0)
    {
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_idle_timelimit=atoi(opts[1]);
    }
    /* SSL/TLS options */
    else if (strcasecmp(opts[0],"ssl")==0)
    {
      log_log(LOG_WARNING,"%s:%d: option %s is currently untested (please report any successes)",filename,lnr,opts[0]);
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      if (strcasecmp(opts[1],"start_tls")==0)
        cfg->ldc_ssl_on=SSL_START_TLS;
      else if (parse_boolean(filename,lnr,opts[1]))
        cfg->ldc_ssl_on=SSL_LDAPS;
    }
    else if (strcasecmp(opts[0],"sslpath")==0)
    {
      log_log(LOG_WARNING,"%s:%d: option %s is currently untested (please report any successes)",filename,lnr,opts[0]);
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_sslpath=xstrdup(opts[1]);
    }
    else if (strcasecmp(opts[0],"tls_checkpeer")==0)
    {
      log_log(LOG_WARNING,"%s:%d: option %s is currently untested (please report any successes)",filename,lnr,opts[0]);
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_tls_checkpeer=parse_boolean(filename,lnr,opts[1]);
    }
    else if (strcasecmp(opts[0],"tls_cacertdir")==0)
    {
      log_log(LOG_WARNING,"%s:%d: option %s is currently untested (please report any successes)",filename,lnr,opts[0]);
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_tls_cacertdir=xstrdup(opts[1]);
    }
    else if (strcasecmp(opts[0],"tls_cacertfile")==0)
    {
      log_log(LOG_WARNING,"%s:%d: option %s is currently untested (please report any successes)",filename,lnr,opts[0]);
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_tls_cacertfile=xstrdup(opts[1]);
    }
    else if (strcasecmp(opts[0],"tls_randfile")==0)
    {
      log_log(LOG_WARNING,"%s:%d: option %s is currently untested (please report any successes)",filename,lnr,opts[0]);
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_tls_randfile=xstrdup(opts[1]);
    }
    else if (strcasecmp(opts[0],"tls_ciphers")==0)
    {
      log_log(LOG_WARNING,"%s:%d: option %s is currently untested (please report any successes)",filename,lnr,opts[0]);
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_tls_ciphers=xstrdup(opts[1]);
    }
    else if (strcasecmp(opts[0],"tls_cert")==0)
    {
      log_log(LOG_WARNING,"%s:%d: option %s is currently untested (please report any successes)",filename,lnr,opts[0]);
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_tls_cert=xstrdup(opts[1]);
    }
    else if (strcasecmp(opts[0],"tls_key")==0)
    {
      log_log(LOG_WARNING,"%s:%d: option %s is currently untested (please report any successes)",filename,lnr,opts[0]);
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_tls_key=xstrdup(opts[1]);
    }
    /* other options */
    else if (strcasecmp(opts[0],"restart")==0)
    {
      log_log(LOG_WARNING,"%s:%d: option %s is currently untested (and may be removed in an upcoming release)",filename,lnr,opts[0]);
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_restart=parse_boolean(filename,lnr,opts[1]);
    }
    else if (strcasecmp(opts[0],"pagesize")==0)
    {
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_pagesize=atoi(opts[1]);
    }
    /* undocumented options */
    else if (strcasecmp(opts[0],"nss_reconnect_tries")==0)
    {
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_reconnect_tries=atoi(opts[1]);
    }
    else if (!strcasecmp(opts[0],"nss_reconnect_sleeptime"))
    {
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_reconnect_sleeptime=atoi(opts[1]);
    }
    else if (strcasecmp(opts[0],"nss_reconnect_maxsleeptime")==0)
    {
      check_argumentcount(filename,lnr,opts[0],nopts==2);
      cfg->ldc_reconnect_maxsleeptime=atoi(opts[1]);
    }
    else
    {
      log_log(LOG_ERR,"%s:%d: unknown keyword: '%s'",filename,lnr,opts[0]);
      exit(EXIT_FAILURE);
    }
  }

  /* we're done reading file, close */
  fclose(fp);
}

void cfg_init(const char *fname)
{
  /* check if we were called before */
  if (nslcd_cfg!=NULL)
  {
    log_log(LOG_CRIT,"cfg_init() may only be called once");
    exit(EXIT_FAILURE);
  }
  /* allocate the memory (this memory is not freed anywhere) */
  nslcd_cfg=(struct ldap_config *)malloc(sizeof(struct ldap_config));
  if (nslcd_cfg==NULL)
  {
    log_log(LOG_CRIT,"malloc() failed to allocate memory");
    exit(EXIT_FAILURE);
  }
  /* clear configuration */
  cfg_defaults(nslcd_cfg);
  /* read configfile */
  cfg_read(fname,nslcd_cfg);
  /* do some sanity checks */
  if (nslcd_cfg->ldc_uris[0]==NULL)
  {
    log_log(LOG_ERR,"no URIs defined in config");
    exit(EXIT_FAILURE);
  }
}
