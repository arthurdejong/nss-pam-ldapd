/*
   test_cfg.c - simple test for the cfg module
   This file is part of the nss-pam-ldapd library.

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
#include <string.h>
#include <assert.h>

#include "common.h"

/* we include cfg.c because we want to test the static methods */
#include "nslcd/cfg.c"

static void test_xstrdup(void)
{
  static const char *foo = "testString123";
  char *bar;
  bar = xstrdup(foo);
  /* we should have a new value */
  assert(bar != NULL);
  /* the contents should be the same */
  assertstreq(foo, bar);
  /* but the pointer should be different */
  assert(foo != bar);
  /* free memory */
  free(bar);
}

static void test_add_uris(void)
{
  static struct ldap_config cfg;
  int i;
  /* set up config */
  cfg_defaults(&cfg);
  assert(cfg.uris[0].uri == NULL);
  /* add a uri */
  add_uri(__FILE__, __LINE__, &cfg, "ldap://localhost");
  assert(cfg.uris[0].uri != NULL);
  assert(cfg.uris[1].uri == NULL);
  /* add some more uris */
  for (i = 1; i < NSS_LDAP_CONFIG_MAX_URIS; i++)
  {
    add_uri(__FILE__, __LINE__, &cfg, "ldap://localhost");
    assert(cfg.uris[i].uri != NULL);
    assert(cfg.uris[i + 1].uri == NULL);
  }
  /* inserting one more entry should call exit():
     add_uri(__FILE__, __LINE__, &cfg, "ldap://localhost");
     assert(cfg.uris[i] != NULL);
     assert(cfg.uris[i + 1] == NULL); */
  /* there is no cfg_free() so we have a memory leak here */
}

static void test_parse_boolean(void)
{
  assert(parse_boolean(__FILE__, __LINE__, "True") == 1);
  assert(parse_boolean(__FILE__, __LINE__, "faLSe") == 0);
  assert(parse_boolean(__FILE__, __LINE__, "1") == 1);
  assert(parse_boolean(__FILE__, __LINE__, "oFF") == 0);
  assert(parse_boolean(__FILE__, __LINE__, "Yes") == 1);
  assert(parse_boolean(__FILE__, __LINE__, "No") == 0);
  /* most other values should call exit():
     assert(parse_boolean(__FILE__, __LINE__, "Foo") == 0); */
}

static void test_parse_scope(void)
{
  struct ldap_config cfg;
  handle_scope(__FILE__, __LINE__, "scope", "sUb", &cfg);
  assert(cfg.scope == LDAP_SCOPE_SUBTREE);
  handle_scope(__FILE__, __LINE__, "scope", "subtree", &cfg);
  assert(cfg.scope == LDAP_SCOPE_SUBTREE);
  handle_scope(__FILE__, __LINE__, "scope", "ONE", &cfg);
  assert(cfg.scope == LDAP_SCOPE_ONELEVEL);
  handle_scope(__FILE__, __LINE__, "scope", "oneLevel", &cfg);
  assert(cfg.scope == LDAP_SCOPE_ONELEVEL);
  handle_scope(__FILE__, __LINE__, "scope", "base", &cfg);
  assert(cfg.scope == LDAP_SCOPE_BASE);
  handle_scope(__FILE__, __LINE__, "scope", "bASe", &cfg);
  assert(cfg.scope == LDAP_SCOPE_BASE);
#ifdef LDAP_SCOPE_CHILDREN
  handle_scope(__FILE__, __LINE__, "scope", "children", &cfg);
  assert(cfg.scope == LDAP_SCOPE_CHILDREN);
#endif /* LDAP_SCOPE_CHILDREN */
  /* most other values should call exit():
     handle_scope(__FILE__, __LINE__, "scope", "BSAE", &cfg); */
}

static void test_parse_map(void)
{
  char *line;
  /* some general assertions */
  assert((LM_ALIASES != LM_ETHERS) && (LM_ALIASES != LM_GROUP) &&
         (LM_ALIASES != LM_HOSTS) && (LM_ALIASES != LM_NETGROUP) &&
         (LM_ALIASES != LM_NETWORKS) && (LM_ALIASES != LM_PASSWD) &&
         (LM_ALIASES != LM_PROTOCOLS) && (LM_ALIASES != LM_RPC) &&
         (LM_ALIASES != LM_SERVICES) && (LM_ALIASES != LM_SHADOW));
  assert((LM_ETHERS != LM_GROUP) && (LM_ETHERS != LM_HOSTS) &&
         (LM_ETHERS != LM_NETGROUP) && (LM_ETHERS != LM_NETWORKS) &&
         (LM_ETHERS != LM_PASSWD) && (LM_ETHERS != LM_PROTOCOLS) &&
         (LM_ETHERS != LM_RPC) && (LM_ETHERS != LM_SERVICES) &&
         (LM_ETHERS != LM_SHADOW));
  assert((LM_GROUP != LM_HOSTS) && (LM_GROUP != LM_NETGROUP) &&
         (LM_GROUP != LM_NETWORKS) && (LM_GROUP != LM_PASSWD) &&
         (LM_GROUP != LM_PROTOCOLS) && (LM_GROUP != LM_RPC) &&
         (LM_GROUP != LM_SERVICES) && (LM_GROUP != LM_SHADOW));
  assert((LM_HOSTS != LM_NETGROUP) && (LM_HOSTS != LM_NETWORKS) &&
         (LM_HOSTS != LM_PASSWD) && (LM_HOSTS != LM_PROTOCOLS) &&
         (LM_HOSTS != LM_RPC) && (LM_HOSTS != LM_SERVICES) &&
         (LM_HOSTS != LM_SHADOW));
  assert((LM_NETGROUP != LM_NETWORKS) && (LM_NETGROUP != LM_PASSWD) &&
         (LM_NETGROUP != LM_PROTOCOLS) && (LM_NETGROUP != LM_RPC) &&
         (LM_NETGROUP != LM_SERVICES) && (LM_NETGROUP != LM_SHADOW));
  assert((LM_NETWORKS != LM_PASSWD) && (LM_NETWORKS != LM_PROTOCOLS) &&
         (LM_NETWORKS != LM_RPC) && (LM_NETWORKS != LM_SERVICES) &&
         (LM_NETWORKS != LM_SHADOW));
  assert((LM_PASSWD != LM_PROTOCOLS) && (LM_PASSWD != LM_RPC) &&
         (LM_PASSWD != LM_SERVICES) && (LM_PASSWD != LM_SHADOW));
  assert((LM_PROTOCOLS != LM_RPC) && (LM_PROTOCOLS != LM_SERVICES) &&
         (LM_PROTOCOLS != LM_SHADOW));
  assert((LM_RPC != LM_SERVICES) && (LM_RPC != LM_SHADOW));
  assert((LM_SERVICES != LM_SHADOW));
  /* test supported names */
  line = "alIas"; assert(get_map(&line) == LM_ALIASES);
  line = "AliasES"; assert(get_map(&line) == LM_ALIASES);
  line = "ether"; assert(get_map(&line) == LM_ETHERS);
  line = "ethers"; assert(get_map(&line) == LM_ETHERS);
  line = "group"; assert(get_map(&line) == LM_GROUP);
  line = "host"; assert(get_map(&line) == LM_HOSTS);
  line = "hosts"; assert(get_map(&line) == LM_HOSTS);
  line = "netgroup"; assert(get_map(&line) == LM_NETGROUP);
  line = "network"; assert(get_map(&line) == LM_NETWORKS);
  line = "networks"; assert(get_map(&line) == LM_NETWORKS);
  line = "passwd"; assert(get_map(&line) == LM_PASSWD);
  line = "protocol"; assert(get_map(&line) == LM_PROTOCOLS);
  line = "protocols"; assert(get_map(&line) == LM_PROTOCOLS);
  line = "rpc"; assert(get_map(&line) == LM_RPC);
  line = "service"; assert(get_map(&line) == LM_SERVICES);
  line = "services"; assert(get_map(&line) == LM_SERVICES);
  line = "shadow"; assert(get_map(&line) == LM_SHADOW);
  line = "unknown"; assert(get_map(&line) == LM_NONE);
  line = "x"; assert(get_map(&line) == LM_NONE);
}

static void test_parse_map_statement(void)
{
  /* TODO: implement */
}

static void test_tokenize(void)
{
  /* this leaks memory all over the place */
  char *line = strdup("yes  this is 1 simple line");
  char *str;
  int i;
  i = get_boolean(__FILE__, __LINE__, __PRETTY_FUNCTION__, &line);
  assert(i == 1);
  str = get_strdup(__FILE__, __LINE__, __PRETTY_FUNCTION__, &line);
  assertstreq(str, "this");
  str = get_strdup(__FILE__, __LINE__, __PRETTY_FUNCTION__, &line);
  assertstreq(str, "is");
  i = get_int(__FILE__, __LINE__, __PRETTY_FUNCTION__, &line);
  assert(i == 1);
  str = get_linedup(__FILE__, __LINE__, __PRETTY_FUNCTION__, &line);
  assertstreq(str, "simple line");
  get_eol(__FILE__, __LINE__, __PRETTY_FUNCTION__, &line);
}

extern const char *passwd_bases[];
extern const char *group_bases[];
extern const char *group_filter;
extern int passwd_scope;

static void test_read(void)
{
  FILE *fp;
  struct ldap_config cfg;
  /* write some stuff to a temporary file */
  fp = fopen("temp.cfg", "w");
  assert(fp != NULL);
  fprintf(fp, "# a line of comments\n"
          "uri ldap://127.0.0.1/\n"
          "uri ldap:/// ldaps://127.0.0.1/\n"
          "base dc=test, dc=tld\n"
          "base passwd ou=Some People,dc=test,dc=tld\n"
          "base group \"\"\n"
          "map\tpasswd uid\t\tsAMAccountName\n"
          "map passwd homeDirectory \"${homeDirectory:-/home/$uid}\"  \n"
          "map    passwd gecos            \"${givenName}. ${sn}\"\n"
          "filter group (&(objeclClass=posixGroup)(gid=1*))\n"
          "\n"
          "scope passwd one\n"
          "cache dn2uid 10m 1s\n");
  fclose(fp);
  /* parse the file */
  cfg_defaults(&cfg);
  cfg_read("temp.cfg", &cfg);
  /* check results */
  assert(cfg.uris[0].uri != NULL);
  assert(cfg.uris[1].uri != NULL);
  assert(cfg.uris[2].uri != NULL);
  assertstreq(cfg.uris[0].uri, "ldap://127.0.0.1/");
  assertstreq(cfg.uris[1].uri, "ldap:///");
  assertstreq(cfg.uris[2].uri, "ldaps://127.0.0.1/");
  assert(cfg.uris[3].uri == NULL);
  assertstreq(cfg.bases[0], "dc=test, dc=tld");
  assertstreq(passwd_bases[0], "ou=Some People,dc=test,dc=tld");
  assertstreq(group_bases[0], "");
  assertstreq(attmap_passwd_uid, "sAMAccountName");
  assertstreq(attmap_passwd_homeDirectory, "\"${homeDirectory:-/home/$uid}\"");
  assertstreq(attmap_passwd_gecos, "\"${givenName}. ${sn}\"");
  assertstreq(group_filter, "(&(objeclClass=posixGroup)(gid=1*))");
  assert(passwd_scope == LDAP_SCOPE_ONELEVEL);
  assert(cfg.cache_dn2uid_positive == 10 * 60);
  assert(cfg.cache_dn2uid_negative == 1);
  /* remove temporary file */
  remove("temp.cfg");
}

/* the main program... */
int main(int UNUSED(argc), char UNUSED(*argv[]))
{
  test_xstrdup();
  test_add_uris();
  test_parse_boolean();
  test_parse_scope();
  test_parse_map();
  test_parse_map_statement();
  test_tokenize();
  test_read();
  return EXIT_SUCCESS;
}
