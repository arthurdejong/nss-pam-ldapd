/*
   test_cfg.c - simple test for the cfg module
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

#include <stdio.h>
#include <string.h>
#include <assert.h>

/* we include cfg.c because we want to test the static methods */
#include "nslcd/cfg.c"

#define assertstreq(str1,str2) \
  (assertstreq_impl(str1,str2,"strcmp(" __STRING(str1) "," __STRING(str2) ")==0", \
                    __FILE__, __LINE__, __ASSERT_FUNCTION))

/* method for determening string equalness */
static void assertstreq_impl(const char *str1,const char *str2,
                             const char *assertion,const char *file,
                             int line,const char *function)
{
  if (strcmp(str1,str2)!=0)
    __assert_fail(assertion,file,line,function);
}

static void test_xstrdup(void)
{
  static const char *foo="testString123";
  char *bar;
  bar=xstrdup(foo);
  /* we should have a new value */
  assert(bar!=NULL);
  /* the contents should be the same */
  assertstreq(foo,bar);
  /* but the pointer should be different */
  assert(foo!=bar);
  /* free memory */
  free(bar);
}

static void test_add_uris(void)
{
  static struct ldap_config cfg;
  int i;
  /* set up config */
  cfg_defaults(&cfg);
  assert(cfg.ldc_uris[0]==NULL);
  /* add a uri */
  add_uri(__FILE__,__LINE__,&cfg,"ldap://localhost");
  assert(cfg.ldc_uris[0]!=NULL);
  assert(cfg.ldc_uris[1]==NULL);
  /* add some more uris */
  for (i=1;i<NSS_LDAP_CONFIG_URI_MAX;i++)
  {
    add_uri(__FILE__,__LINE__,&cfg,"ldap://localhost");
    assert(cfg.ldc_uris[i]!=NULL);
    assert(cfg.ldc_uris[i+1]==NULL);
  }
  /* inserting one more entry should call exit():
  add_uri(__FILE__,__LINE__,&cfg,"ldap://localhost");
  assert(cfg.ldc_uris[i]!=NULL);
  assert(cfg.ldc_uris[i+1]==NULL); */
  /* there is no cfg_free() so we have a memory leak here */
}

static void test_parse_boolean(void)
{
  assert(parse_boolean(__FILE__,__LINE__,"True")==1);
  assert(parse_boolean(__FILE__,__LINE__,"faLSe")==0);
  assert(parse_boolean(__FILE__,__LINE__,"1")==1);
  assert(parse_boolean(__FILE__,__LINE__,"oFF")==0);
  assert(parse_boolean(__FILE__,__LINE__,"Yes")==1);
  assert(parse_boolean(__FILE__,__LINE__,"No")==0);
  /* most other values should call exit():
  assert(parse_boolean(__FILE__,__LINE__,"Foo")==0); */
}


static void test_parse_scope(void)
{
  assert(parse_scope(__FILE__,__LINE__,"sUb")==LDAP_SCOPE_SUBTREE);
  assert(parse_scope(__FILE__,__LINE__,"subtree")==LDAP_SCOPE_SUBTREE);
  assert(parse_scope(__FILE__,__LINE__,"ONE")==LDAP_SCOPE_ONELEVEL);
  assert(parse_scope(__FILE__,__LINE__,"oneLevel")==LDAP_SCOPE_ONELEVEL);
  assert(parse_scope(__FILE__,__LINE__,"base")==LDAP_SCOPE_BASE);
  assert(parse_scope(__FILE__,__LINE__,"bASe")==LDAP_SCOPE_BASE);
  /* most other values should call exit():
  assert(parse_scope(__FILE__,__LINE__,"BSAE")==LDAP_SCOPE_BASE); */
}

static void test_parse_map(void)
{
  /* some general assertions */
  assert((LM_ALIASES!=LM_ETHERS)&&(LM_ALIASES!=LM_GROUP)&&(LM_ALIASES!=LM_HOSTS)&&
         (LM_ALIASES!=LM_NETGROUP)&&(LM_ALIASES!=LM_NETWORKS)&&(LM_ALIASES!=LM_PASSWD)&&
         (LM_ALIASES!=LM_PROTOCOLS)&&(LM_ALIASES!=LM_RPC)&&(LM_ALIASES!=LM_SERVICES)&&
         (LM_ALIASES!=LM_SHADOW));
  assert((LM_ETHERS!=LM_GROUP)&&(LM_ETHERS!=LM_HOSTS)&&(LM_ETHERS!=LM_NETGROUP)&&
         (LM_ETHERS!=LM_NETWORKS)&&(LM_ETHERS!=LM_PASSWD)&&(LM_ETHERS!=LM_PROTOCOLS)&&
         (LM_ETHERS!=LM_RPC)&&(LM_ETHERS!=LM_SERVICES)&&(LM_ETHERS!=LM_SHADOW));
  assert((LM_GROUP!=LM_HOSTS)&&(LM_GROUP!=LM_NETGROUP)&&(LM_GROUP!=LM_NETWORKS)&&
         (LM_GROUP!=LM_PASSWD)&&(LM_GROUP!=LM_PROTOCOLS)&&(LM_GROUP!=LM_RPC)&&
         (LM_GROUP!=LM_SERVICES)&&(LM_GROUP!=LM_SHADOW));
  assert((LM_HOSTS!=LM_NETGROUP)&&(LM_HOSTS!=LM_NETWORKS)&&(LM_HOSTS!=LM_PASSWD)&&
         (LM_HOSTS!=LM_PROTOCOLS)&&(LM_HOSTS!=LM_RPC)&&(LM_HOSTS!=LM_SERVICES)&&
         (LM_HOSTS!=LM_SHADOW));
  assert((LM_NETGROUP!=LM_NETWORKS)&&(LM_NETGROUP!=LM_PASSWD)&&(LM_NETGROUP!=LM_PROTOCOLS)&&
         (LM_NETGROUP!=LM_RPC)&&(LM_NETGROUP!=LM_SERVICES)&&(LM_NETGROUP!=LM_SHADOW));
  assert((LM_NETWORKS!=LM_PASSWD)&&(LM_NETWORKS!=LM_PROTOCOLS)&&(LM_NETWORKS!=LM_RPC)&&
         (LM_NETWORKS!=LM_SERVICES)&&(LM_NETWORKS!=LM_SHADOW));
  assert((LM_PASSWD!=LM_PROTOCOLS)&&(LM_PASSWD!=LM_RPC)&&(LM_PASSWD!=LM_SERVICES)&&         (LM_PASSWD!=LM_SHADOW));
  assert((LM_PROTOCOLS!=LM_RPC)&&(LM_PROTOCOLS!=LM_SERVICES)&&(LM_PROTOCOLS!=LM_SHADOW));
  assert((LM_RPC!=LM_SERVICES)&&(LM_RPC!=LM_SHADOW));
  assert((LM_SERVICES!=LM_SHADOW));
  /* test supported names */
  assert(parse_map(__FILE__,__LINE__,"alIas")==LM_ALIASES);
  assert(parse_map(__FILE__,__LINE__,"AliasES")==LM_ALIASES);
  assert(parse_map(__FILE__,__LINE__,"ether")==LM_ETHERS);
  assert(parse_map(__FILE__,__LINE__,"ethers")==LM_ETHERS);
  assert(parse_map(__FILE__,__LINE__,"group")==LM_GROUP);
  /* assert(parse_map(__FILE__,__LINE__,"groups")==LM_GROUP); */
  assert(parse_map(__FILE__,__LINE__,"host")==LM_HOSTS);
  assert(parse_map(__FILE__,__LINE__,"hosts")==LM_HOSTS);
  assert(parse_map(__FILE__,__LINE__,"netgroup")==LM_NETGROUP);
  /* assert(parse_map(__FILE__,__LINE__,"netgroups")==LM_NETGROUP); */
  assert(parse_map(__FILE__,__LINE__,"network")==LM_NETWORKS);
  assert(parse_map(__FILE__,__LINE__,"networks")==LM_NETWORKS);
  assert(parse_map(__FILE__,__LINE__,"passwd")==LM_PASSWD);
  /* assert(parse_map(__FILE__,__LINE__,"passwds")==LM_PASSWD); */
  assert(parse_map(__FILE__,__LINE__,"protocol")==LM_PROTOCOLS);
  assert(parse_map(__FILE__,__LINE__,"protocols")==LM_PROTOCOLS);
  assert(parse_map(__FILE__,__LINE__,"rpc")==LM_RPC);
  /* assert(parse_map(__FILE__,__LINE__,"rpcs")==LM_RPC); */
  assert(parse_map(__FILE__,__LINE__,"service")==LM_SERVICES);
  assert(parse_map(__FILE__,__LINE__,"services")==LM_SERVICES);
  assert(parse_map(__FILE__,__LINE__,"shadow")==LM_SHADOW);
  /* assert(parse_map(__FILE__,__LINE__,"shadows")==LM_SHADOW); */
  /* most other values should call exit():
  assert(parse_map(__FILE__,__LINE__,"publickey")==LM_SERVICES); */
}

static void test_parse_map_statement(void)
{
  /* FIXME: implement */
}

static void test_tokenize(void)
{
  const char **opts;
  int nopts;
  /* this also has memory leaks (the strdup() calls) */
  opts=tokenize(__FILE__,__LINE__,strdup("this is a simple line"),&nopts);
  assert(nopts==5);
  assertstreq(opts[0],"this");
  assertstreq(opts[1],"is");
  assertstreq(opts[2],"a");
  assertstreq(opts[3],"simple");
  assertstreq(opts[4],"line");
  opts=tokenize(__FILE__,__LINE__,strdup("this contains \"quoted text\""),&nopts);
  assert(nopts==3);
  assertstreq(opts[0],"this");
  assertstreq(opts[1],"contains");
  assertstreq(opts[2],"\"quoted text\"");
}

/* the main program... */
int main(int UNUSED(argc),char UNUSED(*argv[]))
{
  test_xstrdup();
  test_add_uris();
  test_parse_boolean();
  test_parse_scope();
  test_parse_map();
  test_parse_map_statement();
  test_tokenize();
  return EXIT_SUCCESS;
}
