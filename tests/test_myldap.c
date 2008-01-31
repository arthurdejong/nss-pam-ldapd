/*
   test_myldap.c - simple test for the myldap module
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
#include <pthread.h>
#include <errno.h>
#include <assert.h>

#include "nslcd/log.h"
#include "nslcd/cfg.h"
#include "nslcd/myldap.h"

struct worker_args {
  int id;
};

/* this is a simple way to get this into an executable,
   we should probably read a valid config instead */
const char **base_get_var(int UNUSED(map)) {return NULL;}
int *scope_get_var(int UNUSED(map)) {return NULL;}
const char **filter_get_var(int UNUSED(map)) {return NULL;}
const char **attmap_get_var(int UNUSED(map),const char UNUSED(*name)) {return NULL;}

/* the maxium number of results to print (all results are retrieved) */
#define MAXRESULTS 10

/* This is a very basic search test, it performs a test to get certain
   entries from the database. It currently just prints out the DNs for
   the entries. */
static void test_search(void)
{
  MYLDAP_SESSION *session;
  MYLDAP_SEARCH *search;
  MYLDAP_ENTRY *entry;
  const char *attrs[] = { "uid", "cn", "gid", NULL };
  int i;
  int rc;
  /* initialize session */
  printf("test_myldap: test_search(): getting session...\n");
  session=myldap_create_session();
  assert(session!=NULL);
  /* perform search */
  printf("test_myldap: test_search(): doing search...\n");
  search=myldap_search(session,nslcd_cfg->ldc_base,
                       LDAP_SCOPE_SUBTREE,
                       "(objectclass=posixaccount)",
                       attrs);
  assert(search!=NULL);
  /* go over results */
  printf("test_myldap: test_search(): get results...\n");
  for (i=0;(entry=myldap_get_entry(search,&rc))!=NULL;i++)
  {
    if (i<MAXRESULTS)
      printf("test_myldap: test_search(): [%d] DN %s\n",i,myldap_get_dn(entry));
    else if (i==MAXRESULTS)
      printf("test_myldap: test_search(): ...\n");
  }
  printf("test_myldap: test_search(): %d entries returned: %s\n",i,ldap_err2string(rc));
  /* perform another search */
  printf("test_myldap: test_search(): doing search...\n");
  search=myldap_search(session,nslcd_cfg->ldc_base,
                       LDAP_SCOPE_SUBTREE,
                       "(objectclass=posixGroup)",
                       attrs);
  assert(search!=NULL);
  /* go over results */
  printf("test_myldap: test_search(): get results...\n");
  for (i=0;(entry=myldap_get_entry(search,&rc))!=NULL;i++)
  {
    if (i<MAXRESULTS)
      printf("test_myldap: test_search(): [%d] DN %s\n",i,myldap_get_dn(entry));
    else if (i==MAXRESULTS)
      printf("test_myldap: test_search(): ...\n");
  }
  printf("test_myldap: test_search(): %d entries returned: %s\n",i,ldap_err2string(rc));
  /* clean up */
  myldap_session_close(session);
}

/* This search prints a number of attributes from a search */
static void test_get_values(void)
{
  MYLDAP_SESSION *session;
  MYLDAP_SEARCH *search;
  MYLDAP_ENTRY *entry;
  const char *attrs[] = { "uidNumber", "cn", "gidNumber", "uid", "objectClass", NULL };
  const char **vals;
  const char *rdnval;
  int i;
  /* initialize session */
  printf("test_myldap: test_get_values(): getting session...\n");
  session=myldap_create_session();
  assert(session!=NULL);
  /* perform search */
  search=myldap_search(session,nslcd_cfg->ldc_base,
                          LDAP_SCOPE_SUBTREE,
                          "(&(objectClass=posixAccount)(uid=*))",
                          attrs);
  assert(search!=NULL);
  /* go over results */
  for (i=0;(entry=myldap_get_entry(search,NULL))!=NULL;i++)
  {
    if (i<MAXRESULTS)
      printf("test_myldap: test_get_values(): [%d] DN %s\n",i,myldap_get_dn(entry));
    else if (i==MAXRESULTS)
      printf("test_myldap: test_get_values(): ...\n");
    /* try to get uid from attribute */
    vals=myldap_get_values(entry,"uidNumber");
    assert((vals!=NULL)&&(vals[0]!=NULL));
    if (i<MAXRESULTS)
      printf("test_myldap: test_get_values(): [%d] uidNumber=%s\n",i,vals[0]);
    /* try to get gid from attribute */
    vals=myldap_get_values(entry,"gidNumber");
    assert((vals!=NULL)&&(vals[0]!=NULL));
    if (i<MAXRESULTS)
      printf("test_myldap: test_get_values(): [%d] gidNumber=%s\n",i,vals[0]);
    /* write LDF_STRING(PASSWD_NAME) */
    vals=myldap_get_values(entry,"uid");
    assert((vals!=NULL)&&(vals[0]!=NULL));
    if (i<MAXRESULTS)
      printf("test_myldap: test_get_values(): [%d] uid=%s\n",i,vals[0]);
    /* get rdn values */
    rdnval=myldap_get_rdn_value(entry,"cn");
    if (i<MAXRESULTS)
      printf("test_myldap: test_get_values(): [%d] cdrdn=%s\n",i,rdnval==NULL?"NULL":rdnval);
    rdnval=myldap_get_rdn_value(entry,"uid");
    if (i<MAXRESULTS)
      printf("test_myldap: test_get_values(): [%d] uidrdn=%s\n",i,rdnval==NULL?"NULL":rdnval);
    /* check objectclass */
    assert(myldap_has_objectclass(entry,"posixAccount"));
  }
  /* clean up */
  myldap_session_close(session);
}

/* this method tests to see if we can perform two searches within
   one session */
static void test_two_searches(void)
{
  MYLDAP_SESSION *session;
  MYLDAP_SEARCH *search1,*search2;
  MYLDAP_ENTRY *entry;
  const char *attrs[] = { "uidNumber", "cn", "gidNumber", "uid", "objectClass", NULL };
  const char **vals;
  /* initialize session */
  printf("test_myldap: test_two_searches(): getting session...\n");
  session=myldap_create_session();
  assert(session!=NULL);
  /* perform search1 */
  search1=myldap_search(session,nslcd_cfg->ldc_base,
                        LDAP_SCOPE_SUBTREE,
                        "(&(objectClass=posixAccount)(uid=*))",
                        attrs);
  assert(search1!=NULL);
  /* get a result from search1 */
  entry=myldap_get_entry(search1,NULL);
  assert(entry!=NULL);
  printf("test_myldap: test_two_searches(): [search1] DN %s\n",myldap_get_dn(entry));
  vals=myldap_get_values(entry,"cn");
  assert((vals!=NULL)&&(vals[0]!=NULL));
  printf("test_myldap: test_two_searches(): [search1] cn=%s\n",vals[0]);
  /* start a second search */
  search2=myldap_search(session,nslcd_cfg->ldc_base,
                        LDAP_SCOPE_SUBTREE,
                        "(&(objectclass=posixGroup)(gidNumber=*))",
                        attrs);
  assert(search2!=NULL);
  /* get a result from search2 */
  entry=myldap_get_entry(search2,NULL);
  assert(entry!=NULL);
  printf("test_myldap: test_two_searches(): [search2] DN %s\n",myldap_get_dn(entry));
  vals=myldap_get_values(entry,"cn");
  assert((vals!=NULL)&&(vals[0]!=NULL));
  printf("test_myldap: test_two_searches(): [search2] cn=%s\n",vals[0]);
  /* get another result from search1 */
  entry=myldap_get_entry(search1,NULL);
  assert(entry!=NULL);
  printf("test_myldap: test_two_searches(): [search1] DN %s\n",myldap_get_dn(entry));
  vals=myldap_get_values(entry,"cn");
  assert((vals!=NULL)&&(vals[0]!=NULL));
  printf("test_myldap: test_two_searches(): [search1] cn=%s\n",vals[0]);
  /* stop search1 */
  myldap_search_close(search1);
  /* get another result from search2 */
  entry=myldap_get_entry(search2,NULL);
  assert(entry!=NULL);
  printf("test_myldap: test_two_searches(): [search2] DN %s\n",myldap_get_dn(entry));
  vals=myldap_get_values(entry,"cn");
  assert((vals!=NULL)&&(vals[0]!=NULL));
  printf("test_myldap: test_two_searches(): [search2] cn=%s\n",vals[0]);
  /* clean up */
  myldap_session_close(session);
}

/* perform a simple search */
static void *worker(void *arg)
{
  MYLDAP_SESSION *session;
  MYLDAP_SEARCH *search;
  MYLDAP_ENTRY *entry;
  const char *attrs[] = { "uid", "cn", "gid", NULL };
  struct worker_args *args=(struct worker_args *)arg;
  int i;
  int rc;
  /* initialize session */
  session=myldap_create_session();
  assert(session!=NULL);
  /* perform search */
  search=myldap_search(session,nslcd_cfg->ldc_base,
                       LDAP_SCOPE_SUBTREE,
                       "(objectclass=posixaccount)",
                       attrs);
  assert(search!=NULL);
  /* go over results */
  for (i=0;(entry=myldap_get_entry(search,&rc))!=NULL;i++)
  {
    if (i<MAXRESULTS)
      printf("test_myldap: test_threads(): [worker %d] [%d] DN %s\n",args->id,i,myldap_get_dn(entry));
    else if (i==MAXRESULTS)
      printf("test_myldap: test_threads(): [worker %d] ...\n",args->id);
  }
  printf("test_myldap: test_threads(): [worker %d] DONE: %s\n",args->id,ldap_err2string(rc));
  /* clean up */
  myldap_session_close(session);
  return 0;
}

/* thread ids of all running threads */
#define NUM_THREADS 5
pthread_t my_threads[NUM_THREADS];

static void test_threads(void)
{
  int i;
  struct worker_args args[NUM_THREADS];
  /* start worker threads */
  for (i=0;i<NUM_THREADS;i++)
  {
    args[i].id=i;
    assert(pthread_create(&my_threads[i],NULL,worker,&(args[i]))==0);
  }
  /* wait for all threads to die */
  for (i=0;i<NUM_THREADS;i++)
  {
    assert(pthread_join(my_threads[i],NULL)==0);
  }
}

static void test_connections(void)
{
  MYLDAP_SESSION *session;
  MYLDAP_SEARCH *search;
  const char *attrs[] = { "uid", "cn", "gid", NULL };
  char *old_uris[NSS_LDAP_CONFIG_URI_MAX+1];
  int i;
  /* save the old URIs */
  for (i=0;i<(NSS_LDAP_CONFIG_URI_MAX+1);i++)
  {
    old_uris[i]=nslcd_cfg->ldc_uris[i];
    nslcd_cfg->ldc_uris[i]=NULL;
  }
  /* set new URIs */
  i=0;
/*  nslcd_cfg->ldc_uris[i++]="ldapi://%2fdev%2fnull/";*/
  nslcd_cfg->ldc_uris[i++]="ldap://10.10.10.10/";
/*  nslcd_cfg->ldc_uris[i++]="ldapi://%2fdev%2fnonexistent/";*/
  nslcd_cfg->ldc_uris[i++]="ldap://nosuchhost/";
  nslcd_cfg->ldc_uris[i++]=NULL;
  /* initialize session */
  printf("test_myldap: test_connections(): getting session...\n");
  session=myldap_create_session();
  assert(session!=NULL);
  /* perform search */
  printf("test_myldap: test_connections(): doing search...\n");
  search=myldap_search(session,nslcd_cfg->ldc_base,
                       LDAP_SCOPE_SUBTREE,
                       "(objectclass=posixaccount)",
                       attrs);
  assert(search==NULL);
  /* clean up */
  myldap_session_close(session);
  /* restore the old URIs */
  for (i=0;i<(NSS_LDAP_CONFIG_URI_MAX+1);i++)
    nslcd_cfg->ldc_uris[i]=old_uris[i];
}

/* the main program... */
int main(int argc,char *argv[])
{
  assert(argc==2);
  cfg_init(argv[1]);
  /* partially initialize logging */
  log_setdefaultloglevel(LOG_DEBUG);
  test_search();
  test_get_values();
  test_two_searches();
  test_threads();
  test_connections();
  return 0;
}
