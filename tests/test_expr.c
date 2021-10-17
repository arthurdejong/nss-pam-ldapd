/*
   test_expr.c - simple tests for the expr module
   This file is part of the nss-pam-ldapd library.

   Copyright (C) 2009-2021 Arthur de Jong
   Copyright (c) 2016 Giovanni Mascellani

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

/* we include expr.c because we want to test the static methods */
#include "common/expr.c"

static void test_parse_name(void)
{
  char buffer[20];
  int i;
  i = 0;
  assert(parse_name("fooBar", &i, buffer, sizeof(buffer), 0) != NULL);
  assert(i == 6);
  i = 0;
  assert(parse_name("nameThatWillNotFitInBuffer", &i, buffer, sizeof(buffer), 0) == NULL);
  i = 0;
  assert(parse_name("foo Bar", &i, buffer, sizeof(buffer), 0) != NULL);
  assert(i == 3);
  assertstreq(buffer, "foo");
  i = 0;
  assert(parse_name("foo-Bar", &i, buffer, sizeof(buffer), 0) != NULL);
  assert(i == 3);
  assertstreq(buffer, "foo");
  i = 0;
  assert(parse_name("foo-Bar", &i, buffer, sizeof(buffer), 1) != NULL);
  assert(i == 7);
  assertstreq(buffer, "foo-Bar");
}

static const char *expanderfn(const char *name, void UNUSED(*expander_attr))
{
  if (strcmp(name, "empty") == 0)
    return "";
  if (strcmp(name, "null") == 0)
    return NULL;
  if (strcmp(name, "userPassword") == 0)
    return "{crypt}HASH";
  else
    return "foobar";
}

static void test_expr_parse(void)
{
  char buffer[1024];
  assert(expr_parse("$test1", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "foobar");
  assert(expr_parse("\\$test1", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "$test1");
  assert(expr_parse("$empty", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "");
  assert(expr_parse("$foo1$empty-$foo2", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "foobar-foobar");
  assert(expr_parse("$test-var", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "foobar-var");
  assert(expr_parse("${test-var}", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "foobar");
  assert(expr_parse("$foo1+$null+$foo2", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "foobar++foobar");
  assert(expr_parse("${test1}\\$", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "foobar$");
  assert(expr_parse("${test1:-default}", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "foobar");
  assert(expr_parse("${empty:-default}", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "default");
  assert(expr_parse("${test1:+setset}", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "setset");
  assert(expr_parse("${empty:+setset}", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "");
  assert(expr_parse("${empty:-$test1}", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "foobar");
  assert(expr_parse("a/$test1/b", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "a/foobar/b");
  assert(expr_parse("a/$empty/b", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "a//b");
  assert(expr_parse("a${test1}b", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "afoobarb");
  assert(expr_parse("a${test1}b${test2:+${test3:-d$test4}e}c", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "afoobarbfoobarec");
  assert(expr_parse("a${test1}b${test2:+${empty:-d$test4}e}c", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "afoobarbdfoobarec");
  /* test ${var#trim} functions */
  assert(expr_parse("${test1#foo}", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "bar");
  assert(expr_parse("${test1#zoo}", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "foobar");
  assert(expr_parse("${test1#?oo}", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "bar");
  assert(expr_parse("${test1#f\\?o}", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "foobar");
  assert(expr_parse("${userPassword#{crypt\\}}", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "HASH");
  /* test ${var:offset:length} */
  assert(expr_parse("${test1:0:6}", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "foobar");
  assert(expr_parse("${test1:0:10}", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "foobar");
  assert(expr_parse("${test1:0:3}", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "foo");
  assert(expr_parse("${test1:3:0}", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "");
  assert(expr_parse("${test1:3:6}", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "bar");
  assert(expr_parse("${test1:7:0}", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "");
  assert(expr_parse("${test1:7:3}", buffer, sizeof(buffer), expanderfn, NULL) != NULL);
  assertstreq(buffer, "");
  /* these are errors */
  assert(expr_parse("$&", buffer, sizeof(buffer), expanderfn, NULL) == NULL);
  assert(expr_parse("${a", buffer, sizeof(buffer), expanderfn, NULL) == NULL);
}

static void test_buffer_overflow(void)
{
  char buffer[10];
  assert(expr_parse("$test1$empty$test1", buffer, sizeof(buffer), expanderfn, NULL) == NULL);
  assert(expr_parse("long test value", buffer, sizeof(buffer), expanderfn, NULL) == NULL);
  assert(expr_parse("${test1:-long test value}", buffer, sizeof(buffer), expanderfn, NULL) == NULL);
}

static void test_expr_vars(void)
{
  SET *set;
  /* simple test */
  set = set_new();
  assert(expr_vars("$a", set) != NULL);
  assert(set_contains(set, "a"));
  assert(!set_contains(set, "$a"));
  set_free(set);
  /* more elaborate test */
  set = set_new();
  assert(expr_vars("\"${gecos:-$cn}\"", set) != NULL);
  assert(set_contains(set, "gecos"));
  assert(set_contains(set, "cn"));
  set_free(set);
  /* more elaborate test */
  set = set_new();
  assert(expr_vars("\"${homeDirectory:-/home/$uidNumber/$uid}\"", set) != NULL);
  assert(set_contains(set, "homeDirectory"));
  assert(set_contains(set, "uidNumber"));
  assert(set_contains(set, "uid"));
  set_free(set);
  /* a test with attribute options */
  set = set_new();
  assert(expr_vars("\"${homeDirectory;foo:-/home/something}\"", set) != NULL);
  assert(set_contains(set, "homeDirectory;foo"));
  set_free(set);
}

/* the main program... */
int main(int UNUSED(argc), char UNUSED(*argv[]))
{
  test_parse_name();
  test_expr_parse();
  test_buffer_overflow();
  test_expr_vars();
  return EXIT_SUCCESS;
}
