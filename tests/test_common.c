/*
   test_common.c - simple test for the common module
   This file is part of the nss-pam-ldapd library.

   Copyright (C) 2008, 2009 Arthur de Jong

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
#include <assert.h>

#include "nslcd/common.h"

/* this is a simple way to get this into an executable */
const char **base_get_var(int UNUSED(map)) {return NULL;}
int *scope_get_var(int UNUSED(map)) {return NULL;}
const char **filter_get_var(int UNUSED(map)) {return NULL;}
const char **attmap_get_var(int UNUSED(map),const char UNUSED(*name)) {return NULL;}
const char *attmap_get_value(MYLDAP_ENTRY UNUSED(*entry),const char UNUSED(*attr),char UNUSED(*buffer),size_t UNUSED(buflen)) {return "";}
void *attmap_add_attributes(void UNUSED(*set),const char UNUSED(*attr)) {return NULL;}
const char *attmap_set_mapping(const char UNUSED(**var),const char UNUSED(*value)) {return NULL;}

static void test_isvalidname(void)
{
  assert(isvalidname("arthur"));
  assert(!isvalidname("-arthur"));
  assert(isvalidname("arthur-is-nice"));
  assert(isvalidname("sambamachine$"));
  assert(isvalidname("foo\\bar"));
  assert(!isvalidname("\\foo\\bar"));
  assert(!isvalidname("foo\\bar\\"));
}

/* the main program... */
int main(int UNUSED(argc),char UNUSED(*argv[]))
{
  test_isvalidname();
  return 0;
}
