/*
   test_cfg.c - simple test for the cfg module
   This file is part of the nss-pam-ldapd library.

   Copyright (C) 2014 Arthur de Jong

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

#include "nslcd/attmap.h"

static void test_member_map(void)
{
  const char **var;
  const char *res;
  var = attmap_get_var(LM_GROUP, "member");
  assert(var != NULL);
  /* expected mapping */
  res = attmap_set_mapping(var, "uniqueMember");
  assert(res != NULL);
  assertstreq(res, "uniqueMember");
  /* no support for expressions */
  res = attmap_set_mapping(var, "\"$fred\"");
  assert(res == NULL);
  /* but support empty string */
  res = attmap_set_mapping(var, "\"\"");
  assert(res != NULL);
  assertstreq(res, "\"\"");
}

int main(int UNUSED(argc), char UNUSED(*argv[]))
{
  test_member_map();
  return EXIT_SUCCESS;
}
