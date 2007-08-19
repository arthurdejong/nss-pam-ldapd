/*
   test_dict.c - simple test for the dict module
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

#include "common/dict.h"
#include "compat/attrs.h"

/* the main program... */
int main(int UNUSED(argc),char UNUSED(*argv[]))
{
  DICT *dict;
  void *ret;
  static char *value1="value1";
  static char *value2="value2";
  static char *replace2="replace2";

  /* initialize */
  dict=dict_new();

  /* store some entries */
  dict_put(dict,"key1",value1);
  dict_put(dict,"key2",value2);
  dict_put(dict,"key3",dict);
  dict_put(dict,"KEY2",replace2);

  /* check dictionary contents */
  ret=dict_get(dict,"KeY1");
  assert(ret==value1);
  ret=dict_get(dict,"kEy2");
  assert(ret==replace2);
  ret=dict_get(dict,"KeY3");
  assert(ret==dict);
  ret=dict_get(dict,"key4");
  assert(ret==NULL);

  /* remove a key */
  dict_put(dict,"kEy3",NULL);
  ret=dict_get(dict,"keY3");
  assert(ret==NULL);

  /* loop over dictionary contents */
  dict_values_first(dict);
  while ((ret=dict_values_next(dict))!=NULL)
  {
    assert(((ret==value1)||(ret==replace2)));
  }

  /* free dictionary */
  dict_free(dict);

  /* TODO: test dict_values_first() and  dict_values_next() */

  return 0;
}
