/*
   test_dict.c - simple test for the dict module
   This file is part of the nss-ldapd library.

   Copyright (C) 2007, 2008 Arthur de Jong

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
  const char *key;
  void *val;
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
  val=dict_get(dict,"KeY1");
  assert(val==value1);
  val=dict_get(dict,"kEy2");
  assert(val==replace2);
  val=dict_get(dict,"KeY3");
  assert(val==dict);
  val=dict_get(dict,"key4");
  assert(val==NULL);

  /* remove a key */
  dict_put(dict,"kEy3",NULL);
  val=dict_get(dict,"keY3");
  assert(val==NULL);

  /* loop over dictionary contents */
  dict_loop_first(dict);
  while (dict_loop_next(dict,&key,&val)!=NULL)
  {
    assert(((val==value1)||(val==replace2)));
  }

  /* free dictionary */
  dict_free(dict);

  return 0;
}
