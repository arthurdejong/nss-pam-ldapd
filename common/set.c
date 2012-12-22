/*
   set.c - set functions
   This file is part of the nss-pam-ldapd library.

   Copyright (C) 2008, 2009, 2010, 2012 Arthur de Jong

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

#include "set.h"
#include "dict.h"

/*
   The SET object is just a DICT which is passed around. The value
   for each entry in the dict is just the pointer to the dict.
   Another API is provided to give it a more set-like interface.
*/

SET *set_new(void)
{
  return (SET *)dict_new();
}

int set_add(SET *set, const char *value)
{
  return dict_put((DICT *)set, value, set);
}

char *set_pop(SET *set)
{
  const char *key;
  char *value;
  key = dict_getany((DICT *)set);
  if (key == NULL)
    return NULL; /* no more entries in set */
  /* remove the entry from the dict and return a copy */
  value = strdup(key);
  dict_put((DICT *)set, key, NULL);
  return value;
}

int set_contains(SET *set, const char *value)
{
  return dict_get((DICT *)set, value) != NULL;
}

void set_free(SET *set)
{
  dict_free((DICT *)set);
}

const char **set_tolist(SET *set)
{
  return dict_keys((DICT *)set);
}
