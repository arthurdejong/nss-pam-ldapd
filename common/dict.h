/*
   dict.h - dictionary functions
   This file is part of the nss-pam-ldapd library.

   Copyright (C) 2007, 2008, 2009, 2010, 2012 Arthur de Jong

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

#ifndef COMMON__DICT_H
#define COMMON__DICT_H

#include "compat/attrs.h"

/*
   These functions provide a mapping between a string and a pointer.
*/
typedef struct dictionary DICT;

/* Create a new instance of a dictionary. Returns NULL
   in case of memory allocation errors. */
DICT *dict_new(void)
  LIKE_MALLOC MUST_USE;

/* Add a relation in the dictionary. The key is duplicated
   and can be reused by the caller. The pointer is just stored.
   This function returns non-zero in case of memory allocation
   errors. If the key was previously in use the value
   is replaced. All key comparisons are case sensitive. */
int dict_put(DICT *dict, const char *key, void *value);

/* Look up a key in the dictionary and return the associated
   value. NULL is returned if the key is not found in the dictionary.
   All key comparisons are case sensitive. */
void *dict_get(DICT *dict, const char *key)
  MUST_USE;

/* Get a key from the dictionary that has a value set. The caller does
   not need to free the returned value (it is freed when dict_free()
   is called). */
const char *dict_getany(DICT *dict);

/* Delete a key-value association from the dictionary.
   All key comparisons are case sensitive. */
/*void dict_del(DICT *dict, const char *key);*/

/* Remove the dictionary from memory. All allocated storage
   for the dictionary and the keys is freed.
   Note that values are not freed. This is the responsibility
   of the caller. */
void dict_free(DICT *dict);

/* Return the keys of the dict as a list of strings.
   The caller should free the memory with a single call to free(). */
const char **dict_keys(DICT *dict)
  MUST_USE;

#endif /* COMMON__DICT_H */
