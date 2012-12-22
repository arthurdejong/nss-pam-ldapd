/*
   set.h - set functions
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

#ifndef COMMON__SET_H
#define COMMON__SET_H

#include "compat/attrs.h"

/*
   These functions provide a set of strings in an unordered
   collection.
*/
typedef struct set SET;

/* Create a new instance of a set. Returns NULL
   in case of memory allocation errors. */
SET *set_new(void)
  LIKE_MALLOC MUST_USE;

/* Add a string in the set. The value is duplicated
   and can be reused by the caller.
   This function returns non-zero in case of memory allocation
   errors. All value comparisons are case sensitive. */
int set_add(SET *set, const char *value);

/* Return non-zero if the value is in the set.
   All value comparisons are case sensitive. */
int set_contains(SET *set, const char *value)
  MUST_USE;

/* Get an element from the set and removes it from the set.
   Returns NULL on an empty set. A copy of the string in the set
   is returned, the caller should use free() to free it. */
char *set_pop(SET *set);

/* Remove the set from memory. All allocated storage
   for the set and the values is freed. */
void set_free(SET *set);

/* Return the content of the set as a list of strings.
   The caller should free the memory with a single call to free(). */
const char **set_tolist(SET *set)
  MUST_USE;

#endif /* COMMON__SET_H */
