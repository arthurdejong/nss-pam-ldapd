/*
   dict.h - dictionary functions
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

#ifndef _DICT_H
#define _DICT_H

/*
   These functions provide a mapping between a case insensitive
   string and a pointer.
*/
typedef struct dictionary DICT;

/* Create a new instance of a dictionary. Returns NULL
   in case of memory allocation errors. */
DICT *dict_new(void);

/* Add a relation in the dictionary. The key is duplicated
   and can be reused by the caller. The pointer is just stored.
   This function returns non-0 in case of memory allocation
   errors. If the key was previously in use the value
   is replaced. All key comparisons are case insensitive. */
int dict_put(DICT *dict,const char *key,const void *value);

/* Look up a key in the dictionary and return the associated
   value. NULL is returned if the key is not found in the dictionary.
   All key comparisons are case insensitive. */
const void *dict_get(DICT *dict,const char *key); 

/* Delete a key-value association from the dictionary.
   All key comparisons are case insensitive. */
/*void dict_del(LEGACYDICT *dict,const char *key);*/

/* Remove the dictionary from memory. All allocated storage
   for the dictionary and the keys is freed. */
void dict_free(DICT *dict);

/* Function for looping over all dictionary values.
   This resets the search to the beginning of the dictionary.
   This is required before calling dict_values_next(); */
void dict_values_first(DICT *dict);

/* Function for looping over all dictionary values.
   This returns a stored value. NULL is returned when all
   stored values have been returned. */
const void *dict_values_next(DICT *dict);

#endif /* _DICT_H */
