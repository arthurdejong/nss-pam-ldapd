/*
   strndup.c - implementation of strndup() for systems that lack it

   Copyright (C) 2011, 2012 Arthur de Jong

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

#include <stdlib.h>
#include <string.h>

#include "strndup.h"

/* this is a strndup() replacement for systems that don't have it
   (strndup() is in POSIX 2008 now) */
char *strndup(const char *s, size_t size)
{
  char *result;
  result = (char *)malloc(size + 1);
  if (result != NULL)
  {
    strncpy(result, s, size);
    result[size] = '\0';
  }
  return result;
}
