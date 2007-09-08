/*
   common.c - common server code routines
   This file is part of the nss-ldapd library.

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007 Arthur de Jong

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
#include <stdarg.h>

#include "nslcd.h"
#include "common.h"

/* simple wrapper around snptintf() to return non-0 in case
   of any failure (but always keep string 0-terminated) */
int mysnprintf(char *buffer,size_t buflen,const char *format, ...)
{
  int res;
  va_list ap;
  /* do snprintf */
  va_start(ap,format);
  res=vsnprintf(buffer,buflen,format,ap);
  /* NULL-terminate the string just to be on the safe side */
  buffer[buflen-1]='\0';
  /* check if the string was completely written */
  return ((res<0)||(((size_t)res)>=buflen));
}
