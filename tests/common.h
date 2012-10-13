/*
   common.h - common test routines
   This file is part of the nss-pam-ldapd library.

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

#ifndef TEST__COMMON_H
#define TEST__COMMON_H 1

#include <errno.h>

#ifndef __ASSERT_FUNCTION
#define __ASSERT_FUNCTION ""
#endif /* not __ASSERT_FUNCTION */

/* try to find the actual assert function */
#ifndef HAVE___ASSERT_FAIL
/* for Solaris: */
#ifdef sun
#define __assert_fail(assertion,file,line,function) __assert(assertion,file,line)
#endif
/* for FreeBSD: */
#ifdef __FreeBSD__
#define __assert_fail(assertion,file,line,function) __assert(assertion,file,line,function)
#endif
#endif /* not HAVE___ASSERT_FAIL */

/* extra assertion function that epxects both strings to be the same
   (special macro because strcmp() can be a macro that turns ugly in assert) */
#define assertstreq(str1,str2) \
  (assertstreq_impl(str1,str2,"strcmp(" __STRING(str1) "," __STRING(str2) ")==0", \
                    __FILE__, __LINE__, __ASSERT_FUNCTION))

static inline void assertstreq_impl(const char *str1,const char *str2,
                             const char *assertion,const char *file,
                             int line,const char *function)
{
  if (strcmp(str1,str2)!=0)
    __assert_fail(assertion,file,line,function);
}

/* extra assertion function that expects expr to be valid and prints an
   error message that include errno otherwise */
#define assertok(expr) \
  ((expr) \
   ? (void) (0) \
   : __assertok_fail(__STRING(expr),__FILE__,__LINE__,__ASSERT_FUNCTION))


static inline void __assertok_fail(const char *expr,const char *file,
                            int line,const char *function)
{
  char msg[120];
  snprintf(msg,sizeof(msg),"%s (errno=\"%s\")",expr,strerror(errno));
  __assert_fail(msg,file,line,function);
}


#endif /* not TEST__COMMON_H */
