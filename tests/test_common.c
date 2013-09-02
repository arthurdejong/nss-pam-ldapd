/*
   test_common.c - simple test for the common module
   This file is part of the nss-pam-ldapd library.

   Copyright (C) 2008, 2009, 2011, 2012, 2013 Arthur de Jong

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
#include <assert.h>
#include <sys/stat.h>

#include "nslcd/common.h"
#include "nslcd/cfg.h"
#include "nslcd/log.h"

static void test_isvalidname(void)
{
  assert(isvalidname("arthur"));
  assert(!isvalidname("-arthur"));
  assert(isvalidname("arthur-is-nice"));
  assert(isvalidname("sambamachine$"));
  assert(isvalidname("foo\\bar"));
  assert(!isvalidname("\\foo\\bar"));
  assert(!isvalidname("foo\\bar\\"));
  assert(isvalidname("me"));    /* try short name */
  assert(isvalidname("f"));
  assert(isvalidname("(foo bar)"));
}

/* the main program... */
int main(int UNUSED(argc), char UNUSED(*argv[]))
{
  char *srcdir;
  char fname[100];
  /* build the name of the file */
  srcdir = getenv("srcdir");
  if (srcdir == NULL)
    srcdir = ".";
  snprintf(fname, sizeof(fname), "%s/nslcd-test.conf", srcdir);
  fname[sizeof(fname) - 1] = '\0';
  /* ensure that file is not world readable for configuration parsing to
     succeed */
  (void)chmod(fname, (mode_t)0660);
  /* initialize configuration */
  cfg_init(fname);
  /* partially initialize logging */
  log_setdefaultloglevel(LOG_DEBUG);
  /* run the tests */
  test_isvalidname();
  return 0;
}
