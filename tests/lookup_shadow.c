/*
   lookup_shadow.c - simple lookup code for shadow entries

   Copyright (C) 2013 Arthur de Jong

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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#ifndef HAVE_SHADOW_H
/* dummy implementation that does nothing for FreeBSD */
int main(int argc,char *argv[])
{
  fprintf(stderr, "%s: shadow lookups unsupported\n", argv[0]);
  return 1;
}
#else /* HAVE_SHADOW_H */

#include <shadow.h>

static void print_shadow(struct spwd *result)
{
  printf("%s:%s:", result->sp_namp, result->sp_pwdp);
  if (result->sp_lstchg >= 0)
    printf("%d", (int)result->sp_lstchg);
  printf(":");
  if (result->sp_min >= 0)
    printf("%d", (int)result->sp_min);
  printf(":");
  if (result->sp_max >= 0)
    printf("%d", (int)result->sp_max);
  printf(":");
  if (result->sp_warn >= 0)
    printf("%d", (int)result->sp_warn);
  printf(":");
  if (result->sp_inact >= 0)
    printf("%d", (int)result->sp_inact);
  printf(":");
  if (result->sp_expire >= 0)
    printf("%d", (int)result->sp_expire);
  printf(":");
  if (result->sp_flag >= 0)
    printf("%x", (int)result->sp_flag);
  printf("\n");
}

/* the main program... */
int main(int argc,char *argv[])
{
  struct spwd *result;
  /* check arguments */
  if ((argc != 1) && (argc != 2))
  {
    fprintf(stderr, "Usage: %s [USERNAME]\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  /* start lookup */
  if (argc == 2)
  {
    /* get entry by name */
    errno = 0;
    result = getspnam(argv[1]);
    if (result == NULL)
      exit(EXIT_FAILURE);
    print_shadow(result);
  }
  else /* argc == 1 */
  {
    /* get all entries */
    setspent();
    while ((result = getspent()) != NULL)
      print_shadow(result);
    endspent();
  }
  return 0;
}

#endif /* HAVE_SHADOW_H */
