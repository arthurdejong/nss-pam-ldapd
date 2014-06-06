/*
   lookup_groupbyuser.c - simple lookup for groups by user

   Copyright (C) 2014 Arthur de Jong

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
#include <unistd.h>
#include <grp.h>

#ifndef HAVE_GETGROUPLIST
/* dummy implementation that for systems without getgrouplist() */
int main(int argc,char *argv[])
{
  fprintf(stderr, "%s: getgrouplist() not available\n", argv[0]);
  return 1;
}
#else /* HAVE_GETGROUPLIST */

/* the main program... */
int main(int argc,char *argv[])
{
  gid_t groups[1024];
  int ngroups = sizeof(groups);
  int i;
  /* check arguments */
  if ((argc != 1) && (argc != 2))
  {
    fprintf(stderr, "Usage: %s [USERNAME]\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  /* start lookup */
  if (getgrouplist(argv[1], (gid_t)-1, groups, &ngroups) < 0)
  {
    fprintf(stderr, "getgrouplist() failed (%d entries would be returned)\n",
            ngroups);
    exit(EXIT_FAILURE);
  }
  /* print results */
  printf("user=%s groups=", argv[1]);
  for (i = 0; i < ngroups; i++)
  {
    if (groups[i] != (gid_t)-1)
    {
      if (i > 0)
        printf(",");
      printf("%d", groups[i]);
    }
  }
  printf("\n");
  return 0;
}

#endif /* HAVE_GETGROUPLIST */
