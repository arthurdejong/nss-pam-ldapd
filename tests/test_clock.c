/*
   test_clock.c - tests for finding usable system clocks
   This file is part of the nss-pam-ldapd library.

   Copyright (C) 2013-2015 Arthur de Jong

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
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "compat/attrs.h"

/* use clock_gettime() to see if the specified clock is supported */
static int test_clock_gettime(clockid_t c, const char *cname)
{
  struct timespec t1 = {0, 0};
  struct timespec t2 = {0, 0};
  struct timespec t3 = {0, 50 * 1000 * 1000}; /* 50 msec */
  struct timespec t4 = {0, 0};
  long diff;
  int result = 0;
  /* see if we can get resolution (not important so ignore any failures) */
  errno = 0;
  if (clock_getres(c, &t1))
    printf("     clock %s resolution not supported: %s\n", cname, strerror(errno));
  if ((t1.tv_sec != 0) || (t1.tv_nsec != 0))
    printf("     clock %s resolution: %ld.%09ld\n", cname, (long)t1.tv_sec, (long)t1.tv_nsec);
  /* see if we can get the time */
  errno = 0;
  if (clock_gettime(c, &t2))
  {
    printf("FAIL clock %s get time not supported: %s\n",
           cname, strerror(errno));
    if ((t2.tv_sec != 0) || (t2.tv_nsec != 0))
      printf("     clock %s time: %ld.%09ld\n", cname, (long)t2.tv_sec, (long)t2.tv_nsec);
    return -1;
  }
  else
    printf("OK   clock %s time: %ld.%09ld\n", cname, (long)t2.tv_sec, (long)t2.tv_nsec);
  /* quick sleep (assume we're not interrupted) */
  (void)nanosleep(&t3, NULL);
  /* see if we can get the time again */
  errno = 0;
  if (clock_gettime(c, &t4))
  {
    printf("FAIL clock %s get time twice not supported: %s\n",
           cname, strerror(errno));
    if ((t4.tv_sec != 0) || (t4.tv_nsec != 0))
      printf("     clock %s time: %ld.%09ld\n", cname, (long)t4.tv_sec, (long)t4.tv_nsec);
    return -1;
  }
  else
    printf("OK   clock %s time: %ld.%09ld\n", cname, (long)t4.tv_sec, (long)t4.tv_nsec);
  /* calculate difference */
  diff = ((long)t4.tv_sec - (long)t2.tv_sec - (long)t3.tv_sec) * 1000000000L +
         ((long)t4.tv_nsec - (long)t2.tv_nsec - (long)t3.tv_nsec);
  if ((diff < (-10 * 1000 * 1000)) || (diff > (20 * 1000 * 1000)))
  {
    result = -1;
    printf("FAIL ");
  }
  else
    printf("OK   ");
  printf("clock %s time diff: %s%ld.%09ld %.1f%%\n", cname, (diff < 0) ? "-" : "",
         (labs(diff) / 1000000000L), (labs(diff) % 1000000000L),
         (float)labs(diff) / (float)((long)t3.tv_sec * 10000000L + (long)t3.tv_nsec / 100));
  return result;
}

/* wrapper for test_clock_gettime() that passes the clock name */
#define TEST_CLOCK_GETTIME(clock) test_clock_gettime(clock, #clock)

int main(int UNUSED(argc), char UNUSED(*argv[]))
{
  int found_clocks = 0;
#ifdef CLOCK_MONOTONIC_RAW
  if (!TEST_CLOCK_GETTIME(CLOCK_MONOTONIC_RAW))
    found_clocks++;
#endif
#ifdef CLOCK_MONOTONIC_FAST
  if (!TEST_CLOCK_GETTIME(CLOCK_MONOTONIC_FAST))
    found_clocks++;
#endif
#ifdef CLOCK_MONOTONIC_COARSE
  if (!TEST_CLOCK_GETTIME(CLOCK_MONOTONIC_COARSE))
    found_clocks++;
#endif
#ifdef CLOCK_MONOTONIC
  if (!TEST_CLOCK_GETTIME(CLOCK_MONOTONIC))
    found_clocks++;
#endif
#ifdef CLOCK_UPTIME_FAST
  if (!TEST_CLOCK_GETTIME(CLOCK_UPTIME_FAST))
    found_clocks++;
#endif
#ifdef CLOCK_UPTIME
  if (!TEST_CLOCK_GETTIME(CLOCK_UPTIME))
    found_clocks++;
#endif
#ifdef CLOCK_BOOTTIME
  if (!TEST_CLOCK_GETTIME(CLOCK_BOOTTIME))
    found_clocks++;
#endif
#ifdef CLOCK_MONOTONIC_PRECISE
  if (!TEST_CLOCK_GETTIME(CLOCK_MONOTONIC_PRECISE))
    found_clocks++;
#endif
#ifdef CLOCK_UPTIME_PRECISE
  if (!TEST_CLOCK_GETTIME(CLOCK_UPTIME_PRECISE))
    found_clocks++;
#endif
#ifdef CLOCK_HIGHRES
#if CLOCK_HIGHRES == CLOCK_MONOTONIC
  printf("     CLOCK_HIGHRES == CLOCK_MONOTONIC\n");
#else
  /* for Solaris, should be similar to CLOCK_MONOTONIC (it may be an alias) */
  if (!TEST_CLOCK_GETTIME(CLOCK_HIGHRES))
    found_clocks++;
#endif
#endif
#ifdef CLOCK_REALTIME_FAST
  if (!TEST_CLOCK_GETTIME(CLOCK_REALTIME_FAST))
    found_clocks++;
#endif
#ifdef CLOCK_REALTIME_COARSE
  if (!TEST_CLOCK_GETTIME(CLOCK_REALTIME_COARSE))
    found_clocks++;
#endif
  if (!TEST_CLOCK_GETTIME(CLOCK_REALTIME))
    found_clocks++;
#ifdef CLOCK_REALTIME_PRECISE
  if (!TEST_CLOCK_GETTIME(CLOCK_REALTIME_PRECISE))
    found_clocks++;
#endif
  printf("%d usable clocks found\n", found_clocks);
  return !(found_clocks > 0);
}
