/*
   test_tio_timeout.c - tests for tio deadline calculations
   This file is part of the nss-pam-ldapd library.

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

/* we include the source because we want to test static methods */
#include "../common/tio.c"

#include <assert.h>

int main(int UNUSED(argc), char UNUSED(*argv[]))
{
  struct timespec deadline = {0, 0};
  int timeout = 100 * 1000;
  int sleeptime = 1000;
  int low = -100;
  int high = 200;
  int res;
  int ok;
  /* initialise deadline */
  assert(tio_time_remaining(&deadline, timeout) == timeout);
  /* wait one second */
  sleep(sleeptime / 1000);
  /* re-calculate the deadline */
  res = tio_time_remaining(&deadline, timeout);
  /* it should be timeout - sleeptime */
  res = timeout - sleeptime - res;
  ok = (res > low) && (res < high);
  printf("%s: %d msec difference (%swithin %d...%d msec)\n",
         ok ? "OK" : "FAIL", res, ok ? "" : "NOT ",
         low, high);
  return !ok;
}
