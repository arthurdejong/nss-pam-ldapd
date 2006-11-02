/*
   common.c - common functions for NSS lookups

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006 Arthur de Jong

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
   MA 02110-1301 USA
*/

#include "config.h"

#include <nss.h>

#include "nslcd.h"
#include "common.h"

/* translates a nsklcd return code (as defined in nslcd.h) to
   a nss code (as defined in nss.h) */
enum nss_status nslcd2nss(int code)
{
  switch (code)
  {
    case NSLCD_RESULT_UNAVAIL:  return NSS_STATUS_UNAVAIL;
    case NSLCD_RESULT_NOTFOUND: return NSS_STATUS_NOTFOUND;
    case NSLCD_RESULT_SUCCESS:  return NSS_STATUS_SUCCESS;
    default:                return NSS_STATUS_UNAVAIL;
  }
}
