/*
   common.c - common server code routines
   This file is part of the nss-ldapd library.

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006 Arthur de Jong

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

#include "nslcd.h"
#include "common.h"

/* translates a nslcd return code (as defined in nslcd.h) to
   a nss code (as defined in nss.h) */
/* FIXME: this is a temporary hack, get rid of it */
int nss2nslcd(enum nss_status code)
{
  switch (code)
  {
    case NSS_STATUS_UNAVAIL:  return NSLCD_RESULT_UNAVAIL;
    case NSS_STATUS_NOTFOUND: return NSLCD_RESULT_NOTFOUND;
    case NSS_STATUS_SUCCESS:  return NSLCD_RESULT_SUCCESS;
/*    case NSS_STATUS_TRYAGAIN: return NSLCD_RS_SMALLBUF; */
    default:                  return NSLCD_RESULT_UNAVAIL;
  }
}
