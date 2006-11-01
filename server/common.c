/*
   common.c - common server code routines

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

#include "nslcd.h"
#include "common.h"

/* translates a nslcd return code (as defined in nslcd.h) to
   a nss code (as defined in nss.h) */
/* FIXME: this is a temporary hack, get rid of it */
int nss2nslcd(enum nss_status code)
{
  switch (code)
  {
    case NSS_STATUS_UNAVAIL:  return NSLCD_RS_UNAVAIL;
    case NSS_STATUS_NOTFOUND: return NSLCD_RS_NOTFOUND;
    case NSS_STATUS_SUCCESS:  return NSLCD_RS_SUCCESS;
/*    case NSS_STATUS_TRYAGAIN: return NSLCD_RS_SMALLBUF; */
    default:                  return NSLCD_RS_UNAVAIL;
  }
}
