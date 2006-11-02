/*
   nslcd-client.c - request/response functions for nslcd communication

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

#ifndef _NSLCD_CLIENT_H
#define _NSLCD_CLIENT_H 1

#include <stdio.h>

#include "nslcd.h"
#include "nslcd-common.h"

/* returns a socket to the server or NULL on error (see errno),
   socket should be closed with fclose() */
FILE *nslcd_client_open(void);

/* open a client socket */
#define OPEN_SOCK(fp) \
  if ((fp=nslcd_client_open())==NULL) \
    { ERROR_OUT_OPENERROR }

#define WRITE_REQUEST(fp,req) \
  WRITE_INT32(fp,NSLCD_VERSION) \
  WRITE_INT32(fp,req)

#define READ_RESPONSEHEADER(fp,req) \
  READ_TYPE(fp,tmpint32,int32_t); \
  if (tmpint32!=NSLCD_VERSION) \
    { ERROR_OUT_READERROR(fp) } \
  READ_TYPE(fp,tmpint32,int32_t); \
  if (tmpint32!=(req)) \
    { ERROR_OUT_READERROR(fp) }

#define READ_RESPONSE_CODE(fp) \
  READ_TYPE(fp,tmpint32,int32_t); \
  if (tmpint32!=NSLCD_RESULT_SUCCESS) \
    { ERROR_OUT_NOSUCCESS(fp,tmpint32) }

#endif /* not _NSLCD_CLIENT_H */
