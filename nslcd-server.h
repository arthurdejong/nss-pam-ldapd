/*
   nslcd-server.h - server socket routines

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

#ifndef _NSLCD_SERVER_H
#define _NSLCD_SERVER_H 1

#include "nslcd.h"

/* returns a socket ready to answer requests from the client,
   return <0 on error */
int nslcd_server_open(void);

/* read a request message, returns <0 in case of errors,
   this function closes the socket */
int nslcd_server_handlerequest(int sock);

/* LDAP methods */

/* the caller should take care of opening and closing the stream */
int nslcd_getpwnam(FILE *fp,const char *name);

#define WRITE(fp,ptr,size) \
  if (fwrite(ptr,size,1,fp)<1) \
    { fclose(fp); return -1; }

#define WRITE_INT32(fp,i) \
  tmpint32=(int32_t)(i); \
  WRITE(fp,&tmpint32,sizeof(int32_t))

#define WRITE_STRING(fp,str) \
  /* write the size of the string */ \
  WRITE_INT32(fp,strlen(str)); \
  /* write the string itself */ \
  WRITE(fp,str,strlen(str));

#define READ(fp,ptr,size) \
  if (fread(ptr,size,1,fp)<1) \
    { fclose(fp); return -1; }

#define READ_INT32(fp,i) \
  READ(fp,&tmpint32,sizeof(int32_t)); \
  i=tmpint32;
  
#define READ_STRING(fp,field,buffer) \
  /* read the size of the string */ \
  READ(fp,&sz,sizeof(int32_t)); \
  /* FIXME: add error checking and sanity checking */ \
  /* check if read would fit */ \
  if ((bufptr+(size_t)sz+1)>buflen) \
    { fclose(fp); return -1; } /* will not fit */ \
  /* read string from the stream */ \
  READ(fp,buffer+bufptr,(size_t)sz); \
  /* TODO: check that string does not contain \0 */ \
  /* null-terminate string in buffer */ \
  buffer[bufptr+sz]='\0'; \
  /* prepare result */ \
  (field)=buffer+bufptr; \
  bufptr+=sz+1;

#endif /* not _NSLCD_SERVER_H */
