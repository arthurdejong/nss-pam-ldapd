/*
   tio.h - timed io functions
   This file is part of the nss-ldapd library.

   Copyright (C) 2007 Arthur de Jong

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

/*

   Add some documentation here.

   the SIGPIPE signal should be ignored

*/

#ifndef _TIO_H
#define _TIO_H

#include <sys/time.h>
#include <sys/types.h>

#include "compat/attrs.h"

/* generic file handle used for reading and writing
   (something like FILE from stdio.h) */
typedef struct tio_fileinfo TFILE;

/* Open a new TFILE based on the file descriptor.
   The timeout is set for any operation.
   the timeout value is copied so may be dereferenced after the call. */
TFILE *tio_fdopen(int fd,struct timeval *readtimeout,struct timeval *writetimeout)
  LIKE_MALLOC MUST_USE;

/* Read the specified number of bytes from the stream. */
int tio_read(TFILE *fp, void *buf, size_t count);

/* Read and discard the specified number of bytes from the stream. */
int tio_skip(TFILE *fp, size_t count);

/* Write the specified buffer to the stream. */
int tio_write(TFILE *fp, const void *buf, size_t count);

/* Write out all buffered data to the stream. */
int tio_flush(TFILE *fp);

/* this also closes the underlying file descriptor */
int tio_close(TFILE *fp);

#endif /* _TIO_H */
