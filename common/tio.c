/*
   tio.c - timed io functions
   This file is part of the nss-ldapd library.

   Copyright (C) 2007, 2008 Arthur de Jong

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

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>

#include "tio.h"

/* for platforms that don't have ETIME use ETIMEDOUT */
#ifndef ETIME
#define ETIME ETIMEDOUT
#endif /* ETIME */

/* buffer size for both read and write buffers */
/* TODO: pass this along with the open function */
/* Note that this size should not be larger than SSIZE_MAX because otherwise
   write() of such blocks is undefined */
#define TIO_BUFFERSIZE (4*1024)

/* structure that holds a buffer */
struct tio_buffer {
  uint8_t *buffer;
  /* the size is TIO_BUFFERSIZE */
  size_t len; /* the number of bytes used in the buffer (from the start) */
  int start; /* the start of the buffer (space before the start is unused) */
};

/* structure that holds all the state for files */
struct tio_fileinfo {
  int fd;
  struct tio_buffer *readbuffer;
  struct tio_buffer *writebuffer;
  struct timeval readtimeout;
  struct timeval writetimeout;
  int read_resettable; /* whether the tio_reset() function can be called */
#ifdef DEBUG_TIO_STATS
  /* this is used to collect statistics on the use of the streams
     and can be used to tune the buffer sizes */
  size_t byteswritten;
  size_t bytesread;
#endif /* DEBUG_TIO_STATS */
};

/* add the second timeval to the first modifing the first */
static inline void tio_tv_add(struct timeval *tv1, const struct timeval *tv2)
{
  /* BUG: we hope that this does not overflow */
  tv1->tv_usec+=tv2->tv_usec;
  if (tv1->tv_usec>1000000)
  {
    tv1->tv_usec-=1000000;
    tv1->tv_sec+=1;
  }
  tv1->tv_sec+=tv2->tv_sec;
}

/* build a timeval for comparison to when the operation should be finished */
static inline void tio_tv_prepare(struct timeval *deadline, const struct timeval *timeout)
{
  if (gettimeofday(deadline,NULL))
  {
    /* just blank it in case of errors */
    deadline->tv_sec=0;
    deadline->tv_usec=0;
    return;
  }
  tio_tv_add(deadline,timeout);
}

static inline struct tio_buffer *tio_buffer_new(void)
{
  struct tio_buffer *buf;
  /* allocate memory */
  buf = (struct tio_buffer *)malloc(sizeof(struct tio_buffer)+TIO_BUFFERSIZE);
  if (buf==NULL)
    return NULL;
  /* initialize struct */
  buf->buffer=((uint8_t *)buf)+sizeof(struct tio_buffer);
  buf->len=0;
  buf->start=0;
  return buf;
}

static inline void tio_buffer_free(struct tio_buffer *buf)
{
  /* since we allocated only one block we can just free it */
  free(buf);
}

/* update the timeval to the value that is remaining before deadline
   returns non-zero if there is no more time before the deadline */
static inline int tio_tv_remaining(struct timeval *tv, const struct timeval *deadline)
{
  /* get the current time */
  if (gettimeofday(tv,NULL))
  {
    /* 1 second default if gettimeofday() is broken */
    tv->tv_sec=1;
    tv->tv_usec=0;
    return 0;
  }
  /* check if we're too late */
  if ( (tv->tv_sec>deadline->tv_sec) ||
       ( (tv->tv_sec==deadline->tv_sec) && (tv->tv_usec>deadline->tv_usec) ) )
    return -1;
  /* update tv */
  tv->tv_sec=deadline->tv_sec-tv->tv_sec;
  if (tv->tv_usec<deadline->tv_usec)
    tv->tv_usec=deadline->tv_usec-tv->tv_usec;
  else
  {
    tv->tv_sec--;
    tv->tv_usec=1000000+deadline->tv_usec-tv->tv_usec;
  }
  return 0;
}

/* open a new TFILE based on the file descriptor */
TFILE *tio_fdopen(int fd,struct timeval *readtimeout,struct timeval *writetimeout)
{
  struct tio_fileinfo *fp;
  fp=(struct tio_fileinfo *)malloc(sizeof(struct tio_fileinfo));
  if (fp==NULL)
    return NULL;
  fp->fd=fd;
  fp->readbuffer=NULL;
  fp->writebuffer=NULL;
  fp->readtimeout.tv_sec=readtimeout->tv_sec;
  fp->readtimeout.tv_usec=readtimeout->tv_usec;
  fp->writetimeout.tv_sec=writetimeout->tv_sec;
  fp->writetimeout.tv_usec=writetimeout->tv_usec;
  fp->read_resettable=0;
#ifdef DEBUG_TIO_STATS
  fp->byteswritten=0;
  fp->bytesread=0;
#endif /* DEBUG_TIO_STATS */
  return fp;
}

/* wait for any activity on the specified file descriptor using
   the specified deadline */
static int tio_select(int fd, int readfd, const struct timeval *deadline)
{
  struct timeval tv;
  fd_set fdset;
  int rv;
  while (1)
  {
    /* prepare our filedescriptorset */
    FD_ZERO(&fdset);
    FD_SET(fd,&fdset);
    /* figure out the time we need to wait */
    if (tio_tv_remaining(&tv,deadline))
    {
      errno=ETIME;
      return -1;
    }
    /* wait for activity */
    if (readfd)
      rv=select(FD_SETSIZE,&fdset,NULL,NULL,&tv);
    else
      rv=select(FD_SETSIZE,NULL,&fdset,NULL,&tv);
    if (rv>0)
      return 0; /* we have activity */
    else if (rv==0)
    {
      /* no file descriptors were available within the specified time */
      errno=ETIME;
      return -1;
    }
    else if (errno!=EINTR)
      /* some error ocurred */
      return -1;
    /* we just try again on EINTR */
  }
}

/* do a read on the file descriptor, returning the data in the buffer
   if no data was read in the specified time an error is returned */
int tio_read(TFILE *fp, void *buf, size_t count)
{
  struct timeval deadline;
  int rv;
  /* have a more convenient storage type for the buffer */
  uint8_t *ptr=(uint8_t *)buf;
  /* ensure that we have a read buffer */
  if (fp->readbuffer==NULL)
  {
    fp->readbuffer=tio_buffer_new();
    if (fp->readbuffer==NULL)
      return -1; /* error allocating buffer */
  }
  /* build a time by which we should be finished */
  tio_tv_prepare(&deadline,&(fp->readtimeout));
  /* loop until we have returned all the needed data */
  while (1)
  {
    /* check if we have enough data in the buffer */
    if (fp->readbuffer->len >= count)
    {
      if (count>0)
      {
        if (ptr!=NULL)
          memcpy(ptr,fp->readbuffer->buffer+fp->readbuffer->start,count);
        /* adjust buffer position */
        fp->readbuffer->start+=count;
        fp->readbuffer->len-=count;
      }
      return 0;
    }
    /* empty what we have and continue from there */
    if (fp->readbuffer->len > 0)
    {
      if (ptr!=NULL)
      {
        memcpy(ptr,fp->readbuffer->buffer+fp->readbuffer->start,fp->readbuffer->len);
        ptr+=fp->readbuffer->len;
      }
      count-=fp->readbuffer->len;
    }
    /* if we have room in the buffer for more don't clear the buffer */
    if ((fp->read_resettable)&&((fp->readbuffer->start+fp->readbuffer->len)<TIO_BUFFERSIZE))
    {
      fp->readbuffer->start+=fp->readbuffer->len;
    }
    else
    {
      fp->readbuffer->start=0;
      fp->read_resettable=0;
    }
    fp->readbuffer->len=0;
    /* wait until we have input */
    if (tio_select(fp->fd,1,&deadline))
      return -1;
    /* read the input in the buffer */
    rv=read(fp->fd,fp->readbuffer->buffer+fp->readbuffer->start,TIO_BUFFERSIZE-fp->readbuffer->start);
    /* check for errors */
    if ((rv==0)||((rv<0)&&(errno!=EINTR)&&(errno!=EAGAIN)))
      return -1; /* something went wrong with the read */
    /* skip the read part in the buffer */
    fp->readbuffer->len=rv;
#ifdef DEBUG_TIO_STATS
    fp->bytesread+=rv;
#endif /* DEBUG_TIO_STATS */
  }
}

/* Read and discard the specified number of bytes from the stream. */
int tio_skip(TFILE *fp, size_t count)
{
  return tio_read(fp,NULL,count);
}

/* write all the data in the buffer to the stream */
int tio_flush(TFILE *fp)
{
  struct timeval deadline;
  struct sigaction act,oldact;
  int rv;
  /* check write buffer presence */
  if (fp->writebuffer==NULL)
    return 0;
/*
FIXME: we have a race condition here (setting and restoring the signal mask), this is a critical region that should be locked
*/

  /* set up sigaction */
  memset(&act,0,sizeof(struct sigaction));
  act.sa_sigaction=NULL;
  act.sa_handler=SIG_IGN;
  sigemptyset(&act.sa_mask);
  act.sa_flags=SA_RESTART;
  /* build a time by which we should be finished */
  tio_tv_prepare(&deadline,&(fp->writetimeout));
  /* loop until we have written our buffer */
  while (fp->writebuffer->len > 0)
  {
    /* wait until we can write */
    if (tio_select(fp->fd,0,&deadline))
      return -1;
    /* ignore SIGPIPE */
    if (sigaction(SIGPIPE,&act,&oldact)!=0)
      return -1; /* error setting signal handler */
    /* write the buffer */
    rv=write(fp->fd,fp->writebuffer->buffer+fp->writebuffer->start,fp->writebuffer->len);
    /* restore the old handler for SIGPIPE */
    if (sigaction(SIGPIPE,&oldact,NULL)!=0)
      return -1; /* error restoring signal handler */
    /* check for errors */
    if ((rv==0)||((rv<0)&&(errno!=EINTR)&&(errno!=EAGAIN)))
      return -1; /* something went wrong with the write */
    /* skip the written part in the buffer */
    if (rv>0)
    {
      fp->writebuffer->start+=rv;
      fp->writebuffer->len-=rv;
#ifdef DEBUG_TIO_STATS
      fp->byteswritten+=rv;
#endif /* DEBUG_TIO_STATS */
    }
  }
  /* clear buffer and we're done */
  fp->writebuffer->start=0;
  fp->writebuffer->len=0;
  return 0;
}

int tio_write(TFILE *fp, const void *buf, size_t count)
{
  size_t fr;
  const uint8_t *ptr=(const uint8_t *)buf;
  /* ensure that we have a write buffer */
  if (fp->writebuffer==NULL)
  {
    fp->writebuffer=tio_buffer_new();
    if (fp->writebuffer==NULL)
      return -1; /* error allocating buffer */
  }
  /* keep filling the buffer until we have bufferred everything */
  while (count>0)
  {
    /* figure out free size in buffer */
    fr=TIO_BUFFERSIZE-(fp->writebuffer->start+fp->writebuffer->len);
    if (count <= fr)
    {
      /* the data fits in the buffer */
      memcpy(fp->writebuffer->buffer+fp->writebuffer->start+fp->writebuffer->len,ptr,count);
      fp->writebuffer->len+=count;
      return 0;
    }
    else if (fr > 0)
    {
      /* fill the buffer */
      memcpy(fp->writebuffer->buffer+fp->writebuffer->start+fp->writebuffer->len,ptr,fr);
      fp->writebuffer->len+=fr;
      ptr+=fr;
      count-=fr;
    }
    /* write the buffer to the stream */
    if (tio_flush(fp))
      return -1;
  }
  return 0;
}

int tio_close(TFILE *fp)
{
  int retv;
  /* write any buffered data */
  retv=tio_flush(fp);
#ifdef DEBUG_TIO_STATS
  /* dump statistics to stderr */
  fprintf(stderr,"DEBUG_TIO_STATS READ=%d WRITTEN=%d\n",fp->bytesread,fp->byteswritten);
#endif /* DEBUG_TIO_STATS */
  /* close file descriptor */
  if (close(fp->fd))
    retv=-1;
  /* free any allocated buffers */
  if (fp->readbuffer!=NULL)
    tio_buffer_free(fp->readbuffer);
  if (fp->writebuffer!=NULL)
    tio_buffer_free(fp->writebuffer);
  /* free the tio struct itself */
  free(fp);
  /* return the result of the earlier operations */
  return retv;
}

void tio_mark(TFILE *fp)
{
  /* ensure that we have a read buffer */
  if (fp->readbuffer==NULL)
  {
    fp->readbuffer=tio_buffer_new();
    if (fp->readbuffer==NULL)
      return; /* error allocating buffer */
  }
  /* move any data in the buffer to the start of the buffer */
  if ((fp->readbuffer->start>0)&&(fp->readbuffer->len>0))
  {
    memmove(fp->readbuffer->buffer,fp->readbuffer->buffer+fp->readbuffer->start,fp->readbuffer->len);
    fp->readbuffer->start=0;
  }
  /* mark the stream as resettable */
  fp->read_resettable=1;
}

int tio_reset(TFILE *fp)
{
  /* check if the stream is (still) resettable */
  if ((!fp->read_resettable)||(fp->readbuffer==NULL))
    return -1;
  /* reset the buffer */
  fp->readbuffer->len+=fp->readbuffer->start;
  fp->readbuffer->start=0;
  return 0;
}
