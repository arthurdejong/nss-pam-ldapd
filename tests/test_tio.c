/*
   test_tio.c - simple test for the tio module
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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif /* HAVE_STDINT_H */
#include <stdlib.h>

#include "common/tio.h"

/* structure for passing arguments to helper (is a thread) */
struct helper_args {
  int fd;
  size_t blocksize;
  size_t blocks;
  int timeout;
};

static void *help_tiowriter(void *arg)
{
  TFILE *fp;
  struct timeval timeout;
  size_t i,j,k;
  uint8_t *buf;
  struct helper_args *hargs=(struct helper_args *)arg;
  /* allocate the buffer */
  buf=(uint8_t *)malloc(hargs->blocksize);
  assert(buf!=NULL);
  /* set the timeout */
  timeout.tv_sec=hargs->timeout;
  timeout.tv_usec=0;
  /* open the file */
  fp=tio_fdopen(hargs->fd,&timeout,&timeout);
  assert(fp!=NULL);
  /* write the blocks */
  i=0;
  for (k=0;k<hargs->blocks;k++)
  {
    /* fill the buffer */
    for (j=0;j<hargs->blocksize;j++)
      buf[j]=i++;
    assert(tio_write(fp,buf,hargs->blocksize)==0);
  }
  /* close the file flushing the buffer */
  assert(tio_close(fp)==0);
  /* we're done */
  free(buf);
  return NULL;
}

static void *help_tioreader(void *arg)
{
  TFILE *fp;
  struct timeval timeout;
  size_t i,j,k;
  uint8_t *buf;
  struct helper_args *hargs=(struct helper_args *)arg;
  /* allocate the buffer */
  buf=(uint8_t *)malloc(hargs->blocksize);
  assert(buf!=NULL);
  /* set the timeout */
  timeout.tv_sec=hargs->timeout;
  timeout.tv_usec=0;
  /* open the file */
  fp=tio_fdopen(hargs->fd,&timeout,&timeout);
  assert(fp!=NULL);
  /* read the blocks */
  i=0;
  for (k=0;k<hargs->blocks;k++)
  {
    assert(tio_read(fp,buf,hargs->blocksize)==0);
    /* check the buffer */
    for (j=0;j<hargs->blocksize;j++)
      assert(buf[j]==(uint8_t)(i++));
  }
  /* close the file */
  assert(tio_close(fp)==0);
  /* we're done */
  free(buf);
  return NULL;
}

static void *help_normwriter(void *arg)
{
  FILE *fp;
  size_t i,j,k;
  uint8_t *buf;
  struct helper_args *hargs=(struct helper_args *)arg;
  /* allocate the buffer */
  buf=(uint8_t *)malloc(hargs->blocksize);
  assert(buf!=NULL);
  /* open the file */
  fp=fdopen(hargs->fd,"wb");
  assert(fp!=NULL);
  /* write the blocks */
  i=0;
  for (k=0;k<hargs->blocks;k++)
  {
    /* fill the buffer */
    for (j=0;j<hargs->blocksize;j++)
      buf[j]=i++;
    assert(fwrite(buf,hargs->blocksize,1,fp)==1);
  }
  /* close the file flushing the buffer */
  assert(fclose(fp)==0);
  /* we're done */
  free(buf);
  return NULL;
}

static void *help_normreader(void *arg)
{
  FILE *fp;
  size_t i,j,k;
  struct helper_args *hargs=(struct helper_args *)arg;
  /* open the file */
  fp=fdopen(hargs->fd,"rb");
  assert(fp!=NULL);
  /* read the blocks */
  i=0;
  for (k=0;k<hargs->blocks;k++)
  {
    /* check the buffer */
    for (j=0;j<hargs->blocksize;j++)
      assert(fgetc(fp)==(uint8_t)(i++));
  }
  /* close the file */
  assert(fclose(fp)==0);
  return NULL;
}

/*
TODO: test timeout
TODO: test whether a simple request/response works
*/

static int test_blocks(size_t wbs, size_t wbl, size_t rbs, size_t rbl)
{
  int sp[2];
  pthread_t wthread, rthread;
  struct helper_args wargs,rargs;
  /* set up the socket pair */
  assert(socketpair(AF_UNIX,SOCK_STREAM,0,sp)==0);
  /* log */
  printf("test_tio: writing %d blocks of %d bytes (%d total)\n",wbl,wbs,wbl*wbs);
  printf("test_tio: reading %d blocks of %d bytes (%d total)\n",rbl,rbs,rbl*rbs);
  /* start the writer thread */
  wargs.fd=sp[0];
  wargs.blocksize=wbs;
  wargs.blocks=wbl;
  wargs.timeout=2;
  assert(pthread_create(&wthread,NULL,help_tiowriter,&wargs)==0);
/*  sleep(1); */
  /* start the reader thread */
  rargs.fd=sp[1];
  rargs.blocksize=rbs;
  rargs.blocks=rbl;
  rargs.timeout=2;
  assert(pthread_create(&rthread,NULL,help_tioreader,&rargs)==0);
  /* wait for all threads to die */
  assert(pthread_join(wthread,NULL)==0);
  assert(pthread_join(rthread,NULL)==0);
  /* we're done */
  return 0;
}

static void test_reset(void)
{
  int sp[2];
  pthread_t wthread;
  struct helper_args wargs;
  TFILE *fp;
  struct timeval timeout;
  size_t i,j,k,save;
  uint8_t buf[10];
  /* set up the socket pair */
  assert(socketpair(AF_UNIX,SOCK_STREAM,0,sp)==0);
  /* start the writer thread */
  wargs.fd=sp[0];
  wargs.blocksize=4*1024; /* the current TIO_BUFFERSIZE */
  wargs.blocks=5;
  wargs.timeout=2;
  assert(pthread_create(&wthread,NULL,help_tiowriter,&wargs)==0);
  /* set up read handle */
  timeout.tv_sec=2;
  timeout.tv_usec=0;
  fp=tio_fdopen(sp[1],&timeout,&timeout);
  assert(fp!=NULL);
  /* perform 20 reads */
  i=0;
  for (k=0;k<20;k++)
  {
    assert(tio_read(fp,buf,sizeof(buf))==0);
    /* check the buffer */
    for (j=0;j<sizeof(buf);j++)
      assert(buf[j]==(uint8_t)(i++));
  }
  /* mark and perform another 2 reads */
  tio_mark(fp);
  save=i;
  for (k=0;k<2;k++)
  {
    assert(tio_read(fp,buf,sizeof(buf))==0);
    /* check the buffer */
    for (j=0;j<sizeof(buf);j++)
      assert(buf[j]==(uint8_t)(i++));
  }
  /* reset and perform the same 2 reads again and 500 more */
  assert(tio_reset(fp)==0);
  i=save;
  for (k=0;k<502;k++)
  {
    assert(tio_read(fp,buf,sizeof(buf))==0);
    /* check the buffer */
    for (j=0;j<sizeof(buf);j++)
      assert(buf[j]==(uint8_t)(i++));
  }
  /* check that reset is no longer possible */
  assert(tio_reset(fp)!=0);
  /* read the remainder of the data 1526 reads */
  for (k=0;k<1526;k++)
  {
    assert(tio_read(fp,buf,sizeof(buf))==0);
    /* check the buffer */
    for (j=0;j<sizeof(buf);j++)
      assert(buf[j]==(uint8_t)(i++));
  }
  /* close the file */
  assert(tio_close(fp)==0);
  /* wait for the writer thread to die */
  assert(pthread_join(wthread,NULL)==0);
}

/* the main program... */
int main(int UNUSED(argc),char UNUSED(*argv[]))
{
  /* normal read-writes */
  test_blocks(400,11,11,400);
  test_blocks(4*1024,11,4*11,1024);
  test_blocks(5*1023,20,20*1023,5);
  /* reader closes file sooner */
/*  test_blocks(2*6*1023,20,20*1023,5); */
/*  test_blocks(10,10,10,9); */
  /* writer closes file sooner */
/*  test_blocks(4*1023,20,20*1023,5); */
/*  test_blocks(10,9,10,10); */
  /* set tio_mark() and tio_reset() functions */
  test_reset();
  return 0;
}
