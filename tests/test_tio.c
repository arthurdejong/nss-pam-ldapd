/*
   test_tio.c - simple test for the tio module
   This file is part of the nss-pam-ldapd library.

   Copyright (C) 2007, 2008, 2011, 2012, 2013 Arthur de Jong

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
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "common.h"

#include "common/tio.h"

/* for platforms that don't have ETIME use ETIMEDOUT */
#ifndef ETIME
#define ETIME ETIMEDOUT
#endif /* ETIME */

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
  size_t i, j, k;
  uint8_t *buf;
  struct helper_args *hargs = (struct helper_args *)arg;
  /* allocate the buffer */
  buf = (uint8_t *)malloc(hargs->blocksize);
  assert(buf != NULL);
  /* open the file */
  fp = tio_fdopen(hargs->fd, hargs->timeout * 1000, hargs->timeout * 1000,
                  4 * 1024, 8 * 1024, 4 * 1024, 8 * 1024);
  assertok(fp != NULL);
  /* write the blocks */
  i = 0;
  for (k = 0; k < hargs->blocks; k++)
  {
    /* fill the buffer */
    for (j = 0; j < hargs->blocksize; j++)
      buf[j] = i++;
    assertok(tio_write(fp, buf, hargs->blocksize) == 0);
  }
  /* close the file flushing the buffer */
  assertok(tio_close(fp) == 0);
  /* we're done */
  free(buf);
  return NULL;
}

static void *help_tioreader(void *arg)
{
  TFILE *fp;
  size_t i, j, k;
  uint8_t *buf;
  struct helper_args *hargs = (struct helper_args *)arg;
  /* allocate the buffer */
  buf = (uint8_t *)malloc(hargs->blocksize);
  assert(buf != NULL);
  /* open the file */
  fp = tio_fdopen(hargs->fd, hargs->timeout * 1000, hargs->timeout * 1000,
                  4 * 1024, 8 * 1024, 4 * 1024, 8 * 1024);
  assertok(fp != NULL);
  /* read the blocks */
  i = 0;
  for (k = 0; k < hargs->blocks; k++)
  {
    assertok(tio_read(fp, buf, hargs->blocksize) == 0);
    /* check the buffer */
    for (j = 0; j < hargs->blocksize; j++)
      assert(buf[j] == (uint8_t)(i++));
  }
  /* close the file */
  assertok(tio_close(fp) == 0);
  /* we're done */
  free(buf);
  return NULL;
}

static void *help_normwriter(void *arg)
{
  FILE *fp;
  size_t i, j, k;
  uint8_t *buf;
  struct helper_args *hargs = (struct helper_args *)arg;
  /* allocate the buffer */
  buf = (uint8_t *)malloc(hargs->blocksize);
  assert(buf != NULL);
  /* open the file */
  fp = fdopen(hargs->fd, "wb");
  assertok(fp != NULL);
  /* write the blocks */
  i = 0;
  for (k = 0; k < hargs->blocks; k++)
  {
    /* fill the buffer */
    for (j = 0; j < hargs->blocksize; j++)
      buf[j] = i++;
    assertok(fwrite(buf, hargs->blocksize, 1, fp) == 1);
  }
  /* close the file flushing the buffer */
  assertok(fclose(fp) == 0);
  /* we're done */
  free(buf);
  return NULL;
}

static void *help_normreader(void *arg)
{
  FILE *fp;
  size_t i, j, k;
  struct helper_args *hargs = (struct helper_args *)arg;
  /* open the file */
  fp = fdopen(hargs->fd, "rb");
  assertok(fp != NULL);
  /* read the blocks */
  i = 0;
  for (k = 0; k < hargs->blocks; k++)
  {
    /* check the buffer */
    for (j = 0; j < hargs->blocksize; j++)
      assertok(fgetc(fp) == (uint8_t)(i++));
  }
  /* close the file */
  assertok(fclose(fp) == 0);
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
  struct helper_args wargs, rargs;
  /* set up the socket pair */
  assertok(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
  /* log */
  printf("test_tio: writing %d blocks of %d bytes (%d total)\n",
         (int)wbl, (int)wbs, (int)(wbl * wbs));
  printf("test_tio: reading %d blocks of %d bytes (%d total)\n",
         (int)rbl, (int)rbs, (int)(rbl * rbs));
  /* start the writer thread */
  wargs.fd = sp[0];
  wargs.blocksize = wbs;
  wargs.blocks = wbl;
  wargs.timeout = 2;
  assertok(pthread_create(&wthread, NULL, help_tiowriter, &wargs) == 0);
/*  sleep(1); */
  /* start the reader thread */
  rargs.fd = sp[1];
  rargs.blocksize = rbs;
  rargs.blocks = rbl;
  rargs.timeout = 2;
  assertok(pthread_create(&rthread, NULL, help_tioreader, &rargs) == 0);
  /* wait for all threads to die */
  assertok(pthread_join(wthread, NULL) == 0);
  assertok(pthread_join(rthread, NULL) == 0);
  /* we're done */
  return 0;
}

static void test_reset(void)
{
  int sp[2];
  pthread_t wthread;
  struct helper_args wargs;
  TFILE *fp;
  size_t i, j, k, save;
  uint8_t buf[20];
  /* set up the socket pair */
  assertok(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
  /* start the writer thread */
  wargs.fd = sp[0];
  wargs.blocksize = 4 * 1024;
  wargs.blocks = 10;
  wargs.timeout = 2;
  assertok(pthread_create(&wthread, NULL, help_normwriter, &wargs) == 0);
  /* set up read handle */
  fp = tio_fdopen(sp[1], 2000, 2000, 2 * 1024, 4 * 1024, 2 * 1024, 4 * 1024);
  assertok(fp != NULL);
  /* perform 20 reads */
  i = 0;
  for (k = 0; k < 20; k++)
  {
    assertok(tio_read(fp, buf, sizeof(buf)) == 0);
    /* check the buffer */
    for (j = 0; j < sizeof(buf); j++)
      assert(buf[j] == (uint8_t)(i++));
  }
  /* mark and perform another 2 reads */
  tio_mark(fp);
  save = i;
  for (k = 20; k < 22; k++)
  {
    assertok(tio_read(fp, buf, sizeof(buf)) == 0);
    /* check the buffer */
    for (j = 0; j < sizeof(buf); j++)
      assert(buf[j] == (uint8_t)(i++));
  }
  /* check that we can reset */
  assertok(tio_reset(fp) == 0);
  /* perform 204 reads (partially the same as before) */
  i = save;
  for (k = 20; k < 224; k++)
  {
    assert(tio_read(fp, buf, sizeof(buf)) == 0);
    /* check the buffer */
    for (j = 0; j < sizeof(buf); j++)
      assert(buf[j] == (uint8_t)(i++));
  }
  /* check that we can reset */
  assertok(tio_reset(fp) == 0);
  /* perform 502 reads (partially the same) */
  i = save;
  for (k = 20; k < 522; k++)
  {
    assert(tio_read(fp, buf, sizeof(buf)) == 0);
    /* check the buffer */
    for (j = 0; j < sizeof(buf); j++)
      assert(buf[j] == (uint8_t)(i++));
  }
  /* check that reset is no longer possible */
  assertok(tio_reset(fp) != 0);
  /* read the remainder of the data 1526 reads */
  for (k = 522; k < 2048; k++)
  {
    assertok(tio_read(fp, buf, sizeof(buf)) == 0);
    /* check the buffer */
    for (j = 0; j < sizeof(buf); j++)
      assert(buf[j] == (uint8_t)(i++));
  }
  /* close the file */
  assertok(tio_close(fp) == 0);
  /* wait for the writer thread to die */
  assertok(pthread_join(wthread, NULL) == 0);
}

/* this test starts a reader and writer and does not write for a while */
static void test_timeout_reader(void)
{
  int sp[2];
  TFILE *rfp;
  FILE *wfp;
  uint8_t buf[20];
  time_t start, end;
  int saved_errno;
  /* set up the socket pair */
  assertok(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
  /* open the writer */
  assertok((wfp = fdopen(sp[0], "wb")) != NULL);
  /* open the reader */
  assertok((rfp = tio_fdopen(sp[1], 1100, 1100, 2 * 1024, 4 * 1024, 2 * 1024, 4 * 1024)) != NULL);
  printf("test_tio: test_timeout_reader: trying to read a block of %d bytes\n",
         (int)sizeof(buf));
  /* perform a read */
  start = time(NULL);
  errno = 0;
  assertok(tio_read(rfp, buf, sizeof(buf)) != 0);
  saved_errno = errno;
  end = time(NULL);
  printf("test_tio: test_timeout_reader: read 0 blocks of %d bytes in %d second(s) (%s)\n",
         (int)sizeof(buf), (int)(end - start), strerror(saved_errno));
  /* since the read timeout is more than a second end time should be bigger
     than start time */
  assert(end > start);
  /* the error should be timeout */
  assert(saved_errno == ETIME);
  /* close the files */
  assertok(tio_close(rfp) == 0);
  assertok(fclose(wfp) == 0);
}

/* this test starts a writer and an idle reader */
static void test_timeout_writer(void)
{
  int sp[2];
  FILE *rfp;
  TFILE *wfp;
  int i;
  uint8_t buf[20];
  time_t start, end;
  int numblocks = 10000;
  int saved_errno;
  /* set up the socket pair */
  assertok(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
  /* open the reader */
  assertok((rfp = fdopen(sp[0], "rb")) != NULL);
  /* open the writer */
  assertok((wfp = tio_fdopen(sp[1], 1100, 1100, 2 * 1024, 4 * 1024,
                             2 * sizeof(buf), 4 * sizeof(buf) + 1)) != NULL);
  printf("test_tio: test_timeout_writer: trying to write %d blocks of %d bytes\n",
         numblocks, (int)sizeof(buf));
  /* we perform a number of writes to the stream to see if they are buffered */
  start = time(NULL);
  errno = 0;
  for (i = 0; (i < numblocks) && (tio_write(wfp, buf, sizeof(buf)) == 0); i++)
    /* nothing */ ;
  saved_errno = errno;
  end = time(NULL);
  printf("test_tio: test_timeout_writer: written %d blocks of %d bytes in %d second(s) (%s)\n",
       i, (int)sizeof(buf), (int)(end - start), strerror(saved_errno));
  /* at the very least 4 writes should be OK because they filled the tio buffer */
  assert(i >= 4);
  /* but at a certain point the writes should have failed */
  assert(i < numblocks);
  /* since the write timeout is more than a second end time should be bigger
     than start time */
  assert(end > start);
  /* the error should be timeout */
  assert(saved_errno == ETIME);
  /* close the files */
  assertok(tio_close(wfp) != 0); /* fails because of buffered data */
  assertok(fclose(rfp) == 0);
}

/* the main program... */
int main(int UNUSED(argc), char UNUSED(*argv[]))
{
  /* normal read-writes */
  test_blocks(400, 11, 11, 400);
  test_blocks(10 * 1024, 11, 10 * 11, 1024);
  test_blocks(5 * 1023, 20, 20 * 1023, 5);
  /* reader closes file sooner */
/*  test_blocks(2 * 6 * 1023, 20, 20 * 1023, 5); */
/*  test_blocks(10, 10, 10, 9); */
  /* writer closes file sooner */
/*  test_blocks(4 * 1023, 20, 20 * 1023, 5); */
/*  test_blocks(10, 9, 10, 10); */
  /* set tio_mark() and tio_reset() functions */
  test_reset();
  /* test timeout functionality */
  test_timeout_reader();
  test_timeout_writer();
  return 0;
}
