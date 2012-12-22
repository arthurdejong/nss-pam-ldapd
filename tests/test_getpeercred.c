/*
   test_getpeercred.c - simple test for the peercred module
   This file is part of the nss-pam-ldapd library.

   Copyright (C) 2008, 2011, 2012 Arthur de Jong

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
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#ifdef HAVE_GRP_H
#include <grp.h>
#endif /* HAVE_GRP_H */
#include <errno.h>

#include "common.h"

#include "compat/attrs.h"
#include "compat/getpeercred.h"

/* create a named socket */
static int create_socket(const char *name)
{
  int sock;
  struct sockaddr_un addr;
  /* create a socket */
  assertok((sock = socket(PF_UNIX, SOCK_STREAM, 0)) >= 0);
  /* remove existing named socket */
  unlink(name);
  /* create socket address structure */
  memset(&addr, 0, sizeof(struct sockaddr_un));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, name, sizeof(addr.sun_path));
  addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';
  /* bind to the named socket */
  assertok(bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == 0);
  /* close the file descriptor on exit */
  assertok(fcntl(sock, F_SETFD, FD_CLOEXEC) >= 0);
  /* start listening for connections */
  assertok(listen(sock, SOMAXCONN) >= 0);
  /* we're done */
  return sock;
}

/* accept a connection on the socket */
static int acceptconnection(int sock)
{
  int csock;
  int j;
  struct sockaddr_storage addr;
  socklen_t alen;
  /* accept a new connection */
  alen = (socklen_t)sizeof(struct sockaddr_storage);
  assertok((csock = accept(sock, (struct sockaddr *)&addr, &alen)) >= 0);
  /* make sure O_NONBLOCK is not inherited */
  assertok((j = fcntl(csock, F_GETFL, 0)) >= 0);
  assertok(fcntl(csock, F_SETFL, j & ~O_NONBLOCK) >= 0);
  /* return socket */
  return csock;
}

/* open a connection to the named socket */
static int open_socket(const char *name)
{
  int sock;
  struct sockaddr_un addr;
  /* create a socket */
  assertok((sock = socket(PF_UNIX, SOCK_STREAM, 0)) >= 0);
  /* create socket address structure */
  memset(&addr, 0, sizeof(struct sockaddr_un));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, name, sizeof(addr.sun_path));
  addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';
  /* connect to the socket */
  assertok(connect(sock, (struct sockaddr *)&addr, (socklen_t)sizeof(struct sockaddr_un)) >= 0);
  /* return the socket */
  return sock;
}

#define SOCKETNAME "/tmp/test_getpeercred.sock"

#define assertwarn(assertion)                                               \
  if (!(assertion))                                                         \
    fprintf(stderr, "test_getpeercred: %s:%d: %s: Assertion `%s' failed\n", \
            __FILE__, __LINE__, __ASSERT_FUNCTION, __STRING(assertion));

/* the main program... */
int main(int UNUSED(argc), char UNUSED(*argv[]))
{
  int ssock;
  int csock;
  int fsock;
  uid_t uid;
  gid_t gid;
  pid_t pid;
  /* create a socket to listen on */
  ssock = create_socket(SOCKETNAME);
  /* open a connection to the socket */
  csock = open_socket(SOCKETNAME);
  /* get a connection from the server socket */
  fsock = acceptconnection(ssock);
  /* look up client information */
  assert(getpeercred(fsock, &uid, &gid, &pid) == 0);
  assert(uid == geteuid());
  assertwarn(gid == getegid());
  assertwarn(pid == getpid());
  /* remove the socket */
  unlink(SOCKETNAME);
  return 0;
}
