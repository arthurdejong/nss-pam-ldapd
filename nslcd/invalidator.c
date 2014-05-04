/*
   invalidator.c - functions for invalidating external caches

   Copyright (C) 2013-2014 Arthur de Jong

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
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "common.h"
#include "log.h"

/* the write end of a pipe that is used to signal the child process
   to invalidate the cache */
static int signalfd = -1;

/* we have our own implementation because nscd could use different names */
static const char *map2name(enum ldap_map_selector map)
{
  switch (map)
  {
    case LM_ALIASES:   return "aliases";
    case LM_ETHERS:    return "ethers";
    case LM_GROUP:     return "group";
    case LM_HOSTS:     return "hosts";
    case LM_NETGROUP:  return "netgroup";
    case LM_NETWORKS:  return "networks";
    case LM_PASSWD:    return "passwd";
    case LM_PROTOCOLS: return "protocols";
    case LM_RPC:       return "rpc";
    case LM_SERVICES:  return "services";
    case LM_SHADOW:    return "shadow";
    case LM_NFSIDMAP:  return "nfsidmap";
    case LM_NONE:
    default:           return NULL;
  }
}

/* invalidate the specified database */
static void exec_invalidate(const char *db)
{
  pid_t cpid;
  int i, status;
  char *argv[4];
  char cmdline[80];
#ifdef HAVE_EXECVPE
  char *newenviron[] = { NULL };
#endif
  /* build command line */
  if (strcmp(db, "nfsidmap") == 0)
  {
    argv[0] = "nfsidmap";
    argv[1] = "-c";
    argv[2] = NULL;
  }
  else
  {
    argv[0] = "nscd";
    argv[1] = "-i";
    argv[2] = (char *)db;
    argv[3] = NULL;
  }
  if (mysnprintf(cmdline, 80, "%s %s%s%s", argv[0], argv[1],
                 argv[2] != NULL ? " " : "", argv[2] != NULL ? argv[2] : ""))
  {
    log_log(LOG_ERR, "exec_invalidate(): cmdline buffer too small");
    return;
  }
  log_log(LOG_DEBUG, "invalidator: %s", cmdline);
  /* do fork/exec */
  switch (cpid=fork())
  {
    case 0: /* we are the child */
      /* close all file descriptors */
      i = sysconf(_SC_OPEN_MAX) - 1;
      /* if the system does not have OPEN_MAX just close the first 32 and
         hope we have closed enough */
      if (i < 0)
        i = 32;
      for (; i >= 0; i--)
        close(i);
      /* execute command */
#ifdef HAVE_EXECVPE
      execvpe(argv[0], argv, newenviron);
#else
      execvp(argv[0], argv);
#endif
      /* if we are here there has been an error */
      /* we can't log since we don't have any useful file descriptors */
      _exit(EXIT_FAILURE);
      break;
    case -1: /* we are the parent, but have an error */
      log_log(LOG_ERR, "invalidator: fork() failed: %s", strerror(errno));
      break;
    default: /* we are the parent */
      /* wait for child exit */
      do
      {
        errno = 0;
        i = waitpid(cpid, &status, 0);
      }
      while ((i < 0) && (errno == EINTR));
      if (i < 0)
        log_log(LOG_ERR, "invalidator: waitpid(%d) failed: %s", (int)cpid, strerror(errno));
      else if (WIFEXITED(status))
      {
        i = WEXITSTATUS(status);
        if (i == 0)
          log_log(LOG_DEBUG, "invalidator: %s (pid %d) success",
                  cmdline, (int)cpid);
        else
          log_log(LOG_DEBUG, "invalidator: %s (pid %d) failed (%d)",
                  cmdline, (int)cpid, i);
      }
      else if (WIFSIGNALED(status))
      {
        i = WTERMSIG(status);
        log_log(LOG_ERR, "invalidator: %s (pid %d) killed by %s (%d)",
                cmdline, (int)cpid, signame(i), i);
      }
      else
        log_log(LOG_ERR, "invalidator: %s (pid %d) had unknown failure",
                cmdline, (int)cpid);
      break;
  }
}

/* main loop for the invalidator process */
static void handle_requests(int fd)
{
  int i;
  uint8_t c;
  const char *db;
  log_log(LOG_DEBUG, "invalidator: starting");
  /* set up environment */
  (void)chdir("/");
  putenv("PATH=/usr/sbin:/usr/bin:/sbin:/bin");
  /* handle incoming requests */
  while (1)
  {
    i = read(fd, &c, sizeof(uint8_t));
    if (i == 0)
    {
      log_log(LOG_ERR, "invalidator: EOF");
      _exit(EXIT_SUCCESS);
    }
    else if (i < 0)
    {
      if (errno == EINTR)
        log_log(LOG_DEBUG, "invalidator: read failed (ignored): %s",
                strerror(errno));
      else
      {
        log_log(LOG_ERR, "invalidator: read failed: %s", strerror(errno));
        _exit(EXIT_SUCCESS);
      }
    }
    else
    {
      db = map2name((enum ldap_map_selector)c);
      if (db == NULL)
        log_log(LOG_ERR, "invalidator: invalid db received");
      else
        exec_invalidate(db);
    }
  }
}

/* start a child process that holds onto the original privileges with the
   purpose of running external cache invalidation commands */
int invalidator_start(void)
{
  int pipefds[2];
  pid_t cpid;
  int i;
  /* set up a pipe for communication */
  if (pipe(pipefds) < 0)
  {
    log_log(LOG_ERR, "pipe() failed: %s", strerror(errno));
    return -1;
  }
  /* set O_NONBLOCK on the write end to ensure that a hanging invalidator
     process does not bring down the rest of the application */
  if ((i = fcntl(pipefds[1], F_GETFL, 0)) < 0)
  {
    log_log(LOG_ERR, "fctnl(F_GETFL) failed: %s", strerror(errno));
    close(pipefds[0]);
    close(pipefds[1]);
    return -1;
  }
  if (fcntl(pipefds[1], F_SETFL, i | O_NONBLOCK) < 0)
  {
    log_log(LOG_ERR, "fctnl(F_SETFL,O_NONBLOCK) failed: %s", strerror(errno));
    close(pipefds[0]);
    close(pipefds[1]);
    return -1;
  }
  /* fork a child to perfrom the invalidate commands */
  cpid = fork();
  if (cpid < 0)
  {
    log_log(LOG_ERR, "fork() failed: %s", strerror(errno));
    close(pipefds[0]);
    close(pipefds[1]);
    return -1;
  }
  if (cpid == 0)
  {
    /* we are the child: close the write end and handle requests */
    close(pipefds[1]);
    handle_requests(pipefds[0]);
    /* the handle function should't return */
    _exit(EXIT_FAILURE);
  }
  /* we are the parent: close the read end and save the write end */
  close(pipefds[0]);
  signalfd = pipefds[1];
  return 0;
}

/* signal invalidator to invalidate the selected external cache */
void invalidator_do(enum ldap_map_selector map)
{
  uint8_t c;
  int rc;
  if (signalfd < 0)
    return;
  /* LM_NONE is used to signal all maps condigured in reconnect_invalidate */
  if (map == LM_NONE)
  {
    for (map = 0; map < LM_NONE ; map++)
      if (nslcd_cfg->reconnect_invalidate[map])
        invalidator_do(map);
    return;
  }
  /* write a single byte which should be atomic and not fill the PIPE
     buffer too soon on most platforms
     (nslcd should already ignore SIGPIPE) */
  c = (uint8_t)map;
  rc = write(signalfd, &c, sizeof(uint8_t));
  if (rc <= 0)
    log_log(LOG_WARNING, "error signalling invalidator: %s",
            strerror(errno));
}
