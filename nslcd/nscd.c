/*
   nscd.c - functions for invalidating the nscd cache

   Copyright (C) 2013 Arthur de Jong

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
   to call nscd to invalidate the cache */
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
    case LM_NONE:
    default:           return NULL;
  }
}

/* invalidate the specified database in nscd */
static void exec_invalidate(const char *db)
{
  pid_t cpid;
  int i, status;
  char *argv[] = { "nscd", "-i", NULL, NULL };
#ifdef HAVE_EXECVPE
  char *newenviron[] = { NULL };
#endif
  log_log(LOG_DEBUG, "nscd_invalidator: nscd -i %s", db);
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
      argv[2] = (char *)db;
#ifdef HAVE_EXECVPE
      execvpe("nscd", argv, newenviron);
#else
      execvp("nscd", argv);
#endif
      /* if we are here there has been an error */
      /* we can't log since we don't have any useful file descriptors */
      _exit(EXIT_FAILURE);
      break;
    case -1: /* we are the parent, but have an error */
      log_log(LOG_ERR, "nscd_invalidator: fork() failed: %s", strerror(errno));
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
        log_log(LOG_ERR, "nscd_invalidator: waitpid(%d) failed: %s", cpid, strerror(errno));
      else if (WIFEXITED(status))
      {
        i = WEXITSTATUS(status);
        if (i == 0)
          log_log(LOG_DEBUG, "nscd_invalidator: nscd -i %s (pid %d) success",
                  db, cpid);
        else
          log_log(LOG_DEBUG, "nscd_invalidator: nscd -i %s (pid %d) failed (%d)",
                  db, cpid, i);
      }
      else if (WIFSIGNALED(status))
      {
        i = WTERMSIG(status);
        log_log(LOG_ERR, "nscd_invalidator: nscd -i %s (pid %d) killed by %s (%d)",
                db, cpid, signame(i), i);
      }
      else
        log_log(LOG_ERR, "nscd_invalidator: nscd -i %s (pid %d) had unknown failure",
                db, cpid);
      break;
  }
}

/* main loop for the invalidator process */
static void nscd_handle_requests(int fd)
{
  int i;
  uint8_t c;
  const char *db;
  log_log(LOG_DEBUG, "nscd_invalidator: starting");
  /* set up environment */
  chdir("/");
  putenv("PATH=/usr/sbin:/usr/bin:/sbin:/bin");
  /* handle incoming requests */
  while (1)
  {
    i = read(fd, &c, sizeof(uint8_t));
    if (i == 0)
    {
      log_log(LOG_ERR, "nscd_invalidator: EOF");
      _exit(EXIT_SUCCESS);
    }
    else if (i < 0)
    {
      if (errno == EINTR)
        log_log(LOG_DEBUG, "nscd_invalidator: read failed (ignored): %s",
                strerror(errno));
      else
      {
        log_log(LOG_ERR, "nscd_invalidator: read failed: %s", strerror(errno));
        _exit(EXIT_SUCCESS);
      }
    }
    else
    {
      db = map2name((enum ldap_map_selector)c);
      if (db == NULL)
        log_log(LOG_ERR, "nscd_invalidator: invalid db received");
      else
        exec_invalidate(db);
    }
  }
}

/* start a child process that holds onto the original privileges with the
   sole purpose of running nscd -i commands */
int nscd_start_invalidator(void)
{
  int pipefds[2];
  pid_t cpid;
  int i;
  /* set up a pipe for communication */
  if (pipe(pipefds) == -1)
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
  /* fork a child to perfrom the nscd invalidate commands */
  cpid = fork();
  if (cpid == -1)
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
    nscd_handle_requests(pipefds[0]);
    /* the handle function should't return */
    _exit(EXIT_FAILURE);
  }
  /* we are the parent: close the read end and save the write end */
  close(pipefds[0]);
  signalfd = pipefds[1];
  return 0;
}

/* signal nscd to invalidate the selected map */
void nscd_invalidate(enum ldap_map_selector map)
{
  uint8_t c;
  int rc;
  if (signalfd < 0)
    return;
  /* write a single byte which should be atomic and not fill the PIPE
     buffer too soon on most platforms
     (nslcd should already ignore SIGPIPE) */
  c = (uint8_t)map;
  rc = write(signalfd, &c, sizeof(uint8_t));
  if (rc <= 0)
    log_log(LOG_WARNING, "error signalling nscd invalidator: %s",
            strerror(errno));
}
