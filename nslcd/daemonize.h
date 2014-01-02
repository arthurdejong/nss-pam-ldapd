/*
   daemonize.h - definition of functions for daemonising an application

   Copyright (C) 2014 Arthur de Jong

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

#ifndef NSLCD__DAEMONINZE_H
#define NSLCD__DAEMONINZE_H 1

/*
   To properly run as a daemon an application should:

   - close all open file descriptors (see daemonize_closefds() for that)
   - (re)set proper signal handlers and signal mask
   - sanitise the environment
   - fork() / setsid() / fork() to detach from terminal, become process
     leader and run in the background (see daemonize_demon() for that)
   - reconnect stdin/stdout/stderr to /dev/null (see
     daemonize_redirect_stdio() for that)
   - set the umask to a reasonable value
   - chdir(/) to avoid locking any mounts
   - drop privileges as appropriate
   - chroot() if appropriate
   - create and lock a pidfile
   - exit the starting process if initialisation is complete (see
     daemonize_ready() for that)
*/

/* This closes all open file descriptors, except stdin, stdout and stderr. */
void daemonize_closefds(void);

/* Redirect stdio, stdin and stderr to /dev/null. */
void daemonize_redirect_stdio(void);

/* Detach from the controlling terminal and run in the background. This
   function does:
   - double fork and exit first child
   - in the first child call setsid() to detach from any terminal and
     create an independent session
   - keep the parent process waiting until a call to daemonize_ready() is
     done by the deamon process
   This function returns either an error which indicates that the
   daemonizing failed for some reason (usually sets errno), or returns
   without error indicating that the process has been daemonized. */
int daemonize_daemon(void);

/* Signal that the original parent may exit because the service has been
   initialised. The status indicates the exit code of the original process and
   message, if not NULL or an empty string, is printed to stderr. */
void daemonize_ready(int status, const char *message);

#endif /* not NSLCD__DAEMONINZE_H */
