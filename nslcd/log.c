/*
   log.c - logging funtions

   Copyright (C) 2002, 2003, 2008, 2010, 2011, 2012, 2013 Arthur de Jong

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
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "log.h"

/* set the logname */
#undef PACKAGE
#define PACKAGE "nslcd"

/* default loglevel when no logging is configured */
static int prelogging_loglevel = LOG_INFO;

/* loglevel to use before logging to syslog */
static int loglevel = LOG_INFO;

/* the session id that is set for this thread */
static TLS char *sessionid = NULL;

/* the request identifier that is set for this thread */
static TLS char *requestid = NULL;
#define MAX_REQUESTID_LENGTH 40

/* set loglevel when no logging is configured */
void log_setdefaultloglevel(int pri)
{
  prelogging_loglevel = pri;
}

/* start the logging with the configured logging methods
   if no method is configured yet, logging is done to syslog */
void log_startlogging(void)
{
  openlog(PACKAGE, LOG_PID, LOG_DAEMON);
  prelogging_loglevel = -1;
}

/* indicate that we should clear any session identifiers set by
   log_newsession */
void log_clearsession(void)
{
  /* set the session id to empty */
  if (sessionid != NULL)
    sessionid[0] = '\0';
  /* set the request id to empty */
  if (requestid != NULL)
    requestid[0] = '\0';
}

/* indicate that a session id should be included in the output
   and set it to a new value */
void log_newsession(void)
{
  /* ensure that sessionid can hold a string */
  if (sessionid == NULL)
  {
    sessionid = (char *)malloc(7);
    if (sessionid == NULL)
    {
      fprintf(stderr, "malloc() failed: %s", strerror(errno));
      return; /* silently fail */
    }
  }
  sprintf(sessionid, "%06x", (int)(rand() & 0xffffff));
  /* set the request id to empty */
  if (requestid != NULL)
    requestid[0] = '\0';
}

/* indicate that a request identifier should be included in the output
   from this point on, until log_newsession() is called */
void log_setrequest(const char *format, ...)
{
  va_list ap;
  /* ensure that requestid can hold a string */
  if (requestid == NULL)
  {
    requestid = (char *)malloc(MAX_REQUESTID_LENGTH);
    if (requestid == NULL)
    {
      fprintf(stderr, "malloc() failed: %s", strerror(errno));
      return; /* silently fail */
    }
  }
  /* make the message */
  va_start(ap, format);
  vsnprintf(requestid, MAX_REQUESTID_LENGTH, format, ap);
  requestid[MAX_REQUESTID_LENGTH - 1] = '\0';
  va_end(ap);
}

/* log the given message using the configured logging method */
void log_log(int pri, const char *format, ...)
{
  int res;
  char buffer[200];
  va_list ap;
  /* make the message */
  va_start(ap, format);
  res = vsnprintf(buffer, sizeof(buffer), format, ap);
  if ((res < 0) || (res >= (int)sizeof(buffer)))
  {
    /* truncate with "..." */
    buffer[sizeof(buffer) - 2] = '.';
    buffer[sizeof(buffer) - 3] = '.';
    buffer[sizeof(buffer) - 4] = '.';
  }
  buffer[sizeof(buffer) - 1] = '\0';
  va_end(ap);
  /* do the logging */
  if (prelogging_loglevel >= 0)
  {
    /* if logging is not yet defined, log to stderr */
    if (pri <= prelogging_loglevel)
    {
      if ((requestid != NULL) && (requestid[0] != '\0'))
        fprintf(stderr, "%s: [%s] <%s> %s%s\n", PACKAGE, sessionid, requestid,
                pri == LOG_DEBUG ? "DEBUG: " : "", buffer);
      else if ((sessionid != NULL) && (sessionid[0] != '\0'))
        fprintf(stderr, "%s: [%s] %s%s\n", PACKAGE, sessionid,
                pri == LOG_DEBUG ? "DEBUG: " : "", buffer);
      else
        fprintf(stderr, "%s: %s%s\n", PACKAGE,
                pri == LOG_DEBUG ? "DEBUG: " : "", buffer);
    }
  }
  else
  {
    if (pri <= loglevel)
    {
      if ((requestid != NULL) && (requestid[0] != '\0'))
        syslog(pri, "[%s] <%s> %s", sessionid, requestid, buffer);
      else if ((sessionid != NULL) && (sessionid[0] != '\0'))
        syslog(pri, "[%s] %s", sessionid, buffer);
      else
        syslog(pri, "%s", buffer);
    }
  }
}
