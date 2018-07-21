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
#include <pthread.h>
#include <strings.h>

#include "log.h"

/* set the logname */
#undef PACKAGE
#define PACKAGE "nslcd"

/* storage for logging modes */
static struct log_cfg {
  int loglevel;
  const char *scheme;
  FILE *fp; /* NULL == syslog */
  struct log_cfg *next;
} *loglist = NULL;

/* default loglevel when no logging is configured */
static int prelogging_loglevel = LOG_INFO;

#define MAX_REQUESTID_LENGTH 40

#ifdef TLS

/* the session id that is set for this thread */
static TLS char *sessionid = NULL;

/* the request identifier that is set for this thread */
static TLS char *requestid = NULL;

#else /* no TLS, use pthreads */

static pthread_once_t tls_init_once = PTHREAD_ONCE_INIT;
static pthread_key_t sessionid_key;
static pthread_key_t requestid_key;

static void tls_init_keys(void)
{
  pthread_key_create(&sessionid_key, NULL);
  pthread_key_create(&requestid_key, NULL);
}

#endif /* no TLS, use pthreads */

/* set loglevel when no logging is configured */
void log_setdefaultloglevel(int loglevel)
{
  prelogging_loglevel = loglevel;
}

/* add logging method to configuration list */
static void addlogging(int loglevel, const char *scheme, FILE *fp)
{
  struct log_cfg *tmp, *lst;
  /* create new logstruct */
  tmp = (struct log_cfg *)malloc(sizeof(struct log_cfg));
  if (tmp == NULL)
  {
    log_log(LOG_CRIT, "malloc() returned NULL");
    exit(EXIT_FAILURE);
  }
  tmp->loglevel = loglevel;
  tmp->scheme = scheme;
  tmp->fp = fp;
  tmp->next = NULL;
  /* save the struct in the list */
  if (loglist == NULL)
    loglist = tmp;
  else
  {
    for (lst = loglist; lst->next != NULL; lst = lst->next);
    lst->next = tmp;
  }
}

/* configure logging to a file */
void log_addlogging_file(int loglevel, const char *filename)
{
  FILE *fp;
  filename = strdup(filename);
  if (filename == NULL)
  {
    log_log(LOG_CRIT, "strdup() returned NULL");
    exit(EXIT_FAILURE);
  }
  fp = fopen(filename, "a");
  if (fp == NULL)
  {
    log_log(LOG_ERR, "cannot open logfile (%s) for appending: %s",
            filename, strerror(errno));
    exit(1);
  }
  addlogging(loglevel, filename, fp);
}

/* configure logging to syslog */
void log_addlogging_syslog(int loglevel)
{
  openlog(PACKAGE, LOG_PID, LOG_DAEMON);
  addlogging(loglevel, "syslog", NULL);
}

/* configure a null logging mode (no logging) */
void log_addlogging_none()
{
  /* this is a hack, but it's so easy */
  addlogging(LOG_EMERG, "none", NULL);
}

/* start the logging with the configured logging methods
   if no method is configured yet, logging is done to syslog */
void log_startlogging(void)
{
  if (loglist == NULL)
    log_addlogging_syslog(LOG_INFO);
  prelogging_loglevel = -1;
}

/* indicate that we should clear any session identifiers set by
   log_newsession */
void log_clearsession(void)
{
#ifndef TLS
  char *sessionid, *requestid;
  pthread_once(&tls_init_once, tls_init_keys);
  sessionid = pthread_getspecific(sessionid_key);
  requestid = pthread_getspecific(requestid_key);
#endif /* no TLS */
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
#ifndef TLS
  char *sessionid, *requestid;
  pthread_once(&tls_init_once, tls_init_keys);
  sessionid = pthread_getspecific(sessionid_key);
  requestid = pthread_getspecific(requestid_key);
#endif /* no TLS */
  /* ensure that sessionid can hold a string */
  if (sessionid == NULL)
  {
    sessionid = (char *)malloc(7);
    if (sessionid == NULL)
    {
      fprintf(stderr, "malloc() failed: %s", strerror(errno));
      return; /* silently fail */
    }
#ifndef TLS
    pthread_setspecific(sessionid_key, sessionid);
#endif /* no TLS */
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
#ifndef TLS
  char *requestid;
  pthread_once(&tls_init_once, tls_init_keys);
  requestid = pthread_getspecific(requestid_key);
#endif /* no TLS */
  /* ensure that requestid can hold a string */
  if (requestid == NULL)
  {
    requestid = (char *)malloc(MAX_REQUESTID_LENGTH);
    if (requestid == NULL)
    {
      fprintf(stderr, "malloc() failed: %s", strerror(errno));
      return; /* silently fail */
    }
#ifndef TLS
    pthread_setspecific(requestid_key, requestid);
#endif /* no TLS */
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
  struct log_cfg *lst;
  char buffer[512];
  va_list ap;
#ifndef TLS
  char *sessionid, *requestid;
  pthread_once(&tls_init_once, tls_init_keys);
  sessionid = pthread_getspecific(sessionid_key);
  requestid = pthread_getspecific(requestid_key);
#endif /* no TLS */
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
    for (lst = loglist; lst != NULL; lst = lst->next)
    {
      if (pri <= lst->loglevel)
      {
        if (lst->fp == NULL)
        {
          if ((requestid != NULL) && (requestid[0] != '\0'))
            syslog(pri, "[%s] <%s> %s%s", sessionid, requestid,
                   pri == LOG_DEBUG ? "DEBUG: " : "", buffer);
          else if ((sessionid != NULL) && (sessionid[0] != '\0'))
            syslog(pri, "[%s] %s%s", sessionid,
                   pri == LOG_DEBUG ? "DEBUG: " : "", buffer);
          else
            syslog(pri, "%s%s",
                   pri == LOG_DEBUG ? "DEBUG: " : "", buffer);
        }
        else
        {
          if ((requestid != NULL) && (requestid[0] != '\0'))
            fprintf(lst->fp, "%s: [%s] <%s> %s%s\n", PACKAGE, sessionid, requestid,
                    pri == LOG_DEBUG ? "DEBUG: " : "", buffer);
          else if ((sessionid != NULL) && (sessionid[0] != '\0'))
            fprintf(lst->fp, "%s: [%s] %s%s\n", PACKAGE, sessionid,
                    pri == LOG_DEBUG ? "DEBUG: " : "", buffer);
          else
            fprintf(lst->fp, "%s: %s%s\n", PACKAGE,
                    pri == LOG_DEBUG ? "DEBUG: " : "", buffer);
          fflush(lst->fp);
        }
      }
    }
  }
}

static const char *loglevel2str(int loglevel)
{
  switch (loglevel)
  {
    case LOG_CRIT:    return "crit";
    case LOG_ERR:     return "error";
    case LOG_WARNING: return "warning";
    case LOG_NOTICE:  return "notice";
    case LOG_INFO:    return "info";
    case LOG_DEBUG:   return "debug";
    default:          return "???";
  }
}

/* log the logging configuration on DEBUG loglevel */
void log_log_config(void)
{
  struct log_cfg *lst;
  for (lst = loglist; lst != NULL; lst = lst->next)
  {
    if (lst->loglevel == LOG_EMERG)
      log_log(LOG_DEBUG, "CFG: log %s", lst->scheme);
    else
      log_log(LOG_DEBUG, "CFG: log %s %s", lst->scheme,
              loglevel2str(lst->loglevel));
  }
}
