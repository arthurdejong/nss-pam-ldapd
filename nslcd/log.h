/*
   log.h - definitions of logging funtions

   Copyright (C) 2002, 2003, 2007, 2008, 2010, 2011, 2012, 2013 Arthur de Jong

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


#ifndef NSLCD__LOG_H
#define NSLCD__LOG_H 1

#include <syslog.h>
#include "compat/attrs.h"

/* set loglevel when no logging is configured */
void log_setdefaultloglevel(int loglevel);

/* configure logging to a file */
void log_addlogging_file(int loglevel, const char *filename);

/* configure logging to syslog */
void log_addlogging_syslog(int loglevel);

/* configure a null logging mode (no logging) */
void log_addlogging_none(void);

/* start the logging with the configured logging methods
   if no method is configured yet, logging is done to syslog */
void log_startlogging(void);

/* indicate that a session id should be included in the output
   and set it to a new value */
void log_newsession(void);

/* indicate that we should clear any session identifiers set by
   log_newsession */
void log_clearsession(void);

/* indicate that a request identifier should be included in the output
   from this point on, until log_newsession() is called */
void log_setrequest(const char *format, ...)
  LIKE_PRINTF(1, 2);

/* log the given message using the configured logging method */
void log_log(int pri, const char *format, ...)
  LIKE_PRINTF(2, 3);

/* log the logging configuration on DEBUG loglevel */
void log_log_config(void);

#endif /* not NSLCD__LOG_H */
