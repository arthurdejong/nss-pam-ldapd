/*
   log.h - definitions of logging funtions

   Copyright (C) 2002, 2003 Arthur de Jong.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
   MA 02110-1301 USA
*/


#ifndef _LOG_H
#define _LOG_H 1


#include <syslog.h>


/* set loglevel when no logging is configured */
void log_setdefaultloglevel(int loglevel);


/* configure logging to a file */
void log_addlogging_file(const char *filename,int loglevel);


/* configure logging to syslog */
void log_addlogging_syslog(int loglevel);


/* configure a null logging mode (no logging) */
void log_addlogging_none(void);


/* start the logging with the configured logging methods
   if no method is configured yet, logging is done to syslog */
void log_startlogging(void);


/* log the given message using the configured logging method */
void log_log(int pri,const char *format, ...);


/* return the syslog loglevel represented by the string
   return -1 on unknown */
int log_getloglevel(const char *lvl);


#endif /* not _LOG_H */
