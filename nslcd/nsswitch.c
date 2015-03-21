/*
   nsswitch.c - functions for parsing /etc/nsswitch.conf

   Copyright (C) 2011-2015 Arthur de Jong

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
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include "common.h"
#include "log.h"

/* the cached value of whether shadow lookups use LDAP in nsswitch.conf */
#define NSSWITCH_FILE "/etc/nsswitch.conf"
#define CACHED_UNKNOWN 22
static int cached_shadow_uses_ldap = CACHED_UNKNOWN;
static time_t cached_shadow_lastcheck = 0;
#define CACHED_SHADOW_TIMEOUT (60)
static time_t nsswitch_mtime = 0;

/* the maximum line length supported of nsswitch.conf */
#define MAX_LINE_LENGTH          4096

/* check whether /etc/nsswitch.conf should be related to update
   cached_shadow_uses_ldap */
void nsswitch_check_reload(void)
{
  struct stat buf;
  time_t t;
  if ((cached_shadow_uses_ldap != CACHED_UNKNOWN) &&
      ((t = time(NULL)) > (cached_shadow_lastcheck + CACHED_SHADOW_TIMEOUT)))
  {
    cached_shadow_lastcheck = t;
    if (stat(NSSWITCH_FILE, &buf))
    {
      log_log(LOG_ERR, "stat(%s) failed: %s", NSSWITCH_FILE, strerror(errno));
      /* trigger a recheck anyway */
      cached_shadow_uses_ldap = CACHED_UNKNOWN;
      return;
    }
    /* trigger a recheck if file changed */
    if (buf.st_mtime != nsswitch_mtime)
    {
      nsswitch_mtime = buf.st_mtime;
      cached_shadow_uses_ldap = CACHED_UNKNOWN;
    }
  }
}

/* see if the line is a service definition for db and return a pointer to
   the beginning of the services list if it is */
static const char *find_db(const char *line, const char *db)
{
  int i;
  i = strlen(db);
  /* the line should begin with the db we're looking for */
  if (strncmp(line, db, i) != 0)
    return NULL;
  /* followed by a : */
  while (isspace(line[i]))
    i++;
  if (line[i] != ':')
    return NULL;
  i++;
  while (isspace(line[i]))
    i++;
  return line + i;
}

/* check to see if the list of services contains the specified service */
static int has_service(const char *services, const char *service,
                       const char *filename, int lnr)
{
  int i = 0, l;
  if (services == NULL)
    return 0;
  l = strlen(service);
  while (services[i] != '\0')
  {
    /* skip spaces */
    while (isspace(services[i]))
      i++;
    /* check if this is the service */
    if ((strncmp(services + i, service, l) == 0) && (!isalnum(services[i + l])))
      return 1;
    /* skip service name and spaces */
    i++;
    while (isalnum(services[i]))
      i++;
    while (isspace(services[i]))
      i++;
    /* skip action mappings */
    if (services[i] == '[')
    {
      i++; /* skip [ */
      while ((services[i] != ']') && (services[i] != '\0'))
        i++;
      if (services[i] != ']')
      {
        log_log(LOG_WARNING, "%s: error parsing line %d", filename, lnr);
        return 0; /* parse error */
      }
      i++; /* skip ] */
    }
  }
  return 0;
}

static int shadow_uses_ldap(void)
{
  FILE *fp;
  int lnr = 0;
  char linebuf[MAX_LINE_LENGTH];
  const char *services;
  int shadow_found = 0;
  int passwd_has_ldap = 0;
  /* open config file */
  if ((fp = fopen(NSSWITCH_FILE, "r")) == NULL)
  {
    log_log(LOG_ERR, "cannot open %s: %s", NSSWITCH_FILE, strerror(errno));
    return 0;
  }
  /* read file and parse lines */
  while (fgets(linebuf, sizeof(linebuf), fp) != NULL)
  {
    lnr++;
    /* see if we have a shadow line */
    services = find_db(linebuf, "shadow");
    if (services != NULL)
    {
      shadow_found = 1;
      if (has_service(services, MODULE_NAME, NSSWITCH_FILE, lnr))
      {
        fclose(fp);
        return 1;
      }
    }
    /* see if we have a passwd line */
    services = find_db(linebuf, "passwd");
    if (services != NULL)
      passwd_has_ldap = has_service(services, MODULE_NAME, NSSWITCH_FILE, lnr);
  }
  fclose(fp);
  if (shadow_found)
    return 0;
  return passwd_has_ldap;
}

/* check whether shadow lookups are configured to use ldap */
int nsswitch_shadow_uses_ldap(void)
{
  if (cached_shadow_uses_ldap == CACHED_UNKNOWN)
  {
    log_log(LOG_INFO, "(re)loading %s", NSSWITCH_FILE);
    cached_shadow_uses_ldap = shadow_uses_ldap();
    cached_shadow_lastcheck = time(NULL);
  }
  return cached_shadow_uses_ldap;
}
