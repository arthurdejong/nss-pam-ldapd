/*
   nsswitch.c - functions for parsing /etc/nsswitch.conf

   Copyright (C) 2011 Arthur de Jong

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

#include "common.h"
#include "log.h"

/* the maximum line length supported of nsswitch.conf */
#define MAX_LINE_LENGTH          4096


/* TODO: store mtime of file and use it to check reparse */
/* TODO: cache entries for x minutes */

/* see if the line is a service definition for db and return a pointer to
   the beginning of the services list if it is */
static const char *find_db(const char *line,const char *db)
{
  int i;
  i=strlen(db);
  /* the line should begin with the db we're looking for */
  if (strncmp(line,db,i)!=0)
    return NULL;
  /* followed by a : */
  while (isspace(line[i])) i++;
  if (line[i]!=':')
    return NULL;
  i++;
  while (isspace(line[i])) i++;
  return line+i;
}

/* check to see if the list of services contains the specified service */
static int has_service(const char *services,const char *service,
                       const char *filename,int lnr)
{
  int i=0,l;
  if (services==NULL)
    return 0;
  l=strlen(service);
  while (services[i]!='\0')
  {
    /* skip spaces */
    while (isspace(services[i])) i++;
    /* check if this is the service */
    if ((strncmp(services+i,service,l)==0)&&(!isalnum(services[i+l])))
      return 1;
    /* skip service name and spaces */
    i++;
    while (isalnum(services[i])) i++;
    while (isspace(services[i])) i++;
    /* skip action mappings */
    if (services[i]=='[')
    {
      i++; /* skip [ */
      while ((services[i]!=']')&&(services[i]!='\0')) i++;
      if (services[i]!=']')
      {
        log_log(LOG_WARNING,"%s: error parsing line %d",filename,lnr);
        return 0; /* parse error */
      }
      i++; /* skip ] */
    }
  }
  return 0;
}

int nsswitch_db_uses_ldap(const char *filename,const char *db)
{
  FILE *fp;
  int lnr=0;
  char linebuf[MAX_LINE_LENGTH];
  const char *services;
  /* open config file */
  if ((fp=fopen(filename,"r"))==NULL)
  {
    log_log(LOG_ERR,"cannot open %s: %s",filename,strerror(errno));
    return 0;
  }
  /* read file and parse lines */
  while (fgets(linebuf,sizeof(linebuf),fp)!=NULL)
  {
    lnr++;
    services=find_db(linebuf,db);
    if ((services!=NULL)&&has_service(services,"ldap",filename,lnr))
    {
      fclose(fp);
      return 1;
    }
  }
  fclose(fp);
  return 0;
}
