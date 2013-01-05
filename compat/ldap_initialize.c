/*
   ldap_initialize.c - replacement function for ldap_initialize()

   Copyright (C) 2009, 2012, 2013 Arthur de Jong

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

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <lber.h>
#include <ldap.h>

#include "compat/ldap_compat.h"
#include "nslcd/log.h"


/* provide a wrapper around ldap_init() if the system doesn't have
   ldap_initialize() */
int ldap_initialize(LDAP **ldp, const char *url)
{
  char host[80];
  /* check schema part */
  if (strncasecmp(url, "ldap://", 7) == 0)
  {
    strncpy(host, url + 7, sizeof(host));
    host[sizeof(host) - 1] = '\0';
  }
  else if (strncasecmp(url, "ldaps://", 8) == 0)
  {
    strncpy(host, url + 8, sizeof(host));
    host[sizeof(host) - 1] = '\0';
  }
  else
  {
    log_log(LOG_ERR, "ldap_initialize(): schema not supported: %s", url);
    exit(EXIT_FAILURE);
  }
  /* strip trailing slash */
  if ((strlen(host) > 0) && (host[strlen(host) - 1] == '/'))
    host[strlen(host) - 1] = '\0';
  /* call ldap_init() */
  *ldp = ldap_init(host, LDAP_PORT);
  return (*ldp == NULL) ? LDAP_OPERATIONS_ERROR : LDAP_SUCCESS;
}
