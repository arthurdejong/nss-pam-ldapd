/*
   cfg.c - functions for configuration information
   This file contains parts that were part of the nss-ldap
   library which has been forked into the nss-ldapd library.

   Copyright (C) 1997-2005 Luke Howard
   Copyright (C) 2007 West Consulting
   Copyright (C) 2007 Arthur de Jong

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

#include <string.h>

#include "ldap-nss.h"
#include "util.h"
#include "log.h"
#include "dnsconfig.h"

struct ldap_config *nslcd_cfg=NULL;

int _nss_ldap_test_config_flag (unsigned int flag)
{
  return nslcd_cfg != NULL &&
         (nslcd_cfg->ldc_flags&flag);
}

int _nss_ldap_test_initgroups_ignoreuser(const char *user)
{
  char **p;
  if (nslcd_cfg == NULL)
    return 0;

  if (nslcd_cfg->ldc_initgroups_ignoreusers == NULL)
    return 0;

  for (p = nslcd_cfg->ldc_initgroups_ignoreusers; *p != NULL; p++)
    {
      if (strcmp (*p, user) == 0)
        return 1;
    }

  return 0;
}

int cfg_init(void)
{
  static char configbuf[NSS_LDAP_CONFIG_BUFSIZ];
  char *configbufp;
  size_t configbuflen;
  enum nss_status stat;
  if (nslcd_cfg==NULL)
  {
    configbufp=configbuf;
    configbuflen=sizeof(configbuf);
    stat=_nss_ldap_readconfig(&nslcd_cfg,&configbufp,&configbuflen);
    if (stat==NSS_STATUS_NOTFOUND)
    {
      /* config was read but no host information specified; try DNS */
      stat=_nss_ldap_mergeconfigfromdns(nslcd_cfg,&configbufp,&configbuflen);
    }
    if (stat != NSS_STATUS_SUCCESS)
    {
      log_log(LOG_DEBUG,"cfg_init() failed to read config");
      return -1;
    }
  }
  return 0;
}
