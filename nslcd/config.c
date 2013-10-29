/*
   config.c - routines for getting configuration information

   Copyright (C) 2012, 2013 Arthur de Jong

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
#include <string.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif /* HAVE_STDINT_H */
#include <unistd.h>

#include "common.h"
#include "log.h"
#include "cfg.h"

int nslcd_config_get(TFILE *fp, MYLDAP_SESSION UNUSED(*session))
{
  int32_t tmpint32;
  int32_t cfgopt;
  /* read request parameters */
  READ_INT32(fp, cfgopt);
  /* log call */
  log_setrequest("config=%d", (int)cfgopt);
  log_log(LOG_DEBUG, "nslcd_config_get(%d)", (int)cfgopt);
  /* write the response header */
  WRITE_INT32(fp, NSLCD_VERSION);
  WRITE_INT32(fp, NSLCD_ACTION_CONFIG_GET);
  WRITE_INT32(fp, NSLCD_RESULT_BEGIN);
  /* validate request */
  switch (cfgopt)
  {
    case NSLCD_CONFIG_PAM_PASSWORD_PROHIBIT_MESSAGE:
      WRITE_STRING(fp, nslcd_cfg->pam_password_prohibit_message);
      break;
    default:
      /* all other config options are ignored */
      break;
  }
  WRITE_INT32(fp, NSLCD_RESULT_END);
  return 0;
}
