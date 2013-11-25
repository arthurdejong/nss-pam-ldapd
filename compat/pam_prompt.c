/*
   pam_prompt.c - replacement function for pam_prompt()

   Copyright (C) 2010, 2012 Arthur de Jong

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
#include <stdio.h>
#include <stdarg.h>

#include "compat/attrs.h"
#include "compat/pam_compat.h"

int pam_prompt(pam_handle_t *pamh, int style, char **response,
               const char *format, ...)
{
  int rc;
  struct pam_conv *aconv;
  char buffer[200];
  va_list ap;
  struct pam_message msg, *pmsg;
  struct pam_response *resp;
  /* the the conversion function */
  rc = pam_get_item(pamh, PAM_CONV, (PAM_ITEM_CONST void **)&aconv);
  if (rc != PAM_SUCCESS)
    return rc;
  /* make the message string */
  va_start(ap, format);
  vsnprintf(buffer, sizeof(buffer), format, ap);
  buffer[sizeof(buffer) - 1] = '\0';
  va_end(ap);
  /* build the message */
  msg.msg_style = style;
  msg.msg = buffer;
  pmsg = &msg;
  resp = NULL;
  rc = aconv->conv(1, (const struct pam_message **)&pmsg, &resp, aconv->appdata_ptr);
  if (rc != PAM_SUCCESS)
    return rc;
  /* assign response if it is set */
  if (response != NULL)
  {
    if (resp == NULL)
      return PAM_CONV_ERR;
    if (resp[0].resp == NULL)
    {
      free(resp);
      return PAM_CONV_ERR;
    }
    *response = resp[0].resp;
  }
  else
    free(resp[0].resp);
  free(resp);
  return PAM_SUCCESS;
}
