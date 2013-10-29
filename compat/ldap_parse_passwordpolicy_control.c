/*
   ldap_parse_passwordpolicy_control.c - replacement function

   Copyright (C) 2013 Arthur de Jong

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
#include <lber.h>
#include <ldap.h>
#include <string.h>

#include "compat/ldap_compat.h"
#include "compat/attrs.h"

#ifndef PPOLICY_WARNING
#define PPOLICY_WARNING 160
#endif
#ifndef PPOLICY_ERROR
#define PPOLICY_ERROR 129
#endif
#ifndef PPOLICY_EXPIRE
#define PPOLICY_EXPIRE 128
#endif
#ifndef PPOLICY_GRACE
#define PPOLICY_GRACE 129
#endif

/* based on Openldap and pam_ldap implementations */

int ldap_parse_passwordpolicy_control(LDAP UNUSED(*ld), LDAPControl *ctrl,
                                      ber_int_t *expirep, ber_int_t *gracep,
                                      LDAPPasswordPolicyError UNUSED(*errorp))
{
  BerElement *ber;
  ber_tag_t tag;
  ber_len_t berLen;
  char *last;
#ifdef HAVE_BER_GET_ENUM
  int err = PP_noError;
#endif /* HAVE_BER_GET_ENUM */
  /* get a BerElement from the control */
  ber = ber_init(&ctrl->ldctl_value);
  if (ber == NULL)
    return LDAP_LOCAL_ERROR;
  /* go over tags */
  for(tag = ber_first_element(ber, &berLen, &last); tag != LBER_DEFAULT; tag = ber_next_element(ber, &berLen, last))
  {
    switch (tag)
    {
      case PPOLICY_WARNING:
        ber_skip_tag(ber, &berLen);
        tag = ber_peek_tag(ber, &berLen);
        switch (tag)
        {
          case PPOLICY_EXPIRE:
            if (ber_get_int(ber, expirep) == LBER_DEFAULT)
            {
              ber_free(ber, 1);
              return LDAP_DECODING_ERROR;
            }
            break;
          case PPOLICY_GRACE:
            if (ber_get_int(ber, gracep) == LBER_DEFAULT)
            {
              ber_free(ber, 1);
              return LDAP_DECODING_ERROR;
            }
            break;
          default:
            ber_free(ber, 1);
            return LDAP_DECODING_ERROR;
        }
        break;
#ifdef HAVE_BER_GET_ENUM
      case PPOLICY_ERROR:
        if (ber_get_enum(ber, &err) == LBER_DEFAULT)
        {
          ber_free(ber, 1);
          return LDAP_DECODING_ERROR;
        }
        break;
#endif /* HAVE_BER_GET_ENUM */
      default:
        ber_free(ber, 1);
        return LDAP_DECODING_ERROR;
    }
  }
  ber_free(ber, 1);
  return LDAP_SUCCESS;
}
