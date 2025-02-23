/*
   ldap_passwordpolicy_err2txt.c - replacement function

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
#include "common/gettext.h"


const char *ldap_passwordpolicy_err2txt(LDAPPasswordPolicyError error)
{
  switch (error)
  {
    case PP_passwordExpired:        return _("Password expired");
    case PP_accountLocked:          return _("Account locked");
    case PP_changeAfterReset:       return _("Change after reset");
    case PP_passwordModNotAllowed:  return _("Password modification not allowed");
    case PP_mustSupplyOldPassword:  return _("Must supply old password");
    case PP_insufficientPasswordQuality: return _("Insufficient password quality");
    case PP_passwordTooShort:       return _("Password too short");
    case PP_passwordTooYoung:       return _("Password too young");
    case PP_passwordInHistory:      return _("Password in history");
    case PP_noError:                return _("No error");
    default:                        return _("Unknown error");
  }
}
