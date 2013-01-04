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

const char *ldap_passwordpolicy_err2txt(LDAPPasswordPolicyError error)
{
  switch (error)
  {
    case PP_passwordExpired:        return "Password expired";
    case PP_accountLocked:          return "Account locked";
    case PP_changeAfterReset:       return "Change after reset";
    case PP_passwordModNotAllowed:  return "Password modification not allowed";
    case PP_mustSupplyOldPassword:  return "Must supply old password";
    case PP_insufficientPasswordQuality: return "Insufficient password quality";
    case PP_passwordTooShort:       return "Password too short";
    case PP_passwordTooYoung:       return "Password too young";
    case PP_passwordInHistory:      return "Password in history";
    case PP_noError:                return "No error";
    default:                        return "Unknown error";
  }
}
