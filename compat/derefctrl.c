/*
   derefctrl.c - replacement function

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

#ifdef REPLACE_LDAP_CREATE_DEREF_CONTROL
int replacement_ldap_create_deref_control(LDAP *ld, LDAPDerefSpec *ds,
      int iscritical, LDAPControl **ctrlp)
{
  int rc;
  struct berval value;
  if (ctrlp == NULL)
    return LDAP_PARAM_ERROR;
  rc = ldap_create_deref_control_value(ld, ds, &value);
  if (rc != LDAP_SUCCESS)
    return rc;
  rc = ldap_control_create(LDAP_CONTROL_X_DEREF, iscritical, &value, 0, ctrlp);
  if (rc != LDAP_SUCCESS)
  {
    ber_memfree(value.bv_val);
  }
  return rc;
}
#endif /* REPLACE_LDAP_CREATE_DEREF_CONTROL */
