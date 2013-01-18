/*
   ldap_passwd_s.c - replacement function for ldap_passwd_s()
   Parts of this file were based on parts of the pam_ldap library
   (taken from _update_authtok() in pam_ldap.c).

   Copyright (C) 1998-2004 Luke Howard
   Copyright (C) 2009, 2010, 2012 Arthur de Jong

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

#include "compat/ldap_compat.h"
#include "compat/attrs.h"

#ifndef LDAP_EXOP_MODIFY_PASSWD
#ifdef LDAP_EXOP_X_MODIFY_PASSWD
#define LDAP_EXOP_MODIFY_PASSWD LDAP_EXOP_X_MODIFY_PASSWD
#define LDAP_TAG_EXOP_MODIFY_PASSWD_ID LDAP_TAG_EXOP_X_MODIFY_PASSWD_ID
#define LDAP_TAG_EXOP_MODIFY_PASSWD_OLD LDAP_TAG_EXOP_X_MODIFY_PASSWD_OLD
#define LDAP_TAG_EXOP_MODIFY_PASSWD_NEW LDAP_TAG_EXOP_X_MODIFY_PASSWD_NEW
#else /* not LDAP_EXOP_X_MODIFY_PASSWD */
#define LDAP_EXOP_MODIFY_PASSWD "1.3.6.1.4.1.4203.1.11.1"
#define LDAP_TAG_EXOP_MODIFY_PASSWD_ID ((ber_tag_t)0x80U)
#define LDAP_TAG_EXOP_MODIFY_PASSWD_OLD ((ber_tag_t)0x81U)
#define LDAP_TAG_EXOP_MODIFY_PASSWD_NEW ((ber_tag_t)0x82U)
#endif /* not LDAP_EXOP_X_MODIFY_PASSWD */
#endif /* not LDAP_EXOP_MODIFY_PASSWD */

#ifndef LBER_USE_DER
#define LBER_USE_DER 1
#endif /* not LBER_USE_DER */

#ifndef HAVE_BER_MEMFREE
#define ber_memfree free
#endif /* not HAVE_BER_MEMFREE */

#if !HAVE_DECL_LDAP_EXTENDED_OPERATION_S
/* we define this ourselves here because some LDAP header versions don't
   seem to define this */
extern int ldap_extended_operation_s(LDAP *ld, LDAP_CONST char *reqoid,
      struct berval *reqdata, LDAPControl **serverctrls,
      LDAPControl **clientctrls, char **retoidp, struct berval **retdatap);
#endif /* not HAVE_DECL_LDAP_EXTENDED_OPERATION_S */

/* Replacement for password modification. user is the DN of the entry to
   change, oldpw is the old password (may not always be needed?), newpw is
   the new password to set and newpasswd is sometimes returned (though not
   by us). See RFC 3062 for details. */
int ldap_passwd_s(LDAP *ld, struct berval *user, struct berval *oldpw,
                  struct berval *newpw, struct berval UNUSED(*newpasswd),
                  LDAPControl **sctrls, LDAPControl **cctrls)
{
#ifndef HAVE_LDAP_EXTENDED_OPERATION_S
  return LDAP_OPERATIONS_ERROR;
#else /* HAVE_LDAP_EXTENDED_OPERATION_S */
  int rc;
  BerElement *ber;
  struct berval *bv;
  char *retoid;
  struct berval *retdata;
  /* set up request data */
  ber = ber_alloc_t(LBER_USE_DER);
  if (ber == NULL)
    return LDAP_NO_MEMORY;
  ber_printf(ber, "{");
  ber_printf(ber, "tO", LDAP_TAG_EXOP_MODIFY_PASSWD_ID, user);
  if (oldpw != NULL)
    ber_printf(ber, "tO", LDAP_TAG_EXOP_MODIFY_PASSWD_OLD, oldpw);
  ber_printf(ber, "tO", LDAP_TAG_EXOP_MODIFY_PASSWD_NEW, newpw);
  ber_printf(ber, "N}");
  rc = ber_flatten(ber, &bv);
  ber_free(ber, 1);
  if (rc < 0)
    return LDAP_NO_MEMORY;
  /* perform the operation */
  rc = ldap_extended_operation_s(ld, LDAP_EXOP_MODIFY_PASSWD, bv, sctrls,
                                 cctrls, &retoid, &retdata);
  /* free data */
  ber_bvfree(bv);
  if (rc == LDAP_SUCCESS)
  {
    ber_bvfree(retdata);
    ber_memfree(retoid);
  }
  /* return result code */
  return rc;
#endif /* HAVE_LDAP_EXTENDED_OPERATION_S */
}
