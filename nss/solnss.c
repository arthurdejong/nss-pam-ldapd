/*
   solnss.c - Solaris specific NSS interface functions

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

#include <errno.h>

#include "prototypes.h"
#include "common.h"
#include "compat/attrs.h"

nss_backend_t *nss_ldap_constructor(nss_backend_op_t *ops, size_t sizeofops)
{
  struct nss_ldap_backend *ldapbe;
  ldapbe = (struct nss_ldap_backend *)malloc(sizeof(struct nss_ldap_backend));
  if (ldapbe == NULL)
    return NULL;
  ldapbe->ops = ops;
  ldapbe->n_ops = sizeofops / sizeof(nss_backend_op_t);
  ldapbe->fp = NULL;
  return (nss_backend_t *)ldapbe;
}

nss_status_t nss_ldap_destructor(nss_backend_t *be, void UNUSED(*args))
{
  struct nss_ldap_backend *ldapbe = (struct nss_ldap_backend *)be;
  if (ldapbe->fp != NULL)
    (void)tio_close(ldapbe->fp);
  free(ldapbe);
  return NSS_STATUS_SUCCESS;
}
