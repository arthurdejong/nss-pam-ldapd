/*
   aliases.c - NSS lookup functions for aliases database

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006 Arthur de Jong

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
   MA 02110-1301 USA
*/

#include "config.h"

#include <string.h>
#include <nss.h>
#include <errno.h>

#include "exports.h"
#include "nslcd-client.h"
#include "common.h"

enum nss_status _nss_ldap_getaliasbyname_r(const char *name,struct aliasent *result,char *buffer,size_t buflen,int *errnop)
{}

enum nss_status _nss_ldap_setaliasent(void)
{}

enum nss_status _nss_ldap_getaliasent_r(struct aliasent *result,char *buffer,size_t buflen,int *errnop)
{}

enum nss_status _nss_ldap_endaliasent(void)
{}
