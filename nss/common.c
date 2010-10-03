/*
   common.c - common functions for NSS lookups

   Copyright (C) 2010 Arthur de Jong
   Copyright (C) 2010 Symas Corporation

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

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif /* HAVE_STDINT_H */
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#ifdef HAVE_NSS_H
#include <nss.h>
#endif /* HAVE_NSS_H */
#include <string.h>

#include "nslcd.h"
#include "common.h"
#include "common/tio.h"

/* flag used to disable NSS lookups using this module */
int _nss_ldap_enablelookups=1;

#ifdef NSS_FLAVOUR_SOLARIS
/* Adapted from PADL */

/* add a nested netgroup or group to the namelist */
nss_status_t _nss_ldap_namelist_push(struct name_list **head,const char *name)
{
  struct name_list *nl;
  nl=(struct name_list *)malloc(sizeof(*nl));
  if (nl==NULL)
    return NSS_STATUS_TRYAGAIN;
  nl->name=strdup(name);
  if (nl->name==NULL)
  {
    free(nl);
    return NSS_STATUS_TRYAGAIN;
  }
  nl->next=*head;
  *head=nl;
  return NSS_STATUS_SUCCESS;
}

/* remove last nested netgroup or group from the namelist */
void _nss_ldap_namelist_pop(struct name_list **head)
{
  struct name_list *nl;
  nl=*head;
  *head=nl->next;
  free(nl->name);
  free(nl);
}

/* cleanup nested netgroup or group namelist */
void _nss_ldap_namelist_destroy(struct name_list **head)
{
  struct name_list *p,*next;
  for (p=*head;p!=NULL;p=next)
  {
    next=p->next;
    if (p->name!=NULL)
      free(p->name);
    free(p);
  }
  *head=NULL;
}

/*
 *Check whether we have already seen a netgroup or group,
 *to avoid loops in nested netgroup traversal
 */
int _nss_ldap_namelist_find(struct name_list *head,const char *netgroup)
{
  struct name_list *p;
  int found=0;
  for (p=head;p!=NULL;p=p->next)
  {
    if (strcasecmp(p->name,netgroup)==0)
    {
      found++;
      break;
    }
  }
  return found;
}

#endif /* NSS_FLAVOUR_SOLARIS */
