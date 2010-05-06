/*
   pam_compat.h - provide a replacement definitions for some pam functions

   Copyright (C) 2009, 2010 Arthur de Jong

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

#ifndef _COMPAT_PAM_COMPAT_H
#define _COMPAT_PAM_COMPAT_H 1

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif /* HAVE_SECURITY_PAM_APPL_H */
#ifndef HAVE_PAM_PAM_MODULES_H
#include <security/pam_modules.h>
#ifdef HAVE_SECURITY_PAM_EXT_H
#include <security/pam_ext.h>
#endif /* HAVE_SECURITY_PAM_EXT_H */
#else /* not HAVE_PAM_PAM_MODULES_H */
#include <pam/pam_modules.h>
#endif /* not HAVE_PAM_PAM_MODULES_H */
#ifdef HAVE_SECURITY_PAM_MODUTIL_H
#include <security/pam_modutil.h>
#endif /* HAVE_SECURITY_PAM_MODUTIL_H */

/* define our own replacement pam_get_authtok() if it wasn't found */
#ifndef HAVE_PAM_GET_AUTHTOK
int pam_get_authtok(pam_handle_t *pamh,int item,const char **authtok,const char *prompt);
#endif /* HAVE_PAM_GET_AUTHTOK */

/* fall back to using getpwnam() if pam_modutil_getpwnam() isn't defined */
#ifndef HAVE_PAM_MODUTIL_GETGWNAM
#include <sys/types.h>
#include <pwd.h>
#define pam_modutil_getpwnam(pamh,user) getpwnam(user)
#endif /* not HAVE_PAM_MODUTIL_GETGWNAM */

#endif /* _COMPAT_LDAP_COMPAT_H */
