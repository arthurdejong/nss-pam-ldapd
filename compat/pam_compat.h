/*
   pam_compat.h - provide a replacement definitions for some pam functions

   Copyright (C) 2009-2017 Arthur de Jong

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

#ifndef COMPAT__PAM_COMPAT_H
#define COMPAT__PAM_COMPAT_H 1

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

/* find value of PAM_AUTHTOK_RECOVERY_ERR */
#ifndef PAM_AUTHTOK_RECOVERY_ERR
#ifdef PAM_AUTHTOK_RECOVER_ERR
#define PAM_AUTHTOK_RECOVERY_ERR PAM_AUTHTOK_RECOVER_ERR
#else
#define PAM_AUTHTOK_RECOVERY_ERR 21 /* not defined anywhere */
#endif
#endif /* not PAM_AUTHTOK_RECOVERY_ERR */

/* define our own replacement pam_get_authtok() if it wasn't found */
#ifndef HAVE_PAM_GET_AUTHTOK
int pam_get_authtok(pam_handle_t *pamh, int item, const char **authtok,
                    const char *prompt);
#endif /* not HAVE_PAM_GET_AUTHTOK */

/* replace pam_prompt() if needed */
#ifndef HAVE_PAM_PROMPT
int pam_prompt(pam_handle_t *pamh, int style, char **response,
               const char *format, ...)
  LIKE_PRINTF(4, 5);
#endif /* not HAVE_PAM_PROMPT */

/* provide pam_info() if needed */
#if !HAVE_DECL_PAM_INFO
#define pam_info(pamh, format...)                                           \
  pam_prompt(pamh, PAM_TEXT_INFO, NULL, ##format)
#endif /* not HAVE_DECL_PAM_INFO */

/* provide pam_error() if needed */
#if !HAVE_DECL_PAM_ERROR
#define pam_error(pamh, format...)                                          \
  pam_prompt(pamh, PAM_ERROR_MSG, NULL, ##format)
#endif /* not HAVE_DECL_PAM_ERROR */

/* fall back to using getpwnam() if pam_modutil_getpwnam() isn't defined */
#ifndef HAVE_PAM_MODUTIL_GETGWNAM
#include <sys/types.h>
#include <pwd.h>
#define pam_modutil_getpwnam(pamh, user)                                    \
  getpwnam(user)
#endif /* not HAVE_PAM_MODUTIL_GETGWNAM */

/* fall back to using syslog() if pam_syslog() doesn't exist */
#ifndef HAVE_PAM_SYSLOG
#ifndef LOG_AUTHPRIV
#define LOG_AUTHPRIV LOG_AUTH
#endif /* not LOG_AUTHPRIV */
#define pam_syslog(pamh, priority, format...)                               \
    syslog(LOG_AUTHPRIV|(priority), ##format)
#endif /* not HAVE_PAM_SYSLOG */

#endif /* _COMPAT_LDAP_COMPAT_H */
