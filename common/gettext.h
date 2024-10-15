/*
   This file is part of the nss-pam-ldapd library.

   Copyright (C) 2024 Tero Saarni

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

#ifndef COMMON__GETTEXT_H
#define COMMON__GETTEXT_H 1

#if defined ENABLE_NLS && ENABLE_NLS

#include <libintl.h>
#define _(msgid) dgettext(PACKAGE, msgid)

#else

#define _(msgid) (msgid)
#define bindtextdomain(domainname, dirname) \
  ((void)(domainname), (const char *)(dirname))

#endif

#endif /* COMMON__GETTEXT_H */
