/*
   socket.h - compatibility hacks for socket functions

   Copyright (C) 2012 Arthur de Jong

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

#ifndef COMPAT__SOCKET_H
#define COMPAT__SOCKET_H 1

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

/* provide a definition for SUN_LEN for systems without it */
#ifndef SUN_LEN
#define SUN_LEN(addr) (sizeof((addr)->sun_family) + strlen((addr)->sun_path) + 1)
#endif /* not SUN_LEN */

#endif /* not COMPAT__SOCKET_H */
