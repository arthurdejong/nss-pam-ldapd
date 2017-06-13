/*
   ether.h - ethernet definitions for systems lacking those

   Copyright (C) 2008-2017 Arthur de Jong

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

#ifndef COMPAT__ETHER_H
#define COMPAT__ETHER_H 1

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#ifdef HAVE_NETINET_ETHER_H
#include <netinet/ether.h>
#endif

#ifndef HAVE_STRUCT_ETHER_ADDR
struct ether_addr {
  uint8_t ether_addr_octet[6];
};
#endif /* not HAVE_STRUCT_ETHER_ADDR */

#ifndef HAVE_ETHER_ATON_R
struct ether_addr *ether_aton_r(const char *asc, struct ether_addr *addr);
#endif /* not HAVE_ETHER_ATON_R */

#ifdef HAVE_ETHER_ATON
#if !HAVE_DECL_ETHER_ATON
/* we define ether_aton() here because on some platforms the function is
   undefined */
extern struct ether_addr *ether_aton(const char *s);
#endif /* not HAVE_DECL_ETHER_ATON */
#endif /* HAVE_ETHER_ATON */

#endif /* not COMPAT__ETHER_H */
