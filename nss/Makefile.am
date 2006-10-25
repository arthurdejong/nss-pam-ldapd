# Makefile.am - use automake to generate Makefile.in
#
# Copyright (C) 2006 West consulting
# Copyright (C) 2006 Arthur de Jong
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU Library General Public
# License along with this library; if not, write to the Free
# Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
# MA 02110-1301 USA

noinst_LIBRARIES = libnss.a
noinst_PROGRAMS = libnss_ldap.so

libnss_a_SOURCES = common.c common.h exports.h ../nslcd-client.h \
                   passwd.c aliases.c
libnss_a_LIBADD = ../nslcd-client.o

libnss_ldap_so_SOURCES = 
libnss_ldap_so_LDADD = libnss.a
libnss_ldap_so_LDFLAGS = -shared -Wl,-soname,libnss_ldap.so.2

#      gcc -shared -o libnss_NAME.so.2 -Wl,-soname,libnss_NAME.so.2 OBJECTS
