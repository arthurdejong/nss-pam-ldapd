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

sbin_PROGRAMS = nslcd
AM_CFLAGS = -pthread

nslcd_SOURCES = nslcd.c ../nslcd.h ../nslcd-common.h \
                log.c log.h \
                xmalloc.c xmalloc.h \
                common.c common.h \
                alias.c ether.c group.c host.c netgroup.c network.c \
                passwd.c protocol.c rpc.c service.c shadow.c \
                dnsconfig.c dnsconfig.h ldap-nss.c ldap-nss.h \
                ldap-schema.c ldap-schema.h pagectrl.c pagectrl.h \
                resolve.c resolve.h util.c util.h
nslcd_LDADD = @nslcd_LIBS@
