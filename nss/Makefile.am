# Makefile.am - use automake to generate Makefile.in
#
# Copyright (C) 2006 Luke Howard
# Copyright (C) 2006 West Consulting
# Copyright (C) 2006-2015 Arthur de Jong
# Copyright (C) 2010 Symas Corporation
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301 USA

noinst_PROGRAMS = nss_ldap.so

AM_CPPFLAGS=-I$(top_srcdir)
AM_CFLAGS = $(PIC_CFLAGS) $(DEBUG_CFLAGS) $(EXTRA_CFLAGS)

nss_ldap_so_SOURCES = common.c common.h prototypes.h solnss.h \
                      ../nslcd.h ../common/nslcd-prot.h \
                      ../compat/attrs.h
EXTRA_nss_ldap_so_SOURCES = aliases.c ethers.c group.c hosts.c netgroup.c \
                            networks.c passwd.c protocols.c rpc.c services.c \
                            shadow.c solnss.c bsdnss.c
nss_ldap_so_LDADD = $(NSS_MODULE_OBJS)
if NSS_FLAVOUR_SOLARIS
nss_ldap_so_LDADD += solnss.$(OBJEXT) ../common/libdict.a
endif
if NSS_FLAVOUR_FREEBSD
nss_ldap_so_LDADD += bsdnss.$(OBJEXT)
endif
nss_ldap_so_LDADD += ../common/libtio.a ../common/libprot.a
nss_ldap_so_DEPENDENCIES = $(nss_ldap_so_LDADD) exports.map

EXTRA_DIST = exports.glibc exports.solaris exports.freebsd
CLEANFILES = exports.map

exports.map: $(EXTRA_DIST) Makefile
	sed 's/ldap/@MODULE_NAME@/' < $(srcdir)/exports.$(NSS_FLAVOUR) > exports.map

install-exec-local: install-nss_ldap_so
uninstall-local: uninstall-nss_ldap_so

install-nss_ldap_so: nss_ldap.so
	-rm -f $(DESTDIR)$(libdir)/$(NSS_LDAP_SONAME)
	$(mkinstalldirs) $(DESTDIR)$(libdir)
	$(INSTALL_PROGRAM) nss_ldap.so $(DESTDIR)$(libdir)/$(NSS_LDAP_SONAME)

uninstall-nss_ldap_so:
	-rm -f $(DESTDIR)$(libdir)/$(NSS_LDAP_SONAME)
