# Makefile.am - use automake to generate Makefile.in
#
# Copyright (C) 2009 Arthur de Jong
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

noinst_PROGRAMS = pam_ldap.so

AM_CPPFLAGS=-I$(top_srcdir)
AM_CFLAGS = -fPIC

pam_ldap_so_SOURCES = ../nslcd.h ../nslcd-common.h \
                      ../compat/attrs.h pam.c
pam_ldap_so_LDFLAGS = -shared -Wl,--version-script,\$(srcdir)/exports.linux
pam_ldap_so_LDADD = ../common/libtio.a ../nss/common.o -lpam

EXTRA_DIST = exports.linux

install-exec-local: install-pam_ldap_so
uninstall-local: uninstall-pam_ldap_so

# install pam_ldap.so
install-pam_ldap_so: pam_ldap.so
	$(INSTALL_PROGRAM) -D pam_ldap.so $(DESTDIR)$(libdir)/security/pam_ldap.so
uninstall-pam_ldap_so:
	-rm -f $(DESTDIR)$(libdir)/security/pam_ldap.so