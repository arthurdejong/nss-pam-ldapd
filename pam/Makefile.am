# Makefile.am - use automake to generate Makefile.in
#
# Copyright (C) 2009, 2010 Arthur de Jong
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

pam_ldap_so_SOURCES = ../nslcd.h ../common/nslcd-prot.h \
                      ../compat/attrs.h pam.c common.h
pam_ldap_so_LDFLAGS = -shared
if HAVE_VERSION_SCRIPT_FLAG
pam_ldap_so_LDFLAGS += $(VERSION_SCRIPT_FLAG)\$(srcdir)/pam_ldap.map
endif
pam_ldap_so_LDADD = ../common/libtio.a ../common/libprot.a -lpam \
                    ../compat/libcompat.a

EXTRA_DIST = pam_ldap.map

install-exec-local: install-pam_ldap_so
uninstall-local: uninstall-pam_ldap_so

# install pam_ldap.so
install-pam_ldap_so: pam_ldap.so
	$(INSTALL_PROGRAM) -D pam_ldap.so $(DESTDIR)$(libdir)/security/pam_ldap.so
uninstall-pam_ldap_so:
	-rm -f $(DESTDIR)$(libdir)/security/pam_ldap.so
