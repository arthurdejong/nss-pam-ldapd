# Makefile.am - use automake to generate Makefile.in
#
# Copyright (C) 2009, 2010, 2011 Arthur de Jong
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

noinst_PROGRAMS = pam_ldap.so

AM_CPPFLAGS=-I$(top_srcdir)
AM_CFLAGS = $(PIC_CFLAGS) $(DEBUG_CFLAGS) $(EXTRA_CFLAGS)

pam_ldap_so_SOURCES = ../nslcd.h ../common/nslcd-prot.h \
                      ../compat/attrs.h pam.c common.h
pam_ldap_so_LDADD = ../common/libtio.a ../common/libprot.a \
                    ../compat/libcompat.a \
                    -lpam

EXTRA_DIST = pam_ldap.map

install-exec-local: install-pam_ldap_so
uninstall-local: uninstall-pam_ldap_so

install-pam_ldap_so: pam_ldap.so
	-rm -f $(DESTDIR)$(PAM_SECLIB_DIR)/$(PAM_LDAP_SONAME)
	$(mkinstalldirs) $(DESTDIR)$(PAM_SECLIB_DIR)
	$(INSTALL_PROGRAM) pam_ldap.so $(DESTDIR)$(PAM_SECLIB_DIR)/$(PAM_LDAP_SONAME)

uninstall-pam_ldap_so:
	-rm -f $(DESTDIR)$(PAM_SECLIB_DIR)/$(PAM_LDAP_SONAME)
