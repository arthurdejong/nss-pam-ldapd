# Makefile.am - use automake to generate Makefile.in
#
# Copyright (C) 2006 Luke Howard
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

SUBDIRS = nss server tests

man_MANS = nss_ldap.5

EXTRA_DIST = ChangeLog \
             AUTHORS ANNOUNCE NEWS INSTALL README COPYING \
             ldap.conf \
             debian doc exports.linux nss_ldap.5 tests \
             nslcd.h nslcd-common.h

NSS_LDAP_PATH_CONF = @NSS_LDAP_PATH_CONF@
NSS_LDAP_PATH_ROOTPASSWD = @NSS_LDAP_PATH_ROOTPASSWD@

NSS_LDAP_LDFLAGS = @NSS_LDAP_LDFLAGS@
DEFS = @DEFS@
#INCLUDES = -I$(top_builddir) -I$(srcdir)

if GLIBC
LIBC_VERS = `ls /lib/libc-*.so | tail -n 1 |sed -e 's/\/lib\/libc-\(.*\)\.so/\1/'`
NSS_LDAP_LIBC_VERSIONED = libnss_ldap-$(LIBC_VERS).so
NSS_VERS = $(shell ls /lib/libnss_files.so.? | tail -n 1 | sed -e 's/\/lib\/libnss_files\.so\.\(.*\)/\1/')
NSS_LDAP_NSS_VERSIONED = libnss_ldap.so.$(NSS_VERS)
endif

INST_UID=root
if AIX
INST_GID=system
else
INST_GID=root
endif

install-exec-local: nss_ldap.so
	@$(NORMAL_INSTALL)
if GLIBC
	-rm -f $(DESTDIR)$(libdir)/$(NSS_LDAP_LIBC_VERSIONED)
	$(mkinstalldirs) $(DESTDIR)$(libdir)
	$(INSTALL_PROGRAM) -D -o $(INST_UID) -g $(INST_GID) nss_ldap.so $(DESTDIR)$(libdir)/$(NSS_LDAP_LIBC_VERSIONED)
	(cd $(DESTDIR)$(libdir); ln -sf $(NSS_LDAP_LIBC_VERSIONED) $(NSS_LDAP_NSS_VERSIONED))
	$(mkinstalldirs) $(DESTDIR)/usr$(libdir)
	(cd $(DESTDIR)/usr$(libdir); ln -sf ../..$(libdir)/$(NSS_LDAP_NSS_VERSIONED) .)
else
	$(mkinstalldirs) $(DESTDIR)$(libdir)
	$(INSTALL_PROGRAM) -o $(INST_UID) -g $(INST_GID) nss_ldap.so $(DESTDIR)$(libdir)/nss_ldap.so.1
	(cd $(DESTDIR)$(libdir); rm -f nss_ldap.so; ln -s nss_ldap.so.1 nss_ldap.so)
endif

install-data-local:
	@$(NORMAL_INSTALL)
	@if test ! -f $(DESTDIR)$(NSS_LDAP_PATH_CONF); then \
	  $(mkinstalldirs) $(DESTDIR)$(dir $(NSS_LDAP_PATH_CONF)); \
	  $(INSTALL_DATA) -o $(INST_UID) -g $(INST_GID) $(srcdir)/ldap.conf $(DESTDIR)$(NSS_LDAP_PATH_CONF); \
	fi

uninstall-local:
	@$(NORMAL_UNINSTALL)

