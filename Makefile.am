# Makefile.am - use automake to generate Makefile.in
# Copyright (C) 2006 Luke Howard
# Copyright (C) 2006 West consulting
# Copyright (C) 2006 Arthur de Jong
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

noinst_PROGRAMS = nss_ldap.so
INST_UID=root
if AIX
INST_GID=system
else
INST_GID=root
endif

EXTRA_DIST = CVSVersionInfo.txt ChangeLog \
             AUTHORS ANNOUNCE NEWS INSTALL README COPYING \
             ldap.conf nsswitch.ldap

man_MANS = nss_ldap.5

nss_ldap_so_SOURCES = ldap-nss.c ldap-pwd.c ldap-grp.c ldap-netgrp.c ldap-rpc.c \
        ldap-hosts.c ldap-network.c ldap-proto.c ldap-spwd.c \
        ldap-alias.c ldap-service.c ldap-schema.c ldap-ethers.c \
        ldap-automount.c util.c ltf.c resolve.c \
        dnsconfig.c pagectrl.c

nss_ldap_so_LDFLAGS = @nss_ldap_so_LDFLAGS@

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

if USE_NATIVE_LINKER
NATIVE_LINK = $(nss_ldap_so_LD) $(AM_LDFLAGS) -o $@
else
GNU_LINK = $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@
endif

# This is horrible but appears to be the only way to work with
# recent versions of automake. Any better ideas, let me know.
LINK = $(NATIVE_LINK) $(GNU_LINK)

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
	$(INSTALL_DATA) -o $(INST_UID) -g $(INST_GID) $(srcdir)/nsswitch.ldap $(DESTDIR)$(sysconfdir)/nsswitch.ldap;

uninstall-local:
	@$(NORMAL_UNINSTALL)

