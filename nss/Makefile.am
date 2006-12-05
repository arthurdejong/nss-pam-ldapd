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

noinst_PROGRAMS = nss_ldap.so
AM_CFLAGS = -fPIC

# determin version numbers to use in installed files
LIBC_VERS = `ls /lib/libc-*.so | tail -n 1 |sed -e 's/\/lib\/libc-\(.*\)\.so/\1/'`
NSS_VERS = $(shell ls /lib/libnss_files.so.? | tail -n 1 | sed -e 's/\/lib\/libnss_files\.so\.\(.*\)/\1/')
NSS_LDAP_LIBC_VERSIONED = libnss_ldap-$(LIBC_VERS).so
NSS_LDAP_NSS_VERSIONED = libnss_ldap.so.$(NSS_VERS)

nss_ldap_so_SOURCES = common.c common.h prototypes.h \
                      ../nslcd.h ../nslcd-common.h \
                      aliases.c ethers.c group.c hosts.c netgroup.c \
                      networks.c passwd.c protocols.c rpc.c services.c \
                      shadow.c
nss_ldap_so_LDFLAGS = -shared -Wl,-soname,$(NSS_LDAP_NSS_VERSIONED) \
                      -Wl,--version-script,\$(srcdir)/exports.linux
nss_ldap_so_LDADD = @nss_ldap_so_LIBS@

EXTRA_DIST = exports.linux

install-exec-local: install-nss_ldap_so

# install /lib/libnss_ldap.so.2 and create
# /lib/libnss_ldap-2.3.6.so and /usr/lib/libnss_ldap.so symlinks
# (skip the last one for now and see what breaks)
install-nss_ldap_so: nss_ldap.so
	$(INSTALL_PROGRAM) -D nss_ldap.so $(DESTDIR)$(libdir)/$(NSS_LDAP_LIBC_VERSIONED)
	(cd $(DESTDIR)$(libdir); ln -sf $(NSS_LDAP_LIBC_VERSIONED) $(NSS_LDAP_NSS_VERSIONED))
#	$(mkinstalldirs) $(DESTDIR)/usr$(libdir)
#	(cd $(DESTDIR)/usr$(libdir); ln -sf ../..$(libdir)/$(NSS_LDAP_NSS_VERSIONED) libnss_ldap.so)
