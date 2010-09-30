# Makefile.am - use automake to generate Makefile.in
#
# Copyright (C) 2006 Luke Howard
# Copyright (C) 2006 West Consulting
# Copyright (C) 2006, 2007, 2009, 2010 Arthur de Jong
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
AM_CFLAGS = -fPIC

nss_ldap_so_SOURCES = common.c common.h prototypes.h \
                      ../nslcd.h ../common/nslcd-prot.h \
                      ../compat/attrs.h
nss_ldap_so_LDFLAGS = @nss_ldap_so_LDFLAGS@
if HAVE_VERSION_SCRIPT_FLAG
nss_ldap_so_LDFLAGS += $(VERSION_SCRIPT_FLAG)\$(srcdir)/nss_ldap.map
endif
nss_ldap_so_DEPENDENCIES = $(NSS_MODULE_OBJS)
EXTRA_nss_ldap_so_SOURCES = aliases.c ethers.c group.c hosts.c netgroup.c \
                            networks.c passwd.c protocols.c rpc.c services.c \
                            shadow.c

if USE_NATIVE_LINKER
nss_ldap_so_LINK = @nss_ldap_so_LD@ @nss_ldap_so_LDFLAGS@ -o $@
else
nss_ldap_so_LINK = $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAG) -o $@
endif

EXTRA_DIST = nss_ldap.map

install-exec-local: install-nss_ldap_so
uninstall-local: uninstall-nss_ldap_so

install-nss_ldap_so: nss_ldap.so
	-rm -f $(DESTDIR)$(libdir)/$(NSS_LDAP_SONAME)
	$(mkinstalldirs) $(DESTDIR)$(libdir)
	$(INSTALL_PROGRAM) nss_ldap.so $(DESTDIR)$(libdir)/$(NSS_LDAP_SONAME)

uninstall-nss_ldap_so:
	-rm -f $(DESTDIR)$(libdir)/$(NSS_LDAP_SONAME)
