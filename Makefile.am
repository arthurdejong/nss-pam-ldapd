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
             debian doc \
             nslcd.h nslcd-common.h

NSS_LDAP_PATH_CONF = @NSS_LDAP_PATH_CONF@

install-data-local: install-ldap_conf

install-ldap_conf:
	@if [ -f $(DESTDIR)$(NSS_LDAP_PATH_CONF) ]; then \
	  echo "$(DESTDIR)$(NSS_LDAP_PATH_CONF) already exists, install will not overwrite"; \
	else \
	  $(INSTALL_DATA) -D $(srcdir)/ldap.conf $(DESTDIR)$(NSS_LDAP_PATH_CONF); \
	fi
