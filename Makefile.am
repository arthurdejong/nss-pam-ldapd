# Makefile.am - use automake to generate Makefile.in
#
# Copyright (C) 2006 Luke Howard
# Copyright (C) 2006 West Consulting
# Copyright (C) 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013 Arthur de Jong
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

SUBDIRS = compat common
if ENABLE_NSS
  SUBDIRS += nss
endif
if ENABLE_PAM
  SUBDIRS += pam
endif
if ENABLE_NSLCD
  SUBDIRS += nslcd
endif
if ENABLE_PYNSLCD
  SUBDIRS += pynslcd
endif
if ENABLE_UTILS
  SUBDIRS += utils
endif
if ENABLE_NLS
  SUBDIRS += po
endif
SUBDIRS += man tests

EXTRA_DIST = nslcd.conf nslcd.h $(wildcard ChangeLog-20??) \
             $(wildcard m4/*.m4) HACKING ldapns.schema ldapns.ldif

DISTCLEANFILES = confinc.out

DISTCHECK_CONFIGURE_FLAGS = --enable-warnings --enable-pynslcd --enable-utils \
                            --with-pam-seclib-dir="\$${libdir}/security" \
                            --with-ldap-conf-file="\$${prefix}/nslcd.conf" \
                            CPPFLAGS=$(CPPFLAGS) LDFLAGS=$(LDFLAGS) \
                            PYTHON=$(PYTHON)

ACLOCAL_AMFLAGS = -I m4

NSLCD_CONF_PATH = @NSLCD_CONF_PATH@

install-data-local: install-nslcd_conf
uninstall-local: uninstall-nslcd_conf

# install a default configuration file if it is not already there
install-nslcd_conf:
	@if [ -f $(DESTDIR)$(NSLCD_CONF_PATH) ]; then \
	  echo "$(DESTDIR)$(NSLCD_CONF_PATH) already exists, install will not overwrite"; \
	else \
	  $(mkinstalldirs) `dirname $(DESTDIR)$(NSLCD_CONF_PATH)`; \
	  $(INSTALL) -m 600 $(srcdir)/nslcd.conf $(DESTDIR)$(NSLCD_CONF_PATH); \
	fi
uninstall-nslcd_conf:
	-rm -f $(DESTDIR)$(NSLCD_CONF_PATH)

# target for generating the ChangeLog file
changelog:
	git log --date=short --name-only \
	    --format="%x0c%ad  %aN <%aE>%n%n%x09* [%h]%x00%s%n%x00%+b%x00" \
	    e3f0453... | \
	  awk 'BEGIN { RS="\f"; FS="\0" } { if ($$1) { gsub(/\n*$$/, "", $$4); gsub(/^\n*/, "", $$4); gsub(/\n/, ", ", $$4); gsub(/\n*$$/, "", $$3); gsub(/\n/, "\n\t  ", $$3); gsub(/.$$/, "&\n", $$3); print $$1 " " $$4 ": "; print "\t  " $$2 $$3 }}' | \
	  fmt --width=78 -c > ChangeLog

flawfinder.html:
	flawfinder --quiet --html --context --followdotdir . > $@

rats.html:
	rats --quiet --html --context . > $@

splint.txt:
	-env LARCH_PATH=/usr/share/splint/lib/ \
	    LCLIMPORTDIR=/usr/share/splint/imports/ \
	    splint -checks -mustfreefresh \
	           -warnposix +showsummary +showalluses +hints -namechecks \
	           -globstate -predboolint -mustfreeonly -temptrans -kepttrans \
	           -I. -I$(srcdir) -I$(top_builddir) $(DEFS) -D_REENTRANT -DDEBUG \
	           -D__signed__=signed -D__thread= -D__gnuc_va_list=__ptr_t \
	           -Dkrb5_int32=int32_t -Dkrb5_ui_4=uint32_t \
	           -D__u16=uint16_t -D__u32=uint32_t \
	           *.[ch] nss/*.[ch] nslcd/*.[ch] common/*.[ch] compat/*.[ch] > $@ 2>&1

.PHONY: flawfinder.html rats.html splint.txt
