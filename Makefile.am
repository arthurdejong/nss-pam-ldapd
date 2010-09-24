# Makefile.am - use automake to generate Makefile.in
#
# Copyright (C) 2006 Luke Howard
# Copyright (C) 2006 West Consulting
# Copyright (C) 2006, 2007, 2008, 2009 Arthur de Jong
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

if ENABLE_NSS
  MAYBE_NSS = nss
endif
if ENABLE_PAM
  MAYBE_PAM = pam
endif
if ENABLE_NSLCD
  ENABLE_NSLCD = nslcd
endif

SUBDIRS = compat common $(MAYBE_NSS) $(MAYBE_PAM) $(ENABLE_NSLCD) man tests

DEBIAN_FILES = debian/changelog debian/compat debian/control \
               debian/copyright debian/rules debian/NEWS \
               debian/source/format \
               debian/nslcd.conffile \
               debian/nslcd.config \
               debian/nslcd.default \
               debian/nslcd.docs \
               debian/nslcd.examples \
               debian/nslcd.init \
               debian/nslcd.install \
               debian/nslcd.manpages \
               debian/nslcd.postinst \
               debian/nslcd.postrm \
               debian/nslcd.templates \
               debian/libnss-ldapd.config \
               debian/libnss-ldapd.install \
               debian/libnss-ldapd.lintian-overrides \
               debian/libnss-ldapd.postinst \
               debian/libnss-ldapd.postrm \
               debian/libnss-ldapd.templates \
               debian/libpam-ldapd.install \
               debian/libpam-ldapd.lintian-overrides \
               debian/libpam-ldapd.manpages \
               debian/libpam-ldapd.pam-auth-update \
               debian/libpam-ldapd.postinst \
               debian/libpam-ldapd.prerm \
               debian/libpam-ldapd.templates \
               debian/po/POTFILES.in debian/po/templates.pot \
               $(wildcard debian/po/*.po)

EXTRA_DIST = nslcd.conf nslcd.h $(wildcard ChangeLog-20??) \
             $(wildcard m4/*.m4) HACKING $(DEBIAN_FILES)

DISTCHECK_CONFIGURE_FLAGS = --enable-warnings

ACLOCAL_AMFLAGS = -I m4

NSLCD_CONF_PATH = @NSLCD_CONF_PATH@

install-data-local: install-nslcd_conf
uninstall-local: uninstall-nslcd_conf

# install a default configuration file if it is not already there
install-nslcd_conf:
	@if [ -f $(DESTDIR)$(NSLCD_CONF_PATH) ]; then \
	  echo "$(DESTDIR)$(NSLCD_CONF_PATH) already exists, install will not overwrite"; \
	else \
	  $(INSTALL_DATA) -D $(srcdir)/nslcd.conf $(DESTDIR)$(NSLCD_CONF_PATH) || true; \
	fi
uninstall-nslcd_conf:
	-rm -f $(DESTDIR)$(NSLCD_CONF_PATH)

# target for easily creating a Debian package
# the find is an ugly hack to fix a bug if being built on an nfs filesystem
deb: distdir
	find $(distdir) -type d | xargs touch
	cd $(distdir) && \
	  debuild
	rm -rf $(distdir)

# target for generating the ChangeLog file
changelog:
	( svn2cl -i --stdout -r HEAD:1206 ; \
		svn2cl -i --stdout -r 1205:981 --strip-prefix='nss-pam-ldapd' ; \
	  svn2cl -i --stdout -r 980:807 --strip-prefix='nss-ldapd' ; \
	) > ChangeLog

flawfinder.html:
	flawfinder --quiet --html --context --followdotdir . > $@

rats.html:
	rats --quiet --html --context . > $@

splint.txt:
	-env LARCH_PATH=/usr/share/splint/lib/ \
	    LCLIMPORTDIR=/usr/share/splint/imports/ \
	    splint -checks \
	           -warnposix +showsummary +showalluses +hints -namechecks \
	           -globstate -predboolint -mustfreeonly -temptrans -kepttrans \
	           -I. -I$(srcdir) -I$(top_builddir) $(DEFS) -D_REENTRANT -DDEBUG \
	           -D__signed__=signed -D__thread= -D__gnuc_va_list=__ptr_t \
	           -Dkrb5_int32=int32_t -Dkrb5_ui_4=uint32_t \
	           -D__u16=uint16_t -D__u32=uint32_t \
	           *.[ch] nss/*.[ch] nslcd/*.[ch] common/*.[ch] compat/*.[ch] > $@ 2>&1

.PHONY: flawfinder.html rats.html splint.txt
