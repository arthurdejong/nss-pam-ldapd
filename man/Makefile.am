# Makefile.am - use automake to generate Makefile.in
#
# Copyright (C) 2007, 2009, 2010 Arthur de Jong
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

NSLCD_MANS = nslcd.conf.5 nslcd.8
PYNSLCD_MANS = pynslcd.8
PAM_MANS = pam_ldap.8
ALLMANS = $(NSLCD_MANS) $(PYNSLCD_MANS) $(PAM_MANS)

noinst_DATA = $(ALLMANS)
EXTRA_DIST = $(shell echo $(ALLMANS) | sed 's/ \|$$/.xml /g')

# figure out which manual pages to install
dist_man_MANS = $(NSLCD_MANS)
if ENABLE_PAM
  dist_man_MANS += $(PAM_MANS)
endif
if ENABLE_PYNSLCD
  dist_man_MANS += $(PYNSLCD_MANS)
endif

if GENMAN

MAINTAINERCLEANFILES = $(dist_man_MANS)

SUFFIXES = .xml
.xml:
	$(DOCBOOK2X_MAN) \
	  --string-param header-3='$(RELEASE_MONTH)' \
	  --string-param header-4='Version $(VERSION)' \
	  --encoding=utf-8 \
	  $<

.xml.html:
	xmlto xhtml-nochunks $<

endif
