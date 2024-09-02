# Makefile.am - use automake to generate Makefile.in
#
# Copyright (C) 2024 Tero Saarni.
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

# Usage:
#
# The list of source files containing translatable strings is defined in
# POTFILES variable. The list of languages is defined in LINGUAS variable.
#
# After adding new translatable strings to source files the .pot file (template)
# and the .po files (translations) need to be updated by running:
#
#   make generate
#
# New language is added by creating a new .po file with msginit and adding
# the language to LINGUAS variable in this file.
#
#   msginit --locale=[locale]
#

# List of source files containing translatable strings.
POTFILES = $(top_srcdir)/pam/pam.c \
  $(top_srcdir)/nslcd/myldap.c \
  $(top_srcdir)/compat/ldap_passwordpolicy_err2txt.c \
  $(top_srcdir)/compat/pam_get_authtok.c

# List of languages to generate translations for.
LINGUAS = fi sv

POTFILE = $(PACKAGE).pot
POFILES = $(LINGUAS:=.po)
GMOFILES = $(LINGUAS:=.gmo)

# Files to clean when running make clean.
CLEANFILES = $(GMOFILES)

# Files to include when running make dist.
EXTRA_DIST = $(POTFILE) $(POFILES)

all: $(GMOFILES)

# Generate .pot file and update .po files.
generate: $(POTFILE) $(POFILES)

# Generate .pot file from source files.
$(POTFILE): $(POTFILES)
	xgettext --keyword=_ --language=C -o $@ $(POTFILES)

# Update existing .po files with msgmerge.
$(POFILES): $(POTFILE)
	msgmerge --update --no-fuzzy-matching $@ $<

# Compile .po files into .gmo files.
$(GMOFILES): %.gmo: %.po
	msgfmt -c -o $@ $<

install-data-local: $(GMOFILES)
	for lang in $(LINGUAS) ; do \
	  $(MKDIR_P) $(DESTDIR)$(localedir)/$$lang/LC_MESSAGES ; \
	  $(INSTALL) $$lang.gmo $(DESTDIR)$(localedir)/$$lang/LC_MESSAGES/$(PACKAGE).mo ; \
	done
