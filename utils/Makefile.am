# Makefile.am - use automake to generate Makefile.in
#
# Copyright (C) 2013-2016 Arthur de Jong
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

utilsdir = $(datadir)/nslcd-utils

utils_PYTHON = cmdline.py nslcd.py getent.py chsh.py shells.py users.py
nodist_utils_PYTHON = constants.py
CLEANFILES = $(nodist_utils_PYTHON)

all-local: $(nodist_utils_PYTHON)

# clean up locally created compiled Python files
clean-local:
	rm -f *.pyc *.pyo

# copy constants module
constants.py: ../pynslcd/constants.py
	cp ../pynslcd/constants.py .

# create symbolic links to the commands and fix permissions
install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(bindir)
	set -ex; for cmd in getent chsh ; do \
	  chmod a+rx $(DESTDIR)$(utilsdir)/$$cmd.py ; \
	  [ -L $(DESTDIR)$(bindir)/$$cmd.$(MODULE_NAME) ] || $(LN_S) $(utilsdir)/$$cmd.py $(DESTDIR)$(bindir)/$$cmd.$(MODULE_NAME) ; \
	done
