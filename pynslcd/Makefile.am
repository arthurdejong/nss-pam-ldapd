# Makefile.am - use automake to generate Makefile.in
#
# Copyright (C) 2010-2019 Arthur de Jong
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

pynslcddir = $(datadir)/pynslcd

pynslcd_PYTHON = pynslcd.py attmap.py cache.py cfg.py common.py expr.py \
                 mypidfile.py invalidator.py search.py tio.py \
                 config.py alias.py ether.py group.py host.py netgroup.py \
                 network.py passwd.py protocol.py rpc.py service.py \
                 shadow.py pam.py usermod.py
nodist_pynslcd_PYTHON = constants.py
CLEANFILES = $(nodist_pynslcd_PYTHON)

all-local: $(nodist_pynslcd_PYTHON)

# clean up locally created compiled Python files
clean-local:
	-rm -rf *.pyc *.pyo __pycache__

constants.py: constants.py.in $(top_srcdir)/nslcd.h

# create a symbolic link for the pynslcd daemon and fix permissions
install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(sbindir)
	[ -L $(DESTDIR)$(sbindir)/pynslcd ] || $(LN_S) $(pynslcddir)/pynslcd.py $(DESTDIR)$(sbindir)/pynslcd
	chmod a+rx $(DESTDIR)$(pynslcddir)/pynslcd.py
	sed -i -e '1 s|^#!.*|#! $(PYTHON)|;1 s|^#! \([^/].*\)|#! /usr/bin/env \1|' $(DESTDIR)$(pynslcddir)/pynslcd.py
