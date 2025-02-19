# Makefile.am - use automake to generate Makefile.in
#
# Copyright (C) 2006 West Consulting
# Copyright (C) 2006-2019 Arthur de Jong
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

TESTS = test_dict test_set test_tio test_expr test_getpeercred test_cfg \
        test_attmap test_myldap.sh test_common test_nsscmds.sh \
        test_pamcmds.sh test_manpages.sh test_clock \
        test_tio_timeout
if HAVE_PYTHON
  TESTS += test_pycompile.sh test_pylint.sh
endif
if ENABLE_PYNSLCD
  TESTS += test_pynslcd_cache.py test_doctest.sh
endif
if ENABLE_UTILS
  TESTS += test_ldapcmds.sh
endif

TEST_EXTENSIONS = .sh .py
SH_LOG_COMPILER = $(SHELL)
PY_LOG_COMPILER = $(PYTHON)

AM_TESTS_ENVIRONMENT = PYTHON='@PYTHON@'; export PYTHON; \
                       builddir=$(builddir); export builddir;

check_PROGRAMS = test_dict test_set test_tio test_expr test_getpeercred \
                 test_cfg test_attmap test_myldap test_common test_clock \
                 test_tio_timeout lookup_netgroup lookup_shadow \
                 lookup_groupbyuser

EXTRA_DIST = README nslcd-test.conf usernames.txt testenv.sh test_myldap.sh \
             test_nsscmds.sh test_ldapcmds.sh test_pamcmds.sh \
             test_pamcmds.expect test_manpages.sh \
             test_pycompile.sh test_doctest.sh \
             test_pylint.sh pylint.rc \
             test_flake8.sh flake8.ini \
             test_pynslcd_cache.py \
             setup_slapd.sh config.ldif test.ldif

CLEANFILES = $(EXTRA_PROGRAMS) test_pamcmds.log
clean-local:
	-rm -rf *.pyc *.pyo __pycache__ flake8-venv

AM_CPPFLAGS = -I$(top_srcdir)
AM_CFLAGS = $(PTHREAD_CFLAGS) -g $(DEBUG_CFLAGS) $(EXTRA_CFLAGS)

test_dict_SOURCES = test_dict.c ../common/dict.h
test_dict_LDADD = ../common/libdict.a

test_set_SOURCES = test_set.c ../common/set.h
test_set_LDADD = ../common/libdict.a

test_tio_SOURCES = test_tio.c common.h ../common/tio.h
test_tio_LDADD = ../common/tio.o
test_tio_LDFLAGS = $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)

test_expr_SOURCES = test_expr.c common.h
test_expr_LDADD = ../common/set.o ../common/dict.o

test_getpeercred_SOURCES = test_getpeercred.c common.h
test_getpeercred_LDADD = ../compat/libcompat.a

# common objects that are included for the tests of nslcd functionality
common_nslcd_LDADD = ../nslcd/log.o ../nslcd/common.o ../nslcd/invalidator.o \
                     ../nslcd/myldap.o ../nslcd/attmap.o ../nslcd/nsswitch.o \
                     ../nslcd/alias.o ../nslcd/ether.o ../nslcd/group.o \
                     ../nslcd/host.o ../nslcd/netgroup.o ../nslcd/network.o \
                     ../nslcd/passwd.o ../nslcd/protocol.o ../nslcd/rpc.o \
                     ../nslcd/service.o ../nslcd/shadow.o ../nslcd/pam.o \
                     ../common/libtio.a ../common/libdict.a \
                     ../common/libexpr.a ../compat/libcompat.a \
                     @nslcd_LIBS@ @PTHREAD_LIBS@

test_cfg_SOURCES = test_cfg.c common.h
test_cfg_LDADD = $(common_nslcd_LDADD)

test_attmap_SOURCES = test_attmap.c common.h
test_attmap_LDADD = ../nslcd/cfg.o $(common_nslcd_LDADD)

test_myldap_SOURCES = test_myldap.c common.h
test_myldap_LDADD = ../nslcd/cfg.o $(common_nslcd_LDADD)

test_common_SOURCES = test_common.c ../nslcd/common.h
test_common_LDADD = ../nslcd/cfg.o $(common_nslcd_LDADD)

test_clock_SOURCES = test_clock.c

test_tio_timeout_SOURCES = test_tio_timeout.c ../common/tio.h

lookup_netgroup_SOURCES = lookup_netgroup.c

lookup_shadow_SOURCES = lookup_shadow.c

lookup_groupbyuser_SOURCES = lookup_groupbyuser.c
