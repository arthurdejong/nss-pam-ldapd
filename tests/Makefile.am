# Makefile.am - use automake to generate Makefile.in
#
# Copyright (C) 2006 West Consulting
# Copyright (C) 2006, 2007, 2008, 2009, 2010, 2011 Arthur de Jong
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
        test_myldap.sh test_common test_nsscmds.sh test_pamcmds.sh

check_PROGRAMS = test_dict test_set test_tio test_expr test_getpeercred \
                 test_cfg test_myldap test_common

EXTRA_DIST = nslcd-test.conf test_myldap.sh test_nsscmds.sh test_pamcmds.sh \
             in_testenv.sh test_pamcmds.expect usernames.txt

CLEANFILES = $(EXTRA_PROGRAMS)

AM_CPPFLAGS = -I$(top_srcdir)
AM_CFLAGS = $(PTHREAD_CFLAGS) -g

# the following enables verbose protocol debugging information to be dumped
#AM_CPPFLAGS += -DDEBUG_PROT -DDEBUG_PROT_DUMP

# the following enabled verbose tio stats logging
#AM_CPPFLAGS += -DDEBUG_TIO_STATS

test_dict_SOURCES = test_dict.c ../common/dict.h ../common/dict.c
#test_dict_LDADD = ../common/dict.o

test_set_SOURCES = test_set.c ../common/set.h
test_set_LDADD = ../common/libdict.a

test_tio_SOURCES = test_tio.c common.h ../common/tio.h ../common/tio.c
test_tio_LDFLAGS = $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)

test_expr_SOURCES = test_expr.c common.h
test_expr_LDADD = ../common/set.o ../common/dict.o

test_getpeercred_SOURCES = test_getpeercred.c common.h
test_getpeercred_LDADD = ../compat/libcompat.a

# common objects that are included for the tests of nslcd functionality
common_nslcd_LDADD = ../nslcd/log.o ../nslcd/common.o \
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

test_myldap_SOURCES = test_myldap.c common.h
test_myldap_LDADD = ../nslcd/cfg.o $(common_nslcd_LDADD)

test_common_SOURCES = test_common.c ../nslcd/common.h
test_common_LDADD = ../nslcd/cfg.o $(common_nslcd_LDADD)
