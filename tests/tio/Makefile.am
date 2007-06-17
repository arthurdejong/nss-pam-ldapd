# Makefile.am - use automake to generate Makefile.in
#
# Copyright (C) 2007 Arthur de Jong
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

noinst_PROGRAMS = test_tio

AM_CPPFLAGS=-I$(top_srcdir)

test_tio_SOURCES = test_tio.c ../../common/tio.h ../../common/tio.c
#test_tio_LDADD = ../../common/libtio.a
test_tio_CFLAGS = -pthread
test_tio_LDFLAGS = -pthread
