#!/bin/sh

# test_pycompile.sh - see if all Python files compile
#
# Copyright (C) 2013 Arthur de Jong
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

set -e

# find source directory
srcdir="${srcdir-`dirname "$0"`}"
top_srcdir="${top_srcdir-${srcdir}/..}"
python="${PYTHON-python}"

# compile all Python files
${python} -m compileall -f -q "${top_srcdir}"
