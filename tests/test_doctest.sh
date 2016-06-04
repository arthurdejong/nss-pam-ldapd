#!/bin/sh

# test_doctest.sh - run Python doctests
#
# Copyright (C) 2016 Arthur de Jong
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
builddir="${builddir-`dirname "$0"`}"
top_srcdir="${top_srcdir-${srcdir}/..}"
top_builddir="${top_builddir-${builddir}/..}"
python="${PYTHON-python}"

# if Python is missing, ignore
if ! ${python} --version > /dev/null 2> /dev/null
then
  echo "Python (${python}) not found"
  exit 77
fi

# run doctests
for dir in pynslcd utils
do
  echo "Running doctests in $dir..."
  PYTHONPATH="${top_builddir}/${dir}" ${python} -m doctest -v "${top_srcdir}/${dir}"/*.py
done
