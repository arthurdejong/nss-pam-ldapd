#!/bin/sh

# test_doctest.sh - run Python doctests
#
# Copyright (C) 2016-2019 Arthur de Jong
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

# Find Python interpreters
find_python() {
  for p in "${python}" python python2 python2.7 python3 python3.5 python3.6 python3.7 python3.8
  do
    if [ -n "$p" ] && "$p" --version > /dev/null 2> /dev/null
    then
      readlink -f `which $p` 2> /dev/null || true
    fi
  done
}
interpreters=`find_python | sort -u`

# if Python is missing, ignore
if [ -z "$interpreters" ]
then
  echo "Python (${python}) not found"
  exit 77
fi

# run doctests
for python in $interpreters
do
  if ${python} -c 'import ldap'
  then
    echo "Running pynslcd doctests with $python..."
    PYTHONPATH="${top_builddir}/pynslcd" ${python} -m doctest -v "${top_srcdir}/pynslcd"/*.py
  fi
  echo "Running pynslcd doctests with $python..."
  PYTHONPATH="${top_builddir}/utils" ${python} -m doctest -v "${top_srcdir}/utils"/*.py
done
