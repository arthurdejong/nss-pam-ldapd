#!/bin/sh

# test_pylint.sh - run pylint on the source to find errors
#
# Copyright (C) 2013-2019 Arthur de Jong
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
builddir="${builddir-`dirname "$0"`}"
top_builddir="${top_builddir-${builddir}/..}"
PYLINT="${PYLINT-pylint}"

# Find Pylint
for p in ${PYLINT} pylint pylint3
do
  if "$p" --version > /dev/null 2> /dev/null
  then
    pylint="$p"
  fi
done

# if Pylint is missing, ignore
if [ -z "$pylint" ]
then
  echo "Pylint not found"
  exit 77
fi

# get rcfile absolute path
absdir="$( (cd "$srcdir"; pwd) )"
rcfile="$absdir/pylint.rc"

# get the disable option from the configuration file
# (this somehow doesn't work in pylint)
disable=$(sed -n 's/^disable=\(.*\)$/\1/p' "$rcfile")

# run Pylint in both pynslcd and utils directories
for dir in pynslcd utils
do
  echo "Running pylint in $dir..."
  dir_builddir="$(cd "${top_builddir}/${dir}" && pwd)"
  ( cd "${top_srcdir}/${dir}" ;
    PYTHONPATH="${dir_builddir}" "$pylint" --errors-only --rcfile "$rcfile" --disable "$disable" *.py)
done

# Pylint has the following exit codes:
#  0 if everything went fine
#  1 if a fatal message was issued
#  2 if an error message was issued
#  4 if a warning message was issued
#  8 if a refactor message was issued
#  16 if a convention message was issued
#  32 on usage error
# (exit codes are ORed)
