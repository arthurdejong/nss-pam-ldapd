#!/bin/sh

# test_flake8.sh - run Python flake8 tests
#
# Copyright (C) 2019 Arthur de Jong
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

# find virtualenv command
if ! virtualenv --version > /dev/null 2>&1
then
  echo "virtualenv: command not found"
  exit 77
fi

# create virtualenv
venv="${builddir}/flake8-venv"
[ -x "$venv"/bin/pip ] || virtualenv "$venv" --python="$python"
"$venv"/bin/pip install \
  flake8 \
  flake8-author \
  flake8-blind-except \
  flake8-class-newline \
  flake8-commas \
  flake8-deprecated \
  flake8-docstrings \
  flake8-exact-pin \
  flake8-print \
  flake8-quotes \
  flake8-tidy-imports \
  flake8-tuple \
  pep8-naming

# run flake8 over pynslcd
"$venv"/bin/flake8 \
  --config="${srcdir}/flake8.ini" \
  "${top_srcdir}/pynslcd"

# run flake8 over utils
"$venv"/bin/flake8 \
  --config="${srcdir}/flake8.ini" \
  "${top_srcdir}/utils"

# run flake8 over tests
"$venv"/bin/flake8 \
  --config="${srcdir}/flake8.ini" \
  "${top_srcdir}/tests"/*.py
