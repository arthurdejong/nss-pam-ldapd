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

# if Python is missing, ignore
if ! ${python} --version > /dev/null 2> /dev/null
then
  echo "Python (${python}) not found"
  exit 77
fi

# compile all Python files (without writing pyc files)
${python} -c "
import os
import py_compile
import sys
import traceback

top_srcdir = '$top_srcdir'
errors_found = 0
tmpfile = 'tmpfile.pyc'

for root, dirs, files in os.walk(top_srcdir):
    for f in files:
        if f.endswith('.py'):
            filename = os.path.join(root, f)
            try:
                py_compile.compile(filename, tmpfile, doraise=True)
            except py_compile.PyCompileError, e:
                print 'Compiling %s ...' % os.path.abspath(filename)
                print e
                errors_found += 1

os.unlink(tmpfile)

if errors_found:
    print '%d errors found' % errors_found
    sys.exit(1)
"
