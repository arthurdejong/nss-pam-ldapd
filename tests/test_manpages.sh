#!/bin/sh

# test_manpages.sh - run some validity checks on the manual pages
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

# find manual page directory
srcdir="${srcdir-`dirname "$0"`}"
top_srcdir="${top_srcdir-${srcdir}/..}"

# if xmlto is missing, ignore
if (xmlto --version) > /dev/null 2> /dev/null
then
  :
else
  echo "xmlto not found"
  exit 77
fi

# set up a temporary directory
tmpdir="test_manpages.tmp"
rm -rf "$tmpdir"
mkdir "$tmpdir"

# generate HTML for all manual pages
for man in $top_srcdir/man/*.xml
do
  echo "xmlto $man"
  xmlto xhtml-nochunks -o "$tmpdir" "$man"
done

# clean up
rm -rf "$tmpdir"
