#!/bin/sh

# test_pamcmds.sh - test script to start test_pamcmds.expect
#
# Copyright (C) 2011, 2013 Arthur de Jong
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

# ensure that we are running in the test environment
. "$srcdir/in_testenv.sh"

# check if we have expect installed
EXPECT="$(which expect 2> /dev/null || true)"
if [ -x "$EXPECT" ]
then
  :
else
  echo "$0: expect not found, not running tests"
  exit 77
fi

export srcdir
"$EXPECT" "$srcdir/test_pamcmds.expect"
