# coding: utf-8

# shells.py - functions for validating user shells
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

import ctypes
import ctypes.util
import os
import sys


def list_shells():
    """List the shells from /etc/shells."""
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    getusershell = libc.getusershell
    getusershell.restype = ctypes.c_char_p
    libc.setusershell()
    while True:
        shell = getusershell()
        if not shell:
            break
        yield shell.decode('utf-8')
    libc.endusershell()


def shellexists(shell):
    """Check if the provided shell exists and is executable."""
    return os.path.isfile(shell) and os.access(shell, os.X_OK)


def check(shell, asroot=False):
    """Check if the specified shell is valid and exit if it isn't."""
    # if the shell is listed in /etc/shells, everything should be OK
    if shell in list_shells():
        return
    # if we are not root, bail out
    if not asroot:
        if not shell:
            # FIXME: print to stderr
            print('%s: empty shell not allowed' % sys.argv[0])
        else:
            # FIXME: print to stderr
            print('%s: %s is an invalid shell' % (sys.argv[0], shell))
        sys.exit(1)
    # warn if something seems wrong
    if not shell:
        # FIXME: print to stderr
        print('%s: Warning: setting empty shell' % sys.argv[0])
    elif not shellexists(shell):
        print('%s: Warning: %s does not exist' % (sys.argv[0], shell))
