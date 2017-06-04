#!/usr/bin/env python
# coding: utf-8

# chsh.py - program for changing the login shell using nslcd
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

import argparse

from cmdline import VersionAction, ListShellsAction
import constants
import nslcd
import shells
import users


# set up command line parser
parser = argparse.ArgumentParser(
    description='Change the user login shell in LDAP.',
    epilog='Report bugs to <%s>.' % constants.PACKAGE_BUGREPORT)
parser.add_argument('-V', '--version', action=VersionAction)
parser.add_argument('-s', '--shell', help='login shell for the user account')
parser.add_argument('-l', '--list-shells', action=ListShellsAction)
parser.add_argument('username', metavar='USER', nargs='?',
                    help="the user who's shell to change")


def ask_shell(oldshell):
    """Ask the user to provide a shell."""
    shell = raw_input('  Login Shell [%s]: ' % oldshell)
    return shell or oldshell


if __name__ == '__main__':
    # parse arguments
    args = parser.parse_args()
    # check username part
    user = users.User(args.username)
    user.check()
    # check the command line shell if one was provided (to fail early)
    shell = args.shell
    if shell is not None:
        shells.check(shell, user.asroot)
    # prompt for a password if required
    password = user.get_passwd()
    # prompt for a shell if it was not specified on the command line
    if shell is None:
        print('Enter the new value, or press ENTER for the default')
        shell = ask_shell(user.shell)
        shells.check(shell, user.asroot)
    # perform the modification
    result = nslcd.usermod(
        user.username, user.asroot, password, {
            constants.NSLCD_USERMOD_SHELL: shell,
        })
    # TODO: print proper response
