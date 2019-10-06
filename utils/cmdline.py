# coding: utf-8

# cmdline.py - functions for handling command-line options
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

import argparse

import constants


version_string = '''
%s
Written by Arthur de Jong.

Copyright (C) 2013-2019 Arthur de Jong
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
'''.strip() % constants.PACKAGE_STRING


class VersionAction(argparse.Action):

    def __init__(self, option_strings, dest,
                 help='output version information and exit'):
        super(VersionAction, self).__init__(
            option_strings=option_strings,
            dest=argparse.SUPPRESS,
            default=argparse.SUPPRESS,
            nargs=0,
            help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        print(version_string)
        parser.exit()


class ListShellsAction(argparse.Action):

    def __init__(self, option_strings, dest,
                 help='list the shells found in /etc/shells'):
        super(ListShellsAction, self).__init__(
            option_strings=option_strings,
            dest=argparse.SUPPRESS,
            default=argparse.SUPPRESS,
            nargs=0,
            help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        import shells
        for shell in shells.list_shells():
            print(shell)
        parser.exit()
