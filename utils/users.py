# coding: utf-8

# users.py - functions for validating the user to change information for
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

import getpass
import os
import pwd
import sys


class User(object):

    def __init__(self, username):
        self.myuid = os.getuid()
        if username:
            userinfo = pwd.getpwnam(username)
        else:
            self.asroot = False
            userinfo = pwd.getpwuid(self.myuid)
        (self.username, self.password, self.uid, self.gid, self.gecos,
            self.homedir, self.shell) = userinfo
        # if we are trying to modify another user we should be root
        self.asroot = self.myuid != self.uid

    def check(self):
        """Check whether we can modify the user.

        Check if the user is an LDAP user and whether we may modify the user
        information.
        """
        if self.asroot and self.myuid != 0:
            print("%s: you may not modify user '%s'.\n" %
                  (sys.argv[0], self.username))
            sys.exit(1)
        # FIXME: check if the user is an LDAP user

    def get_passwd(self):
        """Ask and return a password that is required to change the user."""
        # FIXME: only ask the password if we require it
        # (e.g. when root and nslcd has userpwmoddn we don't need to)
        return getpass.getpass(
            'LDAP administrator password: '
            if self.asroot else
            'LDAP password for %s: ' % self.username)
        # FIXME: check if the provided password is valid
