
# usermod.py - functions for modifying user information
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
import logging
import os
import os.path

import ldap

import cfg
import constants
import pam
import passwd


def list_shells():
    """List the shells from /etc/shells."""
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    libc.setusershell()
    while True:
        shell = ctypes.c_char_p(libc.getusershell()).value
        if not shell:
            break
        yield shell
    libc.endusershell()


class UserModRequest(pam.PAMRequest):

    action = constants.NSLCD_ACTION_USERMOD

    def read_parameters(self, fp):
        username = fp.read_string()
        asroot = fp.read_int32()
        password = fp.read_string()
        mods = {}
        while True:
            key = fp.read_int32()
            if key == constants.NSLCD_USERMOD_END:
                break
            mods[key] = fp.read_string()
        return dict(username=username,
                    asroot=asroot,
                    password=password,
                    mods=mods)

    def write_result(self, mod, message):
        self.fp.write_int32(mod)
        self.fp.write_string(message)

    def handle_request(self, parameters):
        # fill in any missing userdn, etc.
        self.validate(parameters)
        is_root = (self.calleruid == 0) and parameters['asroot']
        mods = []
        # check if the the user passed the rootpwmoddn
        if parameters['asroot']:
            binddn = cfg.rootpwmoddn
            # check if rootpwmodpw should be used
            if not parameters['password'] and is_root and cfg.rootpwmodpw:
                password = cfg.rootpwmodpw
            else:
                password = parameters['password']
        else:
            binddn = parameters['userdn']
            password = parameters['password']
        # write response header
        self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
        # check home directory modification
        homedir = parameters['mods'].get(constants.NSLCD_USERMOD_HOMEDIR)
        if homedir:
            if is_root:
                mods.append((ldap.MOD_REPLACE, passwd.attmap['homeDirectory'], [homedir]))
            elif not os.path.isabs(homedir):
                self.write_result(constants.NSLCD_USERMOD_HOMEDIR,
                                  'should be an absolute path')
            elif not os.path.isdir(homedir):
                self.write_result(constants.NSLCD_USERMOD_HOMEDIR,
                                  'not a directory')
            else:
                mods.append((ldap.MOD_REPLACE, passwd.attmap['homeDirectory'], [homedir]))
        # check login shell modification
        shell = parameters['mods'].get(constants.NSLCD_USERMOD_SHELL)
        if shell:
            if is_root:
                mods.append((ldap.MOD_REPLACE, passwd.attmap['loginShell'], [shell]))
            elif shell not in list_shells():
                self.write_result(constants.NSLCD_USERMOD_SHELL,
                                  'unlisted shell')
            elif not os.path.isfile(shell) or not os.access(shell, os.X_OK):
                self.write_result(constants.NSLCD_USERMOD_SHELL,
                                  'not an executable')
            else:
                mods.append((ldap.MOD_REPLACE, passwd.attmap['loginShell'], [shell]))
        # get a connection and perform the modification
        if mods:
            try:
                conn, authz, msg = pam.authenticate(binddn, password)
                conn.modify_s(parameters['userdn'], mods)
                logging.info('changed information for %s', parameters['userdn'])
            except (ldap.INVALID_CREDENTIALS, ldap.INSUFFICIENT_ACCESS), e:
                try:
                    msg = e[0]['desc']
                except:
                    msg = str(e)
                logging.debug('modification failed: %s', msg)
                self.write_result(constants.NSLCD_USERMOD_RESULT, msg)
        # write closing statement
        self.fp.write_int32(constants.NSLCD_USERMOD_END)
        self.fp.write_int32(constants.NSLCD_RESULT_END)
