
# passwd.py - lookup functions for user account information
#
# Copyright (C) 2010, 2011 Arthur de Jong
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

import ldap
import ldap.filter

import constants
import common


attmap = common.Attributes(uid='uid',
                           userPassword='"*"',
                           uidNumber='uidNumber',
                           gidNumber='gidNumber',
                           gecos='"${gecos:-$cn}"',
                           homeDirectory='homeDirectory',
                           loginShell='loginShell',
                           objectClass='objectClass')
filter = '(objectClass=posixAccount)'


class Search(common.Search):

    case_sensitive = ('uid', 'uidNumber', )
    limit_attributes = ('uid', 'uidNumber', )
    required = ('uid', 'uidNumber', 'gidNumber', 'gecos', 'homeDirectory',
                'loginShell')


class PasswdRequest(common.Request):

    def write(self, dn, attributes, parameters):
        # get values
        names = attributes['uid']
        if 'shadowAccount' in attributes['objectClass']:
            passwd = 'x'
        else:
            passwd = attributes['userPassword'][0]
        uids = [int(x) for x in attributes['uidNumber']]
        gid = int(attributes['gidNumber'][0])
        gecos = attributes['gecos'][0]
        home = attributes['homeDirectory'][0]
        shell = attributes['loginShell'][0]
        # write results
        for name in names:
            if not common.isvalidname(name):
                print '%s: %s: denied by validnames option' % (dn, self.attmap['uid'])
            else:
                for uid in uids:
                    self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
                    self.fp.write_string(name)
                    self.fp.write_string(passwd)
                    self.fp.write_uid_t(uid)
                    self.fp.write_gid_t(gid)
                    self.fp.write_string(gecos)
                    self.fp.write_string(home)
                    self.fp.write_string(shell)


class PasswdByNameRequest(PasswdRequest):

    action = constants.NSLCD_ACTION_PASSWD_BYNAME

    def read_parameters(self, fp):
        name = fp.read_string()
        common.validate_name(name)
        return dict(uid=name)


class PasswdByUidRequest(PasswdRequest):

    action = constants.NSLCD_ACTION_PASSWD_BYUID

    def read_parameters(self, fp):
        return dict(uidNumber=fp.read_uid_t())


class PasswdAllRequest(PasswdRequest):

    action = constants.NSLCD_ACTION_PASSWD_ALL


def uid2entry(conn, uid):
    """Look up the user by uid and return the LDAP entry or None if the user
    was not found."""
    for dn, attributes in Search(conn, parameters=dict(uid=uid)):
        return dn, attributes


def uid2dn(conn, uid):
    """Look up the user by uid and return the DN or None if the user was
    not found."""
    x = uid2entry(conn, uid)
    if x is not None:
        return x[0]

# FIXME: use cache of dn2uid and try to use DN to get uid attribute


def dn2uid(conn, dn):
    """Look up the user by dn and return a uid or None if the user was
    not found."""
    for dn, attributes in Search(conn, base=dn):
        return attributes['uid'][0]
