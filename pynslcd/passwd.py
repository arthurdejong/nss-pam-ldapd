
# passwd.py - lookup functions for user account information
#
# Copyright (C) 2010-2017 Arthur de Jong
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

import logging

import cache
import cfg
import common
import constants
import search


attmap = common.Attributes(uid='uid',
                           userPassword='"*"',
                           uidNumber='uidNumber',
                           gidNumber='gidNumber',
                           gecos='"${gecos:-$cn}"',
                           homeDirectory='homeDirectory',
                           loginShell='loginShell',
                           objectClass='objectClass')
filter = '(objectClass=posixAccount)'


class Search(search.LDAPSearch):

    case_sensitive = ('uid', 'uidNumber', )
    limit_attributes = ('uid', 'uidNumber', )
    required = ('uid', 'uidNumber', 'gidNumber', 'gecos', 'homeDirectory',
                'loginShell')

    def mk_filter(self):
        if 'uidNumber' in self.parameters:
            self.parameters['uidNumber'] -= cfg.nss_uid_offset
        return super(Search, self).mk_filter()


class Cache(cache.Cache):

    create_sql = '''
        CREATE TABLE IF NOT EXISTS `passwd_cache`
          ( `uid` TEXT PRIMARY KEY,
            `userPassword` TEXT,
            `uidNumber` INTEGER NOT NULL UNIQUE,
            `gidNumber` INTEGER NOT NULL,
            `gecos` TEXT,
            `homeDirectory` TEXT,
            `loginShell` TEXT,
            `mtime` TIMESTAMP NOT NULL );
    '''


class PasswdRequest(common.Request):

    def write(self, name, passwd, uid, gid, gecos, home, shell):
        self.fp.write_string(name)
        self.fp.write_string(passwd)
        self.fp.write_int32(uid)
        self.fp.write_int32(gid)
        self.fp.write_string(gecos)
        self.fp.write_string(home)
        self.fp.write_string(shell)

    def convert(self, dn, attributes, parameters):
        names = attributes['uid']
        if 'shadowAccount' in attributes['objectClass']:
            passwd = 'x'
        else:
            try:
                passwd = attributes['userPassword'][0]
            except IndexError:
                passwd = None
            if not passwd or self.calleruid != 0:
                passwd = '*'
        uids = [int(x) + cfg.nss_uid_offset for x in attributes['uidNumber']]
        gid = int(attributes['gidNumber'][0]) + cfg.nss_gid_offset
        gecos = attributes['gecos'][0]
        home = attributes['homeDirectory'][0]
        shell = attributes['loginShell'][0]
        for name in names:
            if not common.is_valid_name(name):
                logging.warning('%s: %s: denied by validnames option', dn, attmap['uid'])
            else:
                for uid in uids:
                    if uid >= cfg.nss_min_uid:
                        yield (name, passwd, uid, gid, gecos, home, shell)


class PasswdByNameRequest(PasswdRequest):

    action = constants.NSLCD_ACTION_PASSWD_BYNAME

    def read_parameters(self, fp):
        name = fp.read_string()
        common.validate_name(name)
        return dict(uid=name)


class PasswdByUidRequest(PasswdRequest):

    action = constants.NSLCD_ACTION_PASSWD_BYUID

    def read_parameters(self, fp):
        return dict(uidNumber=fp.read_int32())

    def handle_request(self, parameters):
        # check requested numeric id
        if parameters['uidNumber'] >= cfg.nss_min_uid:
            return super(PasswdByUidRequest, self).handle_request(parameters)
        # write the final result code to signify empty results
        self.fp.write_int32(constants.NSLCD_RESULT_END)


class PasswdAllRequest(PasswdRequest):

    action = constants.NSLCD_ACTION_PASSWD_ALL

    def handle_request(self, parameters):
        if not cfg.nss_disable_enumeration:
            return super(PasswdAllRequest, self).handle_request(parameters)


def uid2entry(conn, uid):
    """Look up the user by uid and return the LDAP entry or None if the user
    was not found."""
    for dn, attributes in Search(conn, parameters=dict(uid=uid)):
        if any((int(x) + cfg.nss_uid_offset) >= cfg.nss_min_uid for x in attributes['uidNumber']):
            return dn, attributes


# FIXME: use cache of dn2uid and try to use DN to get uid attribute


def dn2uid(conn, dn):
    """Look up the user by dn and return a uid or None if the user was
    not found."""
    for dn, attributes in Search(conn, base=dn):
        if any((int(x) + cfg.nss_uid_offset) >= cfg.nss_min_uid for x in attributes['uidNumber']):
            return attributes['uid'][0]
