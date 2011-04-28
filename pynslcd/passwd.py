
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


class PasswdRequest(common.Request):

    attmap = { 'uid': 'uid', 'userPassword': 'userPassword',
               'uidNumber': 'uidNumber', 'gidNumber': 'gidNumber',
               'gecos': '"${gecos:-$cn}"', 'cn': 'cn',
               'homeDirectory': 'homeDirectory',
               'loginShell': 'loginShell',
               'objectClass': 'objectClass' }
    filter = '(objectClass=posixAccount)'

    attmap_passwd_uid           = 'uid'
    attmap_passwd_userPassword  = 'userPassword'
    attmap_passwd_uidNumber     = 'uidNumber'
    attmap_passwd_gidNumber     = 'gidNumber'
    attmap_passwd_gecos         = '"${gecos:-$cn}"'
    attmap_passwd_homeDirectory = 'homeDirectory'
    attmap_passwd_loginShell    = 'loginShell'

    # these should be removed
    attmap_passwd_cn = 'cn'

    attributes = ( 'uid', 'userPassword', 'uidNumber', 'gidNumber',
                   'gecos', 'cn', 'homeDirectory', 'loginShell',
                   'objectClass' )

    bases = ( 'ou=people,dc=test,dc=tld', )

    def write(self, entry):
        dn, attributes = entry
        # get uid attribute and check against requested user name
        names = attributes.get('uid', [])
        if self.name:
            if self.name not in names:
                return
            names = ( self.name, )
        # get user password entry
        if 'shadowAccount' in attributes.get('objectClass', []):
            passwd = 'x'
        else:
            passwd = '*';
        # get numeric user and group ids
        uids = ( self.uid, ) if self.uid else attributes.get(self.attmap_passwd_uidNumber, [])
        uids = [ int(x) for x in uids ]
        ( gid, ) = attributes[self.attmap_passwd_gidNumber]
        gid = int(gid)
        # FIXME: use expression here
        gecos = attributes.get(self.attmap_passwd_gecos, [None])[0] or attributes.get(self.attmap_passwd_cn, [''])[0]
        ( home, ) = attributes.get(self.attmap_passwd_homeDirectory, [''])
        ( shell, ) = attributes.get(self.attmap_passwd_loginShell, [''])
        for name in names:
            if not common.isvalidname(name):
                print 'Warning: passwd entry %s contains invalid user name: "%s"' % ( dn, name )
            else:
                for uid in uids:
                    #print '%s:%s:%d:%d:%s:%s:%s' % ( name, passwd, uid, gid, gecos, home, shell )
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

    def read_parameters(self):
        self.name = self.fp.read_string()
        common.validate_name(self.name)

    def mk_filter(self):
        return '(&%s(%s=%s))' % ( self.filter,
                  self.attmap_passwd_uid, ldap.filter.escape_filter_chars(self.name) )


class PasswdByUidRequest(PasswdRequest):

    action = constants.NSLCD_ACTION_PASSWD_BYUID

    def read_parameters(self):
        self.uid = self.fp.read_uid_t()

    def mk_filter(self):
        return '(&%s(%s=%d))' % ( self.filter,
                  self.attmap_passwd_uidNumber, self.uid )


class PasswdAllRequest(PasswdRequest):

    action = constants.NSLCD_ACTION_PASSWD_ALL


def do_search(conn, filter=None, base=None):
    mybases = ( base, ) if base else PasswdRequest.bases
    filter = filter or PasswdRequest.filter
    # perform a search for each search base
    for base in mybases:
        # do the LDAP search
        try:
            res = conn.search_s(base, PasswdRequest.scope, filter, [PasswdRequest.attmap_passwd_uid])
            for entry in res:
                if entry[0]:
                    yield entry
        except ldap.NO_SUCH_OBJECT:
            # FIXME: log message
            pass

def uid2entry(conn, uid):
    """Look up the user by uid and return the LDAP entry or None if the user
    was not found."""
    myfilter = '(&%s(%s=%s))' % ( PasswdRequest.filter,
                  PasswdRequest.attmap_passwd_uid, ldap.filter.escape_filter_chars(uid) )
    for dn, attributes in do_search(conn, myfilter):
        if uid in attributes[PasswdRequest.attmap_passwd_uid]:
            return dn, attributes

def uid2dn(conn, uid):
    """Look up the user by uid and return the DN or None if the user was
    not found."""
    x = uid2entry(conn, uid)
    if x is not None:
        return x[0]

def dn2uid(conn, dn):
    """Look up the user by dn and return a uid or None if the user was
    not found."""
    try:
        for dn, attributes in do_search(conn, base=dn):
            return attributes[PasswdRequest.attmap_passwd_uid][0]
    except ldap.NO_SUCH_OBJECT:
        return None
