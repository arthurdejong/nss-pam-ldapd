
# shadow.py - lookup functions for shadownet addresses
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

import ldap.filter

import constants
import common


class ShadowRequest(common.Request):

    filter = '(objectClass=shadowAccount)'

    attmap_uid              = 'uid'
    attmap_userPassword     = 'userPassword'
    attmap_shadowLastChange = 'shadowLastChange'
    attmap_shadowMin        = 'shadowMin'
    attmap_shadowMax        = 'shadowMax'
    attmap_shadowWarning    = 'shadowWarning'
    attmap_shadowInactive   = 'shadowInactive'
    attmap_shadowExpire     = 'shadowExpire'
    attmap_shadowFlag       = 'shadowFlag'

    attributes = ( 'uid', 'userPassword', 'shadowLastChange', 'shadowMin',
                   'shadowMax', 'shadowWarning', 'shadowInactive',
                   'shadowExpire', 'shadowFlag' )

    bases = ( 'ou=people,dc=test,dc=tld', )

    def write(self, dn, attributes):
        # get name and check against requested name
        names = attributes.get(self.attmap_uid, [])
        if not names:
            print 'Error: entry %s does not contain %s value' % ( dn, self.attmap_uid)
            return
        if self.name:
            if self.name not in names:
                return
            names = ( self.name, )
        # get password
        (passwd, ) = attributes.get(self.attmap_userPassword, ['x'])
        if not passwd or self.calleruid != 0:
            passwd = '*';
        # function for making an int
        def mk_int(attr):
            try:
                return
            except TypeError:
                return None
        # get lastchange date
        lastchangedate = int(attributes.get(self.attmap_shadowLastChange, [-1])[0])
        # we expect an AD 64-bit datetime value;
        # we should do date=date/864000000000-134774
        # but that causes problems on 32-bit platforms,
        # first we devide by 1000000000 by stripping the
        # last 9 digits from the string and going from there */
        if self.attmap_shadowLastChange == 'pwdLastSet':
            lastchangedate = ( lastchangedate / 864000000000 ) - 134774
        # get longs
        mindays = int(attributes.get(self.attmap_shadowMin, [-1])[0])
        maxdays = int(attributes.get(self.attmap_shadowMax, [-1])[0])
        warndays = int(attributes.get(self.attmap_shadowWarning, [-1])[0])
        inactdays = int(attributes.get(self.attmap_shadowInactive, [-1])[0])
        expiredate = int(attributes.get(self.attmap_shadowExpire, [-1])[0])
        flag = int(attributes.get(self.attmap_shadowFlag, [0])[0])
        if self.attmap_shadowFlag == 'pwdLastSet':
            if flag & 0x10000:
                maxdays = -1
            flag = 0
        # write results
        for name in names:
            self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
            self.fp.write_string(name)
            self.fp.write_string(passwd)
            self.fp.write_int32(lastchangedate)
            self.fp.write_int32(mindays)
            self.fp.write_int32(maxdays)
            self.fp.write_int32(warndays)
            self.fp.write_int32(inactdays)
            self.fp.write_int32(expiredate)
            self.fp.write_int32(flag)


class ShadowByNameRequest(ShadowRequest):

    action = constants.NSLCD_ACTION_SHADOW_BYNAME

    def read_parameters(self):
        self.name = self.fp.read_string()

    def mk_filter(self):
        return '(&%s(%s=%s))' % ( self.filter,
                  self.attmap_uid, ldap.filter.escape_filter_chars(self.name) )


class ShadowAllRequest(ShadowRequest):

    action = constants.NSLCD_ACTION_SHADOW_ALL
