
# shadow.py - lookup functions for shadow information
#
# Copyright (C) 2010, 2011, 2012, 2013 Arthur de Jong
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

import cache
import cfg
import common
import constants
import search


attmap = common.Attributes(uid='uid',
                           userPassword='"*"',
                           shadowLastChange='"${shadowLastChange:--1}"',
                           shadowMin='"${shadowMin:--1}"',
                           shadowMax='"${shadowMax:--1}"',
                           shadowWarning='"${shadowWarning:--1}"',
                           shadowInactive='"${shadowInactive:--1}"',
                           shadowExpire='"${shadowExpire:--1}"',
                           shadowFlag='"${shadowFlag:-0}"')
filter = '(objectClass=shadowAccount)'


class Search(search.LDAPSearch):

    case_sensitive = ('uid', )
    limit_attributes = ('uid', )
    required = ('uid', )


class Cache(cache.Cache):

    create_sql = '''
        CREATE TABLE IF NOT EXISTS `shadow_cache`
          ( `uid` TEXT PRIMARY KEY,
            `userPassword` TEXT,
            `shadowLastChange` INTEGER,
            `shadowMin` INTEGER,
            `shadowMax` INTEGER,
            `shadowWarning` INTEGER,
            `shadowInactive` INTEGER,
            `shadowExpire` INTEGER,
            `shadowFlag` INTEGER,
            `mtime` TIMESTAMP NOT NULL );
    '''


class ShadowRequest(common.Request):

    def write(self, name, passwd, lastchangedate, mindays, maxdays, warndays,
              inactdays, expiredate, flag):
        self.fp.write_string(name)
        self.fp.write_string(passwd)
        self.fp.write_int32(lastchangedate)
        self.fp.write_int32(mindays)
        self.fp.write_int32(maxdays)
        self.fp.write_int32(warndays)
        self.fp.write_int32(inactdays)
        self.fp.write_int32(expiredate)
        self.fp.write_int32(flag)

    def convert(self, dn, attributes, parameters):
        names = attributes['uid']
        try:
            passwd = attributes['userPassword'][0]
        except IndexError:
            passwd = None
        if not passwd or self.calleruid != 0:
            passwd = '*'
        # function for making an int
        def mk_int(attr):
            try:
                return int(attr)
            except TypeError:
                return None
        # get lastchange date
        lastchangedate = mk_int(attributes.get('shadowLastChange', [0])[0])
        # we expect an AD 64-bit datetime value;
        # we should do date=date/864000000000-134774
        # but that causes problems on 32-bit platforms,
        # first we devide by 1000000000 by stripping the
        # last 9 digits from the string and going from there */
        if attmap['shadowLastChange'] == 'pwdLastSet':
            lastchangedate = (lastchangedate / 864000000000) - 134774
        # get longs
        mindays = mk_int(attributes.get('shadowMin', [-1])[0])
        maxdays = mk_int(attributes.get('shadowMax', [-1])[0])
        warndays = mk_int(attributes.get('shadowWarning', [-1])[0])
        inactdays = mk_int(attributes.get('shadowInactive', [-1])[0])
        expiredate = mk_int(attributes.get('shadowExpire', [-1])[0])
        flag = mk_int(attributes.get('shadowFlag', [0])[0])
        if attmap['shadowFlag'] == 'pwdLastSet':
            if flag & 0x10000:
                maxdays = -1
            flag = 0
        # return results
        for name in names:
            yield (name, passwd, lastchangedate, mindays, maxdays, warndays,
                   inactdays, expiredate, flag)


class ShadowByNameRequest(ShadowRequest):

    action = constants.NSLCD_ACTION_SHADOW_BYNAME

    def read_parameters(self, fp):
        return dict(uid=fp.read_string())


class ShadowAllRequest(ShadowRequest):

    action = constants.NSLCD_ACTION_SHADOW_ALL

    def handle_request(self, parameters):
        if not cfg.nss_disable_enumeration:
            return super(ShadowAllRequest, self).handle_request(parameters)
