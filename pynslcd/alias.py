
# alias.py - lookup functions for aliasnet addresses
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


class AliasRequest(common.Request):

    filter = '(objectClass=nisMailAlias)'

    attmap_cn         = 'cn'
    attmap_rfc822MailMember = 'rfc822MailMember'

    attributes = ( 'cn', 'rfc822MailMember' )

    def write(self, entry):
        dn, attributes = entry
        # get name and check against requested name
        names = attributes.get(self.attmap_cn, [])
        if not names:
            logging.error('Error: entry %s does not contain %s value', dn, self.attmap_cn)
            return
        if self.name:
            if self.name.lower() not in (x.lower() for x in names):
                return
            names = ( self.name, )
        # get the members of the alias
        members = attributes.get(self.attmap_rfc822MailMember, [])
        if not members:
            logging.error('Error: entry %s does not contain %s value', dn, self.attmap_rfc822MailMember)
            return
        # write results
        for name in names:
            self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
            self.fp.write_string(name)
            self.fp.write_stringlist(members)


class AliasByNameRequest(AliasRequest):

    action = constants.NSLCD_ACTION_ALIAS_BYNAME

    def read_parameters(self):
        self.name = self.fp.read_string()

    def mk_filter(self):
        return '(&%s(%s=%s))' % ( self.filter,
                  self.attmap_cn, ldap.filter.escape_filter_chars(self.name) )


class AliasAllRequest(AliasRequest):

    action = constants.NSLCD_ACTION_ALIAS_ALL
