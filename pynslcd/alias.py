
# alias.py - lookup functions for aliasnet addresses
#
# Copyright (C) 2010, 2011, 2012 Arthur de Jong
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

import common
import constants


attmap = common.Attributes(cn='cn', rfc822MailMember='rfc822MailMember')
filter = '(objectClass=nisMailAlias)'


class Search(common.Search):

    case_insensitive = ('cn', )
    limit_attributes = ('cn', )
    required = ('cn', 'rfc822MailMember')


class AliasRequest(common.Request):

    def write(self, name, members):
        self.fp.write_string(name)
        self.fp.write_stringlist(members)

    def convert(self, dn, attributes, parameters):
        names = attributes['cn']
        members = attributes['rfc822MailMember']
        for name in names:
            yield (name, members)


class AliasByNameRequest(AliasRequest):

    action = constants.NSLCD_ACTION_ALIAS_BYNAME

    def read_parameters(self, fp):
        return dict(cn=fp.read_string())


class AliasAllRequest(AliasRequest):

    action = constants.NSLCD_ACTION_ALIAS_ALL
