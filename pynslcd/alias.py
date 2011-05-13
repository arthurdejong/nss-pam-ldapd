
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

import logging

import constants
import common


attmap = common.Attributes(cn='cn', rfc822MailMember='rfc822MailMember')
filter = '(objectClass=nisMailAlias)'


class AliasRequest(common.Request):

    def write(self, dn, attributes, parameters):
        # get name and check against requested name
        names = attributes['cn']
        if not names:
            logging.error('Error: entry %s does not contain %s value', dn, attmap['cn'])
            return
        if 'cn' in parameters:
            if parameters['cn'].lower() not in (x.lower() for x in names):
                return
            names = ( parameters['cn'], )
        # get the members of the alias
        members = attributes['rfc822MailMember']
        if not members:
            logging.error('Error: entry %s does not contain %s value', dn, attmap['rfc822MailMember'])
            return
        # write results
        for name in names:
            self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
            self.fp.write_string(name)
            self.fp.write_stringlist(members)


class AliasByNameRequest(AliasRequest):

    action = constants.NSLCD_ACTION_ALIAS_BYNAME

    def read_parameters(self, fp):
        return dict(cn=fp.read_string())


class AliasAllRequest(AliasRequest):

    action = constants.NSLCD_ACTION_ALIAS_ALL
