
# protocol.py - protocol name and number lookup routines
#
# Copyright (C) 2011 Arthur de Jong
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

import constants
import common

import struct
import ldap.filter


class ProtocolRequest(common.Request):

    filter = '(objectClass=ipProtocol)'

    attmap_cn               = 'cn'
    attmap_ipProtocolNumber = 'ipProtocolNumber'

    attributes = ( 'cn', 'ipProtocolNumber' )

    def write(self, entry):
        dn, attributes = entry
        # get name
        name = common.get_rdn_value(entry, self.attmap_cn)
        names = attributes.get(self.attmap_cn, [])
        if not names:
            print 'Error: entry %s does not contain %s value' % ( dn, self.attmap_cn )
        if self.name and self.name not in names:
            return # case of result entry did not match
        if not name:
            name = names.pop(0)
        elif name in names:
            names.remove(name)
        # get number
        ( number, ) = attributes.get(self.attmap_ipProtocolNumber, [])
        if not number:
            print 'Error: entry %s does not contain %s value' % ( dn, self.attmap_ipProtocolNumber)
        number = int(number)
        # write result
        self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
        self.fp.write_string(name)
        self.fp.write_stringlist(names)
        self.fp.write_int32(number)


class ProtocolByNameRequest(ProtocolRequest):

    action = constants.NSLCD_ACTION_PROTOCOL_BYNAME

    def read_parameters(self):
        self.name = self.fp.read_string()

    def mk_filter(self):
        return '(&%s(%s=%s))' % ( self.filter,
                  self.attmap_cn, ldap.filter.escape_filter_chars(self.name) )


class ProtocolByNumberRequest(ProtocolRequest):

    action = constants.NSLCD_ACTION_PROTOCOL_BYNUMBER

    def read_parameters(self):
        self.number = self.fp.read_int32()

    def mk_filter(self):
        return '(&%s(%s=%d))' % ( self.filter,
                  self.attmap_ipProtocolNumber, self.number )


class ProtocolAllRequest(ProtocolRequest):

    action = constants.NSLCD_ACTION_PROTOCOL_ALL
