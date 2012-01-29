
# ether.py - lookup functions for ethernet addresses
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

import struct

import common
import constants


def ether_aton(ether):
    """Converst an ethernet address to binary form in network byte order."""
    return struct.pack('BBBBBB', *(int(x, 16) for x in ether.split(':')))


def ether_ntoa(ether):
    """Conversts an ethernet address in network byte order to the string
    representation."""
    return ':'.join('%x' % x for x in struct.unpack('6B', ether))


attmap = common.Attributes(cn='cn', macAddress='macAddress')
filter = '(objectClass=ieee802Device)'


class Search(common.Search):

    case_insensitive = ('cn', )
    limit_attributes = ('cn', 'macAddress')
    required = ('cn', 'macAddress')


class EtherRequest(common.Request):

    def write(self, name, ether):
        self.fp.write_string(name)
        self.fp.write(ether_aton(ether))

    def convert(self, dn, attributes, parameters):
        for name in attributes['cn']:
            for ether in attributes['macAddress']:
                yield (name, ether)


class EtherByNameRequest(EtherRequest):

    action = constants.NSLCD_ACTION_ETHER_BYNAME

    def read_parameters(self, fp):
        return dict(cn=fp.read_string())


class EtherByEtherRequest(EtherRequest):

    action = constants.NSLCD_ACTION_ETHER_BYETHER

    def read_parameters(self, fp):
        return dict(macAddress=ether_ntoa(fp.read(6)))


class EtherAllRequest(EtherRequest):

    action = constants.NSLCD_ACTION_ETHER_ALL
