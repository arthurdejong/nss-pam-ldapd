
# ether.py - lookup functions for ethernet addresses
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

import struct

import constants
import common


def ether_aton(ether):
    """Converst an ethernet address to binary form in network byte order."""
    return struct.pack('BBBBBB', *(int(x, 16) for x in ether.split(':')))

def ether_ntoa(ether):
    """Conversts an ethernet address in network byte order to the string
    representation."""
    return ':'.join('%x' % x for x in struct.unpack('6B', ether))


attmap = common.Attributes(cn='cn', macAddress='macAddress')
filter = '(objectClass=ieee802Device)'


class EtherRequest(common.Request):

    def __init__(self, *args):
        super(EtherRequest, self).__init__(*args)
        self.ether = None

    def write(self, dn, attributes):
        # get name and check against requested name
        names = attributes['cn']
        if not names:
            print 'Error: entry %s does not contain %s value' % ( dn, attmap['cn'])
        if self.name:
            if self.name.lower() not in (x.lower() for x in names):
                return # skip entry
            names = ( self.name, )
        # get addresses and convert to binary form
        addresses = [ether_aton(x) for x in attributes['macAddress']]
        if not addresses:
            print 'Error: entry %s does not contain %s value' % ( dn, attmap['macAddress'])
        if self.ether:
            if self.ether not in addresses:
                return
            addresses = ( self.ether, )
        # write results
        for name in names:
            for ether in addresses:
                self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
                self.fp.write_string(name)
                self.fp.write(ether)


class EtherByNameRequest(EtherRequest):

    action = constants.NSLCD_ACTION_ETHER_BYNAME
    filter_attrs = dict(cn='name')

    def read_parameters(self):
        self.name = self.fp.read_string()


class EtherByEtherRequest(EtherRequest):

    action = constants.NSLCD_ACTION_ETHER_BYETHER

    def read_parameters(self):
        self.ether = self.fp.read(6)

    def mk_filter(self):
        return '(&%s(%s=%s))' % ( self.filter,
                  attmap['macAddress'], ether_ntoa(self.ether) )


class EtherAllRequest(EtherRequest):

    action = constants.NSLCD_ACTION_ETHER_ALL
