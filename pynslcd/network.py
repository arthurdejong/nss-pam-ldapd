
# network.py - lookup functions for network names and addresses
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
import socket


class NetworkRequest(common.Request):

    filter = '(objectClass=ipNetwork)'

    attmap_cn           = 'cn'
    attmap_ipNetworkNumber = 'ipNetworkNumber'

    attributes = ( 'cn', 'ipNetworkNumber' )

    def write(self, entry):
        dn, attributes = entry
        networkname = common.get_rdn_value(entry, self.attmap_cn)
        networknames = attributes.get(self.attmap_cn, [])
        if not networknames:
            print 'Error: entry %s does not contain %s value' % ( dn, self.attmap_cn)
        if not networkname:
            networkname = networknames.pop(0)
        elif networkname in networknames:
            networknames.remove(networkname)
        addresses = attributes.get(self.attmap_ipNetworkNumber, [])
        if not addresses:
            print 'Error: entry %s does not contain %s value' % ( dn, self.attmap_ipNetworkNumber)
        # write result
        self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
        self.fp.write_string(networkname)
        self.fp.write_stringlist(networknames)
        self.fp.write_int32(len(addresses))
        for address in addresses:
            self.fp.write_address(address)


class NetworkByNameRequest(NetworkRequest):

    action = constants.NSLCD_ACTION_NETWORK_BYNAME

    def read_parameters(self):
        self.name = self.fp.read_string()

    def mk_filter(self):
        return '(&%s(%s=%s))' % ( self.filter,
                  self.attmap_cn, ldap.filter.escape_filter_chars(self.name) )


class NetworkByAddressRequest(NetworkRequest):

    action = constants.NSLCD_ACTION_NETWORK_BYADDR

    def read_parameters(self):
        self.address = self.fp.read_address()

    def mk_filter(self):
        return '(&%s(%s=%s))' % ( self.filter,
                  self.attmap_ipNetworkNumber,
                  ldap.filter.escape_filter_chars(self.address) )


class NetworkAllRequest(NetworkRequest):

    action = constants.NSLCD_ACTION_NETWORK_ALL
