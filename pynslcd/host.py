
# host.py - lookup functions for host names and addresses
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


class HostRequest(common.Request):

    filter = '(objectClass=ipHost)'

    attmap_cn           = 'cn'
    attmap_ipHostNumber = 'ipHostNumber'

    attributes = ( 'cn', 'ipHostNumber' )

    def write(self, entry):
        dn, attributes = entry
        hostname = common.get_rdn_value(entry, self.attmap_cn)
        hostnames = attributes.get(self.attmap_cn, [])
        if not hostnames:
            print 'Error: entry %s does not contain %s value' % ( dn, self.attmap_cn )
        if not hostname:
            hostname = hostnames.pop(0)
        elif hostname in hostnames:
            hostnames.remove(hostname)
        addresses = attributes.get(self.attmap_ipHostNumber, [])
        if not addresses:
            print 'Error: entry %s does not contain %s value' % ( dn, self.attmap_ipHostNumber )
        # write result
        self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
        self.fp.write_string(hostname)
        self.fp.write_stringlist(hostnames)
        self.fp.write_int32(len(addresses))
        for address in addresses:
            self.fp.write_address(address)


class HostByNameRequest(HostRequest):

    action = constants.NSLCD_ACTION_HOST_BYNAME

    def read_parameters(self):
        self.name = self.fp.read_string()

    def mk_filter(self):
        return '(&%s(%s=%s))' % ( self.filter,
                  self.attmap_cn, ldap.filter.escape_filter_chars(self.name) )


class HostByAddressRequest(HostRequest):

    action = constants.NSLCD_ACTION_HOST_BYADDR

    def read_parameters(self):
        self.address = self.fp.read_address()

    def mk_filter(self):
        return '(&%s(%s=%s))' % ( self.filter,
                  self.attmap_ipHostNumber,
                  ldap.filter.escape_filter_chars(self.address) )


class HostAllRequest(HostRequest):

    action = constants.NSLCD_ACTION_HOST_ALL
