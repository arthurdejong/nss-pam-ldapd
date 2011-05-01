
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

import logging

import constants
import common


attmap = common.Attributes(cn='cn', ipHostNumber='ipHostNumber')
filter = '(objectClass=ipHost)'


class HostRequest(common.Request):

    def write(self, dn, attributes):
        hostname = common.get_rdn_value(dn, attmap['cn'])
        hostnames = attributes['cn']
        if not hostnames:
            print 'Error: entry %s does not contain %s value' % ( dn, attmap['cn'] )
        if not hostname:
            hostname = hostnames.pop(0)
        elif hostname in hostnames:
            hostnames.remove(hostname)
        addresses = attributes['ipHostNumber']
        if not addresses:
            print 'Error: entry %s does not contain %s value' % ( dn, attmap['ipHostNumber'] )
        # write result
        self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
        self.fp.write_string(hostname)
        self.fp.write_stringlist(hostnames)
        self.fp.write_int32(len(addresses))
        for address in addresses:
            self.fp.write_address(address)


class HostByNameRequest(HostRequest):

    action = constants.NSLCD_ACTION_HOST_BYNAME
    filter_attrs = dict(cn='name')

    def read_parameters(self):
        self.name = self.fp.read_string()


class HostByAddressRequest(HostRequest):

    action = constants.NSLCD_ACTION_HOST_BYADDR
    filter_attrs = dict(ipHostNumber='address')

    def read_parameters(self):
        self.address = self.fp.read_address()


class HostAllRequest(HostRequest):

    action = constants.NSLCD_ACTION_HOST_ALL
