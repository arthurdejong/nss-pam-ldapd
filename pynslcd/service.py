
# service.py - service entry lookup routines
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

import ldap.filter

import constants
import common


class ServiceRequest(common.Request):

    filter = '(objectClass=ipService)'

    attmap_cn                = 'cn'
    attmap_ipServicePort     = 'ipServicePort'
    attmap_ipServiceProtocol = 'ipServiceProtocol'

    attributes = ( 'cn', 'ipServicePort', 'ipServiceProtocol' )

    def __init__(self, *args):
        super(ServiceRequest, self).__init__(*args)
        self.protocol = None

    def write(self, dn, attributes):
        # get name
        name = common.get_rdn_value(dn, self.attmap_cn)
        names = attributes.get(self.attmap_cn, [])
        if not names:
            print 'Error: entry %s does not contain %s value' % ( dn, self.attmap_cn )
        if self.name and self.name not in names + [ name, ]:
            return # case of result entry did not match
        if not name:
            name = names.pop(0)
        elif name in names:
            names.remove(name)
        # get port number
        ( port, ) = attributes.get(self.attmap_ipServicePort, [])
        if not port:
            print 'Error: entry %s does not contain %s value' % ( dn, self.attmap_ipServicePort)
        port = int(port)
        # get protocol
        protocols = attributes.get(self.attmap_ipServiceProtocol, [])
        if self.protocol:
            if self.protocol not in protocols:
                return
            protocols = ( self.protocol, )
        # write result
        for protocol in protocols:
            self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
            self.fp.write_string(name)
            self.fp.write_stringlist(names)
            self.fp.write_int32(port)
            self.fp.write_string(protocol)


class ServiceByNameRequest(ServiceRequest):

    action = constants.NSLCD_ACTION_SERVICE_BYNAME

    def read_parameters(self):
        self.name = self.fp.read_string()
        self.protocol = self.fp.read_string()

    def mk_filter(self):
        if self.protocol:
          return '(&%s(%s=%s)(%s=%s))' % ( self.filter,
                    self.attmap_cn, ldap.filter.escape_filter_chars(self.name),
                    self.attmap_ipServiceProtocol, ldap.filter.escape_filter_chars(self.protocol) )
        else:
          return '(&%s(%s=%s))' % ( self.filter,
                    self.attmap_cn, ldap.filter.escape_filter_chars(self.name) )


class ServiceByNumberRequest(ServiceRequest):

    action = constants.NSLCD_ACTION_SERVICE_BYNUMBER

    def read_parameters(self):
        self.number = self.fp.read_int32()
        self.protocol = self.fp.read_string()

    def mk_filter(self):
        if self.protocol:
          return '(&%s(%s=%d)(%s=%s))' % ( self.filter,
                    self.attmap_ipServicePort, self.number,
                    self.attmap_ipServiceProtocol, ldap.filter.escape_filter_chars(self.protocol) )
        else:
          return '(&%s(%s=%d))' % ( self.filter,
                    self.attmap_ipServicePort, self.number )


class ServiceAllRequest(ServiceRequest):

    action = constants.NSLCD_ACTION_SERVICE_ALL
