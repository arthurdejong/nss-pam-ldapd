
# rpc.py - rpc name lookup routines
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


attmap = common.Attributes(cn='cn', oncRpcNumber='oncRpcNumber')
filter = '(objectClass=oncRpc)'


class RpcRequest(common.Request):

    def write(self, dn, attributes):
        # get name
        name = common.get_rdn_value(dn, attmap['cn'])
        names = attributes['cn']
        if not names:
            print 'Error: entry %s does not contain %s value' % ( dn, attmap['cn'] )
        if self.name and self.name not in names:
            return # case of result entry did not match
        if not name:
            name = names.pop(0)
        elif name in names:
            names.remove(name)
        # get number
        ( number, ) = attributes['oncRpcNumber']
        if not number:
            print 'Error: entry %s does not contain %s value' % ( dn, attmap['oncRpcNumber'])
        number = int(number)
        # write result
        self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
        self.fp.write_string(name)
        self.fp.write_stringlist(names)
        self.fp.write_int32(number)


class RpcByNameRequest(RpcRequest):

    action = constants.NSLCD_ACTION_RPC_BYNAME
    filter_attrs = dict(cn='name')

    def read_parameters(self):
        self.name = self.fp.read_string()


class RpcByNumberRequest(RpcRequest):

    action = constants.NSLCD_ACTION_RPC_BYNUMBER
    filter_attrs = dict(oncRpcNumber='number')

    def read_parameters(self):
        self.number = self.fp.read_int32()


class RpcAllRequest(RpcRequest):

    action = constants.NSLCD_ACTION_RPC_ALL
