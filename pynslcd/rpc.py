
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

    case_sensitive = ('cn', )
    canonical_first = ('cn', )
    required = ('cn', 'oncRpcNumber')

    def write(self, dn, attributes, parameters):
        # get values
        names = attributes['cn']
        name = names.pop(0)
        number = int(attributes['oncRpcNumber'][0])
        # write result
        self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
        self.fp.write_string(name)
        self.fp.write_stringlist(names)
        self.fp.write_int32(number)


class RpcByNameRequest(RpcRequest):

    action = constants.NSLCD_ACTION_RPC_BYNAME

    def read_parameters(self, fp):
        return dict(cn=fp.read_string())


class RpcByNumberRequest(RpcRequest):

    action = constants.NSLCD_ACTION_RPC_BYNUMBER

    def read_parameters(self, fp):
        return dict(oncRpcNumber=fp.read_int32())


class RpcAllRequest(RpcRequest):

    action = constants.NSLCD_ACTION_RPC_ALL
