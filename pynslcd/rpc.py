
# rpc.py - rpc name lookup routines
#
# Copyright (C) 2011, 2012, 2013 Arthur de Jong
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

import cache
import common
import constants
import search


attmap = common.Attributes(cn='cn', oncRpcNumber='oncRpcNumber')
filter = '(objectClass=oncRpc)'


class Search(search.LDAPSearch):

    case_sensitive = ('cn', )
    canonical_first = ('cn', )
    required = ('cn', 'oncRpcNumber')


class Cache(cache.Cache):

    tables = ('rpc_cache', 'rpc_alias_cache')

    create_sql = '''
        CREATE TABLE IF NOT EXISTS `rpc_cache`
          ( `cn` TEXT PRIMARY KEY,
            `oncRpcNumber` INTEGER NOT NULL,
            `mtime` TIMESTAMP NOT NULL );
        CREATE TABLE IF NOT EXISTS `rpc_alias_cache`
          ( `rpc` TEXT NOT NULL,
            `cn` TEXT NOT NULL,
            FOREIGN KEY(`rpc`) REFERENCES `rpc_cache`(`cn`)
            ON DELETE CASCADE ON UPDATE CASCADE );
        CREATE INDEX IF NOT EXISTS `rpc_alias_idx` ON `rpc_alias_cache`(`rpc`);
    '''

    retrieve_sql = '''
        SELECT `rpc_cache`.`cn` AS `cn`, `rpc_alias_cache`.`cn` AS `alias`,
               `oncRpcNumber`, `mtime`
        FROM `rpc_cache`
        LEFT JOIN `rpc_alias_cache`
          ON `rpc_alias_cache`.`rpc` = `rpc_cache`.`cn`
    '''

    retrieve_by = dict(
        cn='''
            ( `rpc_cache`.`cn` = ? OR
              `rpc_cache`.`cn` IN (
                  SELECT `by_alias`.`rpc`
                  FROM `rpc_alias_cache` `by_alias`
                  WHERE `by_alias`.`cn` = ?))
        ''',
    )

    group_by = (0, )  # cn
    group_columns = (1, )  # alias


class RpcRequest(common.Request):

    def write(self, name, aliases, number):
        self.fp.write_string(name)
        self.fp.write_stringlist(aliases)
        self.fp.write_int32(number)

    def convert(self, dn, attributes, parameters):
        names = attributes['cn']
        yield (names[0], names[1:], int(attributes['oncRpcNumber'][0]))


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
