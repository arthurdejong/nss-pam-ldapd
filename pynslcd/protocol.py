
# protocol.py - protocol name and number lookup routines
#
# Copyright (C) 2011-2019 Arthur de Jong
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


attmap = common.Attributes(
    cn='cn',
    ipProtocolNumber='ipProtocolNumber')
filter = '(objectClass=ipProtocol)'


class Search(search.LDAPSearch):

    case_sensitive = ('cn', )
    canonical_first = ('cn', )
    required = ('cn', 'ipProtocolNumber')


class Cache(cache.Cache):

    tables = ('protocol_cache', 'protocol_alias_cache')

    create_sql = '''
        CREATE TABLE IF NOT EXISTS `protocol_cache`
          ( `cn` TEXT PRIMARY KEY,
            `ipProtocolNumber` INTEGER NOT NULL,
            `mtime` TIMESTAMP NOT NULL );
        CREATE TABLE IF NOT EXISTS `protocol_alias_cache`
          ( `protocol` TEXT NOT NULL,
            `cn` TEXT NOT NULL,
            FOREIGN KEY(`protocol`) REFERENCES `protocol_cache`(`cn`)
            ON DELETE CASCADE ON UPDATE CASCADE );
        CREATE INDEX IF NOT EXISTS `protocol_alias_idx` ON `protocol_alias_cache`(`protocol`);
    '''

    retrieve_sql = '''
        SELECT `protocol_cache`.`cn` AS `cn`, `protocol_alias_cache`.`cn` AS `alias`,
               `ipProtocolNumber`, `mtime`
        FROM `protocol_cache`
        LEFT JOIN `protocol_alias_cache`
          ON `protocol_alias_cache`.`protocol` = `protocol_cache`.`cn`
    '''

    retrieve_by = dict(
        cn='''
            ( `protocol_cache`.`cn` = ? OR
              `protocol_cache`.`cn` IN (
                  SELECT `by_alias`.`protocol`
                  FROM `protocol_alias_cache` `by_alias`
                  WHERE `by_alias`.`cn` = ?))
        ''',
    )

    group_by = (0, )  # cn
    group_columns = (1, )  # alias


class ProtocolRequest(common.Request):

    def write(self, name, names, number):
        self.fp.write_string(name)
        self.fp.write_stringlist(names)
        self.fp.write_int32(number)

    def convert(self, dn, attributes, parameters):
        names = attributes['cn']
        yield (names[0], names[1:], int(attributes['ipProtocolNumber'][0]))


class ProtocolByNameRequest(ProtocolRequest):

    action = constants.NSLCD_ACTION_PROTOCOL_BYNAME

    def read_parameters(self, fp):
        return dict(cn=fp.read_string())


class ProtocolByNumberRequest(ProtocolRequest):

    action = constants.NSLCD_ACTION_PROTOCOL_BYNUMBER

    def read_parameters(self, fp):
        return dict(ipProtocolNumber=fp.read_int32())


class ProtocolAllRequest(ProtocolRequest):

    action = constants.NSLCD_ACTION_PROTOCOL_ALL
