
# network.py - lookup functions for network names and addresses
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
    ipNetworkNumber='ipNetworkNumber')
filter = '(objectClass=ipNetwork)'


class Search(search.LDAPSearch):

    canonical_first = ('cn', )
    required = ('cn', )


class Cache(cache.Cache):

    tables = ('network_cache', 'network_alias_cache', 'network_address_cache')

    create_sql = '''
        CREATE TABLE IF NOT EXISTS `network_cache`
          ( `cn` TEXT PRIMARY KEY COLLATE NOCASE,
            `mtime` TIMESTAMP NOT NULL );
        CREATE TABLE IF NOT EXISTS `network_alias_cache`
          ( `network` TEXT NOT NULL COLLATE NOCASE,
            `cn` TEXT NOT NULL COLLATE NOCASE,
            FOREIGN KEY(`network`) REFERENCES `network_cache`(`cn`)
            ON DELETE CASCADE ON UPDATE CASCADE );
        CREATE INDEX IF NOT EXISTS `network_alias_idx` ON `network_alias_cache`(`network`);
        CREATE TABLE IF NOT EXISTS `network_address_cache`
          ( `network` TEXT NOT NULL COLLATE NOCASE,
            `ipNetworkNumber` TEXT NOT NULL,
            FOREIGN KEY(`network`) REFERENCES `network_cache`(`cn`)
            ON DELETE CASCADE ON UPDATE CASCADE );
        CREATE INDEX IF NOT EXISTS `network_address_idx` ON `network_address_cache`(`network`);
    '''

    retrieve_sql = '''
        SELECT `network_cache`.`cn` AS `cn`,
               `network_alias_cache`.`cn` AS `alias`,
               `network_address_cache`.`ipNetworkNumber` AS `ipNetworkNumber`,
               `network_cache`.`mtime` AS `mtime`
        FROM `network_cache`
        LEFT JOIN `network_alias_cache`
          ON `network_alias_cache`.`network` = `network_cache`.`cn`
        LEFT JOIN `network_address_cache`
          ON `network_address_cache`.`network` = `network_cache`.`cn`
    '''

    retrieve_by = dict(
        cn='''
            ( `network_cache`.`cn` = ? OR
              `network_cache`.`cn` IN (
                  SELECT `by_alias`.`network`
                  FROM `network_alias_cache` `by_alias`
                  WHERE `by_alias`.`cn` = ?))
        ''',
        ipNetworkNumber='''
            `network_cache`.`cn` IN (
                SELECT `by_ipNetworkNumber`.`network`
                FROM `network_address_cache` `by_ipNetworkNumber`
                WHERE `by_ipNetworkNumber`.`ipNetworkNumber` = ?)
        ''',
    )

    group_by = (0, )  # cn
    group_columns = (1, 2)  # alias, ipNetworkNumber


class NetworkRequest(common.Request):

    def write(self, networkname, aliases, addresses):
        self.fp.write_string(networkname)
        self.fp.write_stringlist(aliases)
        self.fp.write_int32(len(addresses))
        for address in addresses:
            self.fp.write_address(address)

    def convert(self, dn, attributes, parameters):
        netnames = attributes['cn']
        yield (netnames[0], netnames[1:], attributes['ipNetworkNumber'])


class NetworkByNameRequest(NetworkRequest):

    action = constants.NSLCD_ACTION_NETWORK_BYNAME

    def read_parameters(self, fp):
        return dict(cn=fp.read_string())


class NetworkByAddressRequest(NetworkRequest):

    action = constants.NSLCD_ACTION_NETWORK_BYADDR

    def read_parameters(self, fp):
        return dict(ipNetworkNumber=fp.read_address())


class NetworkAllRequest(NetworkRequest):

    action = constants.NSLCD_ACTION_NETWORK_ALL
