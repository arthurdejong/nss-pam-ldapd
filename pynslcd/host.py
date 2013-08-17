
# host.py - lookup functions for host names and addresses
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


attmap = common.Attributes(cn='cn', ipHostNumber='ipHostNumber')
filter = '(objectClass=ipHost)'


class Search(search.LDAPSearch):

    canonical_first = ('cn', )
    required = ('cn', )


class Cache(cache.Cache):

    tables = ('host_cache', 'host_alias_cache', 'host_address_cache')

    create_sql = '''
        CREATE TABLE IF NOT EXISTS `host_cache`
          ( `cn` TEXT PRIMARY KEY COLLATE NOCASE,
            `mtime` TIMESTAMP NOT NULL );
        CREATE TABLE IF NOT EXISTS `host_alias_cache`
          ( `host` TEXT NOT NULL COLLATE NOCASE,
            `cn` TEXT NOT NULL COLLATE NOCASE,
            FOREIGN KEY(`host`) REFERENCES `host_cache`(`cn`)
            ON DELETE CASCADE ON UPDATE CASCADE );
        CREATE INDEX IF NOT EXISTS `host_alias_idx` ON `host_alias_cache`(`host`);
        CREATE TABLE IF NOT EXISTS `host_address_cache`
          ( `host` TEXT NOT NULL COLLATE NOCASE,
            `ipHostNumber` TEXT NOT NULL,
            FOREIGN KEY(`host`) REFERENCES `host_cache`(`cn`)
            ON DELETE CASCADE ON UPDATE CASCADE );
        CREATE INDEX IF NOT EXISTS `host_address_idx` ON `host_address_cache`(`host`);
    '''

    retrieve_sql = '''
        SELECT `host_cache`.`cn` AS `cn`,
               `host_alias_cache`.`cn` AS `alias`,
               `host_address_cache`.`ipHostNumber` AS `ipHostNumber`,
               `host_cache`.`mtime` AS `mtime`
        FROM `host_cache`
        LEFT JOIN `host_alias_cache`
          ON `host_alias_cache`.`host` = `host_cache`.`cn`
        LEFT JOIN `host_address_cache`
          ON `host_address_cache`.`host` = `host_cache`.`cn`
    '''

    retrieve_by = dict(
        cn='''
            ( `host_cache`.`cn` = ? OR
              `host_cache`.`cn` IN (
                  SELECT `by_alias`.`host`
                  FROM `host_alias_cache` `by_alias`
                  WHERE `by_alias`.`cn` = ?))
        ''',
        ipHostNumber='''
            `host_cache`.`cn` IN (
                SELECT `by_ipHostNumber`.`host`
                FROM `host_address_cache` `by_ipHostNumber`
                WHERE `by_ipHostNumber`.`ipHostNumber` = ?)
        ''',
    )

    group_by = (0, )  # cn
    group_columns = (1, 2)  # alias, ipHostNumber


class HostRequest(common.Request):

    def write(self, hostname, aliases, addresses):
        self.fp.write_string(hostname)
        self.fp.write_stringlist(aliases)
        self.fp.write_int32(len(addresses))
        for address in addresses:
            self.fp.write_address(address)

    def convert(self, dn, attributes, parameters):
        hostnames = attributes['cn']
        yield (hostnames[0], hostnames[1:], attributes['ipHostNumber'])


class HostByNameRequest(HostRequest):

    action = constants.NSLCD_ACTION_HOST_BYNAME

    def read_parameters(self, fp):
        return dict(cn=fp.read_string())


class HostByAddressRequest(HostRequest):

    action = constants.NSLCD_ACTION_HOST_BYADDR

    def read_parameters(self, fp):
        return dict(ipHostNumber=fp.read_address())


class HostAllRequest(HostRequest):

    action = constants.NSLCD_ACTION_HOST_ALL
