
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


class HostQuery(cache.CnAliasedQuery):

    sql = '''
        SELECT `host_cache`.`cn` AS `cn`,
               `host_1_cache`.`cn` AS `alias`,
               `host_2_cache`.`ipHostNumber` AS `ipHostNumber`
        FROM `host_cache`
        LEFT JOIN `host_1_cache`
          ON `host_1_cache`.`host` = `host_cache`.`cn`
        LEFT JOIN `host_2_cache`
          ON `host_2_cache`.`host` = `host_cache`.`cn`
        '''

    def __init__(self, parameters):
        super(HostQuery, self).__init__('host', parameters)


class Cache(cache.Cache):

    create_sql = '''
        CREATE TABLE IF NOT EXISTS `host_cache`
          ( `cn` TEXT PRIMARY KEY COLLATE NOCASE,
            `mtime` TIMESTAMP NOT NULL );
        CREATE TABLE IF NOT EXISTS `host_1_cache`
          ( `host` TEXT NOT NULL COLLATE NOCASE,
            `cn` TEXT NOT NULL COLLATE NOCASE,
            FOREIGN KEY(`host`) REFERENCES `host_cache`(`cn`)
            ON DELETE CASCADE ON UPDATE CASCADE );
        CREATE INDEX IF NOT EXISTS `host_1_idx` ON `host_1_cache`(`host`);
        CREATE TABLE IF NOT EXISTS `host_2_cache`
          ( `host` TEXT NOT NULL COLLATE NOCASE,
            `ipHostNumber` TEXT NOT NULL,
            FOREIGN KEY(`host`) REFERENCES `host_cache`(`cn`)
            ON DELETE CASCADE ON UPDATE CASCADE );
        CREATE INDEX IF NOT EXISTS `host_2_idx` ON `host_2_cache`(`host`);
    '''

    def retrieve(self, parameters):
        query = HostQuery(parameters)
        for row in cache.RowGrouper(query.execute(self.con), ('cn', ), ('alias', 'ipHostNumber', )):
            yield row['cn'], row['alias'], row['ipHostNumber']


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
