
# service.py - service entry lookup routines
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

import datetime

import cache
import common
import constants
import search


attmap = common.Attributes(
    cn='cn',
    ipServicePort='ipServicePort',
    ipServiceProtocol='ipServiceProtocol')
filter = '(objectClass=ipService)'


class Search(search.LDAPSearch):

    case_sensitive = ('cn', 'ipServiceProtocol')
    limit_attributes = ('ipServiceProtocol', )
    canonical_first = ('cn', )
    required = ('cn', 'ipServicePort', 'ipServiceProtocol')


class Cache(cache.Cache):

    tables = ('service_cache', 'service_alias_cache')

    create_sql = '''
        CREATE TABLE IF NOT EXISTS `service_cache`
          ( `cn` TEXT NOT NULL,
            `ipServicePort` INTEGER NOT NULL,
            `ipServiceProtocol` TEXT NOT NULL,
            `mtime` TIMESTAMP NOT NULL,
            UNIQUE (`ipServicePort`, `ipServiceProtocol`) );
        CREATE TABLE IF NOT EXISTS `service_alias_cache`
          ( `ipServicePort` INTEGER NOT NULL,
            `ipServiceProtocol` TEXT NOT NULL,
            `cn` TEXT NOT NULL,
            FOREIGN KEY(`ipServicePort`) REFERENCES `service_cache`(`ipServicePort`)
            ON DELETE CASCADE ON UPDATE CASCADE,
            FOREIGN KEY(`ipServiceProtocol`) REFERENCES `service_cache`(`ipServiceProtocol`)
            ON DELETE CASCADE ON UPDATE CASCADE );
        CREATE INDEX IF NOT EXISTS `service_alias_idx1`
            ON `service_alias_cache`(`ipServicePort`);
        CREATE INDEX IF NOT EXISTS `service_alias_idx2`
            ON `service_alias_cache`(`ipServiceProtocol`);
    '''

    retrieve_sql = '''
        SELECT `service_cache`.`cn` AS `cn`,
               `service_alias_cache`.`cn` AS `alias`,
               `service_cache`.`ipServicePort`,
               `service_cache`.`ipServiceProtocol`,
               `mtime`
        FROM `service_cache`
        LEFT JOIN `service_alias_cache`
          ON `service_alias_cache`.`ipServicePort` = `service_cache`.`ipServicePort`
         AND `service_alias_cache`.`ipServiceProtocol` = `service_cache`.`ipServiceProtocol`
    '''

    retrieve_by = dict(
        cn='''
            ( `service_cache`.`cn` = ? OR
              0 < (
                  SELECT COUNT(*)
                  FROM `service_alias_cache` `by_alias`
                  WHERE `by_alias`.`cn` = ?
                    AND `by_alias`.`ipServicePort` = `service_cache`.`ipServicePort`
                    AND `by_alias`.`ipServiceProtocol` = `service_cache`.`ipServiceProtocol`
                ))
        ''',
    )

    group_by = (0, 2, 3)  # cn, ipServicePort, ipServiceProtocol
    group_columns = (1, )  # alias

    def store(self, name, aliases, port, protocol):
        self.con.execute('''
            INSERT OR REPLACE INTO `service_cache`
            VALUES
              (?, ?, ?, ?)
        ''', (name, port, protocol, datetime.datetime.now()))
        self.con.execute('''
            DELETE FROM `service_alias_cache`
            WHERE `ipServicePort` = ?
              AND `ipServiceProtocol` = ?
        ''', (port, protocol))
        self.con.executemany('''
            INSERT INTO `service_alias_cache`
            VALUES
              (?, ?, ?)
        ''', ((port, protocol, alias) for alias in aliases))


class ServiceRequest(common.Request):

    def write(self, name, aliases, port, protocol):
        self.fp.write_string(name)
        self.fp.write_stringlist(aliases)
        self.fp.write_int32(port)
        self.fp.write_string(protocol)

    def convert(self, dn, attributes, parameters):
        names = attributes['cn']
        port = int(attributes['ipServicePort'][0])
        protocols = attributes['ipServiceProtocol']
        for protocol in protocols:
            yield (names[0], names[1:], port, protocol)


class ServiceByNameRequest(ServiceRequest):

    action = constants.NSLCD_ACTION_SERVICE_BYNAME

    def read_parameters(self, fp):
        name = fp.read_string()
        protocol = fp.read_string()
        if protocol:
            return dict(cn=name, ipServiceProtocol=protocol)
        else:
            return dict(cn=name)


class ServiceByNumberRequest(ServiceRequest):

    action = constants.NSLCD_ACTION_SERVICE_BYNUMBER

    def read_parameters(self, fp):
        number = fp.read_int32()
        protocol = fp.read_string()
        if protocol:
            return dict(ipServicePort=number, ipServiceProtocol=protocol)
        else:
            return dict(ipServicePort=number)


class ServiceAllRequest(ServiceRequest):

    action = constants.NSLCD_ACTION_SERVICE_ALL
