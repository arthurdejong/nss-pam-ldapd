
# service.py - service entry lookup routines
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

import datetime

import cache
import common
import constants
import search


attmap = common.Attributes(cn='cn',
                           ipServicePort='ipServicePort',
                           ipServiceProtocol='ipServiceProtocol')
filter = '(objectClass=ipService)'


class Search(search.LDAPSearch):

    case_sensitive = ('cn', 'ipServiceProtocol')
    limit_attributes = ('ipServiceProtocol', )
    canonical_first = ('cn', )
    required = ('cn', 'ipServicePort', 'ipServiceProtocol')


class ServiceQuery(cache.CnAliasedQuery):

    sql = '''
        SELECT `service_cache`.*,
               `service_1_cache`.`cn` AS `alias`
        FROM `service_cache`
        LEFT JOIN `service_1_cache`
          ON `service_1_cache`.`ipServicePort` = `service_cache`.`ipServicePort`
          AND `service_1_cache`.`ipServiceProtocol` = `service_cache`.`ipServiceProtocol`
        '''

    cn_join = '''
        LEFT JOIN `service_1_cache` `cn_alias`
          ON `cn_alias`.`ipServicePort` = `service_cache`.`ipServicePort`
          AND `cn_alias`.`ipServiceProtocol` = `service_cache`.`ipServiceProtocol`
        '''

    def __init__(self, parameters):
        super(ServiceQuery, self).__init__('service', {})
        for k, v in parameters.items():
            if k == 'cn':
                self.add_query(self.cn_join)
                self.add_where('(`service_cache`.`cn` = ? OR `cn_alias`.`cn` = ?)', [v, v])
            else:
                self.add_where('`service_cache`.`%s` = ?' % k, [v])


class Cache(cache.Cache):

    tables = ('service_cache', 'service_1_cache')

    create_sql = '''
        CREATE TABLE IF NOT EXISTS `service_cache`
          ( `cn` TEXT NOT NULL,
            `ipServicePort` INTEGER NOT NULL,
            `ipServiceProtocol` TEXT NOT NULL,
            `mtime` TIMESTAMP NOT NULL,
            UNIQUE (`ipServicePort`, `ipServiceProtocol`) );
        CREATE TABLE IF NOT EXISTS `service_1_cache`
          ( `ipServicePort` INTEGER NOT NULL,
            `ipServiceProtocol` TEXT NOT NULL,
            `cn` TEXT NOT NULL,
            FOREIGN KEY(`ipServicePort`) REFERENCES `service_cache`(`ipServicePort`)
            ON DELETE CASCADE ON UPDATE CASCADE,
            FOREIGN KEY(`ipServiceProtocol`) REFERENCES `service_cache`(`ipServiceProtocol`)
            ON DELETE CASCADE ON UPDATE CASCADE );
        CREATE INDEX IF NOT EXISTS `service_1_idx1` ON `service_1_cache`(`ipServicePort`);
        CREATE INDEX IF NOT EXISTS `service_1_idx2` ON `service_1_cache`(`ipServiceProtocol`);
    '''

    def store(self, name, aliases, port, protocol):
        self.con.execute('''
            INSERT OR REPLACE INTO `service_cache`
            VALUES
              (?, ?, ?, ?)
        ''', (name, port, protocol, datetime.datetime.now()))
        self.con.execute('''
            DELETE FROM `service_1_cache`
            WHERE `ipServicePort` = ?
              AND `ipServiceProtocol` = ?
        ''', (port, protocol))
        self.con.executemany('''
            INSERT INTO `service_1_cache`
            VALUES
              (?, ?, ?)
        ''', ((port, protocol, alias) for alias in aliases))

    def retrieve(self, parameters):
        query = ServiceQuery(parameters)
        for row in cache.RowGrouper(query.execute(self.con), ('cn', 'ipServicePort', 'ipServiceProtocol'), ('alias', )):
            yield row['cn'], row['alias'], row['ipServicePort'], row['ipServiceProtocol']


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
