
# netgroup.py - lookup functions for netgroups
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

import re

import cache
import common
import constants
import search


_netgroup_triple_re = re.compile(r'^\s*\(\s*(?P<host>.*)\s*,\s*(?P<user>.*)\s*,\s*(?P<domain>.*)\s*\)\s*$')


attmap = common.Attributes(cn='cn',
                           nisNetgroupTriple='nisNetgroupTriple',
                           memberNisNetgroup='memberNisNetgroup')
filter = '(objectClass=nisNetgroup)'


class Search(search.LDAPSearch):

    case_sensitive = ('cn', )
    required = ('cn', )


class Cache(cache.Cache):

    tables = ('netgroup_cache', 'netgroup_triple_cache', 'netgroup_member_cache')

    create_sql = '''
        CREATE TABLE IF NOT EXISTS `netgroup_cache`
          ( `cn` TEXT PRIMARY KEY COLLATE NOCASE,
            `mtime` TIMESTAMP NOT NULL );
        CREATE TABLE IF NOT EXISTS `netgroup_triple_cache`
          ( `netgroup` TEXT NOT NULL COLLATE NOCASE,
            `nisNetgroupTriple` TEXT NOT NULL COLLATE NOCASE,
            FOREIGN KEY(`netgroup`) REFERENCES `netgroup_cache`(`cn`)
            ON DELETE CASCADE ON UPDATE CASCADE );
        CREATE INDEX IF NOT EXISTS `netgroup_triple_idx` ON `netgroup_triple_cache`(`netgroup`);
        CREATE TABLE IF NOT EXISTS `netgroup_member_cache`
          ( `netgroup` TEXT NOT NULL COLLATE NOCASE,
            `memberNisNetgroup` TEXT NOT NULL,
            FOREIGN KEY(`netgroup`) REFERENCES `netgroup_cache`(`cn`)
            ON DELETE CASCADE ON UPDATE CASCADE );
        CREATE INDEX IF NOT EXISTS `netgroup_membe_idx` ON `netgroup_member_cache`(`netgroup`);
    '''

    retrieve_sql = '''
        SELECT `netgroup_cache`.`cn` AS `cn`,
               `netgroup_triple_cache`.`nisNetgroupTriple` AS `nisNetgroupTriple`,
               `netgroup_member_cache`.`memberNisNetgroup` AS `memberNisNetgroup`,
               `netgroup_cache`.`mtime` AS `mtime`
        FROM `netgroup_cache`
        LEFT JOIN `netgroup_triple_cache`
          ON `netgroup_triple_cache`.`netgroup` = `netgroup_cache`.`cn`
        LEFT JOIN `netgroup_member_cache`
          ON `netgroup_member_cache`.`netgroup` = `netgroup_cache`.`cn`
    '''

    group_by = (0, )  # cn
    group_columns = (1, 2)  # nisNetgroupTriple, memberNisNetgroup


class NetgroupRequest(common.Request):

    def write(self, name, triples, members):
        self.fp.write_string(name)
        for triple in triples:
            m = _netgroup_triple_re.match(triple)
            if m:
                self.fp.write_int32(constants.NSLCD_NETGROUP_TYPE_TRIPLE)
                self.fp.write_string(m.group('host'))
                self.fp.write_string(m.group('user'))
                self.fp.write_string(m.group('domain'))
        for member in members:
            self.fp.write_int32(constants.NSLCD_NETGROUP_TYPE_NETGROUP)
            self.fp.write_string(member)
        self.fp.write_int32(constants.NSLCD_NETGROUP_TYPE_END)

    def convert(self, dn, attributes, parameters):
        names = attributes['cn']
        triples = attributes['nisNetgroupTriple']
        members = attributes['memberNisNetgroup']
        for name in names:
            yield (name, triples, members)


class NetgroupByNameRequest(NetgroupRequest):

    action = constants.NSLCD_ACTION_NETGROUP_BYNAME

    def read_parameters(self, fp):
        return dict(cn=fp.read_string())


class NetgroupAllRequest(NetgroupRequest):

    action = constants.NSLCD_ACTION_NETGROUP_ALL
