
# alias.py - lookup functions for email aliases
#
# Copyright (C) 2010-2019 Arthur de Jong
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
    rfc822MailMember='rfc822MailMember')
filter = '(objectClass=nisMailAlias)'


class Search(search.LDAPSearch):

    case_insensitive = ('cn', )
    limit_attributes = ('cn', )
    required = ('cn', 'rfc822MailMember')


class Cache(cache.Cache):

    tables = ('alias_cache', 'alias_member_cache')

    create_sql = '''
        CREATE TABLE IF NOT EXISTS `alias_cache`
          ( `cn` TEXT PRIMARY KEY COLLATE NOCASE,
            `mtime` TIMESTAMP NOT NULL );
        CREATE TABLE IF NOT EXISTS `alias_member_cache`
          ( `alias` TEXT NOT NULL COLLATE NOCASE,
            `rfc822MailMember` TEXT NOT NULL,
            FOREIGN KEY(`alias`) REFERENCES `alias_cache`(`cn`)
            ON DELETE CASCADE ON UPDATE CASCADE );
        CREATE INDEX IF NOT EXISTS `alias_member_idx` ON `alias_member_cache`(`alias`);
    '''

    retrieve_sql = '''
        SELECT `alias_cache`.`cn` AS `cn`,
               `alias_member_cache`.`rfc822MailMember` AS `rfc822MailMember`,
               `alias_cache`.`mtime` AS `mtime`
        FROM `alias_cache`
        LEFT JOIN `alias_member_cache`
          ON `alias_member_cache`.`alias` = `alias_cache`.`cn`
    '''

    retrieve_by = dict(
        rfc822MailMember='''
            `cn` IN (
                SELECT `a`.`alias`
                FROM `alias_member_cache` `a`
                WHERE `a`.`rfc822MailMember` = ?)
        ''',
    )

    group_by = (0, )  # cn
    group_columns = (1, )  # rfc822MailMember


class AliasRequest(common.Request):

    def write(self, name, members):
        self.fp.write_string(name)
        self.fp.write_stringlist(members)

    def convert(self, dn, attributes, parameters):
        names = attributes['cn']
        members = attributes['rfc822MailMember']
        for name in names:
            yield (name, members)


class AliasByNameRequest(AliasRequest):

    action = constants.NSLCD_ACTION_ALIAS_BYNAME

    def read_parameters(self, fp):
        return dict(cn=fp.read_string())


class AliasAllRequest(AliasRequest):

    action = constants.NSLCD_ACTION_ALIAS_ALL
