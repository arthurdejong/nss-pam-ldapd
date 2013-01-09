
# cache.py - caching layer for pynslcd
#
# Copyright (C) 2012 Arthur de Jong
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
import itertools
import os
import sys

import sqlite3


# TODO: probably create a config table




# FIXME: store the cache in the right place and make it configurable
filename = '/tmp/cache.sqlite'
dirname = os.path.dirname(filename)
if not os.path.isdir(dirname):
    os.mkdir(dirname)
con = sqlite3.connect(filename,
                detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
con.row_factory = sqlite3.Row

# FIXME: have some way to remove stale entries from the cache if all items from LDAP are queried (perhas use TTL from all request)

# set up the database
con.executescript('''

    -- store temporary tables in memory
    PRAGMA temp_store = MEMORY;

    -- disable sync() on database (corruption on disk failure)
    PRAGMA synchronous = OFF;

    -- put journal in memory (corruption if crash during transaction)
    PRAGMA journal_mode = MEMORY;

    -- tables for alias cache
    CREATE TABLE IF NOT EXISTS `alias_cache`
      ( `cn` TEXT PRIMARY KEY COLLATE NOCASE,
        `mtime` TIMESTAMP NOT NULL );
    CREATE TABLE IF NOT EXISTS `alias_1_cache`
      ( `alias` TEXT NOT NULL COLLATE NOCASE,
        `rfc822MailMember` TEXT NOT NULL,
        FOREIGN KEY(`alias`) REFERENCES `alias_cache`(`cn`)
        ON DELETE CASCADE ON UPDATE CASCADE );
    CREATE INDEX IF NOT EXISTS `alias_1_idx` ON `alias_1_cache`(`alias`);

    -- table for ethernet cache
    CREATE TABLE IF NOT EXISTS `ether_cache`
      ( `cn` TEXT NOT NULL COLLATE NOCASE,
        `macAddress` TEXT NOT NULL COLLATE NOCASE,
        `mtime` TIMESTAMP NOT NULL,
        UNIQUE (`cn`, `macAddress`) );

    -- table for group cache
    CREATE TABLE IF NOT EXISTS `group_cache`
      ( `cn` TEXT PRIMARY KEY,
        `userPassword` TEXT,
        `gidNumber` INTEGER NOT NULL UNIQUE,
        `mtime` TIMESTAMP NOT NULL );
    CREATE TABLE IF NOT EXISTS `group_3_cache`
      ( `group` TEXT NOT NULL,
        `memberUid` TEXT NOT NULL,
        FOREIGN KEY(`group`) REFERENCES `group_cache`(`cn`)
        ON DELETE CASCADE ON UPDATE CASCADE );
    CREATE INDEX IF NOT EXISTS `group_3_idx` ON `group_3_cache`(`group`);

    -- tables for host cache
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

    -- FIXME: this does not work as entries are never removed from the cache
    CREATE TABLE IF NOT EXISTS `netgroup_cache`
      ( `cn` TEXT NOT NULL,
        `member` TEXT NOT NULL,
        `mtime` TIMESTAMP NOT NULL,
        UNIQUE (`cn`, `member`) );

    -- tables for network cache
    CREATE TABLE IF NOT EXISTS `network_cache`
      ( `cn` TEXT PRIMARY KEY COLLATE NOCASE,
        `mtime` TIMESTAMP NOT NULL );
    CREATE TABLE IF NOT EXISTS `network_1_cache`
      ( `network` TEXT NOT NULL COLLATE NOCASE,
        `cn` TEXT NOT NULL COLLATE NOCASE,
        FOREIGN KEY(`network`) REFERENCES `network_cache`(`cn`)
        ON DELETE CASCADE ON UPDATE CASCADE );
    CREATE INDEX IF NOT EXISTS `network_1_idx` ON `network_1_cache`(`network`);
    CREATE TABLE IF NOT EXISTS `network_2_cache`
      ( `network` TEXT NOT NULL,
        `ipNetworkNumber` TEXT NOT NULL,
        FOREIGN KEY(`network`) REFERENCES `network_cache`(`cn`)
        ON DELETE CASCADE ON UPDATE CASCADE );
    CREATE INDEX IF NOT EXISTS `network_2_idx` ON `network_2_cache`(`network`);

    -- table for passwd cache
    CREATE TABLE IF NOT EXISTS `passwd_cache`
      ( `uid` TEXT PRIMARY KEY,
        `userPassword` TEXT,
        `uidNumber` INTEGER NOT NULL UNIQUE,
        `gidNumber` INTEGER NOT NULL,
        `gecos` TEXT,
        `homeDirectory` TEXT,
        `loginShell` TEXT,
        `mtime` TIMESTAMP NOT NULL );

    -- table for protocol cache
    CREATE TABLE IF NOT EXISTS `protocol_cache`
      ( `cn` TEXT PRIMARY KEY,
        `ipProtocolNumber` INTEGER NOT NULL,
        `mtime` TIMESTAMP NOT NULL );
    CREATE TABLE IF NOT EXISTS `protocol_1_cache`
      ( `protocol` TEXT NOT NULL,
        `cn` TEXT NOT NULL,
        FOREIGN KEY(`protocol`) REFERENCES `protocol_cache`(`cn`)
        ON DELETE CASCADE ON UPDATE CASCADE );
    CREATE INDEX IF NOT EXISTS `protocol_1_idx` ON `protocol_1_cache`(`protocol`);

    -- table for rpc cache
    CREATE TABLE IF NOT EXISTS `rpc_cache`
      ( `cn` TEXT PRIMARY KEY,
        `oncRpcNumber` INTEGER NOT NULL,
        `mtime` TIMESTAMP NOT NULL );
    CREATE TABLE IF NOT EXISTS `rpc_1_cache`
      ( `rpc` TEXT NOT NULL,
        `cn` TEXT NOT NULL,
        FOREIGN KEY(`rpc`) REFERENCES `rpc_cache`(`cn`)
        ON DELETE CASCADE ON UPDATE CASCADE );
    CREATE INDEX IF NOT EXISTS `rpc_1_idx` ON `rpc_1_cache`(`rpc`);

    -- tables for service cache
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

    -- table for shadow cache
    CREATE TABLE IF NOT EXISTS `shadow_cache`
      ( `uid` TEXT PRIMARY KEY,
        `userPassword` TEXT,
        `shadowLastChange` INTEGER,
        `shadowMin` INTEGER,
        `shadowMax` INTEGER,
        `shadowWarning` INTEGER,
        `shadowInactive` INTEGER,
        `shadowExpire` INTEGER,
        `shadowFlag` INTEGER,
        `mtime` TIMESTAMP NOT NULL );

    ''')


class Query(object):

    def __init__(self, query, parameters=None):
        self.query = query
        self.wheres = []
        self.parameters = []
        if parameters:
            for k, v in parameters.items():
                self.add_where('`%s` = ?' % k, [v])

    def add_query(self, query):
        self.query += ' ' + query

    def add_where(self, where, parameters):
        self.wheres.append(where)
        self.parameters += parameters

    def execute(self, con):
        query = self.query
        if self.wheres:
            query += ' WHERE ' + ' AND '.join(self.wheres)
        c = con.cursor()
        return c.execute(query, self.parameters)


class CnAliasedQuery(Query):

    sql = '''
        SELECT `%(table)s_cache`.*,
               `%(table)s_1_cache`.`cn` AS `alias`
        FROM `%(table)s_cache`
        LEFT JOIN `%(table)s_1_cache`
          ON `%(table)s_1_cache`.`%(table)s` = `%(table)s_cache`.`cn`
        '''

    cn_join = '''
        LEFT JOIN `%(table)s_1_cache` `cn_alias`
          ON `cn_alias`.`%(table)s` = `%(table)s_cache`.`cn`
        '''

    def __init__(self, table, parameters):
        args = dict(table=table)
        super(CnAliasedQuery, self).__init__(self.sql % args)
        for k, v in parameters.items():
            if k == 'cn':
                self.add_query(self.cn_join % args)
                self.add_where('(`%(table)s_cache`.`cn` = ? OR `cn_alias`.`cn` = ?)' % args, [v, v])
            else:
                self.add_where('`%s` = ?' % k, [v])


class RowGrouper(object):
    """Pass in query results and group the results by a certain specified
    list of columns."""

    def __init__(self, results, groupby, columns):
        self.groupby = groupby
        self.columns = columns
        self.results = itertools.groupby(results, key=self.keyfunc)

    def __iter__(self):
        return self

    def keyfunc(self, row):
        return tuple(row[x] for x in self.groupby)

    def next(self):
        groupcols, rows = self.results.next()
        tmp = dict((x, list()) for x in self.columns)
        for row in rows:
            for col in self.columns:
                if row[col] is not None:
                    tmp[col].append(row[col])
        result = dict(row)
        result.update(tmp)
        return result


class Cache(object):

    def __init__(self):
        self.con = con
        self.table = sys.modules[self.__module__].__name__

    def store(self, *values):
        """Store the values in the cache for the specified table."""
        simple_values = []
        multi_values = {}
        for n, v in enumerate(values):
            if isinstance(v, (list, tuple, set)):
                multi_values[n] = v
            else:
                simple_values.append(v)
        simple_values.append(datetime.datetime.now())
        args = ', '.join(len(simple_values) * ('?', ))
        con.execute('''
            INSERT OR REPLACE INTO %s_cache
            VALUES
              (%s)
            ''' % (self.table, args), simple_values)
        for n, vlist in multi_values.items():
            con.execute('''
                DELETE FROM %s_%d_cache
                WHERE `%s` = ?
                ''' % (self.table, n, self.table), (values[0], ))
            con.executemany('''
                INSERT INTO %s_%d_cache
                VALUES
                  (?, ?)
                ''' % (self.table, n), ((values[0], x) for x in vlist))

    def retrieve(self, parameters):
        """Retrieve all items from the cache based on the parameters supplied."""
        query = Query('''
            SELECT *
            FROM %s_cache
            ''' % self.table, parameters)
        return (list(x)[:-1] for x in query.execute(self.con))
