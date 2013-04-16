
# cache.py - caching layer for pynslcd
#
# Copyright (C) 2012, 2013 Arthur de Jong
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
# FIXME: have some way to remove stale entries from the cache if all items from LDAP are queried (perhas use TTL from all request)


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
        self.con = _get_connection()
        self.table = sys.modules[self.__module__].__name__
        self.create()

    def create(self):
        """Create the needed tables if neccesary."""
        self.con.executescript(self.create_sql)

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
        self.con.execute('''
            INSERT OR REPLACE INTO %s_cache
            VALUES
              (%s)
            ''' % (self.table, args), simple_values)
        for n, vlist in multi_values.items():
            self.con.execute('''
                DELETE FROM %s_%d_cache
                WHERE `%s` = ?
                ''' % (self.table, n, self.table), (values[0], ))
            self.con.executemany('''
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


# the connection to the sqlite database
_connection = None


# FIXME: make tread safe (is this needed the way the caches are initialised?)
def _get_connection():
    global _connection
    if _connection is None:
        filename = '/tmp/pynslcd_cache.sqlite'
        dirname = os.path.dirname(filename)
        if not os.path.isdir(dirname):
            os.mkdir(dirname)
        connection = sqlite3.connect(
            filename, detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False)
        connection.row_factory = sqlite3.Row
        #  initialise connection properties
        connection.executescript('''
            -- store temporary tables in memory
            PRAGMA temp_store = MEMORY;
            -- disable sync() on database (corruption on disk failure)
            PRAGMA synchronous = OFF;
            -- put journal in memory (corruption if crash during transaction)
            PRAGMA journal_mode = MEMORY;
            ''')
        _connection = connection
    return _connection
