
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
import os
import sys

import sqlite3


# TODO: probably create a config table
# FIXME: have some way to remove stale entries from the cache if all items from LDAP are queried (perhas use TTL from all request)


class regroup(object):

    def __init__(self, results, group_by=None, group_column=None):
        """Regroup the results in the group column by the key columns."""
        self.group_by = tuple(group_by)
        self.group_column = group_column
        self.it = iter(results)
        self.tgtkey = self.currkey = self.currvalue = object()

    def keyfunc(self, row):
        return tuple(row[x] for x in self.group_by)

    def __iter__(self):
        return self

    def next(self):
        # find a start row
        while self.currkey == self.tgtkey:
            self.currvalue = next(self.it)    # Exit on StopIteration
            self.currkey = self.keyfunc(self.currvalue)
        self.tgtkey = self.currkey
        # turn the result row into a list of columns
        row = list(self.currvalue)
        # replace the group column
        row[self.group_column] = list(self._grouper(self.tgtkey))
        return row

    def _grouper(self, tgtkey):
        """Generate the group columns."""
        while self.currkey == tgtkey:
            value = self.currvalue[self.group_column]
            if value is not None:
                yield value
            self.currvalue = next(self.it)    # Exit on StopIteration
            self.currkey = self.keyfunc(self.currvalue)


class Query(object):
    """Helper class to build an SQL query for the cache."""

    def __init__(self, query):
        self.query = query
        self.wheres = []
        self.parameters = []

    def add_where(self, where, parameters):
        self.wheres.append(where)
        self.parameters += parameters

    def execute(self, con):
        query = self.query
        if self.wheres:
            query += ' WHERE ' + ' AND '.join(self.wheres)
        cursor = con.cursor()
        return cursor.execute(query, self.parameters)


class Cache(object):
    """The description of the cache."""

    retrieve_sql = None
    retrieve_by = dict()
    group_by = ()
    group_columns = ()

    def __init__(self):
        self.con = _get_connection()
        self.db = sys.modules[self.__module__].__name__
        if not hasattr(self, 'tables'):
            self.tables = ['%s_cache' % self.db]
        self.create()

    def create(self):
        """Create the needed tables if neccesary."""
        self.con.executescript(self.create_sql)

    def store(self, *values):
        """Store the values in the cache for the specified table.
        The order of the values is the order returned by the Reques.convert()
        function."""
        # split the values into simple (flat) values and one-to-many values
        simple_values = []
        multi_values = []
        for v in values:
            if isinstance(v, (list, tuple, set)):
                multi_values.append(v)
            else:
                simple_values.append(v)
        # insert the simple values
        simple_values.append(datetime.datetime.now())
        args = ', '.join(len(simple_values) * ('?', ))
        self.con.execute('''
            INSERT OR REPLACE INTO %s
            VALUES
              (%s)
            ''' % (self.tables[0], args), simple_values)
        # insert the one-to-many values
        for n, vlist in enumerate(multi_values):
            self.con.execute('''
                DELETE FROM %s
                WHERE `%s` = ?
                ''' % (self.tables[n + 1], self.db), (values[0], ))
            self.con.executemany('''
                INSERT INTO %s
                VALUES
                  (?, ?)
                ''' % (self.tables[n + 1]), ((values[0], x) for x in vlist))

    def retrieve(self, parameters):
        """Retrieve all items from the cache based on the parameters
        supplied."""
        query = Query(self.retrieve_sql or '''
            SELECT *
            FROM %s
            ''' % self.tables[0])
        if parameters:
            for k, v in parameters.items():
                where = self.retrieve_by.get(k, '`%s`.`%s` = ?' % (self.tables[0], k))
                query.add_where(where, where.count('?') * [v])
        # group by
        # FIXME: find a nice way to turn group_by and group_columns into names
        results = query.execute(self.con)
        group_by = list(self.group_by + self.group_columns)
        for column in self.group_columns[::-1]:
            group_by.pop()
            results = regroup(results, group_by, column)
        # strip the mtime from the results
        return (list(x)[:-1] for x in results)

    def __enter__(self):
        return self.con.__enter__();

    def __exit__(self, *args):
        return self.con.__exit__(*args);


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
        # initialise connection properties
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
