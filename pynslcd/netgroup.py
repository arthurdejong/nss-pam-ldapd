
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

import logging
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
    pass


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
