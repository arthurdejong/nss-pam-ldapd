
# netgroup.py - lookup functions for netgroups
#
# Copyright (C) 2011 Arthur de Jong
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

import constants
import common


_netgroup_triple_re = re.compile(r'^\s*\(\s*(?P<host>.*)\s*,\s*(?P<user>.*)\s*,\s*(?P<domain>.*)\s*\)\s*$')


attmap = common.Attributes(cn='cn',
                           nisNetgroupTriple='nisNetgroupTriple',
                           memberNisNetgroup='memberNisNetgroup')
filter = '(objectClass=nisNetgroup)'


class Search(common.Search):

    case_sensitive = ('cn', )
    required = ('cn', )


class NetgroupRequest(common.Request):

    def write(self, dn, attributes, parameters):
        # write the netgroup triples
        for triple in attributes['nisNetgroupTriple']:
            m = _netgroup_triple_re.match(triple)
            if not m:
                print 'Warning: entry %s contains invalid %s value: %r' % ( dn, attmap['nisNetgroupTriple'], triple)
            else:
                self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
                self.fp.write_int32(constants.NSLCD_NETGROUP_TYPE_TRIPLE)
                self.fp.write_string(m.group('host'))
                self.fp.write_string(m.group('user'))
                self.fp.write_string(m.group('domain'))
        # write netgroup members
        for member in attributes['memberNisNetgroup']:
            self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
            self.fp.write_int32(constants.NSLCD_NETGROUP_TYPE_NETGROUP)
            self.fp.write_string(member)


class NetgroupByNameRequest(NetgroupRequest):

    action = constants.NSLCD_ACTION_NETGROUP_BYNAME

    def read_parameters(self, fp):
        return dict(cn=fp.read_string())
