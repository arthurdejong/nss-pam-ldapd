
# ether.py - lookup functions for ethernet addresses
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

import struct

import cache
import common
import constants
import search


def ether_aton(ether):
    """Convert an ethernet address to binary form in network byte order."""
    return struct.pack('BBBBBB', *(int(x, 16) for x in ether.split(':')))


def ether_ntoa(ether, compact=True):
    """Convert an ethernet address in network byte order to a string."""
    fmt = '%x' if compact else '%02x'
    return ':'.join(fmt % x for x in struct.unpack('6B', ether))


attmap = common.Attributes(
    cn='cn',
    macAddress='macAddress')
filter = '(objectClass=ieee802Device)'


class Search(search.LDAPSearch):

    case_insensitive = ('cn', )
    limit_attributes = ('cn', 'macAddress')
    required = ('cn', 'macAddress')

    def mk_filter(self):
        # we need a custom mk_filter because this is an | query
        if 'macAddress' in self.parameters:
            ether = self.parameters['macAddress']
            alt_ether = ether_ntoa(ether_aton(ether), compact=False)
            return '(&%s(|(%s=%s)(%s=%s)))' % (
                self.filter,
                attmap['macAddress'], ether,
                attmap['macAddress'], alt_ether)
        return super(Search, self).mk_filter()


class Cache(cache.Cache):

    create_sql = '''
        CREATE TABLE IF NOT EXISTS `ether_cache`
          ( `cn` TEXT NOT NULL COLLATE NOCASE,
            `macAddress` TEXT NOT NULL COLLATE NOCASE,
            `mtime` TIMESTAMP NOT NULL,
            UNIQUE (`cn`, `macAddress`) );
    '''


class EtherRequest(common.Request):

    def write(self, name, ether):
        self.fp.write_string(name)
        self.fp.write(ether_aton(ether))

    def convert(self, dn, attributes, parameters):
        for name in attributes['cn']:
            for ether in attributes['macAddress']:
                yield (name, ether)


class EtherByNameRequest(EtherRequest):

    action = constants.NSLCD_ACTION_ETHER_BYNAME

    def read_parameters(self, fp):
        return dict(cn=fp.read_string())


class EtherByEtherRequest(EtherRequest):

    action = constants.NSLCD_ACTION_ETHER_BYETHER

    def read_parameters(self, fp):
        return dict(macAddress=ether_ntoa(fp.read(6)))


class EtherAllRequest(EtherRequest):

    action = constants.NSLCD_ACTION_ETHER_ALL
