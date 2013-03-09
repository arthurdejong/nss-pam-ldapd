
# network.py - lookup functions for network names and addresses
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

import cache
import common
import constants
import search


attmap = common.Attributes(cn='cn',
                           ipNetworkNumber='ipNetworkNumber')
filter = '(objectClass=ipNetwork)'


class Search(search.LDAPSearch):

    canonical_first = ('cn', )
    required = ('cn', )


class NetworkQuery(cache.CnAliasedQuery):

    sql = '''
        SELECT `network_cache`.`cn` AS `cn`,
               `network_1_cache`.`cn` AS `alias`,
               `network_2_cache`.`ipNetworkNumber` AS `ipNetworkNumber`
        FROM `network_cache`
        LEFT JOIN `network_1_cache`
          ON `network_1_cache`.`network` = `network_cache`.`cn`
        LEFT JOIN `network_2_cache`
          ON `network_2_cache`.`network` = `network_cache`.`cn`
        '''

    def __init__(self, parameters):
        super(NetworkQuery, self).__init__('network', parameters)


class Cache(cache.Cache):

    def retrieve(self, parameters):
        query = NetworkQuery(parameters)
        for row in cache.RowGrouper(query.execute(self.con), ('cn', ), ('alias', 'ipNetworkNumber', )):
            yield row['cn'], row['alias'], row['ipNetworkNumber']


class NetworkRequest(common.Request):

    def write(self, networkname, aliases, addresses):
        self.fp.write_string(networkname)
        self.fp.write_stringlist(aliases)
        self.fp.write_int32(len(addresses))
        for address in addresses:
            self.fp.write_address(address)

    def convert(self, dn, attributes, parameters):
        netnames = attributes['cn']
        yield (netnames[0], netnames[1:], attributes['ipNetworkNumber'])


class NetworkByNameRequest(NetworkRequest):

    action = constants.NSLCD_ACTION_NETWORK_BYNAME

    def read_parameters(self, fp):
        return dict(cn=fp.read_string())


class NetworkByAddressRequest(NetworkRequest):

    action = constants.NSLCD_ACTION_NETWORK_BYADDR

    def read_parameters(self, fp):
        return dict(ipNetworkNumber=fp.read_address())


class NetworkAllRequest(NetworkRequest):

    action = constants.NSLCD_ACTION_NETWORK_ALL
