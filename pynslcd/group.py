
# group.py - group entry lookup routines
#
# Copyright (C) 2010, 2011, 2012 Arthur de Jong
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

import itertools
import logging

from passwd import dn2uid, uid2dn
import cache
import common
import constants


def clean(lst):
    if lst:
        for i in lst:
            yield i.replace('\0', '')


attmap = common.Attributes(cn='cn',
                           userPassword='"*"',
                           gidNumber='gidNumber',
                           memberUid='memberUid',
                           member='member')
filter = '(objectClass=posixGroup)'


class Search(common.Search):

    case_sensitive = ('cn', )
    limit_attributes = ('cn', 'gidNumber')

    def __init__(self, *args, **kwargs):
        super(Search, self).__init__(*args, **kwargs)
        if 'memberUid' in self.parameters:
            # set up our own attributes that leave out membership attributes
            self.attributes = list(self.attributes)
            self.attributes.remove(attmap['memberUid'])
            self.attributes.remove(attmap['member'])

    def mk_filter(self):
        # we still need a custom mk_filter because this is an | query
        if attmap['member'] and 'memberUid' in self.parameters:
            memberuid = self.parameters['memberUid']
            dn = uid2dn(self.conn, memberuid)
            if dn:
                return '(&%s(|(%s=%s)(%s=%s)))' % (self.filter,
                          attmap['memberUid'], self.escape(memberuid),
                          attmap['member'], self.escape(dn))
        return super(Search, self).mk_filter()


class Cache(cache.Cache):

    retrieve_sql = '''
        SELECT `cn`, `userPassword`, `gidNumber`, `memberUid`
        FROM `group_cache`
        LEFT JOIN `group_3_cache`
          ON `group_3_cache`.`group` = `group_cache`.`cn`
        '''

    def retrieve(self, parameters):
        query = cache.Query(self.retrieve_sql, parameters)
        # return results returning the members as a set
        q = itertools.groupby(query.execute(self.con),
                key=lambda x: (x['cn'], x['userPassword'], x['gidNumber']))
        for k, v in q:
            yield k + (set(x['memberUid'] for x in v if x['memberUid'] is not None), )


class GroupRequest(common.Request):

    def write(self, name, passwd, gid, members):
        self.fp.write_string(name)
        self.fp.write_string(passwd)
        self.fp.write_gid_t(gid)
        self.fp.write_stringlist(members)

    def convert(self, dn, attributes, parameters):
        # get group names and check against requested group name
        names = attributes['cn']
        # get group group password
        passwd = attributes['userPassword'][0]
        # get group id(s)
        gids = [int(x) for x in attributes['gidNumber']]
        # build member list
        members = set()
        # add the memberUid values
        for member in clean(attributes['memberUid']):
            if common.isvalidname(member):
                members.add(member)
        # translate and add the member values
        for memberdn in clean(attributes['member']):
            member = dn2uid(self.conn, memberdn)
            if member and common.isvalidname(member):
                members.add(member)
        # actually return the results
        for name in names:
            if not common.isvalidname(name):
                logging.warning('%s: %s: denied by validnames option', dn,
                                attmap['cn'])
            else:
                for gid in gids:
                    yield (name, passwd, gid, members)


class GroupByNameRequest(GroupRequest):

    action = constants.NSLCD_ACTION_GROUP_BYNAME

    def read_parameters(self, fp):
        name = fp.read_string()
        common.validate_name(name)
        return dict(cn=name)


class GroupByGidRequest(GroupRequest):

    action = constants.NSLCD_ACTION_GROUP_BYGID

    def read_parameters(self, fp):
        return dict(gidNumber=fp.read_gid_t())


class GroupByMemberRequest(GroupRequest):

    action = constants.NSLCD_ACTION_GROUP_BYMEMBER

    def read_parameters(self, fp):
        memberuid = fp.read_string()
        common.validate_name(memberuid)
        return dict(memberUid=memberuid)


class GroupAllRequest(GroupRequest):

    action = constants.NSLCD_ACTION_GROUP_ALL
