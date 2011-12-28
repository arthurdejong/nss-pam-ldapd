
# group.py - group entry lookup routines
#
# Copyright (C) 2010, 2011 Arthur de Jong
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
import ldap.filter

import constants
import common
from passwd import dn2uid, uid2dn


def clean(lst):
    if lst:
        for i in lst:
            yield i.replace('\0', '')


attmap = common.Attributes(cn='cn',
                           userPassword='"*"',
                           gidNumber='gidNumber',
                           memberUid='memberUid',
                           member='member')
filter = '(|(objectClass=posixGroup)(objectClass=groupOfNames))'


class Search(common.Search):

    case_sensitive = ('cn', )
    limit_attributes = ('cn', 'gidNumber')

    def __init__(self, *args, **kwargs):
        super(Search, self).__init__(*args, **kwargs)
        if attmap['member'] and 'memberUid' in self.parameters:
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
                          attmap['memberUid'], ldap.filter.escape_filter_chars(memberuid),
                          attmap['member'], ldap.filter.escape_filter_chars(dn))
        return super(Search, self).mk_filter()


class GroupRequest(common.Request):

    wantmembers = True

    def write(self, dn, attributes, parameters):
        # get group names and check against requested group name
        names = attributes['cn']
        # get group group password
        passwd = attributes['userPassword'][0]
        # get group id(s)
        gids = [int(x) for x in attributes['gidNumber']]
        # build member list
        members = set()
        if self.wantmembers:
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
                print '%s: %s: denied by validnames option' % (dn, attmap['cn'])
            else:
                for gid in gids:
                    self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
                    self.fp.write_string(name)
                    self.fp.write_string(passwd)
                    self.fp.write_gid_t(gid)
                    self.fp.write_stringlist(members)


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
    wantmembers = False

    def read_parameters(self, fp):
        memberuid = fp.read_string()
        common.validate_name(memberuid)
        return dict(memberUid=memberuid)


class GroupAllRequest(GroupRequest):

    action = constants.NSLCD_ACTION_GROUP_ALL
