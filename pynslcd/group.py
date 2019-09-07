
# group.py - group entry lookup routines
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

import logging

import ldap
from ldap.filter import escape_filter_chars

import cache
import cfg
import common
import constants
import passwd
import search


def clean(lst):
    if lst:
        for i in lst:
            yield i.replace('\0', '')


attmap = common.Attributes(
    cn='cn',
    userPassword='"*"',
    gidNumber='gidNumber',
    memberUid='memberUid',
    member='member')
filter = '(objectClass=posixGroup)'


class Search(search.LDAPSearch):

    case_sensitive = ('cn', )
    limit_attributes = ('cn', 'gidNumber')

    def __init__(self, *args, **kwargs):
        super(Search, self).__init__(*args, **kwargs)
        if (cfg.nss_getgrent_skipmembers or
                'memberUid' in self.parameters or
                'member' in self.parameters):
            # set up our own attributes that leave out membership attributes
            self.attributes = list(self.attributes)
            if attmap['memberUid'] in self.attributes:
                self.attributes.remove(attmap['memberUid'])
            if attmap['member'] in self.attributes:
                self.attributes.remove(attmap['member'])

    def mk_filter(self):
        # we still need a custom mk_filter because this is an | query
        if attmap['member'] and 'memberUid' in self.parameters:
            memberuid = self.parameters['memberUid']
            entry = passwd.uid2entry(self.conn, memberuid)
            if entry:
                return '(&%s(|(%s=%s)(%s=%s)))' % (
                    self.filter,
                    attmap['memberUid'], escape_filter_chars(memberuid),
                    attmap['member'], escape_filter_chars(entry[0]),
                )
        if 'gidNumber' in self.parameters:
            self.parameters['gidNumber'] -= cfg.nss_gid_offset
        return super(Search, self).mk_filter()


class Cache(cache.Cache):

    tables = ('group_cache', 'group_member_cache')

    create_sql = '''
        CREATE TABLE IF NOT EXISTS `group_cache`
          ( `cn` TEXT PRIMARY KEY,
            `userPassword` TEXT,
            `gidNumber` INTEGER NOT NULL UNIQUE,
            `mtime` TIMESTAMP NOT NULL );
        CREATE TABLE IF NOT EXISTS `group_member_cache`
          ( `group` TEXT NOT NULL,
            `memberUid` TEXT NOT NULL,
            FOREIGN KEY(`group`) REFERENCES `group_cache`(`cn`)
            ON DELETE CASCADE ON UPDATE CASCADE );
        CREATE INDEX IF NOT EXISTS `group_member_idx` ON `group_member_cache`(`group`);
    '''

    retrieve_sql = '''
        SELECT `group_cache`.`cn` AS `cn`, `userPassword`, `gidNumber`,
               `memberUid`, `mtime`
        FROM `group_cache`
        LEFT JOIN `group_member_cache`
          ON `group_member_cache`.`group` = `group_cache`.`cn`
    '''

    retrieve_by = dict(
        memberUid='''
            `cn` IN (
                SELECT `a`.`group`
                FROM `group_member_cache` `a`
                WHERE `a`.`memberUid` = ?)
        ''',
    )

    group_by = (0, )  # cn
    group_columns = (3, )  # memberUid


class GroupRequest(common.Request):

    def write(self, name, passwd, gid, members):
        self.fp.write_string(name)
        self.fp.write_string(passwd)
        self.fp.write_int32(gid)
        self.fp.write_stringlist(members)

    def get_members(self, attributes, members, subgroups, seen):
        # add the memberUid values
        for member in clean(attributes['memberUid']):
            if common.is_valid_name(member):
                members.add(member)
        # translate and add the member values
        if attmap['member']:
            for memberdn in clean(attributes['member']):
                if memberdn in seen:
                    continue
                seen.add(memberdn)
                member = passwd.dn2uid(self.conn, memberdn)
                if member and common.is_valid_name(member):
                    members.add(member)
                elif cfg.nss_nested_groups:
                    subgroups.append(memberdn)

    def convert(self, dn, attributes, parameters):
        # get group names and check against requested group name
        names = attributes['cn']
        # get group password
        try:
            passwd = attributes['userPassword'][0]
        except IndexError:
            passwd = None
        if not passwd or self.calleruid != 0:
            passwd = '*'
        # get group id(s)
        gids = [int(x) + cfg.nss_gid_offset for x in attributes['gidNumber']]
        # build member list
        members = set()
        subgroups = []
        seen = set([dn])
        self.get_members(attributes, members, subgroups, seen)
        # go over subgroups to find more members
        while subgroups:
            memberdn = subgroups.pop(0)
            for dn2, attributes2 in self.search(self.conn, base=memberdn, scope=ldap.SCOPE_BASE):
                self.get_members(attributes2, members, subgroups, seen)
        # actually return the results
        for name in names:
            if not common.is_valid_name(name):
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
        return dict(gidNumber=fp.read_int32())


class GroupByMemberRequest(GroupRequest):

    action = constants.NSLCD_ACTION_GROUP_BYMEMBER

    def read_parameters(self, fp):
        memberuid = fp.read_string()
        common.validate_name(memberuid)
        return dict(memberUid=memberuid)

    def get_results(self, parameters):
        seen = set()
        for dn, attributes in self.search(self.conn, parameters=parameters):
            seen.add(dn)
            for values in self.convert(dn, attributes, parameters):
                yield values
        if cfg.nss_nested_groups and attmap['member']:
            tocheck = list(seen)
            # find parent groups
            while tocheck:
                group = tocheck.pop(0)
                for dn, attributes in self.search(self.conn, parameters=dict(member=group)):
                    if dn not in seen:
                        seen.add(dn)
                        tocheck.append(dn)
                        for result in self.convert(dn, attributes, parameters):
                            yield result

    def handle_request(self, parameters):
        # check whether requested user is in nss_initgroups_ignoreusers
        if parameters['memberUid'] in cfg.nss_initgroups_ignoreusers:
            # write the final result code to signify empty results
            self.fp.write_int32(constants.NSLCD_RESULT_END)
            return
        return super(GroupByMemberRequest, self).handle_request(parameters)


class GroupAllRequest(GroupRequest):

    action = constants.NSLCD_ACTION_GROUP_ALL

    def handle_request(self, parameters):
        if not cfg.nss_disable_enumeration:
            return super(GroupAllRequest, self).handle_request(parameters)
