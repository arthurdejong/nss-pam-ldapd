
# group.py - group entry lookup routines
#
# Copyright (C) 2010 Arthur de Jong
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

import constants
import common
import cfg

import logging
import ldap
import ldap.filter


def clean(lst):
    for i in lst:
        yield i.replace('\0', '')

class GroupRequest(common.Request):

    filter = '(|(objectClass=posixGroup)(objectClass=groupOfUniqueNames))'

    attmap_group_cn           = 'cn'
    attmap_group_userPassword = 'userPassword'
    attmap_group_gidNumber    = 'gidNumber'
    attmap_group_memberUid    = 'memberUid'
    attmap_group_uniqueMember = 'uniqueMember'

    attributes = ( 'cn', 'userPassword', 'gidNumber', 'memberUid',
                   'uniqueMember' )

    wantmembers = True

    def write(self, entry):
        dn, attributes = entry
        # get uid attribute and check against requested user name
        names = attributes.get('uid', [])
        if self.name:
            if self.name not in names:
                return
            names = ( self.name, )
        # get user password entry
        passwd = '*'
        # get numeric user and group ids
        uids = ( self.uid, ) if self.uid else attributes.get(self.attmap_group_uidNumber, [])
        uids = [ int(x) for x in uids ]
        ( gid, ) = attributes[self.attmap_group_gidNumber]
        gid = int(gid)
        # FIXME: use expression here
        gecos = attributes.get(self.attmap_group_gecos, [None])[0] or attributes.get(self.attmap_group_cn, [''])[0]
        ( home, ) = attributes.get(self.attmap_group_homeDirectory, [''])
        ( shell, ) = attributes.get(self.attmap_group_loginShell, [''])
        for name in names:
            if not common.isvalidname(name):
                print 'Warning: group entry %s contains invalid user name: "%s"' % ( dn, name )
            else:
                for uid in uids:
                    self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
                    self.fp.write_string(name)
                    self.fp.write_string(passwd)
                    self.fp.write_uid_t(uid)
                    self.fp.write_gid_t(gid)
                    self.fp.write_string(gecos)
                    self.fp.write_string(home)
                    self.fp.write_string(shell)

    def write(self, entry):
        dn, attributes = entry
        # get group names and check against requested group name
        names = attributes.get(self.attmap_group_cn, [])
        if self.name:
            if self.name not in names:
                return
            names = ( self.name, )
        # get group group password
        ( passwd, ) = attributes.get(self.attmap_group_userPassword, ['*'])
        # get group id(s)
        gids = ( self.gid, ) if self.gid else attributes.get(self.attmap_group_gidNumber, [])
        gids = [ int(x) for x in gids ]
        # build member list
        members = set()
        if self.wantmembers:
            # add the memberUid values
            for member in clean(attributes.get(self.attmap_group_memberUid, [])):
                #print 'found member %r' % member
                if common.isvalidname(member):
                    members.add(member)
            # translate and add the uniqueMember values
            from passwd import dn2uid
            for memberdn in clean(attributes.get(self.attmap_group_uniqueMember, [])):
                member = dn2uid(self.conn, memberdn)
                #print 'found memberdn %r, member=%r' % ( memberdn, member)
                if member:
                    members.add(member)
        # actually return the results
        for name in names:
            if not common.isvalidname(name):
                print 'Warning: group entry %s contains invalid group name: "%s"' % ( dn, name )
            else:
                for gid in gids:
                    self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
                    self.fp.write_string(name)
                    self.fp.write_string(passwd)
                    self.fp.write_gid_t(gid)
                    self.fp.write_stringlist(members)


class GroupByNameRequest(GroupRequest):

    action = constants.NSLCD_ACTION_GROUP_BYNAME

    def read_parameters(self):
        self.name = self.fp.read_string()
        common.validate_name(self.name)

    def mk_filter(self):
        return '(&%s(%s=%s))' % ( self.filter,
                  self.attmap_group_cn, ldap.filter.escape_filter_chars(self.name) )


class GroupByGidRequest(GroupRequest):

    action = constants.NSLCD_ACTION_GROUP_BYGID

    def read_parameters(self):
        self.gid = self.fp.read_gid_t()

    def mk_filter(self):
        return '(&%s(%s=%d))' % ( self.filter,
                  self.attmap_group_gidNumber, self.gid )


class GroupByMemberRequest(GroupRequest):

    action = constants.NSLCD_ACTION_GROUP_BYMEMBER
    wantmembers = False
    attributes = ( 'cn', 'userPassword', 'gidNumber' )

    def read_parameters(self):
        self.memberuid = self.fp.read_string()
        common.validate_name(self.memberuid)

    def mk_filter(self):
        # try to translate uid to DN
        # TODO: only do this if memberuid attribute is mapped
        import passwd
        dn = passwd.uid2dn(self.conn, self.memberuid)
        if dn:
            return '(&%s(|(%s=%s)(%s=%s)))' % ( self.filter,
                      self.attmap_group_memberUid, ldap.filter.escape_filter_chars(self.memberuid),
                      self.attmap_group_uniqueMember, ldap.filter.escape_filter_chars(dn) )
        else:
            return '(&%s(%s=%s))' % ( self.filter,
                      self.attmap_group_memberUid, ldap.filter.escape_filter_chars(self.memberuid) )


class GroupAllRequest(GroupRequest):

    action = constants.NSLCD_ACTION_GROUP_ALL
