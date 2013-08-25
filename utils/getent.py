#!/usr/bin/env python
# coding: utf-8

# getent.py - program for querying nslcd
#
# Copyright (C) 2013 Arthur de Jong
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

import argparse
import re
import socket
import struct
import sys

from cmdline import VersionAction
from nslcd import NslcdClient
import constants


epilog = '''
supported databases:
  aliases, ethers, group, group.bymember, hosts, hostsv4, hostsv6,
  netgroup, netgroup.norec, networks, networksv4, networksv6, passwd,
  protocols, rpc, services, shadow

Report bugs to <%s>.
'''.strip() % constants.PACKAGE_BUGREPORT

# set up command line parser
parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description='Query information in LDAP via nslcd.',
    epilog=epilog)
parser.add_argument('-V', '--version', action=VersionAction)
parser.add_argument('database', metavar='DATABASE',
                    help='any database supported by nslcd')
parser.add_argument('key', metavar='KEY', nargs='?',
                    help='filter returned database values by key')


def getent_aliases(database, key=None):
    if not key:
        con = NslcdClient(constants.NSLCD_ACTION_ALIAS_ALL)
    else:
        con = NslcdClient(constants.NSLCD_ACTION_ALIAS_BYNAME)
        con.write_string(key)
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        print '%-16s%s' % (
                con.read_string() + ': ',
                ', '.join(con.read_stringlist()),
            )


def getent_ethers(database, key=None):
    if not key:
        con = NslcdClient(constants.NSLCD_ACTION_ETHER_ALL)
    elif re.match('^[0-9a-fA-F]{1,2}(:[0-9a-fA-F]{1,2}){5}$', key):
        con = NslcdClient(constants.NSLCD_ACTION_ETHER_BYETHER)
        con.write_ether(key)
    else:
        con = NslcdClient(constants.NSLCD_ACTION_ETHER_BYNAME)
        con.write_string(key)
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        name = con.read_string()
        ether = con.read_ether()
        print '%s %s' % (ether, name)


def getent_group(database, key=None):
    if not key:
        con = NslcdClient(constants.NSLCD_ACTION_GROUP_ALL)
    elif database == 'group.bymember':
        con = NslcdClient(constants.NSLCD_ACTION_GROUP_BYMEMBER)
        con.write_string(key)
    elif re.match('^\d+$', key):
        con = NslcdClient(constants.NSLCD_ACTION_GROUP_BYGID)
        con.write_int32(int(key))
    else:
        con = NslcdClient(constants.NSLCD_ACTION_GROUP_BYNAME)
        con.write_string(key)
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        print '%s:%s:%d:%s' % (
                con.read_string(),
                con.read_string(),
                con.read_int32(),
                ','.join(con.read_stringlist()),
            )


def _get_ipv4(value):
    try:
        return socket.inet_pton(socket.AF_INET, value)
    except socket.error:
        return None


def _get_ipv6(value):
    try:
        return socket.inet_pton(socket.AF_INET6, value)
    except socket.error:
        return None


def _get_af(database):
    if database.endswith('v4'):
        return socket.AF_INET
    elif database.endswith('v6'):
        return socket.AF_INET6
    else:
        return None


def getent_hosts(database, key=None):
    db_af = _get_af(database)
    if not key:
        con = NslcdClient(constants.NSLCD_ACTION_HOST_ALL)
    else:
        ipv4_addr = _get_ipv4(key)
        ipv6_addr = _get_ipv6(key)
        if ipv4_addr and db_af in (socket.AF_INET, None):
            con = NslcdClient(constants.NSLCD_ACTION_HOST_BYADDR)
            con.write_address(socket.AF_INET, ipv4_addr)
        elif ipv6_addr and db_af in (socket.AF_INET, None):
            con = NslcdClient(constants.NSLCD_ACTION_HOST_BYADDR)
            con.write_address(socket.AF_INET6, ipv6_addr)
        else:
            con = NslcdClient(constants.NSLCD_ACTION_HOST_BYNAME)
            con.write_string(key)
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        names = ' '.join([con.read_string()] + con.read_stringlist())
        for af, address in con.read_addresslist():
            if db_af in (af, None):
                print '%-15s %s' % (address, names)


def _read_netgroup(con):
    """Read netgroup name, members and tripples from stream."""
    name = con.read_string()
    members = []
    tripples = []
    while True:
        member_type = con.read_int32()
        if member_type == constants.NSLCD_NETGROUP_TYPE_NETGROUP:
            members.append(con.read_string())
        elif member_type == constants.NSLCD_NETGROUP_TYPE_TRIPLE:
            tripples.append((
                    con.read_string(), con.read_string(),
                    con.read_string()
                ))
        else:
            break
    return name, members, tripples


def _get_getgroups(con, recurse, netgroups=None):
    if netgroups is None:
        netgroups = {}
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        name, members, tripples = _read_netgroup(con)
        if not recurse:
            yield (name, members, tripples)
        else:
            netgroups[name] = None
            for netgroup in members:
                if netgroup not in netgroups:
                    con2 = NslcdClient(constants.NSLCD_ACTION_NETGROUP_BYNAME)
                    con2.write_string(netgroup)
                    all(_get_getgroups(con2, recurse, netgroups))
                if netgroups.get(netgroup, None) is not None:
                    tripples += netgroups[netgroup][1]
            netgroups[name] = (members, tripples)
            yield (name, [], tripples)


def getent_netgroup(database, key=None):
    if not key:
        con = NslcdClient(constants.NSLCD_ACTION_NETGROUP_ALL)
    else:
        con = NslcdClient(constants.NSLCD_ACTION_NETGROUP_BYNAME)
        con.write_string(key)
    for name, members, tripples in _get_getgroups(con, database == 'netgroup'):
        print '%-15s %s' % (name, ' '.join(
                members +
                ['(%s, %s, %s)' % (host, user, domain)
                 for host, user, domain in tripples]
            ))


def getent_networks(database, key=None):
    db_af = _get_af(database)
    if not key:
        con = NslcdClient(constants.NSLCD_ACTION_NETWORK_ALL)
    else:
        ipv4_addr = _get_ipv4(key)
        ipv6_addr = _get_ipv6(key)
        if ipv4_addr and db_af in (socket.AF_INET, None):
            con = NslcdClient(constants.NSLCD_ACTION_NETWORK_BYADDR)
            con.write_address(socket.AF_INET, ipv4_addr)
        elif ipv6_addr and db_af in (socket.AF_INET, None):
            con = NslcdClient(constants.NSLCD_ACTION_NETWORK_BYADDR)
            con.write_address(socket.AF_INET6, ipv6_addr)
        else:
            con = NslcdClient(constants.NSLCD_ACTION_NETWORK_BYNAME)
            con.write_string(key)
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        names = ' '.join([con.read_string()] + con.read_stringlist())
        for af, address in con.read_addresslist():
            if db_af in (af, None):
                print '%-15s %s' % (address, names)


def getent_passwd(database, key=None):
    if not key:
        con = NslcdClient(constants.NSLCD_ACTION_PASSWD_ALL)
    elif re.match('^\d+$', key):
        con = NslcdClient(constants.NSLCD_ACTION_PASSWD_BYUID)
        con.write_int32(int(key))
    else:
        con = NslcdClient(constants.NSLCD_ACTION_PASSWD_BYNAME)
        con.write_string(key)
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        print '%s:%s:%d:%d:%s:%s:%s' % (
                con.read_string(),
                con.read_string(),
                con.read_int32(),
                con.read_int32(),
                con.read_string(),
                con.read_string(),
                con.read_string(),
            )


def getent_protocols(database, key=None):
    if not key:
        con = NslcdClient(constants.NSLCD_ACTION_PROTOCOL_ALL)
    elif re.match('^\d+$', key):
        con = NslcdClient(constants.NSLCD_ACTION_PROTOCOL_BYNUMBER)
        con.write_int32(int(key))
    else:
        con = NslcdClient(constants.NSLCD_ACTION_PROTOCOL_BYNAME)
        con.write_string(key)
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        name = con.read_string()
        aliases = con.read_stringlist()
        number = con.read_int32()
        print '%-21s %d %s' % (name, number, ' '.join(aliases))


def getent_rpc(database, key=None):
    if not key:
        con = NslcdClient(constants.NSLCD_ACTION_RPC_ALL)
    elif re.match('^\d+$', key):
        con = NslcdClient(constants.NSLCD_ACTION_RPC_BYNUMBER)
        con.write_int32(int(key))
    else:
        con = NslcdClient(constants.NSLCD_ACTION_RPC_BYNAME)
        con.write_string(key)
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        name = con.read_string()
        aliases = con.read_stringlist()
        number = con.read_int32()
        print '%-15s %d  %s' % (name, number, ' '.join(aliases))


def getent_services(database, key=None):
    if not key:
        con = NslcdClient(constants.NSLCD_ACTION_SERVICE_ALL)
    else:
        value = key
        protocol = ''
        if '/' in value:
            value, protocol = value.split('/', 1)
        if re.match('^\d+$', value):
            con = NslcdClient(constants.NSLCD_ACTION_SERVICE_BYNUMBER)
            con.write_int32(int(value))
            con.write_string(protocol)
        else:
            con = NslcdClient(constants.NSLCD_ACTION_SERVICE_BYNAME)
            con.write_string(value)
            con.write_string(protocol)
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        name = con.read_string()
        aliases = con.read_stringlist()
        number = con.read_int32()
        protocol = con.read_string()
        print '%-21s %d/%s %s' % (name, number, protocol, ' '.join(aliases))


def getent_shadow(database, key=None):
    if not key:
        con = NslcdClient(constants.NSLCD_ACTION_SHADOW_ALL)
    else:
        con = NslcdClient(constants.NSLCD_ACTION_SHADOW_BYNAME)
        con.write_string(key)
    value2str = lambda x: str(x) if x != -1 else ''
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        print '%s:%s:%s:%s:%s:%s:%s:%s:%s' % (
                con.read_string(),
                con.read_string(),
                value2str(con.read_int32()),
                value2str(con.read_int32()),
                value2str(con.read_int32()),
                value2str(con.read_int32()),
                value2str(con.read_int32()),
                value2str(con.read_int32()),
                value2str(con.read_int32()),
            )


if __name__ == '__main__':
    args = parser.parse_args()
    try:
        if args.database == 'aliases':
            getent_aliases(args.database, args.key)
        elif args.database == 'ethers':
            getent_ethers(args.database, args.key)
        elif args.database in ('group', 'group.bymember'):
            getent_group(args.database, args.key)
        elif args.database in ('hosts', 'hostsv4', 'hostsv6'):
            getent_hosts(args.database, args.key)
        elif args.database in ('netgroup', 'netgroup.norec'):
            getent_netgroup(args.database, args.key)
        elif args.database in ('networks', 'networksv4', 'networksv6'):
            getent_networks(args.database, args.key)
        elif args.database == 'passwd':
            getent_passwd(args.database, args.key)
        elif args.database == 'protocols':
            getent_protocols(args.database, args.key)
        elif args.database == 'rpc':
            getent_rpc(args.database, args.key)
        elif args.database == 'services':
            getent_services(args.database, args.key)
        elif args.database == 'shadow':
            getent_shadow(args.database, args.key)
        else:
            parser.error('Unknown database: %s' % args.database)
    except struct.error:
        print 'Problem communicating with nslcd'
        sys.exit(1)
