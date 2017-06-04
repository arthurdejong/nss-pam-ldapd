#!/usr/bin/env python
# coding: utf-8

# getent.py - program for querying nslcd
#
# Copyright (C) 2013-2017 Arthur de Jong
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
    description='Query information in %s via nslcd.' %
    constants.MODULE_NAME.upper(),
    epilog=epilog)
parser.add_argument('-V', '--version', action=VersionAction)
parser.add_argument('database', metavar='DATABASE',
                    help='any database supported by nslcd')
parser.add_argument('keys', metavar='KEY', nargs='*',
                    help='filter returned database values by key')


def write_aliases(con):
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        print('%-16s%s' % (
                con.read_string() + ': ',
                ', '.join(con.read_stringlist()),
            ))


def getent_aliases(database, keys=None):
    if not keys:
        write_aliases(NslcdClient(constants.NSLCD_ACTION_ALIAS_ALL))
        return
    for key in keys:
        con = NslcdClient(constants.NSLCD_ACTION_ALIAS_BYNAME)
        con.write_string(key)
        write_aliases(con)


def write_ethers(con):
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        name = con.read_string()
        ether = con.read_ether()
        print('%s %s' % (ether, name))


def getent_ethers(database, keys=None):
    if not keys:
        write_ethers(NslcdClient(constants.NSLCD_ACTION_ETHER_ALL))
        return
    for key in keys:
        if re.match('^[0-9a-fA-F]{1,2}(:[0-9a-fA-F]{1,2}){5}$', key):
            con = NslcdClient(constants.NSLCD_ACTION_ETHER_BYETHER)
            con.write_ether(key)
        else:
            con = NslcdClient(constants.NSLCD_ACTION_ETHER_BYNAME)
            con.write_string(key)
        write_ethers(con)


def write_group(con):
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        print('%s:%s:%d:%s' % (
                con.read_string(),
                con.read_string(),
                con.read_int32(),
                ','.join(con.read_stringlist()),
            ))


def getent_group(database, keys=None):
    if not keys:
        write_group(NslcdClient(constants.NSLCD_ACTION_GROUP_ALL))
        return
    for key in keys:
        if database == 'group.bymember':
            con = NslcdClient(constants.NSLCD_ACTION_GROUP_BYMEMBER)
            con.write_string(key)
        elif re.match('^\d+$', key):
            con = NslcdClient(constants.NSLCD_ACTION_GROUP_BYGID)
            con.write_int32(int(key))
        else:
            con = NslcdClient(constants.NSLCD_ACTION_GROUP_BYNAME)
            con.write_string(key)
        write_group(con)


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


def write_hosts(con, db_af):
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        names = ' '.join([con.read_string()] + con.read_stringlist())
        for af, address in con.read_addresslist():
            if db_af in (af, None):
                print('%-15s %s' % (address, names))


def getent_hosts(database, keys=None):
    db_af = _get_af(database)
    if not keys:
        write_hosts(NslcdClient(constants.NSLCD_ACTION_HOST_ALL), db_af)
        return
    for key in keys:
        ipv4_addr = _get_ipv4(key)
        ipv6_addr = _get_ipv6(key)
        if ipv4_addr and db_af in (socket.AF_INET, None):
            con = NslcdClient(constants.NSLCD_ACTION_HOST_BYADDR)
            con.write_address(socket.AF_INET, ipv4_addr)
        elif ipv6_addr and db_af in (socket.AF_INET6, None):
            con = NslcdClient(constants.NSLCD_ACTION_HOST_BYADDR)
            con.write_address(socket.AF_INET6, ipv6_addr)
        else:
            con = NslcdClient(constants.NSLCD_ACTION_HOST_BYNAME)
            con.write_string(key)
        write_hosts(con, db_af)


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


def write_netgroup(con, recurse):
    for name, members, tripples in _get_getgroups(con, recurse):
        print('%-15s %s' % (name, ' '.join(
                members +
                ['(%s, %s, %s)' % (host, user, domain)
                 for host, user, domain in tripples]
            )))


def getent_netgroup(database, keys=None):
    recurse = database == 'netgroup'
    if not keys:
        write_netgroup(
            NslcdClient(constants.NSLCD_ACTION_NETGROUP_ALL), recurse)
        return
    for key in keys:
        con = NslcdClient(constants.NSLCD_ACTION_NETGROUP_BYNAME)
        con.write_string(key)
        write_netgroup(con, recurse)


def write_networks(con, db_af):
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        names = ' '.join([con.read_string()] + con.read_stringlist())
        for af, address in con.read_addresslist():
            if db_af in (af, None):
                print('%-22s %s' % (names, address))


def getent_networks(database, keys=None):
    db_af = _get_af(database)
    if not keys:
        write_networks(NslcdClient(constants.NSLCD_ACTION_NETWORK_ALL), db_af)
        return
    for key in keys:
        ipv4_addr = _get_ipv4(key)
        ipv6_addr = _get_ipv6(key)
        if ipv4_addr and db_af in (socket.AF_INET, None):
            con = NslcdClient(constants.NSLCD_ACTION_NETWORK_BYADDR)
            con.write_address(socket.AF_INET, ipv4_addr)
        elif ipv6_addr and db_af in (socket.AF_INET6, None):
            con = NslcdClient(constants.NSLCD_ACTION_NETWORK_BYADDR)
            con.write_address(socket.AF_INET6, ipv6_addr)
        else:
            con = NslcdClient(constants.NSLCD_ACTION_NETWORK_BYNAME)
            con.write_string(key)
        write_networks(con, db_af)


def write_passwd(con):
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        print('%s:%s:%d:%d:%s:%s:%s' % (
                con.read_string(),
                con.read_string(),
                con.read_int32(),
                con.read_int32(),
                con.read_string(),
                con.read_string(),
                con.read_string(),
            ))


def getent_passwd(database, keys=None):
    if not keys:
        write_passwd(NslcdClient(constants.NSLCD_ACTION_PASSWD_ALL))
        return
    for key in keys:
        if re.match('^\d+$', key):
            con = NslcdClient(constants.NSLCD_ACTION_PASSWD_BYUID)
            con.write_int32(int(key))
        else:
            con = NslcdClient(constants.NSLCD_ACTION_PASSWD_BYNAME)
            con.write_string(key)
        write_passwd(con)


def write_protocols(con):
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        name = con.read_string()
        aliases = con.read_stringlist()
        number = con.read_int32()
        print('%-21s %d %s' % (name, number, ' '.join(aliases)))


def getent_protocols(database, keys=None):
    if not keys:
        write_protocols(NslcdClient(constants.NSLCD_ACTION_PROTOCOL_ALL))
        return
    for key in keys:
        if re.match('^\d+$', key):
            con = NslcdClient(constants.NSLCD_ACTION_PROTOCOL_BYNUMBER)
            con.write_int32(int(key))
        else:
            con = NslcdClient(constants.NSLCD_ACTION_PROTOCOL_BYNAME)
            con.write_string(key)
        write_protocols(con)


def write_rpc(con):
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        name = con.read_string()
        aliases = con.read_stringlist()
        number = con.read_int32()
        print('%-15s %d  %s' % (name, number, ' '.join(aliases)))


def getent_rpc(database, keys=None):
    if not keys:
        write_rpc(NslcdClient(constants.NSLCD_ACTION_RPC_ALL))
        return
    for key in keys:
        if re.match('^\d+$', key):
            con = NslcdClient(constants.NSLCD_ACTION_RPC_BYNUMBER)
            con.write_int32(int(key))
        else:
            con = NslcdClient(constants.NSLCD_ACTION_RPC_BYNAME)
            con.write_string(key)
        write_rpc(con)


def write_services(con):
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        name = con.read_string()
        aliases = con.read_stringlist()
        number = con.read_int32()
        protocol = con.read_string()
        print('%-21s %d/%s %s' % (name, number, protocol, ' '.join(aliases)))


def getent_services(database, keys=None):
    if not keys:
        write_services(NslcdClient(constants.NSLCD_ACTION_SERVICE_ALL))
        return
    for key in keys:
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
        write_services(con)


def _shadow_value2str(number):
    return str(number) if number != -1 else ''


def write_shadow(con):
    while con.get_response() == constants.NSLCD_RESULT_BEGIN:
        print('%s:%s:%s:%s:%s:%s:%s:%s:%s' % (
                con.read_string(),
                con.read_string(),
                _shadow_value2str(con.read_int32()),
                _shadow_value2str(con.read_int32()),
                _shadow_value2str(con.read_int32()),
                _shadow_value2str(con.read_int32()),
                _shadow_value2str(con.read_int32()),
                _shadow_value2str(con.read_int32()),
                _shadow_value2str(con.read_int32()),
            ))


def getent_shadow(database, keys=None):
    if not keys:
        write_shadow(NslcdClient(constants.NSLCD_ACTION_SHADOW_ALL))
        return
    for key in keys:
        con = NslcdClient(constants.NSLCD_ACTION_SHADOW_BYNAME)
        con.write_string(key)
        write_shadow(con)


if __name__ == '__main__':
    args = parser.parse_args()
    try:
        if args.database == 'aliases':
            getent_aliases(args.database, args.keys)
        elif args.database == 'ethers':
            getent_ethers(args.database, args.keys)
        elif args.database in ('group', 'group.bymember'):
            getent_group(args.database, args.keys)
        elif args.database in ('hosts', 'hostsv4', 'hostsv6'):
            getent_hosts(args.database, args.keys)
        elif args.database in ('netgroup', 'netgroup.norec'):
            getent_netgroup(args.database, args.keys)
        elif args.database in ('networks', 'networksv4', 'networksv6'):
            getent_networks(args.database, args.keys)
        elif args.database == 'passwd':
            getent_passwd(args.database, args.keys)
        elif args.database == 'protocols':
            getent_protocols(args.database, args.keys)
        elif args.database == 'rpc':
            getent_rpc(args.database, args.keys)
        elif args.database == 'services':
            getent_services(args.database, args.keys)
        elif args.database == 'shadow':
            getent_shadow(args.database, args.keys)
        else:
            parser.error('Unknown database: %s' % args.database)
    except struct.error:
        print('Problem communicating with nslcd')
        sys.exit(1)
