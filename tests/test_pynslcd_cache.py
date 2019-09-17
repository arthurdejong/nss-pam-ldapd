#!/usr/bin/env python

# test_pynslcd_cache.py - tests for the pynslcd caching functionality
#
# Copyright (C) 2013-2019 Arthur de Jong
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

import os
import os.path
import sys
import unittest

# fix the Python path
sys.path.insert(1, os.path.abspath(os.path.join(sys.path[0], '..', 'pynslcd')))
sys.path.insert(2, os.path.abspath(os.path.join('..', 'pynslcd')))


# TODO: think about case-sensitivity of cache searches (have tests for that)


class TestAlias(unittest.TestCase):

    def setUp(self):
        import alias
        cache = alias.Cache()
        cache.store('alias1', ['member1', 'member2'])
        cache.store('alias2', ['member1', 'member3'])
        cache.store('alias3', [])
        self.cache = cache
        if not hasattr(self, 'assertItemsEqual'):
            self.assertItemsEqual = self.assertCountEqual

    def test_by_name(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='alias1')),
            [
                ['alias1', ['member1', 'member2']],
            ])

    def test_by_member(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(rfc822MailMember='member1')),
            [
                ['alias1', ['member1', 'member2']],
                ['alias2', ['member1', 'member3']],
            ])

    def test_all(self):
        self.assertItemsEqual(
            self.cache.retrieve({}),
            [
                ['alias1', ['member1', 'member2']],
                ['alias2', ['member1', 'member3']],
                ['alias3', []],
            ])


class TestEther(unittest.TestCase):

    def setUp(self):
        import ether
        cache = ether.Cache()
        cache.store('name1', '0:18:8a:54:1a:11')
        cache.store('name2', '0:18:8a:54:1a:22')
        self.cache = cache
        if not hasattr(self, 'assertItemsEqual'):
            self.assertItemsEqual = self.assertCountEqual

    def test_by_name(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='name1')),
            [
                ['name1', '0:18:8a:54:1a:11'],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='name2')),
            [
                ['name2', '0:18:8a:54:1a:22'],
            ])

    def test_by_ether(self):
        # ideally we should also support alternate representations
        self.assertItemsEqual(
            self.cache.retrieve(dict(macAddress='0:18:8a:54:1a:22')),
            [
                ['name2', '0:18:8a:54:1a:22'],
            ])

    def test_all(self):
        self.assertItemsEqual(
            self.cache.retrieve({}),
            [
                ['name1', '0:18:8a:54:1a:11'],
                ['name2', '0:18:8a:54:1a:22'],
            ])


class TestGroup(unittest.TestCase):

    def setUp(self):
        import group
        cache = group.Cache()
        cache.store('group1', 'pass1', 10, ['user1', 'user2'])
        cache.store('group2', 'pass2', 20, ['user1', 'user2', 'user3'])
        cache.store('group3', 'pass3', 30, [])
        cache.store('group4', 'pass4', 40, ['user2'])
        self.cache = cache
        if not hasattr(self, 'assertItemsEqual'):
            self.assertItemsEqual = self.assertCountEqual

    def test_by_name(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='group1')),
            [
                ['group1', 'pass1', 10, ['user1', 'user2']],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='group3')),
            [
                ['group3', 'pass3', 30, []],
            ])

    def test_by_gid(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(gidNumber=10)),
            [
                ['group1', 'pass1', 10, ['user1', 'user2']],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(gidNumber=40)),
            [
                ['group4', 'pass4', 40, ['user2']],
            ])

    def test_all(self):
        self.assertItemsEqual(
            self.cache.retrieve({}),
            [
                ['group1', 'pass1', 10, ['user1', 'user2']],
                ['group2', 'pass2', 20, ['user1', 'user2', 'user3']],
                ['group3', 'pass3', 30, []],
                ['group4', 'pass4', 40, ['user2']],
            ])

    def test_bymember(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(memberUid='user1')),
            [
                ['group1', 'pass1', 10, ['user1', 'user2']],
                ['group2', 'pass2', 20, ['user1', 'user2', 'user3']],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(memberUid='user2')),
            [
                ['group1', 'pass1', 10, ['user1', 'user2']],
                ['group2', 'pass2', 20, ['user1', 'user2', 'user3']],
                ['group4', 'pass4', 40, ['user2']],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(memberUid='user3')),
            [
                ['group2', 'pass2', 20, ['user1', 'user2', 'user3']],
            ])


class TestHost(unittest.TestCase):

    def setUp(self):
        import host
        cache = host.Cache()
        cache.store('hostname1', [], ['127.0.0.1'])
        cache.store('hostname2', ['alias1', 'alias2'], ['127.0.0.2', '127.0.0.3'])
        self.cache = cache
        if not hasattr(self, 'assertItemsEqual'):
            self.assertItemsEqual = self.assertCountEqual

    def test_by_name(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='hostname1')),
            [
                ['hostname1', [], ['127.0.0.1']],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='hostname2')),
            [
                ['hostname2', ['alias1', 'alias2'], ['127.0.0.2', '127.0.0.3']],
            ])

    def test_by_alias(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='alias1')),
            [
                ['hostname2', ['alias1', 'alias2'], ['127.0.0.2', '127.0.0.3']],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='alias2')),
            [
                ['hostname2', ['alias1', 'alias2'], ['127.0.0.2', '127.0.0.3']],
            ])

    def test_by_address(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(ipHostNumber='127.0.0.3')),
            [
                ['hostname2', ['alias1', 'alias2'], ['127.0.0.2', '127.0.0.3']],
            ])


class TestNetgroup(unittest.TestCase):

    def setUp(self):
        import netgroup
        cache = netgroup.Cache()
        cache.store(
            'netgroup1',
            ['(host1, user1,)', '(host1, user2,)', '(host2, user1,)'],
            ['netgroup2'])
        cache.store(
            'netgroup2', ['(host3, user1,)', '(host3, user3,)'], [])
        self.cache = cache
        if not hasattr(self, 'assertItemsEqual'):
            self.assertItemsEqual = self.assertCountEqual

    def test_by_name(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='netgroup1')),
            [
                [
                    'netgroup1',
                    ['(host1, user1,)', '(host1, user2,)', '(host2, user1,)'],
                    ['netgroup2'],
                ],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='netgroup2')),
            [
                ['netgroup2', ['(host3, user1,)', '(host3, user3,)'], []],
            ])


class TestNetwork(unittest.TestCase):

    def setUp(self):
        import network
        cache = network.Cache()
        cache.store('networkname1', [], ['127.0.0.1'])
        cache.store('networkname2', ['alias1', 'alias2'], ['127.0.0.2', '127.0.0.3'])
        self.cache = cache
        if not hasattr(self, 'assertItemsEqual'):
            self.assertItemsEqual = self.assertCountEqual

    def test_by_name(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='networkname1')),
            [
                ['networkname1', [], ['127.0.0.1']],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='networkname2')),
            [
                ['networkname2', ['alias1', 'alias2'], ['127.0.0.2', '127.0.0.3']],
            ])

    def test_by_alias(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='alias1')),
            [
                ['networkname2', ['alias1', 'alias2'], ['127.0.0.2', '127.0.0.3']],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='alias2')),
            [
                ['networkname2', ['alias1', 'alias2'], ['127.0.0.2', '127.0.0.3']],
            ])

    def test_by_address(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(ipNetworkNumber='127.0.0.3')),
            [
                ['networkname2', ['alias1', 'alias2'], ['127.0.0.2', '127.0.0.3']],
            ])


class TestPasswd(unittest.TestCase):

    def setUp(self):
        import passwd
        cache = passwd.Cache()
        cache.store('name', 'passwd', 100, 200, 'gecos', '/home/user', '/bin/bash')
        cache.store('name2', 'passwd2', 101, 202, 'gecos2', '/home/user2', '/bin/bash')
        self.cache = cache
        if not hasattr(self, 'assertItemsEqual'):
            self.assertItemsEqual = self.assertCountEqual

    def test_by_name(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(uid='name')),
            [
                [u'name', u'passwd', 100, 200, u'gecos', u'/home/user', u'/bin/bash'],
            ])

    def test_by_unknown_name(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(uid='notfound')),
            [])

    def test_by_number(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(uidNumber=100)),
            [
                [u'name', u'passwd', 100, 200, u'gecos', u'/home/user', u'/bin/bash'],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(uidNumber=101)),
            [
                ['name2', 'passwd2', 101, 202, 'gecos2', '/home/user2', '/bin/bash'],
            ])

    def test_all(self):
        self.assertItemsEqual(
            self.cache.retrieve({}),
            [
                [u'name', u'passwd', 100, 200, u'gecos', u'/home/user', u'/bin/bash'],
                [u'name2', u'passwd2', 101, 202, u'gecos2', u'/home/user2', u'/bin/bash'],
            ])


class TestProtocol(unittest.TestCase):

    def setUp(self):
        import protocol
        cache = protocol.Cache()
        cache.store('protocol1', ['alias1', 'alias2'], 100)
        cache.store('protocol2', ['alias3'], 200)
        cache.store('protocol3', [], 300)
        self.cache = cache
        if not hasattr(self, 'assertItemsEqual'):
            self.assertItemsEqual = self.assertCountEqual

    def test_by_name(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='protocol1')),
            [
                ['protocol1', ['alias1', 'alias2'], 100],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='protocol2')),
            [
                ['protocol2', ['alias3'], 200],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='protocol3')),
            [
                ['protocol3', [], 300],
            ])

    def test_by_unknown_name(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='notfound')),
            [])

    def test_by_number(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(ipProtocolNumber=100)),
            [
                ['protocol1', ['alias1', 'alias2'], 100],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(ipProtocolNumber=200)),
            [
                ['protocol2', ['alias3'], 200],
            ])

    def test_by_alias(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='alias1')),
            [
                ['protocol1', ['alias1', 'alias2'], 100],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='alias3')),
            [
                ['protocol2', ['alias3'], 200],
            ])

    def test_all(self):
        self.assertItemsEqual(
            self.cache.retrieve({}),
            [
                ['protocol1', ['alias1', 'alias2'], 100],
                ['protocol2', ['alias3'], 200],
                ['protocol3', [], 300],
            ])


class TestRpc(unittest.TestCase):

    def setUp(self):
        import rpc
        cache = rpc.Cache()
        cache.store('rpc1', ['alias1', 'alias2'], 100)
        cache.store('rpc2', ['alias3'], 200)
        cache.store('rpc3', [], 300)
        self.cache = cache
        if not hasattr(self, 'assertItemsEqual'):
            self.assertItemsEqual = self.assertCountEqual

    def test_by_name(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='rpc1')),
            [
                ['rpc1', ['alias1', 'alias2'], 100],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='rpc2')),
            [
                ['rpc2', ['alias3'], 200],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='rpc3')),
            [
                ['rpc3', [], 300],
            ])

    def test_by_unknown_name(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='notfound')),
            [])

    def test_by_number(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(oncRpcNumber=100)),
            [
                ['rpc1', ['alias1', 'alias2'], 100],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(oncRpcNumber=200)),
            [
                ['rpc2', ['alias3'], 200],
            ])

    def test_by_alias(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='alias1')),
            [
                ['rpc1', ['alias1', 'alias2'], 100],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='alias3')),
            [
                ['rpc2', ['alias3'], 200],
            ])

    def test_all(self):
        self.assertItemsEqual(
            self.cache.retrieve({}),
            [
                ['rpc1', ['alias1', 'alias2'], 100],
                ['rpc2', ['alias3'], 200],
                ['rpc3', [], 300],
            ])


class TestService(unittest.TestCase):

    def setUp(self):
        import service
        cache = service.Cache()
        cache.store('service1', ['alias1', 'alias2'], 100, 'tcp')
        cache.store('service1', ['alias1', 'alias2'], 100, 'udp')
        cache.store('service2', ['alias3'], 200, 'udp')
        cache.store('service3', [], 300, 'udp')
        self.cache = cache
        if not hasattr(self, 'assertItemsEqual'):
            self.assertItemsEqual = self.assertCountEqual

    def test_by_name(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='service1')),
            [
                ['service1', ['alias1', 'alias2'], 100, 'tcp'],
                ['service1', ['alias1', 'alias2'], 100, 'udp'],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='service2')),
            [
                ['service2', ['alias3'], 200, 'udp'],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='service3')),
            [
                ['service3', [], 300, 'udp'],
            ])

    def test_by_name_and_protocol(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='service1', ipServiceProtocol='udp')),
            [
                ['service1', ['alias1', 'alias2'], 100, 'udp'],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='service1', ipServiceProtocol='tcp')),
            [
                ['service1', ['alias1', 'alias2'], 100, 'tcp'],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='service2', ipServiceProtocol='udp')),
            [
                ['service2', ['alias3'], 200, 'udp'],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(cn='service2', ipServiceProtocol='tcp')),
            [])

    def test_by_unknown_name(self):
        self.assertItemsEqual(self.cache.retrieve(dict(cn='notfound')), [])

    def test_by_number(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(ipServicePort=100)),
            [
                ['service1', ['alias1', 'alias2'], 100, 'tcp'],
                ['service1', ['alias1', 'alias2'], 100, 'udp'],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(ipServicePort=200)),
            [
                ['service2', ['alias3'], 200, 'udp'],
            ])

    def test_by_number_and_protocol(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(ipServicePort=100, ipServiceProtocol='udp')),
            [
                ['service1', ['alias1', 'alias2'], 100, 'udp'],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(ipServicePort=100, ipServiceProtocol='tcp')),
            [
                ['service1', ['alias1', 'alias2'], 100, 'tcp'],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(ipServicePort=200, ipServiceProtocol='udp')),
            [
                ['service2', ['alias3'], 200, 'udp'],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(ipServicePort=200, ipServiceProtocol='tcp')),
            [])

    def test_by_alias(self):
        self.assertItemsEqual(self.cache.retrieve(dict(cn='alias1')), [
            ['service1', ['alias1', 'alias2'], 100, 'udp'],
            ['service1', ['alias1', 'alias2'], 100, 'tcp'],
        ])
        self.assertItemsEqual(self.cache.retrieve(dict(cn='alias3')), [
            ['service2', ['alias3'], 200, 'udp'],
        ])

    def test_all(self):
        self.assertItemsEqual(self.cache.retrieve({}), [
            ['service1', ['alias1', 'alias2'], 100, 'tcp'],
            ['service1', ['alias1', 'alias2'], 100, 'udp'],
            ['service2', ['alias3'], 200, 'udp'],
            ['service3', [], 300, 'udp'],
        ])


class Testshadow(unittest.TestCase):

    def setUp(self):
        import shadow
        cache = shadow.Cache()
        cache.store('name', 'passwd', 15639, 0, 7, -1, -1, -1, 0)
        cache.store('name2', 'passwd2', 15639, 0, 7, -1, -1, -1, 0)
        self.cache = cache
        if not hasattr(self, 'assertItemsEqual'):
            self.assertItemsEqual = self.assertCountEqual

    def test_by_name(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(uid='name')),
            [
                [u'name', u'passwd', 15639, 0, 7, -1, -1, -1, 0],
            ])
        self.assertItemsEqual(
            self.cache.retrieve(dict(uid='name2')),
            [
                [u'name2', u'passwd2', 15639, 0, 7, -1, -1, -1, 0],
            ])

    def test_by_unknown_name(self):
        self.assertItemsEqual(
            self.cache.retrieve(dict(uid='notfound')),
            [])

    def test_all(self):
        self.assertItemsEqual(
            self.cache.retrieve({}), [
                [u'name', u'passwd', 15639, 0, 7, -1, -1, -1, 0],
                [u'name2', u'passwd2', 15639, 0, 7, -1, -1, -1, 0],
            ])


if __name__ == '__main__':
    unittest.main()
