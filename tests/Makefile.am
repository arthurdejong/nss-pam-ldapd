# Makefile.am - use automake to generate Makefile.in
#
# Copyright (C) 2006 West consulting
# Copyright (C) 2006 Arthur de Jong
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU Library General Public
# License along with this library; if not, write to the Free
# Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
# MA 02110-1301 USA

noinst_PROGRAMS = test_aliases test_ethers test_group test_hosts \
                  test_netgroup test_networks test_passwd test_protocols \
                  test_rpc test_services test_shadow

AM_CFLAGS=-DDEBUG_PROT -DDEBUG_PROT_DUMP

test_aliases_SOURCES = test_aliases.c ../nss/aliases.c ../nss/common.c ../nslcd.h ../nss/prototypes.h
test_ethers_SOURCES = test_ethers.c ../nss/ethers.c ../nss/common.c ../nslcd.h ../nss/prototypes.h
test_group_SOURCES = test_group.c ../nss/group.c ../nss/common.c ../nslcd.h ../nss/prototypes.h
test_hosts_SOURCES = test_hosts.c ../nss/hosts.c ../nss/common.c ../nslcd.h ../nss/prototypes.h
test_netgroup_SOURCES = test_netgroup.c ../nss/netgroup.c ../nss/common.c ../nslcd.h ../nss/prototypes.h
test_networks_SOURCES = test_networks.c ../nss/networks.c ../nss/common.c ../nslcd.h ../nss/prototypes.h
test_passwd_SOURCES = test_passwd.c ../nss/passwd.c ../nss/common.c ../nslcd.h ../nss/prototypes.h
test_protocols_SOURCES = test_protocols.c ../nss/protocols.c ../nss/common.c ../nslcd.h ../nss/prototypes.h
test_rpc_SOURCES = test_rpc.c ../nss/rpc.c ../nss/common.c ../nslcd.h ../nss/prototypes.h
test_services_SOURCES = test_services.c ../nss/services.c ../nss/common.c ../nslcd.h ../nss/prototypes.h
test_shadow_SOURCES = test_shadow.c ../nss/shadow.c ../nss/common.c ../nslcd.h ../nss/prototypes.h
