
# cfg.py - module for accessing configuration information
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

import ldap

# these values are defined here

# the name of the program
program_name = 'pynslcd'
# the debugging level
debug = 0
# whether the --check option was passed
check = False
# the number of threads to start
threads = 5

# the user id nslcd should be run as
uid = None
# the group id nslcd should be run as
gid = None

# the LDAP server to use
# FIXME: support multiple servers and have a fail-over mechanism
ldap_uri = 'ldapi:///'

# default search scope for searches
scope = ldap.SCOPE_SUBTREE

# LDAP search bases to search
bases = ( 'dc=test, dc=tld', )

# the users for which no initgroups() searches should be done
nss_initgroups_ignoreusers = []

# the DN to use to perform password modifications as root
rootpwmoddn = 'cn=admin, dc=test, dc=tld'
rootpwmodpw = 'test'

# FIXME: implement reading configuration from file
def read(cfgfile):
    pass
