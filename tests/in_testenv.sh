#!/bin/sh

# in_testenv.sh - script to check whether we are running in test environment
#
# Copyright (C) 2011 Arthur de Jong
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

# This script expects to be run in an environment where nss-pam-ldapd
# is deployed with an LDAP server with the proper content (and nslcd running).
# It's probably best to run this in an environment without nscd (this breaks
# the services tests).

# check if LDAP is configured correctly
cfgfile="/etc/nslcd.conf"
if [ -r "$cfgfile" ]
then
  :
else
  echo "$0: $cfgfile: not found"
  exit 77
fi

uri=`sed -n 's/^uri *//p' "$cfgfile" | head -n 1`
base="dc=test,dc=tld"

# try to fetch the base DN (fail with exit 77 to indicate problem)
ldapsearch -b "$base" -s base -x -H "$uri" > /dev/null 2>&1 || {
  echo "$0: LDAP server $uri not available for $base"
  exit 77
}

# basic check to see if nslcd is running
if [ -S /var/run/nslcd/socket ] && \
   [ -f /var/run/nslcd/nslcd.pid ] && \
   kill -s 0 `cat /var/run/nslcd/nslcd.pid` > /dev/null 2>&1
then
  :
else
  echo "$0: nslcd not running"
  exit 77
fi

# TODO: check if nscd is running

# TODO: check if /etc/nsswitch.conf is correct

echo "$0: using LDAP server $uri"
