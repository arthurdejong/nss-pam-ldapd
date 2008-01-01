#!/bin/sh

# test.sh - simple test script to check output of name lookup commands
#
# Copyright (C) 2007, 2008 Arthur de Jong
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

# This script expects to be run in an environment where nss-ldapd
# is deployed with an LDAP server with the proper contents (nslcd running).
# FIXME: update the above description and provide actual LDIF file
# It's probably best to run this in an environment without nscd.

# note that nscd should not be running (breaks services test)

set -e

# check if LDAP is configured correctly
cfgfile="/etc/nss-ldapd.conf"
uri=`sed -n 's/^uri *//p' "$cfgfile" | head -n 1`
base="dc=test,dc=tld"

# try to fetch the base DN (fail with exit 77 to indicate problem)
ldapsearch -b "$base" -s base -x -H "$uri" > /dev/null 2>&1 || {
  echo "LDAP server $uri not available for $base"
  exit 77
}

# basic check to see if nslcd is running
if ! [ -S /var/run/nslcd/socket ] || \
   ! [ -f /var/run/nslcd/nslcd.pid ] || \
   ! kill -s 0 `cat /var/run/nslcd/nslcd.pid` > /dev/null 2>&1
then
  echo "nslcd not running"
  exit 77
fi

# TODO: check if nscd is running

# TODO: check if /etc/nsswitch.conf is correct

echo "using LDAP server $uri"

# the total number of errors
FAIL=0

check() {
  # the command to execute
  cmd="$1"
  # save the expected output
  expectfile=`mktemp -t expected.XXXXXX 2> /dev/null || tempfile -s .expected 2> /dev/null`
  cat > "$expectfile"
  # run the command
  echo 'checking "'"$cmd"'"'
  actualfile=`mktemp -t actual.XXXXXX 2> /dev/null || tempfile -s .actual 2> /dev/null`
  eval "$cmd" > "$actualfile" 2>&1 || true
  # check for differences
  if ! diff -Nauwi "$expectfile" "$actualfile"
  then
    FAIL=`expr $FAIL + 1`
  fi
  # remove temporary files
  rm "$expectfile" "$actualfile"
}

###########################################################################

echo "testing aliases..."

# check all aliases
check "getent aliases|sort" << EOM
bar2:           foobar@example.com
bar:            foobar@example.com
foo:            bar@example.com
EOM

# get alias by name
check "getent aliases foo" << EOM
foo:            bar@example.com
EOM

# get alias by second name
check "getent aliases bar2" << EOM
bar2:           foobar@example.com
EOM

###########################################################################

echo "testing ether..."

# get an entry by hostname
check "getent ethers testhost" << EOM
0:18:8a:54:1a:8e testhost
EOM

# get an entry by alias name
check "getent ethers testhostalias" << EOM
0:18:8a:54:1a:8e testhostalias
EOM

# get an entry by ethernet address
check "getent ethers 0:18:8a:54:1a:8b" << EOM
0:18:8a:54:1a:8b testhost2
EOM

# get entry by ip address
# this does not currently work, but maybe it should
#check "getent ethers 10.0.0.1" << EOM
#0:18:8a:54:1a:8e testhost
#EOM

# get all ethers (unsupported)
check "getent ethers" << EOM
Enumeration not supported on ethers
EOM

###########################################################################

echo "testing group..."

check "getent group testgroup" << EOM
testgroup:*:6100:arthur,test
EOM

# this does not work because users is in /etc/group but it would
# be nice if libc supported this
#check "getent group users" << EOM
#users:*:100:arthur,test
#EOM

check "getent group 6100" << EOM
testgroup:*:6100:arthur,test
EOM

check "groups arthur" << EOM
arthur : users testgroup
EOM

check "getent group | egrep '^(testgroup|users):'" << EOM
users:x:100:
testgroup:*:6100:arthur,test
users:*:100:arthur,test
EOM

check "getent group | wc -l" << EOM
44
EOM

check "getent group | grep ^largegroup" << EOM
largegroup:*:1005:akraskouskas,alat,ameisinger,bdevera,behrke,bmoldan,btempel,cjody,clouder,cmanno,dbye,dciviello,dfirpo,dgivliani,dgosser,emcquiddy,enastasi,fcunard,gcubbison,gdaub,gdreitzler,ghanauer,gpomerance,gsusoev,gtinnel,gvollrath,gzuhlke,hgalavis,hhaffey,hhydrick,hmachesky,hpaek,hpolk,hsweezer,htomlinson,hzagami,igurwell,ihashbarger,jyeater,kbradbury,khathway,kklavetter,lbuchtel,lgandee,lkhubba,lmauracher,lseehafer,lvittum,mblanchet,mbodley,mciaccia,mjuris,ndipanfilo,nfilipek,nfunchess,ngata,ngullett,nkraker,nriofrio,nroepke,nrybij,oclunes,oebrani,okveton,osaines,otrevor,pdossous,phaye,psowa,purquilla,rkoonz,rlatessa,rworkowski,sdebry,sgurski,showe,slaforge,tabdelal,testusr2,testusr3,tfalconeri,tpaa,uschweyen,utrezize,vchevalier,vdelnegro,vleyton,vmedici,vmigliori,vpender,vwaltmann,wbrettschneide,wselim,wvalcin,wworf,yautin,ykisak,zgingrich,znightingale,zwinterbottom
EOM

check "getent group largegroup" << EOM
largegroup:*:1005:akraskouskas,alat,ameisinger,bdevera,behrke,bmoldan,btempel,cjody,clouder,cmanno,dbye,dciviello,dfirpo,dgivliani,dgosser,emcquiddy,enastasi,fcunard,gcubbison,gdaub,gdreitzler,ghanauer,gpomerance,gsusoev,gtinnel,gvollrath,gzuhlke,hgalavis,hhaffey,hhydrick,hmachesky,hpaek,hpolk,hsweezer,htomlinson,hzagami,igurwell,ihashbarger,jyeater,kbradbury,khathway,kklavetter,lbuchtel,lgandee,lkhubba,lmauracher,lseehafer,lvittum,mblanchet,mbodley,mciaccia,mjuris,ndipanfilo,nfilipek,nfunchess,ngata,ngullett,nkraker,nriofrio,nroepke,nrybij,oclunes,oebrani,okveton,osaines,otrevor,pdossous,phaye,psowa,purquilla,rkoonz,rlatessa,rworkowski,sdebry,sgurski,showe,slaforge,tabdelal,testusr2,testusr3,tfalconeri,tpaa,uschweyen,utrezize,vchevalier,vdelnegro,vleyton,vmedici,vmigliori,vpender,vwaltmann,wbrettschneide,wselim,wvalcin,wworf,yautin,ykisak,zgingrich,znightingale,zwinterbottom
EOM

###########################################################################

echo "testing hosts..."

check "getent hosts testhost" << EOM
10.0.0.1        testhost testhostalias
EOM

check "getent hosts testhostalias" << EOM
10.0.0.1        testhost testhostalias
EOM

check "getent hosts 10.0.0.1" << EOM
10.0.0.1        testhost testhostalias
EOM

check "getent hosts | grep testhost" << EOM
10.0.0.1        testhost testhostalias
EOM

# dummy test for IPv6 envoronment
check "getent hosts ::1" << EOM
::1             ip6-localhost ip6-loopback
EOM

# TODO: add more tests for IPv6 support

###########################################################################

echo "testing netgroup..."

# check netgroup lookup of test netgroup
check "getent netgroup tstnetgroup" << EOM
tstnetgroup          (aap, , ) (noot, , )
EOM

###########################################################################

echo "testing networks..."

check "getent networks testnet" << EOM
testnet               10.0.0.0
EOM

check "getent networks 10.0.0.0" << EOM
testnet               10.0.0.0
EOM

check "getent networks | grep testnet" << EOM
testnet               10.0.0.0
EOM

###########################################################################

echo "testing passwd..."

check "getent passwd ecolden" << EOM
ecolden:x:5972:1000:Estelle Colden:/home/ecolden:/bin/bash
EOM

check "getent passwd arthur" << EOM
arthur:x:1000:100:Arthur de Jong:/home/arthur:/bin/bash
EOM

check "getent passwd 4089" << EOM
jguzzetta:x:4089:1000:Josephine Guzzetta:/home/jguzzetta:/bin/bash
EOM

# count the number of passwd entries in the 4000-5999 range
check "getent passwd | grep -c ':x:[45][0-9][0-9][0-9]:'" << EOM
2000
EOM

###########################################################################

echo "testing protocols..."

check "getent protocols protfoo" << EOM
protfoo               140 protfooalias
EOM

check "getent protocols protfooalias" << EOM
protfoo               140 protfooalias
EOM

check "getent protocols 140" << EOM
protfoo               140 protfooalias
EOM

check "getent protocols icmp" << EOM
icmp                  1 ICMP
EOM

check "getent protocols | grep protfoo" << EOM
protfoo               140 protfooalias
EOM

###########################################################################

echo "testing rpc..."

check "getent rpc rpcfoo" << EOM
rpcfoo          160002  rpcfooalias
EOM

check "getent rpc rpcfooalias" << EOM
rpcfoo          160002  rpcfooalias
EOM

check "getent rpc 160002" << EOM
rpcfoo          160002  rpcfooalias
EOM

check "getent rpc | grep rpcfoo" << EOM
rpcfoo          160002  rpcfooalias
EOM

###########################################################################

echo "testing services..."

check "getent services foosrv" << EOM
foosrv                15349/tcp
EOM

check "getent services foosrv/tcp" << EOM
foosrv                15349/tcp
EOM

check "getent services foosrv/udp" << EOM
EOM

check "getent services 15349/tcp" << EOM
foosrv                15349/tcp
EOM

check "getent services 15349/udp" << EOM
EOM

check "getent services barsrv" << EOM
barsrv                15350/tcp
EOM

check "getent services barsrv/tcp" << EOM
barsrv                15350/tcp
EOM

check "getent services barsrv/udp" << EOM
barsrv                15350/udp
EOM

check "getent services | egrep '(foo|bar)srv' | sort" << EOM
barsrv                15350/tcp
barsrv                15350/udp
foosrv                15349/tcp
EOM

check "getent services | wc -l" << EOM
505
EOM

###########################################################################

echo "testing shadow..."

# NOTE: the output of this should depend on whether we are root or not

check "getent shadow ecordas" << EOM
ecordas:*::::7:2::0
EOM

check "getent shadow arthur" << EOM
arthur:*::100:200:7:2::0
EOM

# check if the number of passwd entries matches the number of shadow entries
numpasswd=`getent passwd | wc -l`
check "getent shadow | wc -l" << EOM
$numpasswd
EOM

# check if the names of users match between passwd and shadow
getent passwd | sed 's/:.*//' | sort | \
  check "getent shadow | sed 's/:.*//' | sort"

###########################################################################
# determine the result

if [ $FAIL -eq 0 ]
then
  echo "all tests passed"
  exit 0
else
  echo "$FAIL tests failed"
  exit 1
fi
