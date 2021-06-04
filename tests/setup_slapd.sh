#!/bin/sh

# run_slapd.sh - configure and run a slapd instance
#
# Copyright (C) 2013-2021 Arthur de Jong
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

set -e

# find source directory (used for finding LDIF files)
srcdir="${srcdir-`dirname "$0"`}"

# present usage information
usage() {
  echo "Usage: $0 PATH {setup|start|stop|clean|dump_config|dump_db}" >&2
}

# examine directory for usability
check_dir() {
  if ! [ -e "$1" ]
  then
    echo "notfound"
  elif ! [ -d "$1" ]
  then
    echo "unknown"
  elif [ -z "$(find "$basedir" -mindepth 1 -maxdepth 1 2>/dev/null || true)" ]
  then
    echo "empty"
  elif [ -d "$1/ldapdb" ]
  then
    if [ -f "$basedir/setup-complete" ]
    then
      echo "complete"
    else
      echo "incomplete"
    fi
  else
    echo "unknown"
  fi
}

# check whether our slapd is running
our_slapd_is_running() {
  if [ -f "$basedir/slapd.pid" ] && kill -s 0 `cat "$basedir/slapd.pid"` > /dev/null 2>&1
  then
    return 0  # is running
  fi
  return 1
}

# the directory where to construct the environment
if test $# -lt 2
then
  usage
  exit 1
fi
basedir="$1"

# gather configuration information
user="$( (getent passwd openldap || getent passwd ldap || getent passwd nobody) | sed 's/:.*//')"
group="$( (getent group openldap || getent group ldap || getent group nogroup) | sed 's/:.*//')"

case "$2" in
  setup)
    if our_slapd_is_running
    then
      "$0" "$basedir" stop
    fi
    echo -n "Creating blank $basedir slapd environment..."
    case `check_dir "$basedir"` in
      notfound|empty|complete|incomplete) ;;
      *)
        echo "FAILED: already exists and is not empty or old environment"
        exit 1
        ;;
    esac
    rm -rf "$basedir"
    mkdir -p "$basedir/slapd.d" "$basedir/ldapdb" || (echo " FAILED"; exit 1)
    echo " done."
    echo "Loading cn=config..."
    tmpldif=`mktemp -t slapadd.XXXXXX`
    sed "s|@BASEDIR@|$basedir|g" < "$srcdir/config.ldif" > "$tmpldif"
    if [ -f /etc/ldap/schema/ppolicy.ldif ]
    then
      sed -i "s|#PPOLICY#||g" "$tmpldif"
    fi
    slapadd -v -F "$basedir/slapd.d" -b "cn=config" -l "$tmpldif" || (echo " FAILED"; exit 1)
    rm -f "$tmpldif"
    echo "Loading dc=test,dc=tld..."
    slapadd -F "$basedir/slapd.d" -b "dc=test,dc=tld" -l "$srcdir/test.ldif" || (echo " FAILED"; exit 1)
    echo -n "Fixing permissions..."
    chown -R "$user":"$group" "$basedir" || (echo " FAILED"; exit 1)
    touch "$basedir/setup-complete"
    echo " done."
    exit 0
    ;;
  start)
    echo -n "Starting OpenLDAP: slapd"
    case `check_dir "$basedir"` in
      complete) ;;
      *)
        echo " FAILED: environment not ready"
        exit 1
        ;;
    esac
    if our_slapd_is_running
    then
      echo " already running."
      exit 0
    fi
    shift
    shift
    slapd -F "$basedir/slapd.d" -u "$user" -g "$group" \
      -h "ldap:/// ldaps:/// ldapi:///" "$@" || (echo " FAILED"; exit 1)
    echo "."
    ;;
  stop)
    # (perhaps implement stop-any)
    echo -n "Stopping OpenLDAP: slapd"
    if ! our_slapd_is_running
    then
      echo " not running."
      exit 0
    fi
    for i in 1 2 3 4 5
    do
      [ -f "$basedir/slapd.pid" ] && kill `cat "$basedir/slapd.pid"` > /dev/null 2>&1 || true
      sleep 0.1 > /dev/null 2>&1 || true
      if ! our_slapd_is_running
      then
        echo " done."
        exit 0
      fi
      echo -n " ."
      sleep 1
    done
    echo " FAILED"
    exit 1
    ;;
  clean)
    if our_slapd_is_running
    then
      "$0" "$basedir" stop
    fi
    echo -n "Cleaning $basedir... "
    case `check_dir "$basedir"` in
      complete|incomplete) ;;
      *)
        echo "FAILED: does not contain environment"
        exit 1
        ;;
    esac
    rm -rf "$basedir"
    echo "done."
    exit 0
    ;;
  dump_config)
    case `check_dir "$basedir"` in
      complete) ;;
      *)
        echo "Dumping config FAILED: environment not ready"
        exit 1
        ;;
    esac
    slapcat -F "$basedir/slapd.d" -b "cn=config" -o ldif-wrap=no \
      | sed '/^\(structuralObjectClass\|entryUUID\|creatorsName\|createTimestamp\|entryCSN\|modifiersName\|modifyTimestamp\):/d;$d'
    ;;
  dump_db)
    case `check_dir "$basedir"` in
      complete) ;;
      *)
        echo "Dumping database FAILED: environment not ready"
        exit 1
        ;;
    esac
    slapcat -F "$basedir/slapd.d" -b "dc=test,dc=tld" -o ldif-wrap=no \
      | sed '/^\(structuralObjectClass\|entryUUID\|creatorsName\|createTimestamp\|entryCSN\|modifiersName\|modifyTimestamp\):/d;$d'
    ;;
  *)
    usage
    exit 1
    ;;
esac
