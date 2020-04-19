   nss-pam-ldapd - NSS and PAM libraries for name lookups and authentication
                   using LDAP

   nss-pam-ldapd started as nss-ldapd which was a fork from nss_ldap which was
   originally written by Luke Howard of PADL Software Pty Ltd.

   In 2006 Arthur de Jong of West Consuling forked the library to split it
   into a thin NSS part and a server part. Most of the code was rewritten.

   The software was renamed to nss-pam-ldapd when PAM code contributed by
   Howard Chu for the OpenLDAP nssov module was integrated. Solaris
   compatibility was developed by Ted C. Cheng of Symas Corporation.

   https://arthurdejong.org/nss-pam-ldapd/

   Copyright (C) 1997-2006 Luke Howard
   Copyright (C) 2006-2007 West Consulting
   Copyright (C) 2006-2018 Arthur de Jong
   Copyright (C) 2009 Howard Chu
   Copyright (C) 2010 Symas Corporation

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301 USA


INTRODUCTION
============

This is the nss-pam-ldapd library which consists of an NSS module to do name
lookups to an LDAP directory server and a PAM module to do authentication to
an LDAP server. The NSS part of this library was forked from nss_ldap as
provided by Luke Howard of PADL Software Pty Ltd. The PAM module was mostly
provided by Howard Chu of the OpenLDAP project.

The NSS library allows distributing account, group, host and other
configuration information from a central LDAP server. Because LDAP is a
hierarchical directory service, information can be organised in a manner which
reflects an organisational structure. This contrasts with the flat, single
domain policy of NIS. LDAP has many of the advantages of NIS+ (security and
scalability) without the complexity. The system will work alongside your
existing NIS, NIS+, DNS and flat file name services.

The PAM library (module) can be used to perform authentication based on
information inside the LDAP directory.

Both libraries consist of a thin NSS or PAM part that proxies the requests to
a local daemon (nslcd) that handles the LDAP lookups. This simplifies the
software architecture and fixes some scalability and locking problems in the
original design of nss_ldap.

It is also possible to use the thin NSS and PAM modules together with the
nssov overlay in the OpenLDAP server (slapd).

The three parts (NSS module, PAM module, and nslcd server) can be built
separately and are not strongly tied together. This means that for instance
you can still use pam_ldap and use the NSS module from nss-pam-ldapd or use an
alternative implementation of nslcd (for instance with the nssov slapd overlay
or the pynslcd implementation).

improvements over nss_ldap
--------------------------

The fork from nss_ldap was done to implement some major design changes to fix
some structural problems in the library.

One of those problems were host name lookups through LDAP which could cause
deadlocks. Another is that nss_ldap loaded an SSL library into executables
that may not be designed to load it (e.g. problem with suid applications).

A number of refactoring steps were done to simplify the code and improve
maintainability. Legacy code was removed and support for non-Linux operating
systems was initially removed to make the code more readable. Portability was
re-added using compatibility wrappers.

The most practical improvements over nss_ldap are:
- the LDAP library is not loaded for every process doing LDAP lookups
- the number of connections to the LDAP server is limited, because not every
  process will open its own connection
- hostname lookups should now be deadlock-free because the LDAP server name is
  no longer looked up using the ldap method
- avoid problems with TLS connections in suid binaries and other process-local
  configuration
- it is easier to debug because logging in nslcd can be enabled without
  the need to restart all processes doing name lookups
- unavailability timeouts are global instead of per-process

comparison to pam_ldap
----------------------

The PAM module that is currently implemented contains functionality for
authentication, account management, password management and session
management. The nslcd daemon currently implements authentication,
authorisation and password modification. The OpenLDAP nssov overlay also
implements session functionality.

supported C libraries (for NSS module)
--------------------------------------

This library currently supports the GNU C Library, the Solaris C library and
the FreeBSD C library.

supported name databases
------------------------

Currently the following name databases are supported:

  aliases, ethers, group, hosts, netgroup, networks, passwd, protocols, rpc,
  services and shadow

When using IPv6 ipHostNumber attributes, the address in LDAP must be in the
preferred form as defined in section 2.2 of RFC1884, specifically the format
as returned by inet_ntop(3). All leading zeros should be omitted and the
longest range of zeroes should be replaced with :: (e.g.
fe80::218:bff:fe55:c9f).

MAC addresses in the macAddress attribute should be in maximal, colon
separated hex notation (e.g. 00:00:92:90:ee:e2).

automounter map lookups (which are also defined in /etc/nsswitch.conf) are
currently not supported because the NSS interface is not used for these. The
common autofs implementation (on GNU/Linux) currently uses its own method for
getting the maps from LDAP.

Although mail aliases are exposed through NSS, most mail servers parse
/etc/aliases themselves (bypassing NSS) and getting aliases from LDAP requires
some configuration in the mail server.

The publickey, bootparams and netmasks are currently unsupported. Some
investigation should be done if these are needed for anything, which
interfaces should be exported and how the LDAP schema part should look like.

supported PAM implementation
----------------------------

The PAM module is currently only regularly tested on Linux PAM but other PAM
implementations should also work.

supported LDAP libraries
------------------------

The current version of nss-pam-ldapd has been developed with OpenLDAP 2.4 but
other LDAP libraries and older versions of OpenLDAP may also work.

unsupported features
--------------------

Since nss-pam-ldapd was forked from nss_ldap most of the features that came
with nss_ldap are available. The most important differences:
- the configuration file formats are not fully compatible
- rootbinddn/rootbindpw support is removed and is not likely to return
  (the rootpwmoddn and rootpwmodpw work differently but accomplish the same
  thing)

For the PAM module some functionality is missing. Comparing it to pam_ldap:
- only BIND authentication is supported
- only LDAP password modify EXOP is supported as password changing mechanism

Some things work a little different in nss-pam-ldapd. For instance the
attribute defaults and overrides of nss_ldap are implemented with mapping
expressions and pam_ldap's pam_check_*_attr options can be implemented with
the pam_authz_search option.


INSTALLATION
============

The nss-pam-ldapd library uses autoconf and automake for building. Installing
nss-pam-ldapd should be as simple as:

  % ./configure
  % make
  % make install

It is a good idea to first go through the options of configure by running:

  % ./configure --help

The last step (make install) should install the libnss_ldap.so.* and
pam_ldap.so files and the daemon (nslcd). The proper location of the NSS and
PAM modules are guessed. The boot process needs to be modified to start the
nslcd daemon at the right time.

It is recommended to create a dedicated user for the nslcd daemon. Configure
this user in /etc/nslcd.conf using the uid and gid options.


CONFIGURATION
=============

After installation, the name service switch configuration file
(/etc/nsswitch.conf) needs to be modified to do name lookups using the new
module. This consists mostly of adding ldap in the list of lookup methods in
the right place. See the nsswitch.conf(5) manual page for details on the
format. As an example the file could look a little like this:

  # the following contain normal unix user and group information
  passwd:         files ldap
  group:          files ldap
  shadow:         files ldap

  # hostname lookups through ldap before dns should work now
  hosts:          files ldap dns
  networks:       files ldap

  # normal flat-file definitions
  protocols:      files ldap
  services:       files ldap
  ethers:         files ldap
  rpc:            files ldap
  netgroup:       ldap

  # whether alias lookups really use NSS depends on the mail server
  aliases:        files ldap

Configuring PAM differs a little from platform to platform but this is a
minimal set-up for files under /etc/pam.d:

  auth   sufficient   pam_unix.so
  auth   sufficient   pam_ldap.so use_first_pass
  auth   required     pam_deny.so

  account   required     pam_unix.so
  account   sufficient   pam_ldap.so
  account   required     pam_permit.so

  session   required   pam_unix.so
  session   optional   pam_ldap.so

  password   sufficient   pam_unix.so nullok md5 shadow use_authtok
  password   sufficient   pam_ldap.so try_first_pass
  password   required     pam_deny.so

Lastly, a configuration file for nslcd (by default /etc/nslcd.conf) needs to
be made. See the shipped manual page for details on the format and options. It
should at the very least contain something like:

  # the location of LDAP server
  uri ldap://localhost/

  # search base for all queries.
  base dc=example,dc=net

service discovery through DNS
-----------------------------

nss-pam-ldapd supports looking up LDAP server names through DNS SRV records as
specified in RFC 2782. However, Priority and Weight are not considered
separately and a single list of servers in added as if they had been specified
with uri options in the configuration file.

To use this feature specify DNS as an uri in the configuration file and
include something like the following in your zone:

  _ldap._tcp  SRV  10 0  389  ldapserver


LDAP SCHEMA
===========

nss-pam-ldapd supports a wide range of possible LDAP schema configurations and
it can be customized heavily. The LDAP schema used is described in RFC 2307.
Groups using the member attribute that hold distinguished names (RFC 2307bis)
are also supported (but see group membership below for more information).

default attributes
------------------

This paragraph describes the mapping between the NSS lookups and the LDAP
database. The mapping may be modified by changing the nslcd.conf configuration
file. See the nslcd.conf(5) manual page for details.

aliases (objectClass=nisMailAlias)
  cn                - alias name
  rfc822MailMember  - members of the alias (recipients)
ethers (objectClass=ieee802Device)
  cn                - host name
  macAddress        - ethernet address
group (objectClass=posixGroup)
  cn                - group name
  userPassword      - password (by default mapped to "*")
  gidNumber         - gid
  memberUid         - members (user names)
  member            - members (DN values)
hosts (objectClass=ipHost)
  cn                - host name (and aliases)
  ipHostNumber      - addresses
netgroup (objectClass=nisNetgroup)
  cn                - netgroup name
  nisNetgroupTriple - triplets describing netgroup entries
  memberNisNetgroup - reference to other netgroup
networks (objectClass=ipNetwork)
  cn                - network name
  ipNetworkNumber   - network address
passwd (objectClass=posixAccount)
  uid               - account name
  userPassword      - password (by default mapped to "*")
  uidNumber         - uid
  gidNumber         - gid
  gecos             - gecos
  homeDirectory     - home directory
  loginShell        - shell
protocols (objectClass=ipProtocol)
  cn                - protocol name
  ipProtocolNumber  - protocol number
rpc (oncRpc)
  cn                - rpc name
  oncRpcNumber      - rpc number
services (objectClass=ipService)
  cn                - service name
  ipServicePort     - service port
  ipServiceProtocol - service protocol
shadow (objectClass=shadowAccount)
  uid               - use name
  userPassword      - password
  shadowLastChange  - date of last password change
  shadowMin         - days before password may be changed again
  shadowMax         - days after which password must be changed
  shadowWarning     - days before max password age to present a warning
  shadowInactive    - days after max password age that account is disabled
  shadowExpire      - account expiration date
  shadowFlag        - reserved field

using Microsoft Active Directory
--------------------------------

When using Microsoft Active Directory server some changes need to be made to
the nslcd.conf configuration file. The included sample configuration file has
some commented out attribute mappings for such a set-up.

group membership
----------------

Currently, two ways of specifying group membership are supported. The first,
by using the memberUid attribute, is the simplest and by far the fastest
(takes the least number of lookups). The attribute values are user names (same
as the uid attribute for posixAccount entries) and are returned without
further processing.

The second method is to use DN values in the member attribute (attribute names
can be changed by using the attribute mapping options as described in the
manual page). This is potentially a lot slower because in the worst case every
DN has to be looked up in the LDAP server to find the proper value for the uid
attribute.

If the LDAP server supports the deref control (provided by the deref overlay
in OpenLDAP) the DN to uid expansing is performed by the LDAP server.

If the DN value already contains a uid value (e.g. uid=arthur, dc=example,
dc=com) a further lookup is skipped and the uid value from the DN is used.

For other DN values an extra lookup is performed to expand it to a uid. These
lookups are cached and are configurable with the cache dn2uid configuration
option.

The member attribute may also contain the DN of another group entry. These
nested groups are parsed recursively depending on the nss_nested_groups
option.

Currently, the memberOf attribute in posixAccount entries is unsupported.

case sensitivity
----------------

Most values in NSS databases are considered case-sensitive (e.g. the user
"Foo" is a different user from the user "foo"). Most values in an LDAP
database are however considered case-insensitive. nss-pam-ldapd tries to solve
this problem by adding an extra filtering layer to ensure that when looking
for the user "foo" it will not consider a user "Foo" that is found in LDAP.

For the group, netgroup, passwd, protocols, rpc, services and shadow maps the
matches will be checked case-sensitively and for aliases, ethers, hosts and
networks matches will be case-insensitive (this seems to be what Glibc is
doing currently in flat files). Only searching for groups by user is done
case-insensitive. In all cases the case-use in the LDAP directory is returned.

This behaviour can be disabled with the ignorecase configuration option but
may be a security risk.

Note that having entries that only differ in case is a bad idea and will
likely get you in trouble. One example of such a problem is that the DN
uid=test,dc=example,dc=com is considered the same in LDAP as
uid=TEST,dc=example,dc=com.


REPORTING BUGS
==============

If you find any bugs or missing features please send email to
  nss-pam-ldapd-users@lists.arthurdejong.org
If you are using a packaged version of nss-pam-ldapd you are encouraged to use
the distributor's bug tracking system. Please include as much information as
possible (platform, output of configure if compilation fails, error messages,
output of nslcd -d, etc). Patches are more than welcome (also see the file
HACKING).
