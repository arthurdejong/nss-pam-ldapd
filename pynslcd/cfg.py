
# cfg.py - module for accessing configuration information
#
# Copyright (C) 2010-2019 Arthur de Jong
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

import logging
import re

import ldap


# the number of threads to start
threads = 5
# the user id nslcd should be run as
uid = None
# the group id nslcd should be run as
gid = None
# the configured loggers
logs = []

# the LDAP server to use
uri = None  # FIXME: support multiple servers and have a fail-over mechanism
# LDAP protocol version to use (perhaps fix at 3?)
ldap_version = ldap.VERSION3
# the DN to use when binding
binddn = None  # FIXME: add support
bindpw = None  # FIXME: add support
# the DN to use to perform password modifications as root
rootpwmoddn = None
rootpwmodpw = None

# SASL configuration
sasl_mech = None  # FIXME: add support
sasl_realm = None  # FIXME: add support
sasl_authcid = None  # FIXME: add support
sasl_authzid = None  # FIXME: add support
sasl_secprops = None  # FIXME: add support
sasl_canonicalize = None  # FIXME: add support

# LDAP bases to search
bases = []
# default search scope for searches
scope = ldap.SCOPE_SUBTREE

deref = ldap.DEREF_NEVER
referrals = True

# timing configuration
bind_timelimit = 10  # FIXME: add support
timelimit = ldap.NO_LIMIT
idle_timelimit = 0  # FIXME: add support
reconnect_sleeptime = 1  # FIXME: add support
reconnect_retrytime = 10

# SSL/TLS options
ssl = None
tls_reqcert = None
tls_cacertdir = None
tls_cacertfile = None
tls_randfile = None
tls_ciphers = None
tls_cert = None
tls_key = None

# other options
pagesize = 0  # FIXME: add support
nss_initgroups_ignoreusers = set()
nss_min_uid = 0
nss_uid_offset = 0
nss_gid_offset = 0
nss_nested_groups = False
nss_getgrent_skipmembers = False
nss_disable_enumeration = False
validnames = re.compile(r'^[a-z0-9._@$][a-z0-9._@$ \\~-]{0,98}[a-z0-9._@$~-]$', re.IGNORECASE)
pam_authc_ppolicy = True
pam_authz_searches = []
pam_password_prohibit_message = None
reconnect_invalidate = set()


# allowed boolean values
_boolean_options = {'on': True, 'yes': True, 'true': True, '1': True,
                    'off': False, 'no': False, 'false': False, '0': False}

# allowed log levels (we log notice which is unsupported in Python to warning)
_log_levels = {'crit': logging.CRITICAL, 'error': logging.ERROR,
               'err': logging.ERROR, 'warning': logging.WARNING,
               'notice': logging.WARNING, 'info': logging.INFO,
               'debug': logging.DEBUG, 'none': logging.INFO}

# allowed values for scope option
if not hasattr(ldap, 'SCOPE_CHILDREN') and ldap.VENDOR_VERSION >= 20400:
    ldap.SCOPE_CHILDREN = 3   # OpenLDAP extension
_scope_options = dict(sub=ldap.SCOPE_SUBTREE, subtree=ldap.SCOPE_SUBTREE,
                      one=ldap.SCOPE_ONELEVEL, onelevel=ldap.SCOPE_ONELEVEL,
                      base=ldap.SCOPE_BASE)
if hasattr(ldap, 'SCOPE_CHILDREN'):
    _scope_options['children'] = ldap.SCOPE_CHILDREN

# allowed values for the deref option
_deref_options = dict(never=ldap.DEREF_NEVER,
                      searching=ldap.DEREF_SEARCHING,
                      finding=ldap.DEREF_FINDING,
                      always=ldap.DEREF_ALWAYS)

# allowed values for the ssl option
_ssl_options = dict(start_tls='STARTTLS', starttls='STARTTLS',
                    on='LDAPS', off=None)

# allowed values for the tls_reqcert option
_tls_reqcert_options = {'never': ldap.OPT_X_TLS_NEVER,
                        'no': ldap.OPT_X_TLS_NEVER,
                        'allow': ldap.OPT_X_TLS_ALLOW,
                        'try': ldap.OPT_X_TLS_TRY,
                        'demand': ldap.OPT_X_TLS_DEMAND,
                        'yes': ldap.OPT_X_TLS_DEMAND,
                        'hard': ldap.OPT_X_TLS_HARD}


def _get_maps():
    # separate function as not to pollute the namespace and avoid import loops
    import alias, ether, group, host, netgroup, network, passwd  # noqa: E401
    import protocol, rpc, service, shadow  # noqa: E401
    import sys
    return dict(
        alias=alias, aliases=alias,
        ether=ether, ethers=ether,
        group=group,
        host=host, hosts=host,
        netgroup=netgroup,
        network=network, networks=network,
        passwd=passwd,
        protocol=protocol, protocols=protocol,
        rpc=rpc,
        service=service, services=service,
        shadow=shadow,
        none=sys.modules[__name__],
    )


class ParseError(Exception):

    def __init__(self, filename, lineno, message):
        self.message = '%s:%d: %s' % (filename, lineno, message)

    def __repr__(self):
        return self.message

    __str__ = __repr__


def read(filename):  # noqa: C901 (many simple branches)
    maps = _get_maps()
    lineno = 0
    for line in open(filename, 'r'):
        lineno += 1
        line = line.strip()
        # skip comments and blank lines
        if re.match(r'(#.*)?$', line, re.IGNORECASE):
            continue
        # parse options with a single integer argument
        m = re.match(
            r'(?P<keyword>threads|ldap_version|bind_timelimit|timelimit|'
            r'idle_timelimit|reconnect_sleeptime|reconnect_retrytime|pagesize|'
            r'nss_min_uid|nss_uid_offset|nss_gid_offset)\s+(?P<value>\d+)',
            line, re.IGNORECASE)
        if m:
            globals()[m.group('keyword').lower()] = int(m.group('value'))
            continue
        # parse options with a single boolean argument
        m = re.match(
            r'(?P<keyword>referrals|nss_nested_groups|nss_getgrent_skipmembers|'
            r'nss_disable_enumeration|pam_authc_ppolicy)\s+(?P<value>%s)' % (
                '|'.join(_boolean_options.keys())),
            line, re.IGNORECASE)
        if m:
            globals()[m.group('keyword').lower()] = _boolean_options[m.group('value').lower()]
            continue
        # parse options with a single no-space value
        m = re.match(
            r'(?P<keyword>uid|gid|bindpw|rootpwmodpw|sasl_mech)\s+(?P<value>\S+)',
            line, re.IGNORECASE)
        if m:
            globals()[m.group('keyword').lower()] = m.group('value')
            continue
        # parse options with a single value that can contain spaces
        m = re.match(
            r'(?P<keyword>binddn|rootpwmoddn|sasl_realm|sasl_authcid|'
            r'sasl_authzid|sasl_secprops|krb5_ccname|tls_cacertdir|'
            r'tls_cacertfile|tls_randfile|tls_ciphers|tls_cert|tls_key|'
            r'pam_password_prohibit_message)\s+(?P<value>\S.*)',
            line, re.IGNORECASE)
        if m:
            globals()[m.group('keyword').lower()] = m.group('value')
            continue
        # log <SCHEME> [<LEVEL>]
        m = re.match(
            r'log\s+(?P<scheme>syslog|/\S*)(\s+(?P<level>%s))?' % (
                '|'.join(_log_levels.keys())),
            line, re.IGNORECASE)
        if m:
            logs.append((m.group('scheme'), _log_levels[str(m.group('level')).lower()]))
            continue
        # uri <URI>
        m = re.match(r'uri\s+(?P<uri>\S+)', line, re.IGNORECASE)
        if m:
            # FIXME: support multiple URI values
            # FIXME: support special DNS and DNS:domain values
            global uri
            uri = m.group('uri')
            continue
        # base <MAP>? <BASEDN>
        m = re.match(
            r'base\s+((?P<map>%s)\s+)?(?P<value>\S.*)' % (
                '|'.join(maps.keys())),
            line, re.IGNORECASE)
        if m:
            mod = maps[str(m.group('map')).lower()]
            if not hasattr(mod, 'bases'):
                mod.bases = []
            mod.bases.append(m.group('value'))
            continue
        # filter <MAP> <SEARCHFILTER>
        m = re.match(
            r'filter\s+(?P<map>%s)\s+(?P<value>\S.*)' % (
                '|'.join(maps.keys())),
            line, re.IGNORECASE)
        if m:
            mod = maps[m.group('map').lower()]
            mod.filter = m.group('value')
            continue
        # scope <MAP>? <SCOPE>
        m = re.match(
            r'scope\s+((?P<map>%s)\s+)?(?P<value>%s)' % (
                '|'.join(maps.keys()),
                '|'.join(_scope_options.keys())),
            line, re.IGNORECASE)
        if m:
            mod = maps[str(m.group('map')).lower()]
            mod.scope = _scope_options[m.group('value').lower()]
            continue
        # map <MAP> <ATTRIBUTE> <ATTMAPPING>
        m = re.match(
            r'map\s+(?P<map>%s)\s+(?P<attribute>\S+)\s+(?P<value>\S.*)' % (
                '|'.join(maps.keys())),
            line, re.IGNORECASE)
        if m:
            mod = maps[m.group('map').lower()]
            attribute = m.group('attribute')
            if attribute not in mod.attmap:
                raise ParseError(filename, lineno, 'attribute %s unknown' % attribute)
            mod.attmap[attribute] = m.group('value')
            # TODO: filter out attributes that cannot be an expression
            continue
        # deref <DEREF>
        m = re.match(
            r'deref\s+(?P<value>%s)' % '|'.join(_deref_options.keys()),
            line, re.IGNORECASE)
        if m:
            global deref
            deref = _deref_options[m.group('value').lower()]
            continue
        # nss_initgroups_ignoreusers <USER,USER>|<ALLLOCAL>
        m = re.match(
            r'nss_initgroups_ignoreusers\s+(?P<value>\S.*)',
            line, re.IGNORECASE)
        if m:
            users = m.group('value')
            if users.lower() == 'alllocal':
                # get all users known to the system currently (since nslcd
                # isn't yet running, this should work)
                import pwd
                users = (x.pw_name for x in pwd.getpwall())
            else:
                users = users.split(',')
                # TODO: warn about unknown users
            nss_initgroups_ignoreusers.update(users)
            continue
        # pam_authz_search <FILTER>
        m = re.match(r'pam_authz_search\s+(?P<value>\S.*)', line, re.IGNORECASE)
        if m:
            from expr import Expression
            pam_authz_searches.append(Expression(m.group('value')))
            # TODO: check pam_authz_search expression to only contain
            # username, service, ruser, rhost, tty, hostname, fqdn, dn or
            # uid variables
            continue
        # ssl <on|off|start_tls>
        m = re.match(
            r'ssl\s+(?P<value>%s)' % '|'.join(_ssl_options.keys()),
            line, re.IGNORECASE)
        if m:
            global ssl
            ssl = _ssl_options[m.group('value').lower()]
            continue
        # sasl_canonicalize yes|no
        m = re.match(
            r'(ldap_?)?sasl_(?P<no>no)?canon(icali[sz]e)?\s+(?P<value>%s)' % (
                '|'.join(_boolean_options.keys())),
            line, re.IGNORECASE)
        if m:
            global sasl_canonicalize
            sasl_canonicalize = _boolean_options[m.group('value').lower()]
            if m.group('no'):
                sasl_canonicalize = not sasl_canonicalize
            continue
        # tls_reqcert <demand|hard|yes...>
        m = re.match(
            r'tls_reqcert\s+(?P<value>%s)' % (
                '|'.join(_tls_reqcert_options.keys())),
            line, re.IGNORECASE)
        if m:
            global tls_reqcert
            tls_reqcert = _tls_reqcert_options[m.group('value').lower()]
            continue
        # validnames /REGEX/i?
        m = re.match(
            r'validnames\s+/(?P<value>.*)/(?P<flags>[i]?)$',
            line, re.IGNORECASE)
        if m:
            global validnames
            flags = 0 | re.IGNORECASE if m.group('flags') == 'i' else 0
            validnames = re.compile(m.group('value'), flags=flags)
            continue
        # reconnect_invalidate <MAP>,<MAP>,...
        m = re.match(
            r'reconnect_invalidate\s+(?P<value>\S.*)',
            line, re.IGNORECASE)
        if m:
            dbs = re.split('[ ,]+', m.group('value').lower())
            for db in dbs:
                if db not in list(maps.keys()) + ['nfsidmap']:
                    raise ParseError(filename, lineno, 'map %s unknown' % db)
            reconnect_invalidate.update(dbs)
            continue
        # unrecognised line
        raise ParseError(filename, lineno, 'error parsing line %r' % line)
    # if logging is not configured, default to syslog
    if not logs:
        logs.append(('syslog', logging.INFO))
    # dump config (debugging code)
    for k, v in globals().items():
        if not k.startswith('_'):
            logging.debug('%s=%r', k, v)


def get_usergid():
    """Return user info and group id."""
    import pwd
    import grp
    u = pwd.getpwnam(uid)
    if gid is None:
        g = u.pw_gid
    else:
        g = grp.getgrnam(gid).gr_gid
    return u, g
