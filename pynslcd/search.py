
# search.py - functions for searching the LDAP database
#
# Copyright (C) 2010, 2011, 2012, 2013 Arthur de Jong
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
import sys

import ldap
import ldap.ldapobject

import cfg


# global indicator that there was some error connection to an LDAP server
server_error = False

# global indicator of first search operation
first_search = True


class Connection(ldap.ldapobject.ReconnectLDAPObject):

    def __init__(self):
        ldap.ldapobject.ReconnectLDAPObject.__init__(self, cfg.uri,
            retry_max=1, retry_delay=cfg.reconnect_retrytime)
        # set connection-specific LDAP options
        if cfg.ldap_version:
            self.set_option(ldap.OPT_PROTOCOL_VERSION, cfg.ldap_version)
        if cfg.deref:
            self.set_option(ldap.OPT_DEREF, cfg.deref)
        if cfg.timelimit:
            self.set_option(ldap.OPT_TIMELIMIT, cfg.timelimit)
            self.set_option(ldap.OPT_TIMEOUT, cfg.timelimit)
            self.set_option(ldap.OPT_NETWORK_TIMEOUT, cfg.timelimit)
        if cfg.referrals:
            self.set_option(ldap.OPT_REFERRALS, cfg.referrals)
        if cfg.sasl_canonicalize is not None:
            self.set_option(ldap.OPT_X_SASL_NOCANON, not cfg.sasl_canonicalize)
        self.set_option(ldap.OPT_RESTART, True)
        # TODO: register a connection callback (like dis?connect_cb() in myldap.c)
        if cfg.ssl or cfg.uri.startswith('ldaps://'):
            self.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_HARD)
        # TODO: the following should probably be done on the first search
        #       together with binding, not when creating the connection object
        if cfg.ssl == 'STARTTLS':
            self.start_tls_s()

    def reconnect_after_fail(self):
        import invalidator
        logging.info('connected to LDAP server %s', cfg.uri)
        invalidator.invalidate()

    def search_s(self, *args, **kwargs):
        # wrapper function to keep the global server_error state
        global server_error, first_search
        try:
            res = ldap.ldapobject.ReconnectLDAPObject.search_s(self, *args, **kwargs)
        except ldap.SERVER_DOWN:
            server_error = True
            raise
        if server_error or first_search:
            self.reconnect_after_fail()
            server_error = False
            first_search = False
        return res


class LDAPSearch(object):
    """
    Class that performs an LDAP search. Subclasses are expected to define the
    actual searches and should implement the following members:

      case_sensitive - check that these attributes are present in the response
                       if they were in the request
      case_insensitive - check that these attributes are present in the
                         response if they were in the request
      limit_attributes - override response attributes with request attributes
                         (ensure that only one copy of the value is returned)
      required - attributes that are required
      canonical_first - search the DN for these attributes and ensure that
                        they are listed first in the attribute values
      mk_filter() (optional) - function that returns the LDAP search filter

    The module that contains the Search class can also contain the following
    definitions:

      bases - list of search bases to be used, if absent or empty falls back
              to cfg.bases
      scope - search scope, falls back to cfg.scope if absent or empty
      filter - an LDAP search filter
      attmap - an attribute mapping definition (using he Attributes class)

    """

    canonical_first = []
    required = []
    case_sensitive = []
    case_insensitive = []
    limit_attributes = []

    def __init__(self, conn, base=None, scope=None, filter=None,
                 attributes=None, parameters=None):
        self.conn = conn
        # load information from module that defines the class
        module = sys.modules[self.__module__]
        if base:
            self.bases = [base]
        else:
            self.bases = getattr(module, 'bases', cfg.bases)
        self.scope = scope or getattr(module, 'scope', cfg.scope)
        self.filter = filter or getattr(module, 'filter', None)
        self.attmap = getattr(module, 'attmap', None)
        self.attributes = attributes or self.attmap.attributes()
        self.parameters = parameters or {}

    def __iter__(self):
        return self.items()

    def items(self):
        """Return the results from the search."""
        filter = self.mk_filter()
        for base in self.bases:
            logging.debug('LDAPSearch(base=%r, filter=%r)', base, filter)
            try:
                for entry in self.conn.search_s(base, self.scope, filter, self.attributes):
                    if entry[0]:
                        entry = self._transform(entry[0], entry[1])
                        if entry:
                            yield entry
            except ldap.NO_SUCH_OBJECT:
                # FIXME: log message
                pass

    def mk_filter(self):
        """Return the active search filter (based on the read parameters)."""
        if self.parameters:
            return '(&%s%s)' % (
                self.filter,
                ''.join(self.attmap.mk_filter(attribute, value)
                        for attribute, value in self.parameters.items()))
        return self.filter

    def _transform(self, dn, attributes):
        """Handle a single search result entry filtering it with the request
        parameters, search options and attribute mapping."""
        # translate the attributes using the attribute mapping
        if self.attmap:
            attributes = self.attmap.translate(attributes)
        # make sure value from DN is first value
        for attr in self.canonical_first:
            primary_value = self.attmap.get_rdn_value(dn, attr)
            if primary_value:
                values = attributes[attr]
                if primary_value in values:
                    values.remove(primary_value)
                attributes[attr] = [primary_value] + values
        # check that these attributes have at least one value
        for attr in self.required:
            if not attributes.get(attr, None):
                logging.warning('%s: %s: missing', dn, self.attmap[attr])
                return
        # check that requested attribute is present (case sensitive)
        for attr in self.case_sensitive:
            value = self.parameters.get(attr, None)
            if value and str(value) not in attributes[attr]:
                logging.debug('%s: %s: does not contain %r value', dn, self.attmap[attr], value)
                return  # not found, skip entry
        # check that requested attribute is present (case insensitive)
        for attr in self.case_insensitive:
            value = self.parameters.get(attr, None)
            if value and str(value).lower() not in (x.lower() for x in attributes[attr]):
                logging.debug('%s: %s: does not contain %r value', dn, self.attmap[attr], value)
                return  # not found, skip entry
        # limit attribute values to requested value
        for attr in self.limit_attributes:
            if attr in self.parameters:
                attributes[attr] = [self.parameters[attr]]
        # return the entry
        return dn, attributes
