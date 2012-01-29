
# common.py - functions that are used by different modules
#
# Copyright (C) 2010, 2011, 2012 Arthur de Jong
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
import ldap.dn

from attmap import Attributes
import cache
import cfg
import constants


def isvalidname(name):
    """Checks to see if the specified name seems to be a valid user or group
    name.

    This test is based on the definition from POSIX (IEEE Std 1003.1, 2004,
    3.426 User Name, 3.189 Group Name and 3.276 Portable Filename Character Set):
    http://www.opengroup.org/onlinepubs/009695399/basedefs/xbd_chap03.html#tag_03_426
    http://www.opengroup.org/onlinepubs/009695399/basedefs/xbd_chap03.html#tag_03_189
    http://www.opengroup.org/onlinepubs/009695399/basedefs/xbd_chap03.html#tag_03_276

    The standard defines user names valid if they contain characters from
    the set [A-Za-z0-9._-] where the hyphen should not be used as first
    character. As an extension this test allows some more characters."""
    return bool(cfg.validnames.search(name))


def validate_name(name):
    """Checks to see if the specified name seems to be a valid user or group
    name. See isvalidname()."""
    if not cfg.validnames.search(name):
        raise ValueError('%r: denied by validnames option' % name)


class Search(object):
    """
    Class that performs a search. Subclasses are expected to define the actual
    searches and should implement the following members:

      case_sensitive - check that these attributes are present in the response
                       if they were in the request
      case_insensitive - check that these attributes are present in the
                         response if they were in the request
      limit_attributes - override response attributes with request attributes
      required - attributes that are required
      canonical_first - search the DN for these attributes and ensure that
                        they are listed first in the attribute values
      mk_filter() (optional) - function that returns the LDAP search filter

    The module that contains the Request class can also contain the following
    definitions:

      attmap - an attribute mapping definition (using he Attributes class)
      filter - an LDAP search filter
      bases - search bases to be used, falls back to cfg.bases
      scope - search scope, falls back to cfg.scope

    """

    canonical_first = []
    required = []
    case_sensitive = []
    case_insensitive = []
    limit_attributes = []

# FIXME: figure out which of these arguments are actually needed

    def __init__(self, conn, base=None, scope=None, filter=None, attributes=None,
                 parameters=None):
        # load information from module that defines the class
        self.conn = conn
        module = sys.modules[self.__module__]
        self.attmap = getattr(module, 'attmap', None)
        self.filter = filter or getattr(module, 'filter', None)
        self.parameters = parameters or {}
        if base:
            self.bases = [base]
        else:
            self.bases = getattr(module, 'bases', cfg.bases)
        self.scope = scope or getattr(module, 'scope', cfg.scope)
        self.attributes = attributes or self.attmap.attributes()

    def __iter__(self):
        return self.items()

    def items(self):
        """Return the results from the search."""
        filter = self.mk_filter()
        for base in self.bases:
            logging.debug('SEARCHING %s', base)
            try:
                for entry in self.conn.search_s(base, self.scope, filter, self.attributes):
                    if entry[0]:
                        entry = self.handle_entry(entry[0], entry[1])
                        if entry:
                            yield entry
            except ldap.NO_SUCH_OBJECT:
                # FIXME: log message
                pass

    def escape(self, value):
        """Escape the provided value so it may be used in a search filter."""
        return ldap.filter.escape_filter_chars(str(value))

    def mk_filter(self):
        """Return the active search filter (based on the read parameters)."""
        if self.parameters:
            return '(&%s(%s))' % (self.filter,
                ')('.join('%s=%s' % (self.attmap[attribute], self.escape(value))
                          for attribute, value in self.parameters.items()))
        return self.filter

    def handle_entry(self, dn, attributes):
        """Handle an entry with the specified attributes, filtering it with
        the request parameters where needed."""
        # translate the attributes using the attribute mapping
        attributes = self.attmap.translate(attributes)
        # make sure value from DN is first value
        for attr in self.canonical_first:
            primary_value = get_rdn_value(dn, self.attmap[attr])
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


class Request(object):
    """
    Request handler class. Subclasses are expected to handle actual requests
    and should implement the following members:

      action - the NSLCD_ACTION_* action that should trigger this handler

      read_parameters() - a function that reads the request parameters of the
                          request stream
      write() - function that writes a single LDAP entry to the result stream

    """

    def __init__(self, fp, conn, calleruid):
        self.fp = fp
        self.conn = conn
        self.calleruid = calleruid
        module = sys.modules[self.__module__]
        self.search = getattr(module, 'Search', None)
        if not hasattr(module, 'cache_obj'):
            cache_cls = getattr(module, 'Cache', None)
            module.cache_obj = cache_cls() if cache_cls else None
        self.cache = module.cache_obj

    def read_parameters(self, fp):
        """This method should read the parameters from ths stream and
        store them in self."""
        pass

    def handle_request(self, parameters):
        """This method handles the request based on the parameters read
        with read_parameters()."""
        try:
            with cache.con:
                for dn, attributes in self.search(conn=self.conn, parameters=parameters):
                    for values in self.convert(dn, attributes, parameters):
                        self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
                        self.write(*values)
                        if self.cache:
                            self.cache.store(*values)
        except ldap.SERVER_DOWN:
            if self.cache:
                logging.debug('read from cache')
                # we assume server went down before writing any entries
                for values in self.cache.retrieve(parameters):
                    self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
                    self.write(*values)
            else:
                raise
        # write the final result code
        self.fp.write_int32(constants.NSLCD_RESULT_END)

    def __call__(self):
        parameters = self.read_parameters(self.fp) or {}
        logging.debug('%s(%r)', self.__class__.__name__, parameters)
        self.fp.write_int32(constants.NSLCD_VERSION)
        self.fp.write_int32(self.action)
        self.handle_request(parameters)


def get_handlers(module):
    """Return a dictionary mapping actions to Request classes."""
    import inspect
    res = {}
    if isinstance(module, basestring):
        module = __import__(module, globals())
    for name, cls in inspect.getmembers(module, inspect.isclass):
        if issubclass(cls, Request) and hasattr(cls, 'action'):
            res[cls.action] = cls
    return res


def get_rdn_value(dn, attribute):
    return dict((x, y) for x, y, z in ldap.dn.str2dn(dn)[0])[attribute]
