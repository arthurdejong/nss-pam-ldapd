
# common.py - functions that are used by different modules
#
# Copyright (C) 2010, 2011 Arthur de Jong
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

import re
import ldap
import ldap.dn
import sys

import cfg
import constants
from attmap import Attributes


_validname_re = re.compile(r'^[a-z0-9._@$][a-z0-9._@$ \\~-]{0,98}[a-z0-9._@$~-]$', re.IGNORECASE)


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
    return bool(_validname_re.match(name))


def validate_name(name):
    """Checks to see if the specified name seems to be a valid user or group
    name. See isvalidname()."""
    if not _validname_re.match(name):
        raise ValueError('%r: invalid user name' % name)


class Request(object):
    """
    Request handler class. Subclasses are expected to handle actual requests
    and should implement the following members:

      action - the NSLCD_ACTION_* action that should trigger this handler

      case_sensitive - check that these attributes are present in the response
                       if they were in the request
      case_insensitive - check that these attributes are present in the
                         response if they were in the request
      limit_attributes - override response attributes with request attributes
      required - attributes that are required
      canonical_first - search the DN for these attributes and ensure that
                        they are listed first in the attribute values
      read_parameters() - a function that reads the request parameters of the
                          request stream
      mk_filter() (optional) - function that returns the LDAP search filter
      write() - function that writes a single LDAP entry to the result stream

    The module that contains the Request class can also contain the following
    definitions:

      attmap - an attribute mapping definition (using he Attributes class)
      filter - an LDAP search filter
      bases - search bases to be used, falls back to cfg.bases
      scope - search scope, falls back to cfg.scope

    """

    def __init__(self, fp, conn, calleruid):
        self.fp = fp
        self.conn = conn
        self.calleruid = calleruid
        # load information from module that defines the class
        module = sys.modules[self.__module__]
        self.attmap = getattr(module, 'attmap', None)
        self.filter = getattr(module, 'filter', None)
        self.bases = getattr(module, 'bases', cfg.bases)
        self.scope = getattr(module, 'scope', cfg.scope)

    def read_parameters(self, fp):
        """This method should read the parameters from ths stream and
        store them in self."""
        pass

    def mk_filter(self, parameters):
        """Return the active search filter (based on the read parameters)."""
        if parameters:
            return '(&%s(%s))' % (self.filter,
                ')('.join('%s=%s' % (self.attmap[attribute],
                                     ldap.filter.escape_filter_chars(str(value)))
                          for attribute, value in parameters.items()))
        return self.filter

    def handle_entry(self, dn, attributes, parameters):
        """Handle an entry with the specified attributes, filtering it with
        the request parameters where needed."""
        # translate the attributes using the attribute mapping
        attributes = self.attmap.translate(attributes)
        # make sure value from DN is first value
        for attr in getattr(self, 'canonical_first', []):
            primary_value = get_rdn_value(dn, self.attmap[attr])
            if primary_value:
                values = attributes[attr]
                if primary_value in values:
                    values.remove(primary_value)
                attributes[attr] = [primary_value] + values
        # check that these attributes have at least one value
        for attr in getattr(self, 'required', []):
            if not attributes.get(attr, None):
                print '%s: attribute %s not found' % (dn, self.attmap[attr])
                return
        # check that requested attribute is present (case sensitive)
        for attr in getattr(self, 'case_sensitive', []):
            value = parameters.get(attr, None)
            if value and str(value) not in attributes[attr]:
                print '%s: attribute %s does not contain %r value' % (dn, self.attmap[attr], value)
                return  # not found, skip entry
        # check that requested attribute is present (case insensitive)
        for attr in getattr(self, 'case_insensitive', []):
            value = parameters.get(attr, None)
            if value and str(value).lower() not in (x.lower() for x in attributes[attr]):
                print '%s: attribute %s does not contain %r value' % (dn, self.attmap[attr], value)
                return  # not found, skip entry
        # limit attribute values to requested value
        for attr in getattr(self, 'limit_attributes', []):
            if attr in parameters:
                attributes[attr] = [parameters[attr]]
        # write the result entry
        self.write(dn, attributes, parameters)

    def handle_request(self, parameters):
        """This method handles the request based on the parameters read
        with read_parameters()."""
        # get search results
        for base in self.bases:
            # do the LDAP search
            try:
                res = self.conn.search_s(base, self.scope, self.mk_filter(parameters),
                                         self.attmap.attributes())
                for entry in res:
                    if entry[0]:
                        self.handle_entry(entry[0], entry[1], parameters)
            except ldap.NO_SUCH_OBJECT:
                # FIXME: log message
                pass
        # write the final result code
        self.fp.write_int32(constants.NSLCD_RESULT_END)

    def __call__(self):
        parameters = self.read_parameters(self.fp) or {}
        # TODO: log call with parameters
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
