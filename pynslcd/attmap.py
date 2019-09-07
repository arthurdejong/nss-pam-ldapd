
# attmap.py - attribute mapping class
#
# Copyright (C) 2011-2019 Arthur de Jong
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

"""Module for handling attribute mappings used for LDAP searches.

>>> attrs = Attributes(
...     uid='uid',
...     userPassword='userPassword',
...     uidNumber='uidNumber',
...     gidNumber='gidNumber',
...     gecos='"${gecos:-$cn}"',
...     homeDirectory='homeDirectory',
...     loginShell='loginShell')
>>> 'cn' in attrs.attributes()
True
>>> attrs.translate({'uid': ['UIDVALUE', '2nduidvalue'], 'cn': ['COMMON NAME', ]}) == {
...     'uid': ['UIDVALUE', '2nduidvalue'], 'loginShell': [], 'userPassword': [],
...     'uidNumber': [], 'gidNumber': [], 'gecos': ['COMMON NAME'], 'homeDirectory': []}
True
>>> attrs['uidNumber']  # a representation fit for logging and filters
'uidNumber'
>>> attrs['gecos']
'"${gecos:-$cn}"'
"""

import re

import ldap.dn
from ldap.filter import escape_filter_chars

from expr import Expression


# exported names
__all__ = ('Attributes', )


# TODO: support objectSid attributes


# regular expression to match function attributes
attribute_func_re = re.compile(r'^(?P<function>[a-z]+)\((?P<attribute>.*)\)$')


class SimpleMapping(str):
    """Simple mapping to another attribute name."""

    def attributes(self):
        return [self]

    def mk_filter(self, value):
        return '(%s=%s)' % (
            self, escape_filter_chars(str(value)))

    def values(self, variables):
        """Expand the expression using the variables specified."""
        return variables.get(self, [])


class ExpressionMapping(object):
    """Class for parsing and expanding an expression."""

    def __init__(self, value):
        """Parse the expression as a string."""
        self.value = value
        self.expression = Expression(value[1:-1])

    def __str__(self):
        return self.value

    def __repr__(self):
        return repr(str(self))

    def values(self, variables):
        """Expand the expression using the variables specified."""
        return [self.expression.value(variables)]

    def attributes(self):
        """Return the attributes defined in the expression."""
        return self.expression.variables()


class FunctionMapping(object):
    """Mapping to a function to another attribute."""

    def __init__(self, mapping):
        self.mapping = mapping
        m = attribute_func_re.match(mapping)
        self.attribute = m.group('attribute')
        self.function = getattr(self, m.group('function'))

    def __str__(self):
        return self.mapping

    def __repr__(self):
        return repr(str(self))

    def upper(self, value):
        return value.upper()

    def lower(self, value):
        return value.lower()

    def attributes(self):
        return [self.attribute]

    def mk_filter(self, value):
        return '(%s=%s)' % (
            self.attribute, escape_filter_chars(value))

    def values(self, variables):
        return [self.function(value)
                for value in variables.get(self.attribute, [])]


class Attributes(dict):
    """Dictionary-like class for handling attribute mapping."""

    def __init__(self, *args, **kwargs):
        self.update(*args, **kwargs)

    def __setitem__(self, attribute, mapping):
        # translate the mapping into a mapping object
        if mapping[0] == '"' and mapping[-1] == '"':
            mapping = ExpressionMapping(mapping)
        elif '(' in mapping:
            mapping = FunctionMapping(mapping)
        else:
            mapping = SimpleMapping(mapping)
        super(Attributes, self).__setitem__(attribute, mapping)

    def update(self, *args, **kwargs):
        for arg in args:
            other = dict(arg)
            for key in other:
                self[key] = other[key]
        for key in kwargs:
            self[key] = kwargs[key]

    def attributes(self):
        """Return the attributes that are referenced in this attribute mapping.

        These are the attributes that should be requested in the search.
        """
        attributes = set()
        for mapping in self.values():
            attributes.update(mapping.attributes())
        return list(attributes)

    def mk_filter(self, attribute, value):
        """Construct a search filter for the attribute value combination."""
        mapping = self.get(attribute, SimpleMapping(attribute))
        return mapping.mk_filter(value)

    def translate(self, variables):
        """Return a dictionary with every attribute mapped to their value."""
        results = dict()
        for attribute, mapping in self.items():
            results[attribute] = mapping.values(variables)
        return results

    def get_rdn_value(self, dn, attribute):
        """Extract the attribute value from from DN or return None."""
        return self.translate(dict(
            (x, [y])
            for x, y, z in ldap.dn.str2dn(dn)[0]
        ))[attribute][0]
