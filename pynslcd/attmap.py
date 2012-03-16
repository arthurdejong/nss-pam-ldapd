
# attmap.py - attribute mapping class
#
# Copyright (C) 2011, 2012 Arthur de Jong
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

>>> attrs = Attributes(uid='uid',
...                    userPassword='userPassword',
...                    uidNumber='uidNumber',
...                    gidNumber='gidNumber',
...                    gecos='"${gecos:-$cn}"',
...                    homeDirectory='homeDirectory',
...                    loginShell='loginShell')
>>> 'cn' in attrs.attributes()
True
>>> attrs.translate({'uid': ['UIDVALUE', '2nduidvalue'], 'cn': ['COMMON NAME', ]})
{'uid': ['UIDVALUE', '2nduidvalue'], 'loginShell': [], 'userPassword': [], 'uidNumber': [], 'gidNumber': [], 'gecos': ['COMMON NAME'], 'homeDirectory': []}
>>> attrs['uidNumber']  # a representation fit for logging and filters
'uidNumber'
>>> attrs['gecos']
'"${gecos:-$cn}"'
"""

import ldap
import re
from ldap.filter import escape_filter_chars as escape


# exported names
__all__ = ('Attributes', )


# FIXME: support multiple attribute values
# TODO: support objectSid attributes
# TODO: do more expression validity checking


# regular expression to match function attributes
attribute_func_re = re.compile('^(?P<function>[a-z]+)\((?P<attribute>.*)\)$')


class MyIter(object):
    """Custom iterator-like class with a back() method."""

    def __init__(self, value):
        self.value = value
        self.pos = 0

    def next(self):
        self.pos += 1
        return self.value[self.pos - 1]

    def back(self):
        self.pos -= 1

    def __iter__(self):
        return self

    def get_name(self):
        """Read a variable name from the value iterator."""
        name = ''
        for c in self:
            if not c.isalnum():
                self.back()
                return name
            name += c
        return name


class DollarExpression(object):
    """Class for handling a variable $xxx ${xxx}, ${xxx:-yyy} or ${xxx:+yyy}
    expression."""

    def __init__(self, value):
        """Parse the expression as the start of a $-expression."""
        self.op = None
        self.expr = None
        c = value.next()
        if c == '{':
            self.name = value.get_name()
            c = value.next()
            if c == '}':
                return
            self.op = c + value.next()
            self.expr = Expression(value, endat='}')
        elif c == '(':
            self.name = None
            self.op = value.get_name()
            c = value.next()
            if c != '(':
                raise ValueError("Expecting '('")
            self.expr = Expression(value, endat=')')
            c = value.next()
            if c != ')':
                raise ValueError("Expecting ')'")
        else:
            value.back()
            self.name = value.get_name()

    def value(self, variables):
        """Expand the expression using the variables specified."""
        value = variables.get(self.name, [''])[0]
        # FIXME: expand list
        if self.op == ':-':
            return value if value else self.expr.value(variables)
        elif self.op == ':+':
            return self.expr.value(variables) if value else ''
        elif self.op == 'lower':
            return self.expr.value(variables).lower()
        elif self.op == 'upper':
            return self.expr.value(variables).upper()
        return value

    def variables(self, results):
        """Add the variables used in the expression to results."""
        if self.name:
            results.add(self.name)
        if self.expr:
            self.expr.variables(results)


class Expression(object):
    """Class for parsing and expanding an expression."""

    def __init__(self, value, endat=None):
        """Parse the expression as a string."""
        if not isinstance(value, MyIter):
            self.expression = value
            value = MyIter(value)
        if not endat:
            endat = value.next()  # skip opening quote
        expr = []
        literal = ''
        c = value.next()
        while c != endat:
            if c == '$':
                if literal:
                    expr.append(literal)
                expr.append(DollarExpression(value))
                literal = ''
            elif c == '\\':
                literal += value.next()
            else:
                literal += c
            c = value.next()
        if literal:
            expr.append(literal)
        self.expr = expr

    def value(self, variables):
        """Expand the expression using the variables specified."""
        res = ''
        for x in self.expr:
            if hasattr(x, 'value'):
                res += x.value(variables)
            else:
                res += x
        return res

    def variables(self, results=None):
        """Return the variables defined in the expression."""
        if not results:
            results = set()
        for x in self.expr:
            if hasattr(x, 'variables'):
                x.variables(results)
        return results

    def __str__(self):
        return self.expression

    def __repr__(self):
        return repr(str(self))


class SimpleMapping(str):
    """Simple mapping to another attribute name."""

    def attributes(self):
        return [self]

    def mk_filter(self, value):
        return '(%s=%s)' % (self, escape(str(value)))

    def values(self, variables):
        """Expand the expression using the variables specified."""
        return variables.get(self, [])


class ExpressionMapping(str):
    """Class for parsing and expanding an expression."""

    def __init__(self, value):
        """Parse the expression as a string."""
        self.expression = Expression(value)

    def values(self, variables):
        """Expand the expression using the variables specified."""
        return [self.expression.value(variables)]

    def attributes(self):
        """Return the attributes defined in the expression."""
        return self.expression.variables()


class FunctionMapping(str):
    """Mapping to a function to another attribute."""

    def __init__(self, mapping):
        self.mapping = mapping
        m = attribute_func_re.match(mapping)
        self.attribute = m.group('attribute')
        self.function = getattr(self, m.group('function'))

    def upper(self, value):
        return value.upper()

    def lower(self, value):
        return value.lower()

    def attributes(self):
        return [self.attribute]

    def mk_filter(self, value):
        return '(%s=%s)' % (self.attribute, escape(value))

    def values(self, variables):
        return [self.function(value)
                for value in variables.get(self.attribute, [])]


class Attributes(dict):
    """Dictionary-like class for handling attribute mapping."""

    def __init__(self, *args, **kwargs):
        self.update(*args, **kwargs)

    def __setitem__(self, attribute, mapping):
        # translate the mapping into a mapping object
        if mapping[0] == '"':
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
        """Return the list of attributes that are referenced in this
        attribute mapping. These are the attributes that should be
        requested in the search."""
        attributes = set()
        for mapping in self.itervalues():
            attributes.update(mapping.attributes())
        return list(attributes)

    def mk_filter(self, attribute, value):
        """Construct a search filter for searching for the attribute value
        combination."""
        mapping = self.get(attribute, SimpleMapping(attribute))
        return mapping.mk_filter(value)

    def translate(self, variables):
        """Return a dictionary with every attribute mapped to their value from
        the specified variables."""
        results = dict()
        for attribute, mapping in self.iteritems():
            results[attribute] = mapping.values(variables)
        return results

    def get_rdn_value(self, dn, attribute):
        """Extract the attribute value from from DN if possible. Return None
        otherwise."""
        return self.translate(dict((x, [y]) for x, y, z in ldap.dn.str2dn(dn)[0]))[attribute][0]
