
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

    action: the NSLCD_ACTION_* action that should trigger this handler
    read_parameters: a function that reads the request parameters of the
                     request stream
    filter: LDAP search filter
    mk_filter (optional): function that returns the LDAP search filter
    write: function that writes a single LDAP entry to the result stream
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

    def attributes(self):
        """Return the attributes that should be used in the LDAP search."""
        return self.attmap.attributes()

    def mk_filter(self, parameters):
        """Return the active search filter (based on the read parameters)."""
        if parameters:
            return '(&%s(%s))' % ( self.filter,
                ')('.join('%s=%s' % (self.attmap[attribute],
                                     ldap.filter.escape_filter_chars(str(value)))
                          for attribute, value in parameters.items()) )
        return self.filter

    def handle_request(self, parameters):
        """This method handles the request based on the parameters read
        with read_parameters()."""
        # get search results
        for base in self.bases:
            # do the LDAP search
            try:
                res = self.conn.search_s(base, self.scope, self.mk_filter(parameters), self.attributes())
                for entry in res:
                    if entry[0]:
                        self.write(entry[0], self.attmap.mapped(entry[1]), parameters)
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
