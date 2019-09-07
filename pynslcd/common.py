
# common.py - functions that are used by different modules
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
import sys

import ldap

from attmap import Attributes  # noqa: F401 (used by other modules)
import cfg
import constants


def is_valid_name(name):
    """Check if the specified name seems to be a valid user or group name.

    This test is based on the definition from POSIX (IEEE Std 1003.1, 2004,
    3.426 User Name, 3.189 Group Name and 3.276 Portable Filename Character
    Set):
    http://www.opengroup.org/onlinepubs/009695399/basedefs/xbd_chap03.html#tag_03_426
    http://www.opengroup.org/onlinepubs/009695399/basedefs/xbd_chap03.html#tag_03_189
    http://www.opengroup.org/onlinepubs/009695399/basedefs/xbd_chap03.html#tag_03_276

    The standard defines user names valid if they contain characters from the
    set [A-Za-z0-9._-] where the hyphen should not be used as first
    character. As an extension this test allows some more characters.
    """
    return bool(cfg.validnames.search(name))


def validate_name(name):
    """Check if the specified name seems to be a valid user or group name.

    This raises an exception if this is not the case.
    """
    if not cfg.validnames.search(name):
        raise ValueError('%r: denied by validnames option' % name)


class Request(object):
    """Request handler class.

    Subclasses are expected to handle actual requests and should implement
    the following members:

      action - the NSLCD_ACTION_* action that should trigger this handler
      read_parameters() - a function that reads the request parameters of the
                          request stream
      write() - function that writes a single LDAP entry to the result stream
      convert() - function that generates result entries from an LDAP result

    """

    def __init__(self, fp, conn, calleruid):
        self.fp = fp
        self.conn = conn
        self.calleruid = calleruid
        module = sys.modules[self.__module__]
        self.search = getattr(module, 'Search', None)
        self.cache = None

    def read_parameters(self, fp):
        """Read and return the parameters from the stream."""
        pass

    def get_results(self, parameters):
        """Provide the result entries by performing a search."""
        for dn, attributes in self.search(self.conn, parameters=parameters):
            for values in self.convert(dn, attributes, parameters):
                yield values

    def handle_request(self, parameters):
        """Handle the request based on the parameters."""
        try:
            for values in self.get_results(parameters):
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

    def log(self, parameters):
        parameters = dict(parameters)
        for param in ('password', 'oldpassword', 'newpassword'):
            if parameters.get(param):
                parameters[param] = '***'
        logging.debug('%s(%r)', self.__class__.__name__, parameters)

    def __call__(self):
        parameters = self.read_parameters(self.fp) or {}
        self.log(parameters)
        self.fp.write_int32(constants.NSLCD_VERSION)
        self.fp.write_int32(self.action)
        self.handle_request(parameters)


def get_handlers(module):
    """Return a dictionary mapping actions to Request classes."""
    import inspect
    res = {}
    if isinstance(module, (type(''), type(u''))):
        module = __import__(module, globals())
    for name, cls in inspect.getmembers(module, inspect.isclass):
        if issubclass(cls, Request) and hasattr(cls, 'action'):
            res[cls.action] = cls
    return res
