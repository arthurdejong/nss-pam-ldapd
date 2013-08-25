
# tio.py - I/O functions
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

import os
import socket
import struct


# definition for reading and writing INT32 values
_int32 = struct.Struct('!i')

# FIXME: use something from constants.py to determine the correct size
_struct_timeval = struct.Struct('ll')


class TIOStreamError(Exception):
    pass


class TIOStream(object):
    """File-like object that allows reading and writing nslcd-protocol
    entities."""

    def __init__(self, conn):
        conn.setblocking(1)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, _struct_timeval.pack(0, 500000))
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, _struct_timeval.pack(60, 0))
        self.fp = os.fdopen(conn.fileno(), 'w+b', 1024 * 1024)

    def read(self, size):
        return self.fp.read(size)

    def read_int32(self):
        return _int32.unpack(self.read(_int32.size))[0]

    def read_string(self, maxsize=None):
        num = self.read_int32()
        if maxsize and num >= maxsize:
            raise TIOStreamError()
        return self.read(num)

    def read_address(self):
        """Read an address (usually IPv4 or IPv6) from the stream and return
        the address as a string representation."""
        af = self.read_int32()
        return socket.inet_ntop(af, self.read_string(maxsize=64))

    def write(self, value):
        self.fp.write(value)

    def write_int32(self, value):
        self.write(_int32.pack(value))

    def write_string(self, value):
        self.write_int32(len(value))
        self.write(value)

    def write_stringlist(self, value):
        lst = tuple(value)
        self.write_int32(len(lst))
        for string in lst:
            self.write_string(string)

    @staticmethod
    def _to_address(value):
        # try IPv4 first
        try:
            return socket.AF_INET, socket.inet_pton(socket.AF_INET, value)
        except socket.error:
            pass  # try the next one
        # fall back to IPv6
        return socket.AF_INET6, socket.inet_pton(socket.AF_INET6, value)

    def write_address(self, value):
        """Write an address (usually IPv4 or IPv6) in a string representation
        to the stream."""
        # first try to make it into an IPv6 address
        af, address = TIOStream._to_address(value)
        self.write_int32(af)
        self.write_string(address)

    def close(self):
        try:
            self.fp.close()
        except IOError:
            pass

    def __del__(self):
        self.close()
