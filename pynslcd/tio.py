
# tio.py - I/O functions
#
# Copyright (C) 2010 Arthur de Jong
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

import struct
import os
import socket
import errno

# definition for reading and writing INT32 values
_int32 = struct.Struct('i')

# FIXME: use something from config.py to determine the correct size
_uid_t = struct.Struct('i')

# FIXME: use something from config.py to determine the correct size
_gid_t = struct.Struct('i')

# FIXME: use something from config.py to determine the correct size
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
        self.fp = os.fdopen(conn.fileno(), 'w+b', 1024*1024)

    def read(self, size):
        return self.fp.read(size)

    def read_int32(self):
        return _int32.unpack(self.read(_int32.size))[0]

    def read_uid_t(self):
        return _uid_t.unpack(self.read(_uid_t.size))[0]

    def read_gid_t(self):
        return _gid_t.unpack(self.read(_gid_t.size))[0]

    def read_string(self, maxsize=None):
        len = self.read_int32()
        if maxsize and len >= maxsize:
            raise TIOStreamError()
        return self.read(len)

    def write(self, value):
        self.fp.write(value)

    def write_int32(self, value):
        self.write(_int32.pack(value))

    def write_uid_t(self, value):
        self.write(_uid_t.pack(value))

    def write_gid_t(self, value):
        self.write(_gid_t.pack(value))

    def write_string(self, value):
        self.write_int32(len(value))
        self.write(value)

    def write_stringlist(self, value):
        lst = tuple(value)
        self.write_int32(len(lst))
        for string in lst:
            self.write_string(string)

    def close(self):
        try:
            self.fp.close()
        except IOError:
            pass

    def __del__(self):
        self.close()
