# coding: utf-8

# nslcd.py - functions for doing nslcd requests
#
# Copyright (C) 2013 Arthur de Jong
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

import fcntl
import os
import socket
import struct

import constants


# definition for reading and writing INT32 values
_int32 = struct.Struct('!i')


class NslcdClient(object):

    def __init__(self, action):
        # set up the socket (store in class to avoid closing it)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        fcntl.fcntl(self.sock, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        # connect to nslcd
        self.sock.connect(constants.NSLCD_SOCKET)
        #self.sock.setblocking(1)
        self.fp = os.fdopen(self.sock.fileno(), 'r+b', 1024 * 1024)
        # write a request header with a request code
        self.action = action
        self.write_int32(constants.NSLCD_VERSION)
        self.write_int32(action)

    def write(self, value):
        self.fp.write(value)

    def write_int32(self, value):
        self.write(_int32.pack(value))

    def write_string(self, value):
        self.write_int32(len(value))
        self.write(value)

    def write_ether(self, value):
        value = struct.pack('BBBBBB', *(int(x, 16) for x in value.split(':')))
        self.write(value)

    def write_address(self, af, value):
        self.write_int32(af)
        self.write_string(value)

    def read(self, size):
        return self.fp.read(size)

    def read_int32(self):
        return _int32.unpack(self.read(_int32.size))[0]

    def read_string(self):
        num = self.read_int32()
        return self.read(num)

    def read_stringlist(self):
        num = self.read_int32()
        return [self.read_string() for x in xrange(num)]

    def read_ether(self):
        value = self.fp.read(6)
        return ':'.join('%x' % x for x in struct.unpack('6B', value))

    def read_address(self):
        af = self.read_int32()
        return af, socket.inet_ntop(af, self.read_string())

    def read_addresslist(self):
        num = self.read_int32()
        return [self.read_address() for x in xrange(num)]

    def get_response(self):
        # complete the request if required and check response header
        if self.action:
            # flush the stream
            self.fp.flush()
            # read and check response version number
            assert self.read_int32() == constants.NSLCD_VERSION
            assert self.read_int32() == self.action
            self.action = None
        # get the NSLCD_RESULT_* marker and return it
        return self.read_int32()

    def close(self):
        if hasattr(self, 'fp'):
            try:
                self.fp.close()
            except IOError:
                pass

    def __del__(self):
        self.close()


def usermod(username, asroot=False, password=None, args=None):
    # open a connection to nslcd
    con = NslcdClient(constants.NSLCD_ACTION_USERMOD)
    # write the request information
    con.write_string(username)
    con.write_int32(1 if asroot else 0)
    con.write_string(password)
    for k, v in args.items():
        con.write_int32(k)
        con.write_string(v)
    con.write_int32(constants.NSLCD_USERMOD_END)
    # read the response
    assert con.get_response() == constants.NSLCD_RESULT_BEGIN
    response = {}
    while True:
        key = con.read_int32()
        if key == constants.NSLCD_USERMOD_END:
            break
        response[key] = con.read_string()
    # return the response
    return response
