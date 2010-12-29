
# debugio.py - module for debugging an I/O stream
#
# Copyright (C) 2008, 2009 Arthur de Jong
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

class DebugIO():
    """This class is a file-like object that writes from one file and
    writes to another. It is mainly used for debugging the serial protocol
    without a serial connection."""

    def __init__(self, name):
        import os
        if not os.path.exists(name+'.in'): os.mkfifo(name+'.in')
        if not os.path.exists(name+'.out'): os.mkfifo(name+'.out')
        r = open(name+'.in', 'r', 0)
        w = open(name+'.out', 'w', 0)
        self._r = r
        self._w = w
        self.write = w.write
        self.portstr = 'debuging to %s.in and %s.out' % ( name, name )
        self._timeout = None

    def close(self):
        self._r.close()
        self._w.close()

    def inWaiting(self):
        # we are never out of data and 100 should be enough for everybody
        return 100

    def setTimeout(self, seconds):
        self._timeout = seconds

    def getTimeout(self):
        return self._timeout

    def read(self, size):
        import select
        read = ''
        if size > 0:
            while len(read) < size:
                ready, _, _ = select.select([self._r.fileno()], [], [], self._timeout)
                if not ready:
                    break   #timeout
                buf = self._r.read(size-len(read))
                read = read + buf
                if self._timeout >= 0 and not buf:
                    break  #early abort on timeout
        return read

