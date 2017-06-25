
# mypidfile.py - functions for properly locking a PIDFile
#
# Copyright (C) 2010-2017 Arthur de Jong
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

import errno
import fcntl
import os

import cfg


class MyPIDLockFile(object):
    """Implementation of a PIDFile fit for use with the daemon module
    that locks the PIDFile with fcntl.lockf()."""

    def __init__(self, path):
        self.path = path

    def __enter__(self):
        """Lock the PID file and write the process ID to the file."""
        # create the directory for the pidfile if needed
        piddir = os.path.dirname(self.path)
        if not os.path.isdir(piddir):
            os.mkdir(piddir)
            u, gid = cfg.get_usergid()
            os.chown(piddir, u.u.pw_uid, gid)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0644)
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            pidfile = os.fdopen(fd, 'w')
        except:
            os.close(fd)
            raise
        pidfile.write('%d\n' % os.getpid())
        pidfile.truncate()
        pidfile.flush()
        self.pidfile = pidfile
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Release the lock (close the lockfile)."""
        fcntl.lockf(self.pidfile.fileno(), fcntl.LOCK_UN)
        self.pidfile.close()
        del self.pidfile

    def is_locked(self):
        """Check whether the file is already present and locked."""
        try:
            fd = os.open(self.path, os.O_RDWR, 0644)
            # Python doesn't seem to have F_TEST so we'll just try to lock
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # if we're here we must have aquired the lock
            fcntl.lockf(fd, fcntl.LOCK_UN)
            return False
        except (IOError, OSError), e:
            if e.errno == errno.ENOENT:
                return False
            if e.errno in (errno.EACCES, errno.EAGAIN):
                return True
            raise
        finally:
            if 'fd' in locals():
                os.close(fd)
