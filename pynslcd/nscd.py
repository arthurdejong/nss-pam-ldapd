
# nscd.py - functions for invalidating the nscd cache
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
import logging
import os
import subprocess
import struct

import cfg


# the file descriptor used for sending messages to the child process
signalfd = None


# mapping between map name and signal character
_db_to_char = dict(
        aliases='A', ethers='E', group='G', hosts='H', netgroup='U',
        networks='N', passwd='P', protocols='L', rpc='R', services='V',
        shadow='S',
    )
_char_to_db = dict((reversed(item) for item in _db_to_char.items()))


def exec_invalidate(db):
    logging.debug('nscd_invalidator: nscd -i %s', db)
    try:
        p = subprocess.Popen(['nscd', '-i', 'passwd'],
                             bufsize=4096, close_fds=True,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, ignored = p.communicate()
        if output:
            output = ': %s' % output[:1024].strip()
        if p.returncode == 0:
            logging.debug('nscd_invalidator: nscd -i %s (pid %d) success%s',
                          db, p.pid, output)
        elif p.returncode > 0:
            logging.debug('nscd_invalidator: nscd -i %s (pid %d) failed (%d)%s',
                          db, p.pid, p.returncode, output)
        else:  # p.returncode < 0
            logging.error('nscd_invalidator: nscd -i %s (pid %d) killed by signal %d%s',
                          db, p.pid, -p.returncode, output)
    except:
        logging.warn('nscd_invalidator: nscd -i %s failed', db, exc_info=True)


def loop(fd):
    # set process title
    try:
        import setproctitle
        setproctitle.setproctitle('(nscd invalidator)')
    except ImportError:
        pass
    # set up clean environment
    os.chdir('/')
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    while True:
        db = os.read(fd, 1)
        # FIXME: define the characters and maps somewhere
        if db == '':
            break
        db = _char_to_db.get(db, None)
        if db:
            exec_invalidate(db)


def start_invalidator():
    r, w = os.pipe()
    # mark write end as non-blocking
    flags = fcntl.fcntl(w, fcntl.F_GETFL)
    fcntl.fcntl(w, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    cpid = os.fork()
    if cpid == 0:
        # we are the child
        os.close(w)
        loop(r)
        os._exit(1)
    # we are the parent
    global signalfd
    signalfd = w
    os.close(r)


def invalidate(db=None):
    if signalfd is None:
        return  # nothing to do
    if db:
        db = _db_to_char.get(db, '')
    else:
        db = ''.join(_db_to_char[x] for x in cfg.nscd_invalidate)
    try:
        os.write(signalfd, db)
    except:
        logging.warn('nscd_invalidator: nscd -i %s failed', db, exc_info=True)
