
# invalidator.py - functions for invalidating external caches
#
# Copyright (C) 2013-2019 Arthur de Jong
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

import cfg


# the file descriptor used for sending messages to the child process
signalfd = None


# mapping between map name and signal character
_db_to_char = dict(
    aliases='A', ethers='E', group='G', hosts='H', netgroup='U',
    networks='N', passwd='P', protocols='L', rpc='R', services='V',
    shadow='S', nfsidmap='F',
)
_char_to_db = dict((reversed(item) for item in _db_to_char.items()))


def exec_invalidate(*args):
    cmd = ' '.join(args)
    logging.debug('invalidator: %s', cmd)
    try:
        p = subprocess.Popen(args, bufsize=4096, close_fds=True,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, ignored = p.communicate()
        if output:
            output = ': %s' % output[:1024].strip()
        if p.returncode == 0:
            logging.debug('invalidator: %s (pid %d) success%s',
                          cmd, p.pid, output)
        elif p.returncode > 0:
            logging.debug('invalidator: %s (pid %d) failed (%d)%s',
                          cmd, p.pid, p.returncode, output)
        else:  # p.returncode < 0
            logging.error('invalidator: %s (pid %d) killed by signal %d%s',
                          cmd, p.pid, -p.returncode, output)
    except Exception:
        logging.warning('invalidator: %s failed', cmd, exc_info=True)


def loop(fd):
    # set process title
    try:
        import setproctitle
        setproctitle.setproctitle('(invalidator)')
    except ImportError:
        pass
    # set up clean environment
    os.chdir('/')
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    while True:
        db = os.read(fd, 1).decode('ascii')
        if db == '':
            break  # close process down
        db = _char_to_db.get(db, None)
        if db == 'nfsidmap':
            exec_invalidate('nfsidmap', '-c')
        elif db:
            exec_invalidate('nscd', '-i', db)


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
        db = ''.join(_db_to_char[x] for x in cfg.reconnect_invalidate)
    try:
        os.write(signalfd, db.encode('ascii'))
    except Exception:
        logging.warning('requesting invalidation (%s) failed', db, exc_info=True)
