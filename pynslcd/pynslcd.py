#!/usr/bin/env python

# pynslcd.py - main daemon module
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

import os
import sys
import daemon
import mypidfile
import threading
import logging
import logging.handlers
import signal
import ldap

import constants  # from nslcd.h
import config     # from configure
import cfg        # from nslcd.conf
import common

from tio import TIOStream


# configure logging
class MyFormatter(logging.Formatter):
    def format(self, record):
        msg = logging.Formatter.format(self, record)
        if record.levelno == logging.DEBUG:
            msg = 'DEBUG: %s' % msg
        return msg
#logging.basicConfig(level=logging.INFO)
# , format='%(message)s'
formatter = MyFormatter('%(message)s')
stderrhandler = logging.StreamHandler(sys.stderr)
stderrhandler.setFormatter(formatter)
##sysloghandler = logging.handlers.SysLogHandler(address='/dev/log')
##sysloghandler.setFormatter(formatter)
#logging.getLogger().setFormatter(MyFormatter())
logging.getLogger().addHandler(stderrhandler)

#logger = logging.getLogger()
#logger.setLevel(logging.INFO)
#syslog = logging.handlers.SysLogHandler(address='/dev/log')
#formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
#syslog.setFormatter(formatter)
#logger.addHandler(syslog)

def display_version(fp):
    fp.write('%(PACKAGE_STRING)s\n'
             'Written by Arthur de Jong.\n'
             '\n'
             'Copyright (C) 2010 Arthur de Jong\n'
             'This is free software; see the source for copying conditions.  There is NO\n'
             'warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n'
             % { 'PACKAGE_STRING': config.PACKAGE_STRING, } );

def display_usage(fp):
    fp.write("Usage: %(program_name)s [OPTION]...\n"
             "Name Service LDAP connection daemon.\n"
             "  -c, --check        check if the daemon already is running\n"
             "  -d, --debug        don't fork and print debugging to stderr\n"
             "      --help         display this help and exit\n"
             "      --version      output version information and exit\n"
             "\n"
             "Report bugs to <%(PACKAGE_BUGREPORT)s>.\n"
             % { 'program_name': cfg.program_name,
                 'PACKAGE_BUGREPORT': config.PACKAGE_BUGREPORT, } )

def parse_cmdline():
    """Parse command-line arguments."""
    import getopt
    cfg.program_name = sys.argv[0] or 'pynslcd'
    try:
        optlist, args = getopt.gnu_getopt(sys.argv[1:],
          'cdhV', ('check', 'debug', 'help', 'version', ))
        for flag, arg in optlist:
            if flag in ('-c', '--check'):
                cfg.check = True
            elif flag in ('-d', '--debug'):
                cfg.debug += 1
            elif flag in ('-h', '--help'):
                display_usage(sys.stdout)
                sys.exit(0)
            elif flag in ('-V', '--version'):
                display_version(sys.stdout)
                sys.exit(0)
        if len(args):
            raise getopt.GetoptError('unrecognized option \'%s\'' % args[0], args[0])
    except getopt.GetoptError, reason:
        sys.stderr.write("%(program_name)s: %(reason)s\n"
                         "Try '%(program_name)s --help' for more information.\n"
                          % { 'program_name': cfg.program_name,
                              'reason': reason, })
        sys.exit(1)

def create_socket():
    """Returns a socket ready to answer requests from the client."""
    import socket
    import fcntl
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    # remove existing named socket
    try:
        os.unlink(config.NSLCD_SOCKET)
    except OSError:
        pass # ignore any problems
    # bind to named socket
    sock.bind((config.NSLCD_SOCKET))
    # close the file descriptor on exit
    fcntl.fcntl(sock, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
    # set permissions of socket so anybody can do requests
    os.chmod(config.NSLCD_SOCKET, 0666)
    # start listening for connections
    sock.listen(socket.SOMAXCONN)
    return sock

def log_newsession():
    pass
    # FIXME: implement

def getpeercred(fd):
    return (None, None, None)
    # FIXME: implement and return uid, gid, pid

handlers = {}
handlers.update(common.get_handlers('alias'))
handlers.update(common.get_handlers('ether'))
handlers.update(common.get_handlers('group'))
handlers.update(common.get_handlers('pam'))
handlers.update(common.get_handlers('passwd'))
handlers.update(common.get_handlers('shadow'))

def acceptconnection(session):
    # accept a new connection
    conn, addr = nslcd_serversocket.accept()
    # See: http://docs.python.org/library/socket.html#socket.socket.settimeout
    fp = None
    try:
        # probably use finally
        # indicate new connection to logging module (genrates unique id)
        log_newsession()
        # log connection
        try:
            uid, gid, pid = getpeercred(conn)
            logging.debug('connection from pid=%r uid=%r gid=%r', pid, uid, gid)
        except:
            raise # FIXME: handle exception gracefully
        # create a stream object
        fp = TIOStream(conn)
        # read request
        version = fp.read_int32()
        if version != constants.NSLCD_VERSION:
            logging.debug('wrong nslcd version id (%r)', version)
            return
        action = fp.read_int32()
        try:
            handler = handlers[action]
        except KeyError:
            logging.warn('invalid action id: %r', action)
            return
        handler(fp, session, uid)()
    finally:
        if fp:
            fp.close()

def disable_nss_ldap():
    """Disable the nss_ldap module to avoid lookup loops."""
    import ctypes
    lib = ctypes.CDLL(config.NSS_LDAP_SONAME)
    ctypes.c_int.in_dll(lib, '_nss_ldap_enablelookups').value = 0

def worker():
    # create a new LDAP session
    #session = myldap_create_session()
    session = ldap.initialize(cfg.ldap_uri)
    # start waiting for incoming connections
    while True:
        # wait for a new connection
        acceptconnection(session)
        # FIXME: handle exceptions

if __name__ == '__main__':
    # parse options
    parse_cmdline()
    # clean the environment
    os.environ.clear()
    os.putenv('HOME', '/')
    os.putenv('TMPDIR', '/tmp')
    os.putenv('LDAPNOINIT', '1')
    # disable ldap lookups of host names to avoid lookup loop
    disable_nss_ldap()
    # set log level
    if cfg.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    # FIXME: implement
    #if myldap_set_debuglevel(cfg.debug) != LDAP_SUCCESS:
    #    sys.exit(1)
    # read configuration file
    cfg.read(config.NSLCD_CONF_PATH)
    # set a default umask for the pidfile and socket
    os.umask(0022)
    # see if someone already locked the pidfile
    pidfile = mypidfile.MyPIDLockFile(config.NSLCD_PIDFILE)
    # see if --check option was given
    if cfg.check:
        if pidfile.is_locked():
            logging.debug('pidfile (%s) is locked', config.NSLCD_PIDFILE)
            sys.exit(0)
        else:
            logging.debug('pidfile (%s) is not locked', config.NSLCD_PIDFILE)
            sys.exit(1)
    # normal check for pidfile locked
    if pidfile.is_locked():
        logging.error('daemon may already be active, cannot acquire lock (%s)', config.NSLCD_PIDFILE)
        sys.exit(1)
    # daemonize
    if cfg.debug:
        daemon = pidfile
    else:
        daemon = daemon.DaemonContext(
                      pidfile=pidfile,
                      signal_map={
                          signal.SIGTERM: 'terminate',
                          signal.SIGINT:  'terminate',
                          signal.SIGPIPE: None,
                      })
    # start daemon
    with daemon:
        # start normal logging
        if not cfg.debug:
            log_startlogging();
        logging.info('version %s starting', config.VERSION)
        # create socket
        nslcd_serversocket = create_socket();
        # drop all supplemental groups
        try:
            os.setgroups(())
        except OSError, e:
            logging.warn('cannot setgroups(()) (ignored): %s', e)
        # change to nslcd gid
        if cfg.gid is not None:
            import grp
            os.setgid(grp.getgrnam(cfg.gid).gr_gid)
        # change to nslcd uid
        if cfg.uid is not None:
            import pwd
            u = pwd.getpwnam(cfg.uid)
            os.setuid(u.pw_uid)
            os.environ['HOME'] = u.pw_dir
        logging.info('accepting connections')
        # start worker threads
        threads = []
        for i in range(cfg.threads):
            thread = threading.Thread(target=worker, name='thread%d' % i)
            thread.setDaemon(True)
            thread.start()
            logging.debug('started thread %s' % thread.getName())
            threads.append(thread)
        # wait for all threads to die
        for thread in threads:
            thread.join(10000)
