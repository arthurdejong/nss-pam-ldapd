#!/usr/bin/env python

# pynslcd.py - main daemon module
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
import logging.handlers
import os
import signal
import sys
import syslog
import threading

import daemon
import ldap

import cfg
import common
import constants
import invalidator
import mypidfile
import search
from tio import TIOStream


# the name of the program
program_name = 'pynslcd'

# flag to indicate whether we are in debugging mode
debugging = 0

# flag to indicate we shouldn't daemonize
nofork = False

# flag to indicate user requested the --check option
checkonly = False


class MyFormatter(logging.Formatter):

    def format(self, record):
        record.prefix = 'DEBUG: ' if record.levelno == logging.DEBUG else ''
        return super(MyFormatter, self).format(record)


class MySysLogHandler(logging.Handler):

    mapping = {
        logging.DEBUG: syslog.LOG_DEBUG,
        logging.INFO: syslog.LOG_INFO,
        logging.WARNING: syslog.LOG_WARNING,
        logging.ERROR: syslog.LOG_ERR,
        logging.CRITICAL: syslog.LOG_CRIT,
    }

    def __init__(self):
        super(MySysLogHandler, self).__init__()
        syslog.openlog(program_name, syslog.LOG_PID, syslog.LOG_DAEMON)

    def emit(self, record):
        priority = self.mapping.get(record.levelno, syslog.LOG_WARNING)
        msg = self.format(record)
        for line in msg.splitlines():
            syslog.syslog(priority, line)


# configure logging
stderrhandler = logging.StreamHandler(sys.stderr)
stderrhandler.setFormatter(MyFormatter('pynslcd: %(prefix)s%(message)s'))
logging.getLogger().addHandler(stderrhandler)
logging.getLogger().setLevel(logging.INFO)


def display_version(fp):
    fp.write('%(PACKAGE_STRING)s\n'
             'Written by Arthur de Jong.\n'
             '\n'
             'Copyright (C) 2010-2019 Arthur de Jong\n'
             'This is free software; see the source for copying conditions.  There is NO\n'
             'warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n'
             % {'PACKAGE_STRING': constants.PACKAGE_STRING})


def display_usage(fp):
    fp.write("Usage: %(program_name)s [OPTION]...\n"
             "Name Service LDAP connection daemon.\n"
             "  -c, --check        check if the daemon already is running\n"
             "  -d, --debug        don't fork and print debugging to stderr\n"
             "  -n, --nofork       don't fork\n"
             "      --help         display this help and exit\n"
             "      --version      output version information and exit\n"
             "\n"
             "Report bugs to <%(PACKAGE_BUGREPORT)s>.\n"
             % {'program_name': program_name,
                'PACKAGE_BUGREPORT': constants.PACKAGE_BUGREPORT})


def parse_cmdline():
    """Parse command-line arguments."""
    import getopt
    global program_name
    program_name = sys.argv[0] or program_name
    try:
        optlist, args = getopt.gnu_getopt(
            sys.argv[1:], 'cdnhV',
            ('check', 'debug', 'nofork', 'help', 'version'))
        for flag, arg in optlist:
            if flag in ('-c', '--check'):
                global checkonly
                checkonly = True
            elif flag in ('-d', '--debug'):
                global debugging
                debugging += 1
            elif flag in ('-n', '--nofork'):
                global nofork
                nofork = True
            elif flag in ('-h', '--help'):
                display_usage(sys.stdout)
                sys.exit(0)
            elif flag in ('-V', '--version'):
                display_version(sys.stdout)
                sys.exit(0)
        if len(args):
            raise getopt.GetoptError('unrecognized option \'%s\'' % args[0], args[0])
    except getopt.GetoptError as reason:
        sys.stderr.write(
            "%(program_name)s: %(reason)s\n"
            "Try '%(program_name)s --help' for more information.\n" % {
                'program_name': program_name,
                'reason': reason,
            })
        sys.exit(1)


def create_socket():
    """Return a socket ready to answer requests from the client."""
    import socket
    import fcntl
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    # remove existing named socket
    try:
        os.unlink(constants.NSLCD_SOCKET)
    except OSError:
        pass  # ignore any problems
    # bind to named socket
    sock.bind(constants.NSLCD_SOCKET)
    # close the file descriptor on exit
    fcntl.fcntl(sock, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
    # set permissions of socket so anybody can do requests
    os.chmod(constants.NSLCD_SOCKET, 0o666)
    # start listening for connections
    sock.listen(socket.SOMAXCONN)
    return sock


def log_newsession():
    pass
    # FIXME: implement


def getpeercred(fd):
    """Return uid, gid and pid of calling application."""
    import struct
    import socket
    try:
        SO_PEERCRED = getattr(socket, 'SO_PEERCRED', 17)  # noqa: N806
        creds = fd.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize('3i'))
        pid, uid, gid = struct.unpack('3i', creds)
        return uid, gid, pid
    except socket.error:
        return None, None, None


handlers = {}
handlers.update(common.get_handlers('config'))
handlers.update(common.get_handlers('alias'))
handlers.update(common.get_handlers('ether'))
handlers.update(common.get_handlers('group'))
handlers.update(common.get_handlers('host'))
handlers.update(common.get_handlers('netgroup'))
handlers.update(common.get_handlers('network'))
handlers.update(common.get_handlers('passwd'))
handlers.update(common.get_handlers('protocol'))
handlers.update(common.get_handlers('rpc'))
handlers.update(common.get_handlers('service'))
handlers.update(common.get_handlers('shadow'))
handlers.update(common.get_handlers('pam'))
handlers.update(common.get_handlers('usermod'))


def acceptconnection(nslcd_serversocket, session):
    # accept a new connection
    conn, addr = nslcd_serversocket.accept()
    # See: http://docs.python.org/library/socket.html#socket.socket.settimeout
    fp = None
    try:
        # indicate new connection to logging module (generates unique id)
        log_newsession()
        # log connection
        uid, gid, pid = getpeercred(conn)
        logging.debug('connection from pid=%r uid=%r gid=%r', pid, uid, gid)
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
            logging.warning('invalid action id: 0x%08x', action)
            return
        handler(fp, session, uid)()
    finally:
        if fp:
            fp.close()


def disable_nss_ldap():
    """Disable the nss_ldap module to avoid lookup loops."""
    import ctypes
    try:
        lib = ctypes.CDLL(constants.NSS_LDAP_SONAME)
    except OSError:
        return  # ignore errors in opening NSS module
    try:
        ctypes.c_int.in_dll(
            lib, '_nss_%s_enablelookups' % constants.MODULE_NAME).value = 0
    except ValueError:
        logging.warning('probably older NSS module loaded', exc_info=True)
    try:
        version_info = (ctypes.c_char_p * 2).in_dll(lib, '_nss_ldap_version')
        logging.debug('NSS_LDAP %s %s', version_info[0], version_info[1])
    except ValueError:
        logging.warning('probably older NSS module loaded', exc_info=True)


def worker(nslcd_serversocket):
    session = search.Connection()
    while True:
        try:
            acceptconnection(nslcd_serversocket, session)
        except Exception:
            logging.exception('exception in worker')
            # ignore all exceptions, just keep going


def main():  # noqa: C901 (long function)
    # parse options
    parse_cmdline()
    # clean the environment
    os.environ.clear()
    os.environ['HOME'] = '/'
    os.environ['TMPDIR'] = '/tmp'
    os.environ['LDAPNOINIT'] = '1'
    # set log level
    if debugging:
        logging.getLogger().setLevel(logging.DEBUG)
    # disable ldap lookups of host names to avoid lookup loop
    disable_nss_ldap()
    # TODO: implement
    # if myldap_set_debuglevel(cfg.debug) != LDAP_SUCCESS:
    #    sys.exit(1)
    # read configuration file
    cfg.read(constants.NSLCD_CONF_PATH)
    # set process title
    try:
        import setproctitle
        setproctitle.setproctitle('pynslcd')
    except ImportError:
        pass
    # set a default umask for the pidfile and socket
    os.umask(0o022)
    # see if someone already locked the pidfile
    pidfile = mypidfile.MyPIDLockFile(constants.NSLCD_PIDFILE)
    # see if --check option was given
    if checkonly:
        if pidfile.is_locked():
            logging.debug('pidfile (%s) is locked', constants.NSLCD_PIDFILE)
            sys.exit(0)
        else:
            logging.debug('pidfile (%s) is not locked', constants.NSLCD_PIDFILE)
            sys.exit(1)
    # normal check for pidfile locked
    if pidfile.is_locked():
        logging.error('daemon may already be active, cannot acquire lock (%s)',
                      constants.NSLCD_PIDFILE)
        sys.exit(1)
    # daemonize
    if debugging or nofork:
        ctx = pidfile
    else:
        ctx = daemon.DaemonContext(
            pidfile=pidfile,
            signal_map={
                signal.SIGTERM: u'terminate',
                signal.SIGINT: u'terminate',
                signal.SIGPIPE: None,
            })
    # start daemon
    with ctx:
        try:
            # start normal logging as configured
            if not debugging:
                for method, level in cfg.logs:
                    if method == 'syslog':
                        handler = MySysLogHandler()
                        handler.setFormatter(MyFormatter('%(prefix)s%(message)s'))
                    else:
                        handler = logging.FileHandler(method, encoding='utf-8')
                        handler.setFormatter(MyFormatter('%(asctime)s %(prefix)s%(message)s'))
                    handler.setLevel(level)
                    logging.getLogger().addHandler(handler)
                logging.getLogger().setLevel(min(level for method, level in cfg.logs))
                logging.getLogger().removeHandler(stderrhandler)
            logging.info('version %s starting', constants.VERSION)
            # start invalidator sub-process if needed
            if cfg.reconnect_invalidate:
                invalidator.start_invalidator()
            # create socket
            nslcd_serversocket = create_socket()
            # load supplementary groups
            if cfg.uid is not None:
                u, gid = cfg.get_usergid()
                # set supplementary groups, gid and uid
                os.initgroups(u.pw_name, gid)
                os.setgid(gid)
                os.setuid(u.pw_uid)
                os.environ['HOME'] = u.pw_dir
            logging.info('accepting connections')
            # set global LDAP configuration
            if cfg.tls_reqcert is not None:
                ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, cfg.tls_reqcert)
            if cfg.tls_cacertdir:
                ldap.set_option(ldap.OPT_X_TLS_CACERTDIR, cfg.tls_cacertdir)
            if cfg.tls_cacertfile:
                ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, cfg.tls_cacertfile)
            if cfg.tls_randfile:
                ldap.set_option(ldap.OPT_X_TLS_RANDOM_FILE, cfg.tls_randfile)
            if cfg.tls_ciphers:
                ldap.set_option(ldap.OPT_X_TLS_CIPHER_SUITE, cfg.tls_ciphers)
            if cfg.tls_cert:
                ldap.set_option(ldap.OPT_X_TLS_CERTFILE, cfg.tls_cert)
            if cfg.tls_key:
                ldap.set_option(ldap.OPT_X_TLS_KEYFILE, cfg.tls_key)
            # start worker threads
            threads = []
            for i in range(cfg.threads):
                thread = threading.Thread(
                    target=worker, args=(nslcd_serversocket, ),
                    name='thread%d' % i)
                thread.setDaemon(True)
                thread.start()
                logging.debug('started thread %s', thread.getName())
                threads.append(thread)
            # wait for all threads to die
            for thread in threads:
                thread.join(10000)
        except Exception:
            logging.exception('main loop exit')
            # no need to re-raise since we are exiting anyway


if __name__ == '__main__':
    main()
