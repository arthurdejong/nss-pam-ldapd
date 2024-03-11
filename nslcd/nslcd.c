/*
   nslcd.c - ldap local connection daemon

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006-2024 Arthur de Jong

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301 USA
*/

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif /* HAVE_STDINT_H */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/wait.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif /* HAVE_GETOPT_H */
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <grp.h>
#ifdef HAVE_NSS_H
#include <nss.h>
#endif /* HAVE_NSS_H */
#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif /* HAVE_PTHREAD_NP_H */
#ifndef HAVE_GETOPT_LONG
#include "compat/getopt_long.h"
#endif /* not HAVE_GETOPT_LONG */
#include <dlfcn.h>
#include <libgen.h>
#include <limits.h>

#include "nslcd.h"
#include "log.h"
#include "cfg.h"
#include "common.h"
#include "common/gettext.h"
#include "compat/attrs.h"
#include "compat/getpeercred.h"
#include "compat/socket.h"
#include "daemonize.h"

/* read timeout is half a second because clients should send their request
   quickly, write timeout is 60 seconds because clients could be taking some
   time to process the results */
#define READ_TIMEOUT 500
#define WRITE_TIMEOUT 60 * 1000

/* buffer sizes for I/O */
#define READBUFFER_MINSIZE 32
#define READBUFFER_MAXSIZE 64
#define WRITEBUFFER_MINSIZE 1024
#define WRITEBUFFER_MAXSIZE 1 * 1024 * 1024

/* adjust the oom killer score */
#define OOM_SCORE_ADJ_FILE "/proc/self/oom_score_adj"
#define OOM_SCORE_ADJ "-1000"

/* flag to indicate if we are in debugging mode */
static int nslcd_debugging = 0;

/* flag to indicate we shouldn't daemonize */
static int nslcd_nofork = 0;

/* flag to indicate user requested the --check option */
static int nslcd_checkonly = 0;

/* name of the configuration file to load */
static char *nslcd_conf_path = NSLCD_CONF_PATH;

/* flag to indicate user requested the --test option */
static int nslcd_testconfig = 0;

/* the flag to indicate that a signal was received */
static volatile int nslcd_receivedsignal = 0;

/* the server socket used for communication */
static int nslcd_serversocket = -1;

/* thread ids of all running threads */
static pthread_t *nslcd_threads;

/* if we don't have clearenv() we have to do this the hard way */
#ifndef HAVE_CLEARENV

/* the definition of the environment */
extern char **environ;

/* the environment we want to use */
static char *sane_environment[] = {
  "HOME=/",
  "TMPDIR=/tmp",
  "LDAPNOINIT=1",
  NULL
};

#endif /* not HAVE_CLEARENV */

/* display version information */
static void display_version(FILE *fp)
{
  fprintf(fp, "%s\n", PACKAGE_STRING);
  fprintf(fp, "Written by Luke Howard and Arthur de Jong.\n\n");
  fprintf(fp, "Copyright (C) 1997-2019 Arthur de Jong and others\n"
              "This is free software; see the source for copying conditions.  There is NO\n"
              "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
}

/* display usage information */
static void display_usage(FILE *fp, const char *program_name)
{
  fprintf(fp, "Usage: %s [OPTION]...\n", program_name);
  fprintf(fp, "Name Service LDAP connection daemon.\n");
  fprintf(fp, "  -c, --check        check if the daemon already is running\n");
  fprintf(fp, "  -d, --debug        don't fork and print debugging to stderr\n");
  fprintf(fp, "  -n, --nofork       don't fork\n");
  fprintf(fp, "  -f, --config=FILE  alternative configuration file (default %s)\n", NSLCD_CONF_PATH);
  fprintf(fp, "  -t, --test         test configuration for validity and exit\n");
  fprintf(fp, "      --help         display this help and exit\n");
  fprintf(fp, "      --version      output version information and exit\n");
  fprintf(fp, "\n" "Report bugs to <%s>.\n", PACKAGE_BUGREPORT);
}

/* the definition of options for getopt(). see getopt(2) */
static struct option const nslcd_options[] = {
  {"check",   no_argument,       NULL, 'c'},
  {"debug",   no_argument,       NULL, 'd'},
  {"nofork",  no_argument,       NULL, 'n'},
  {"config",  required_argument, NULL, 'f'},
  {"test",    no_argument,       NULL, 't'},
  {"help",    no_argument,       NULL, 'h'},
  {"version", no_argument,       NULL, 'V'},
  {NULL,      0,                 NULL, 0}
};
#define NSLCD_OPTIONSTRING "cndf:thV"

/* parse command line options and save settings in struct  */
static void parse_cmdline(int argc, char *argv[])
{
  int optc;
  while ((optc = getopt_long(argc, argv, NSLCD_OPTIONSTRING, nslcd_options, NULL)) != -1)
  {
    switch (optc)
    {
      case 'c': /* -c, --check        check if the daemon already is running */
        nslcd_checkonly = 1;
        break;
      case 'd': /* -d, --debug        don't fork and print debugging to stderr */
        nslcd_debugging++;
        log_setdefaultloglevel(LOG_DEBUG);
        break;
      case 'n': /* -n, --nofork       don't fork */
        nslcd_nofork++;
        break;
      case 'f': /* -f, --config=FILE  alternative configuration file */
        nslcd_conf_path = strdup(optarg);
        if (nslcd_conf_path == NULL)
        {
          log_log(LOG_CRIT, "strdup() failed to allocate memory");
          exit(EXIT_FAILURE);
        }
        break;
      case 't': /* -t, --test        test configuration for validity and exit */
        nslcd_testconfig = 1;
        break;
      case 'h': /*     --help         display this help and exit */
        display_usage(stdout, argv[0]);
        exit(EXIT_SUCCESS);
      case 'V': /*     --version      output version information and exit */
        display_version(stdout);
        exit(EXIT_SUCCESS);
      case ':': /* missing required parameter */
      case '?': /* unknown option character or extraneous parameter */
      default:
        fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
        exit(EXIT_FAILURE);
    }
  }
  /* check for remaining arguments */
  if (optind < argc)
  {
    fprintf(stderr, "%s: unrecognized option '%s'\n", argv[0], argv[optind]);
    fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
    exit(EXIT_FAILURE);
  }
}

/* signal handler for storing information on received signals */
static void sig_handler(int signum)
{
  /* just save the signal to indicate that we're stopping */
  nslcd_receivedsignal = signum;
}

/* do some cleaning up before terminating */
static void exithandler(void)
{
  /* remove existing named socket */
  if (unlink(NSLCD_SOCKET) < 0)
  {
    log_log(LOG_DEBUG, "unlink() of " NSLCD_SOCKET " failed (ignored): %s",
            strerror(errno));
  }
  /* remove pidfile */
  if (unlink(NSLCD_PIDFILE) < 0)
  {
    log_log(LOG_DEBUG, "unlink() of " NSLCD_PIDFILE " failed (ignored): %s",
            strerror(errno));
  }
  /* log exit */
  log_log(LOG_INFO, "version %s bailing out", VERSION);
}

/* create the directory for the specified file to reside in */
static void mkdirname(const char *filename)
{
  char *tmpname, *path;
  tmpname = strdup(filename);
  if (tmpname == NULL)
    return;
  path = dirname(tmpname);
  if (mkdir(path, (mode_t)0755) == 0)
  {
    /* if directory was just created, set correct ownership */
    if (lchown(path, nslcd_cfg->uid, nslcd_cfg->gid) < 0)
      log_log(LOG_WARNING, "problem setting permissions for %s: %s",
              path, strerror(errno));
  }
  free(tmpname);
}

/* returns a socket ready to answer requests from the client,
   exit()s on error */
static int create_socket(const char *filename)
{
  int sock;
  int i;
  struct sockaddr_un addr;
  /* create a socket */
  if ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
  {
    log_log(LOG_ERR, "cannot create socket: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }
  if (sock >= (int)FD_SETSIZE)
  {
    log_log(LOG_ERR, "socket file descriptor number too high (%d)", sock);
    exit(EXIT_FAILURE);
  }
  /* remove existing named socket */
  if (unlink(filename) < 0)
  {
    log_log(LOG_DEBUG, "unlink() of %s failed (ignored): %s",
            filename, strerror(errno));
  }
  /* do not block on accept() */
  if ((i = fcntl(sock, F_GETFL, 0)) < 0)
  {
    log_log(LOG_ERR, "fctnl(F_GETFL) failed: %s", strerror(errno));
    if (close(sock))
      log_log(LOG_WARNING, "problem closing socket: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }
  if (fcntl(sock, F_SETFL, i | O_NONBLOCK) < 0)
  {
    log_log(LOG_ERR, "fctnl(F_SETFL,O_NONBLOCK) failed: %s", strerror(errno));
    if (close(sock))
      log_log(LOG_WARNING, "problem closing socket: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }
  /* create the directory if needed */
  mkdirname(filename);
  /* create socket address structure */
  memset(&addr, 0, sizeof(struct sockaddr_un));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, filename, sizeof(addr.sun_path));
  addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';
  /* bind to the named socket */
  if (bind(sock, (struct sockaddr *)&addr, SUN_LEN(&addr)))
  {
    log_log(LOG_ERR, "bind() to %s failed: %s", filename, strerror(errno));
    if (close(sock))
      log_log(LOG_WARNING, "problem closing socket: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }
  /* close the file descriptor on exec */
  if (fcntl(sock, F_SETFD, FD_CLOEXEC) < 0)
  {
    log_log(LOG_ERR, "fctnl(F_SETFL,FD_CLOEXEC) on %s failed: %s",
            filename, strerror(errno));
    if (close(sock))
      log_log(LOG_WARNING, "problem closing socket: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }
  /* set permissions of socket so anybody can do requests */
  /* Note: we use chmod() here instead of fchmod() because
     fchmod does not work on sockets
     http://www.opengroup.org/onlinepubs/009695399/functions/fchmod.html
     http://lkml.org/lkml/2005/5/16/11 */
  if (chmod(filename, (mode_t)0666))
  {
    log_log(LOG_ERR, "chmod(0666) of %s failed: %s",
            filename, strerror(errno));
    if (close(sock))
      log_log(LOG_WARNING, "problem closing socket: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }
  /* start listening for connections */
  if (listen(sock, SOMAXCONN) < 0)
  {
    log_log(LOG_ERR, "listen() failed: %s", strerror(errno));
    if (close(sock))
      log_log(LOG_WARNING, "problem closing socket: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }
  /* we're done */
  return sock;
}

/* read the version information and action from the stream
   this function returns the read action in location pointer to by action */
static int read_header(TFILE *fp, int32_t *action)
{
  int32_t tmpint32;
  int32_t protocol;
  /* read the protocol version */
  READ_INT32(fp, protocol);
  if (protocol != (int32_t)NSLCD_VERSION)
  {
    log_log(LOG_DEBUG, "invalid nslcd version id: 0x%08x", (unsigned int)protocol);
    return -1;
  }
  /* read the request type */
  READ_INT32(fp, *action);
  return 0;
}

/* read a request message, returns <0 in case of errors,
   this function closes the socket */
static void handleconnection(int sock, MYLDAP_SESSION *session)
{
  TFILE *fp;
  int32_t action;
  pid_t pid = (pid_t)-1;
  uid_t uid = (uid_t)-1;
  gid_t gid = (gid_t)-1;
  char peerinfo[80];
  /* log connection */
  if (getpeercred(sock, &uid, &gid, &pid))
    log_log(LOG_DEBUG, "connection from unknown client: %s", strerror(errno));
  else
  {
    peerinfo[0] = '\0';
    if (pid != (pid_t)-1)
      mysnprintf(peerinfo + strlen(peerinfo), sizeof(peerinfo) - strlen(peerinfo) - 1,
                 " pid=%lu", (unsigned long int)pid);
    if (uid != (uid_t)-1)
      mysnprintf(peerinfo + strlen(peerinfo), sizeof(peerinfo) - strlen(peerinfo) - 1,
                 " uid=%lu", (unsigned long int)uid);
    if (gid != (gid_t)-1)
      mysnprintf(peerinfo + strlen(peerinfo), sizeof(peerinfo) - strlen(peerinfo) - 1,
                 " gid=%lu", (unsigned long int)gid);
    log_log(LOG_DEBUG, "connection from %s", (peerinfo[0] == '\0') ? "unknown" : peerinfo);
  }
  /* create a stream object */
  if ((fp = tio_fdopen(sock, READ_TIMEOUT, WRITE_TIMEOUT,
                       READBUFFER_MINSIZE, READBUFFER_MAXSIZE,
                       WRITEBUFFER_MINSIZE, WRITEBUFFER_MAXSIZE)) == NULL)
  {
    log_log(LOG_WARNING, "cannot create stream for writing: %s",
            strerror(errno));
    (void)close(sock);
    return;
  }
  /* read request */
  if (read_header(fp, &action))
  {
    (void)tio_close(fp);
    return;
  }
  /* handle request */
  switch (action)
  {
    case NSLCD_ACTION_CONFIG_GET:       (void)nslcd_config_get(fp, session); break;
    case NSLCD_ACTION_ALIAS_BYNAME:     (void)nslcd_alias_byname(fp, session); break;
    case NSLCD_ACTION_ALIAS_ALL:        (void)nslcd_alias_all(fp, session); break;
    case NSLCD_ACTION_ETHER_BYNAME:     (void)nslcd_ether_byname(fp, session); break;
    case NSLCD_ACTION_ETHER_BYETHER:    (void)nslcd_ether_byether(fp, session); break;
    case NSLCD_ACTION_ETHER_ALL:        (void)nslcd_ether_all(fp, session); break;
    case NSLCD_ACTION_GROUP_BYNAME:     (void)nslcd_group_byname(fp, session); break;
    case NSLCD_ACTION_GROUP_BYGID:      (void)nslcd_group_bygid(fp, session); break;
    case NSLCD_ACTION_GROUP_BYMEMBER:   (void)nslcd_group_bymember(fp, session); break;
    case NSLCD_ACTION_GROUP_ALL:
      if (!nslcd_cfg->nss_disable_enumeration) (void)nslcd_group_all(fp, session);
      break;
    case NSLCD_ACTION_HOST_BYNAME:      (void)nslcd_host_byname(fp, session); break;
    case NSLCD_ACTION_HOST_BYADDR:      (void)nslcd_host_byaddr(fp, session); break;
    case NSLCD_ACTION_HOST_ALL:         (void)nslcd_host_all(fp, session); break;
    case NSLCD_ACTION_NETGROUP_BYNAME:  (void)nslcd_netgroup_byname(fp, session); break;
    case NSLCD_ACTION_NETGROUP_ALL:     (void)nslcd_netgroup_all(fp, session); break;
    case NSLCD_ACTION_NETWORK_BYNAME:   (void)nslcd_network_byname(fp, session); break;
    case NSLCD_ACTION_NETWORK_BYADDR:   (void)nslcd_network_byaddr(fp, session); break;
    case NSLCD_ACTION_NETWORK_ALL:      (void)nslcd_network_all(fp, session); break;
    case NSLCD_ACTION_PASSWD_BYNAME:    (void)nslcd_passwd_byname(fp, session, uid); break;
    case NSLCD_ACTION_PASSWD_BYUID:     (void)nslcd_passwd_byuid(fp, session, uid); break;
    case NSLCD_ACTION_PASSWD_ALL:
      if (!nslcd_cfg->nss_disable_enumeration) (void)nslcd_passwd_all(fp, session, uid);
      break;
    case NSLCD_ACTION_PROTOCOL_BYNAME:  (void)nslcd_protocol_byname(fp, session); break;
    case NSLCD_ACTION_PROTOCOL_BYNUMBER:(void)nslcd_protocol_bynumber(fp, session); break;
    case NSLCD_ACTION_PROTOCOL_ALL:     (void)nslcd_protocol_all(fp, session); break;
    case NSLCD_ACTION_RPC_BYNAME:       (void)nslcd_rpc_byname(fp, session); break;
    case NSLCD_ACTION_RPC_BYNUMBER:     (void)nslcd_rpc_bynumber(fp, session); break;
    case NSLCD_ACTION_RPC_ALL:          (void)nslcd_rpc_all(fp, session); break;
    case NSLCD_ACTION_SERVICE_BYNAME:   (void)nslcd_service_byname(fp, session); break;
    case NSLCD_ACTION_SERVICE_BYNUMBER: (void)nslcd_service_bynumber(fp, session); break;
    case NSLCD_ACTION_SERVICE_ALL:      (void)nslcd_service_all(fp, session); break;
    case NSLCD_ACTION_SHADOW_BYNAME:    (void)nslcd_shadow_byname(fp, session, uid); break;
    case NSLCD_ACTION_SHADOW_ALL:
      if (!nslcd_cfg->nss_disable_enumeration) (void)nslcd_shadow_all(fp, session, uid);
      break;
    case NSLCD_ACTION_PAM_AUTHC:        (void)nslcd_pam_authc(fp, session, uid); break;
    case NSLCD_ACTION_PAM_AUTHZ:        (void)nslcd_pam_authz(fp, session); break;
    case NSLCD_ACTION_PAM_SESS_O:       (void)nslcd_pam_sess_o(fp, session); break;
    case NSLCD_ACTION_PAM_SESS_C:       (void)nslcd_pam_sess_c(fp, session); break;
    case NSLCD_ACTION_PAM_PWMOD:        (void)nslcd_pam_pwmod(fp, session, uid); break;
    case NSLCD_ACTION_USERMOD:          (void)nslcd_usermod(fp, session, uid); break;
    default:
      log_log(LOG_WARNING, "invalid request id: 0x%08x", (unsigned int)action);
      break;
  }
  /* we're done with the request */
  myldap_session_cleanup(session);
  (void)tio_close(fp);
  return;
}

/* test to see if we can lock the specified file */
static int is_locked(const char *filename)
{
  int fd;
  if (filename != NULL)
  {
    errno = 0;
    if ((fd = open(filename, O_RDWR, 0644)) < 0)
    {
      if (errno == ENOENT)
        return 0; /* if file doesn't exist it cannot be locked */
      log_log(LOG_ERR, "cannot open lock file (%s): %s", filename, strerror(errno));
      exit(EXIT_FAILURE);
    }
    if (lockf(fd, F_TEST, 0) < 0)
    {
      if (close(fd))
        log_log(LOG_WARNING, "problem closing fd: %s", strerror(errno));
      return -1;
    }
    if (close(fd))
      log_log(LOG_WARNING, "problem closing fd: %s", strerror(errno));
  }
  return 0;
}

/* write the current process id to the specified file */
static void create_pidfile(const char *filename)
{
  int fd;
  char buffer[20];
  if (filename != NULL)
  {
    mkdirname(filename);
    if ((fd = open(filename, O_RDWR | O_CREAT, 0644)) < 0)
    {
      log_log(LOG_ERR, "cannot create pid file (%s): %s",
              filename, strerror(errno));
      exit(EXIT_FAILURE);
    }
    if (lockf(fd, F_TLOCK, 0) < 0)
    {
      log_log(LOG_ERR, "cannot lock pid file (%s): %s",
              filename, strerror(errno));
      exit(EXIT_FAILURE);
    }
    if (ftruncate(fd, 0) < 0)
    {
      log_log(LOG_ERR, "cannot truncate pid file (%s): %s",
              filename, strerror(errno));
      exit(EXIT_FAILURE);
    }
    mysnprintf(buffer, sizeof(buffer), "%lu\n", (unsigned long int)getpid());
    if (write(fd, buffer, strlen(buffer)) != (int)strlen(buffer))
    {
      log_log(LOG_ERR, "error writing pid file (%s): %s",
              filename, strerror(errno));
      exit(EXIT_FAILURE);
    }
    /* we keep the pidfile open so the lock remains valid */
  }
}

/* try to install signal handler and check result */
static void install_sighandler(int signum, void (*handler) (int))
{
  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = handler;
  sigemptyset(&act.sa_mask);
  act.sa_flags = SA_RESTART | SA_NOCLDSTOP;
  if (sigaction(signum, &act, NULL) != 0)
  {
    log_log(LOG_ERR, "error installing signal handler for '%s': %s",
            signame(signum), strerror(errno));
    exit(EXIT_FAILURE);
  }
}

static void worker_cleanup(void *arg)
{
  MYLDAP_SESSION *session = (MYLDAP_SESSION *)arg;
  myldap_session_close(session);
}

static void *worker(void UNUSED(*arg))
{
  MYLDAP_SESSION *session;
  int csock;
  int j;
  struct sockaddr_storage addr;
  socklen_t alen;
  fd_set fds;
  struct timeval tv;
  /* create a new LDAP session */
  session = myldap_create_session();
  /* clean up the session if we're done */
  pthread_cleanup_push(worker_cleanup, session);
  /* start waiting for incoming connections */
  while (1)
  {
    /* time out connection to LDAP server if needed */
    myldap_session_check(session);
    /* set up the set of fds to wait on */
    FD_ZERO(&fds);
    FD_SET(nslcd_serversocket, &fds);
    /* set up our timeout value */
    tv.tv_sec = nslcd_cfg->idle_timelimit;
    tv.tv_usec = 0;
    /* wait for a new connection */
    j = select(nslcd_serversocket + 1, &fds, NULL, NULL,
               nslcd_cfg->idle_timelimit > 0 ? &tv : NULL);
    /* check result of select() */
    if (j < 0)
    {
      if (errno == EINTR)
        log_log(LOG_DEBUG, "select() failed (ignored): %s", strerror(errno));
      else
        log_log(LOG_ERR, "select() failed: %s", strerror(errno));
      continue;
    }
    /* see if our file descriptor is actually ready */
    if (!FD_ISSET(nslcd_serversocket, &fds))
      continue;
    /* wait for a new connection */
    alen = (socklen_t)sizeof(struct sockaddr_storage);
    csock = accept(nslcd_serversocket, (struct sockaddr *)&addr, &alen);
    if (csock < 0)
    {
      if ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))
        log_log(LOG_DEBUG, "accept() failed (ignored): %s", strerror(errno));
      else
        log_log(LOG_ERR, "accept() failed: %s", strerror(errno));
      continue;
    }
    /* make sure O_NONBLOCK is not inherited */
    if ((j = fcntl(csock, F_GETFL, 0)) < 0)
    {
      log_log(LOG_ERR, "fctnl(F_GETFL) failed: %s", strerror(errno));
      if (close(csock))
        log_log(LOG_WARNING, "problem closing socket: %s", strerror(errno));
      continue;
    }
    if (fcntl(csock, F_SETFL, j & ~O_NONBLOCK) < 0)
    {
      log_log(LOG_ERR, "fctnl(F_SETFL,~O_NONBLOCK) failed: %s", strerror(errno));
      if (close(csock))
        log_log(LOG_WARNING, "problem closing socket: %s", strerror(errno));
      continue;
    }
    /* indicate new connection to logging module (generates unique id) */
    log_newsession();
    /* handle the connection */
    handleconnection(csock, session);
    /* indicate end of session in log messages */
    log_clearsession();
  }
  pthread_cleanup_pop(1);
  return NULL;
}

/* function to disable lookups through the nss_ldap module to avoid lookup
   loops */
static void disable_nss_ldap(void)
{
  void *handle;
  char *error;
  char **version_info;
  int *enable_flag;
  /* try to load the NSS module */
#ifdef RTLD_NODELETE
  handle = dlopen(NSS_LDAP_SONAME, RTLD_LAZY | RTLD_NODELETE);
#else /* not RTLD_NODELETE */
  handle = dlopen(NSS_LDAP_SONAME, RTLD_LAZY);
#endif /* RTLD_NODELETE */
  if (handle == NULL)
  {
    log_log(LOG_WARNING, "Warning: NSS_LDAP module not loaded: %s", dlerror());
    return;
  }
  /* clear any existing errors */
  dlerror();
  /* lookup the NSS version if possible */
  version_info = (char **)dlsym(handle, "_nss_" MODULE_NAME "_version");
  error = dlerror();
  if ((version_info != NULL) && (error == NULL))
    log_log(LOG_DEBUG, "NSS_LDAP %s %s", version_info[0], version_info[1]);
  else
    log_log(LOG_WARNING, "Warning: NSS_LDAP version missing: %s", error);
  /* clear any existing errors */
  dlerror();
  /* try to look up the flag */
  enable_flag = (int *)dlsym(handle, "_nss_" MODULE_NAME "_enablelookups");
  error = dlerror();
  if ((enable_flag == NULL) || (error != NULL))
  {
    log_log(LOG_WARNING, "Warning: %s (probably older NSS module loaded)",
            error);
    /* fall back to changing the way host lookup is done */
#ifdef HAVE___NSS_CONFIGURE_LOOKUP
    if (__nss_configure_lookup("hosts", "files dns"))
      log_log(LOG_ERR, "unable to override hosts lookup method: %s",
              strerror(errno));
#endif /* HAVE___NSS_CONFIGURE_LOOKUP */
    dlclose(handle);
    return;
  }
  /* disable nss_ldap */
  *enable_flag = 0;
#ifdef RTLD_NODELETE
  /* only close the handle if RTLD_NODELETE was used */
  dlclose(handle);
#endif /* RTLD_NODELETE */
}

/* poke the OOM killer so nslcd will never get killed */
static void adjust_oom_score(void)
{
  int oom_adj_fd;
  if ((oom_adj_fd = open(OOM_SCORE_ADJ_FILE, O_WRONLY)) >= 0)
  {
    if (write(oom_adj_fd, OOM_SCORE_ADJ, strlen(OOM_SCORE_ADJ)) < 0)
      log_log(LOG_WARNING, "writing oom score adjustment of %s failed: %s",
        OOM_SCORE_ADJ, strerror(errno));
    close(oom_adj_fd);
  }
  else
  {
    log_log(LOG_DEBUG, "could not open %s to adjust the OOM score: %s",
      OOM_SCORE_ADJ_FILE, strerror(errno));
  }
}

/* the main program... */
int main(int argc, char *argv[])
{
  int i;
  sigset_t signalmask, oldmask;
#ifdef HAVE_PTHREAD_TIMEDJOIN_NP
  struct timespec ts;
#endif /* HAVE_PTHREAD_TIMEDJOIN_NP */
  /* block all these signals so our worker threads won't handle them */
  sigemptyset(&signalmask);
  sigaddset(&signalmask, SIGHUP);
  sigaddset(&signalmask, SIGINT);
  sigaddset(&signalmask, SIGQUIT);
  sigaddset(&signalmask, SIGABRT);
  sigaddset(&signalmask, SIGPIPE);
  sigaddset(&signalmask, SIGTERM);
  sigaddset(&signalmask, SIGUSR1);
  sigaddset(&signalmask, SIGUSR2);
  pthread_sigmask(SIG_BLOCK, &signalmask, &oldmask);
  /* close all file descriptors (except stdin/out/err) */
  daemonize_closefds();
  /* parse the command line */
  parse_cmdline(argc, argv);
  /* initialize locale before environment is cleared */
#ifdef ENABLE_NLS
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif
  /* clean the environment */
#ifdef HAVE_CLEARENV
  if (clearenv() || putenv("HOME=/") || putenv("TMPDIR=/tmp") ||
      putenv("LDAPNOINIT=1"))
  {
    log_log(LOG_ERR, "clearing environment failed");
    exit(EXIT_FAILURE);
  }
#else /* not HAVE_CLEARENV */
  /* this is a bit ugly */
  environ = sane_environment;
#endif /* not HAVE_CLEARENV */
  /* disable the nss_ldap module for this process */
  disable_nss_ldap();
  /* set LDAP log level */
  if (myldap_set_debuglevel(nslcd_debugging) != LDAP_SUCCESS)
    exit(EXIT_FAILURE);
  /* read configuration file */
  cfg_init(nslcd_conf_path);
  /* exit if we only wanted to check the configuration */
  if (nslcd_testconfig)
  {
    log_log(LOG_INFO, "config (%s) OK", nslcd_conf_path);
    exit(EXIT_SUCCESS);
  }
  /* set default mode for pidfile and socket */
  (void)umask((mode_t)0022);
  /* see if someone already locked the pidfile
     if --check option was given exit TRUE if daemon runs
     (pidfile locked), FALSE otherwise */
  if (nslcd_checkonly)
  {
    if (is_locked(NSLCD_PIDFILE))
    {
      log_log(LOG_DEBUG, "pidfile (%s) is locked", NSLCD_PIDFILE);
      exit(EXIT_SUCCESS);
    }
    else
    {
      log_log(LOG_DEBUG, "pidfile (%s) is not locked", NSLCD_PIDFILE);
      exit(EXIT_FAILURE);
    }
  }
  /* change directory */
  if (chdir("/") != 0)
  {
    log_log(LOG_ERR, "chdir failed: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }
  /* normal check for pidfile locked */
  if (is_locked(NSLCD_PIDFILE))
  {
    log_log(LOG_ERR, "nslcd may already be active, cannot acquire lock (%s): %s",
            NSLCD_PIDFILE, strerror(errno));
    exit(EXIT_FAILURE);
  }
  /* daemonize */
  if ((!nslcd_debugging) && (!nslcd_nofork))
  {
    errno = 0;
    if (daemonize_daemon() != 0)
    {
      log_log(LOG_ERR, "unable to daemonize: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
  }
  /* intilialize logging */
  if (!nslcd_debugging)
  {
    daemonize_redirect_stdio();
    log_startlogging();
  }
  /* write pidfile */
  create_pidfile(NSLCD_PIDFILE);
  /* log start */
  log_log(LOG_INFO, "version %s starting", VERSION);
  /* install handler to close stuff off on exit and log notice */
  if (atexit(exithandler))
  {
    log_log(LOG_ERR, "atexit() failed: %s", strerror(errno));
    daemonize_ready(EXIT_FAILURE, "atexit() failed\n");
    exit(EXIT_FAILURE);
  }
  adjust_oom_score();
  /* start subprocess to do invalidating if reconnect_invalidate is set */
  for (i = 0; i < LM_NONE; i++)
    if (nslcd_cfg->reconnect_invalidate[i])
      break;
  if (i < LM_NONE)
    invalidator_start();
  /* change nslcd group and supplemental groups */
  if ((nslcd_cfg->gid != NOGID) && (nslcd_cfg->uidname != NULL))
  {
#ifdef HAVE_INITGROUPS
    /* load supplementary groups */
    if (initgroups(nslcd_cfg->uidname, nslcd_cfg->gid) < 0)
      log_log(LOG_WARNING, "cannot initgroups(\"%s\",%lu) (ignored): %s",
              nslcd_cfg->uidname, (unsigned long int)nslcd_cfg->gid, strerror(errno));
    else
      log_log(LOG_DEBUG, "initgroups(\"%s\",%lu) done",
              nslcd_cfg->uidname, (unsigned long int)nslcd_cfg->gid);
#else /* not HAVE_INITGROUPS */
#ifdef HAVE_SETGROUPS
    /* just drop all supplemental groups */
    if (setgroups(0, NULL) < 0)
      log_log(LOG_WARNING, "cannot setgroups(0,NULL) (ignored): %s",
              strerror(errno));
    else
      log_log(LOG_DEBUG, "setgroups(0,NULL) done");
#else /* not HAVE_SETGROUPS */
    log_log(LOG_DEBUG, "neither initgroups() or setgroups() available");
#endif /* not HAVE_SETGROUPS */
#endif /* not HAVE_INITGROUPS */
  }
  /* change to nslcd gid */
  if (nslcd_cfg->gid != NOGID)
  {
    if (setgid(nslcd_cfg->gid) != 0)
    {
      log_log(LOG_ERR, "cannot setgid(%lu): %s",
              (unsigned long int)nslcd_cfg->gid, strerror(errno));
      daemonize_ready(EXIT_FAILURE, "cannot setgid()\n");
      exit(EXIT_FAILURE);
    }
    log_log(LOG_DEBUG, "setgid(%lu) done", (unsigned long int)nslcd_cfg->gid);
  }
  /* change to nslcd uid */
  if (nslcd_cfg->uid != NOUID)
  {
    if (setuid(nslcd_cfg->uid) != 0)
    {
      log_log(LOG_ERR, "cannot setuid(%lu): %s",
              (unsigned long int)nslcd_cfg->uid, strerror(errno));
      daemonize_ready(EXIT_FAILURE, "cannot setuid()\n");
      exit(EXIT_FAILURE);
    }
    log_log(LOG_DEBUG, "setuid(%lu) done", (unsigned long int)nslcd_cfg->uid);
  }
  /* create socket */
  nslcd_serversocket = create_socket(NSLCD_SOCKET);
  /* start worker threads */
  log_log(LOG_INFO, "accepting connections");
  nslcd_threads = (pthread_t *)malloc(nslcd_cfg->threads * sizeof(pthread_t));
  if (nslcd_threads == NULL)
  {
    log_log(LOG_CRIT, "main(): malloc() failed to allocate memory");
    daemonize_ready(EXIT_FAILURE, "malloc() failed to allocate memory\n");
    exit(EXIT_FAILURE);
  }
  for (i = 0; i < nslcd_cfg->threads; i++)
  {
    if (pthread_create(&nslcd_threads[i], NULL, worker, NULL))
    {
      log_log(LOG_ERR, "unable to start worker thread %d: %s",
              i, strerror(errno));
      daemonize_ready(EXIT_FAILURE, "unable to start worker thread\n");
      exit(EXIT_FAILURE);
    }
  }
  /* install signal handlers for some signals */
  install_sighandler(SIGHUP, sig_handler);
  install_sighandler(SIGINT, sig_handler);
  install_sighandler(SIGQUIT, sig_handler);
  install_sighandler(SIGABRT, sig_handler);
  install_sighandler(SIGPIPE, SIG_IGN);
  install_sighandler(SIGTERM, sig_handler);
  install_sighandler(SIGUSR1, sig_handler);
  install_sighandler(SIGUSR2, SIG_IGN);
  /* signal the starting process to exit because we can provide services now */
  daemonize_ready(EXIT_SUCCESS, NULL);
  /* enable receiving of signals */
  pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
  /* wait until we received a signal */
  while ((nslcd_receivedsignal == 0) || (nslcd_receivedsignal == SIGUSR1))
  {
    sleep(INT_MAX); /* sleep as long as we can or until we receive a signal */
    if (nslcd_receivedsignal == SIGUSR1)
    {
      log_log(LOG_INFO, "caught signal %s (%d), refresh retries",
              signame(nslcd_receivedsignal), nslcd_receivedsignal);
      myldap_immediate_reconnect();
      nslcd_receivedsignal = 0;
    }
  }
  /* print something about received signal */
  log_log(LOG_INFO, "caught signal %s (%d), shutting down",
          signame(nslcd_receivedsignal), nslcd_receivedsignal);
  /* cancel all running threads */
  for (i = 0; i < nslcd_cfg->threads; i++)
    if (pthread_cancel(nslcd_threads[i]))
      log_log(LOG_WARNING, "failed to stop thread %d (ignored): %s",
              i, strerror(errno));
  /* close server socket to trigger failures in threads waiting on accept() */
  close(nslcd_serversocket);
  /* if we can, wait a few seconds for the threads to finish */
#ifdef HAVE_PTHREAD_TIMEDJOIN_NP
  ts.tv_sec = time(NULL) + 3;
  ts.tv_nsec = 0;
#endif /* HAVE_PTHREAD_TIMEDJOIN_NP */
  for (i = 0; i < nslcd_cfg->threads; i++)
  {
#ifdef HAVE_PTHREAD_TIMEDJOIN_NP
    if (pthread_timedjoin_np(nslcd_threads[i], NULL, &ts) == -1) {
      if (errno != EBUSY)
        log_log(LOG_ERR, "thread %d cannot be joined (ignoring): %s", i,
                strerror(errno));
      log_log(LOG_ERR, "thread %d is still running, shutting down anyway", i);
    }
#else
    if (pthread_kill(nslcd_threads[i], 0) == 0)
      log_log(LOG_ERR, "thread %d is still running, shutting down anyway", i);
#endif /* HAVE_PTHREAD_TIMEDJOIN_NP */
  }
  /* we're done */
  return EXIT_SUCCESS;
}
