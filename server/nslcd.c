/*
   nslcd.c - ldap local connection daemon

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006 Arthur de Jong

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
   MA 02110-1301 USA
*/

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
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
#ifdef HAVE_GRP_H
#include <grp.h>
#endif /* HAVE_GRP_H */
#include <nss.h>
#include <pthread.h>

#include "nslcd.h"
#include "log.h"
#include "common.h"


/* the definition of the environment */
extern char **environ;


/* flag to indictate if we are in debugging mode */
static int nslcd_debugging=0;


/* the exit flag to indicate that a signal was received */
static volatile int nslcd_exitsignal=0;


/* the server socket used for communication */
static int nslcd_serversocket=-1;


/* thread ids of all running threads */
#define NUM_THREADS 5
pthread_t nslcd_threads[NUM_THREADS];


/* display version information */
static void display_version(FILE *fp)
{
  fprintf(fp,"%s\n",PACKAGE_STRING);
  fprintf(fp,"Written by Luke Howard and Arthur de Jong.\n\n");
  fprintf(fp,"Copyright (C) 1997-2006 Luke Howard, Arthur de Jong and West Consulting\n"
             "This is free software; see the source for copying conditions.  There is NO\n"
             "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
}


/* display usage information to stdout and exit(status) */
static void display_usage(FILE *fp,const char *program_name)
{
  fprintf(fp,"Usage: %s [OPTION]...\n",program_name);
  fprintf(fp,"Name Service LDAP connection daemon.\n");
  fprintf(fp,"  -f, --config=FILE  use FILE as configfile (default %s)\n",NSS_LDAP_PATH_CONF);
  fprintf(fp,"  -d, --debug        don't fork and print debugging to stderr\n");
  fprintf(fp,"      --help         display this help and exit\n");
  fprintf(fp,"      --version      output version information and exit\n");
  fprintf(fp,"\n"
             "Report bugs to <%s>.\n",PACKAGE_BUGREPORT);
}


/* the definition of options for getopt(). see getopt(2) */
static struct option const nslcd_options[] =
{
  { "debug",       no_argument,       NULL, 'd' },
  { "help",        no_argument,       NULL, 'h' },
  { "version",     no_argument,       NULL, 'V' },
  { NULL, 0, NULL, 0 }
};
#define NSLCD_OPTIONSTRING "dhV"


/* parse command line options and save settings in struct  */
static void parse_cmdline(int argc,char *argv[])
{
  int optc;
  while ((optc=getopt_long(argc,argv,NSLCD_OPTIONSTRING,nslcd_options,NULL))!=-1)
  {
    switch (optc)
    {
    case 'd': /* -d, --debug        don't fork and print debugging to stderr */
      nslcd_debugging=1;
      log_setdefaultloglevel(LOG_DEBUG);
      break;
    case 'h': /*     --help         display this help and exit */
      display_usage(stdout,argv[0]);
      exit(0);
    case 'V': /*     --version      output version information and exit */
      display_version(stdout);
      exit(0);
    case ':': /* missing required parameter */
    case '?': /* unknown option character or extraneous parameter */
    default:
      fprintf(stderr,"Try `%s --help' for more information.\n",
              argv[0]);
      exit(1);
    }
  }
  /* check for remaining arguments */
  if (optind<argc)
  {
    fprintf(stderr,"%s: unrecognized option `%s'\n",
            argv[0],argv[optind]);
    fprintf(stderr,"Try `%s --help' for more information.\n",
            argv[0]);
    exit(1);
  }
}


/* get a name of a signal with a given signal number */
static const char *signame(int signum)
{
  switch (signum)
  {
  case SIGHUP:  return "SIGHUP";  /* Hangup detected */
  case SIGINT:  return "SIGINT";  /* Interrupt from keyboard */
  case SIGQUIT: return "SIGQUIT"; /* Quit from keyboard */
  case SIGILL:  return "SIGILL";  /* Illegal Instruction */
  case SIGABRT: return "SIGABRT"; /* Abort signal from abort(3) */
  case SIGFPE:  return "SIGFPE";  /* Floating point exception */
  case SIGKILL: return "SIGKILL"; /* Kill signal */
  case SIGSEGV: return "SIGSEGV"; /* Invalid memory reference */
  case SIGPIPE: return "SIGPIPE"; /* Broken pipe */
  case SIGALRM: return "SIGALRM"; /* Timer signal from alarm(2) */
  case SIGTERM: return "SIGTERM"; /* Termination signal */
  case SIGUSR1: return "SIGUSR1"; /* User-defined signal 1 */
  case SIGUSR2: return "SIGUSR2"; /* User-defined signal 2 */
  case SIGCHLD: return "SIGCHLD"; /* Child stopped or terminated */
  case SIGCONT: return "SIGCONT"; /* Continue if stopped */
  case SIGSTOP: return "SIGSTOP"; /* Stop process */
  case SIGTSTP: return "SIGTSTP"; /* Stop typed at tty */
  case SIGTTIN: return "SIGTTIN"; /* tty input for background process */
  case SIGTTOU: return "SIGTTOU"; /* tty output for background process */
#ifdef SIGBUS
  case SIGBUS:  return "SIGBUS";  /* Bus error */
#endif
#ifdef SIGPOLL
  case SIGPOLL: return "SIGPOLL"; /* Pollable event */
#endif
#ifdef SIGPROF
  case SIGPROF: return "SIGPROF"; /* Profiling timer expired */
#endif
#ifdef SIGSYS
  case SIGSYS:  return "SIGSYS";  /* Bad argument to routine */
#endif
#ifdef SIGTRAP
  case SIGTRAP: return "SIGTRAP"; /* Trace/breakpoint trap */
#endif
#ifdef SIGURG
  case SIGURG:  return "SIGURG";  /* Urgent condition on socket */
#endif
#ifdef SIGVTALRM
  case SIGVTALRM: return "SIGVTALRM"; /* Virtual alarm clock */
#endif
#ifdef SIGXCPU
  case SIGXCPU: return "SIGXCPU"; /* CPU time limit exceeded */
#endif
#ifdef SIGXFSZ
  case SIGXFSZ: return "SIGXFSZ"; /* File size limit exceeded */
#endif
  default:      return "UNKNOWN";
  }
}


/* signal handler for closing down */
static RETSIGTYPE sigexit_handler(int signum)
{
  int i;
  nslcd_exitsignal=signum;
  /* cancel all running threads */
  for (i=0;i<NUM_THREADS;i++)
    pthread_cancel(nslcd_threads[i]);
  
}

/* do some cleaning up before terminating */
static void exithandler(void)
{
  if (nslcd_serversocket >= 0)
  {
    if (close(nslcd_serversocket))
      log_log(LOG_WARNING,"problem closing server socket (ignored): %s",strerror(errno));
  }
  log_log(LOG_INFO,"version %s bailing out",VERSION);
}


/* returns a socket ready to answer requests from the client,
   return <0 on error */
static int open_socket(void)
{
  int sock;
  struct sockaddr_un addr;

  /* create a socket */
  if ( (sock=socket(PF_UNIX,SOCK_STREAM,0))<0 )
  {
    log_log(LOG_ERR,"cannot create socket: %s",strerror(errno));
    exit(1);
  }

  /* create socket address structure */
  memset(&addr,0,sizeof(struct sockaddr_un));
  addr.sun_family=AF_UNIX;
  strcpy(addr.sun_path,NSLCD_SOCKET);

  /* unlink to socket */
  if (unlink(NSLCD_SOCKET)<0)
  {
    log_log(LOG_DEBUG,"unlink() of "NSLCD_SOCKET" failed (ignored): %s",
            strerror(errno));
  }

  /* bind to the socket */
  if (bind(sock,(struct sockaddr *)&addr,sizeof(struct sockaddr_un))<0)
  {
    log_log(LOG_ERR,"bind() to "NSLCD_SOCKET" failed: %s",
            strerror(errno));
    if (close(sock))
      log_log(LOG_WARNING,"problem closing socket: %s",strerror(errno));
    exit(1);
  }

  /* close the file descriptor on exit */
  if (fcntl(sock,F_SETFD,FD_CLOEXEC)<0)
  {
    log_log(LOG_ERR,"fctnl(F_SETFL,O_NONBLOCK) failed: %s",strerror(errno));
    if (close(sock))
      log_log(LOG_WARNING,"problem closing socket: %s",strerror(errno));
    exit(1);
  }

  /* start listening for connections */
  if (listen(sock,SOMAXCONN)<0)
  {
    log_log(LOG_ERR,"listen() failed: %s",strerror(errno));
    if (close(sock))
      log_log(LOG_WARNING,"problem closing socket: %s",strerror(errno));
    exit(1);
  }

  /* we're done */
  return sock;
}

/* read the version information and action from the stream
   this function returns the read action in location pointer to by action */
static int read_header(FILE *fp,int32_t *action)
{
  int32_t tmpint32;
  /* read the protocol version */
  READ_TYPE(fp,tmpint32,int32_t);
  if (tmpint32 != NSLCD_VERSION)
  {
    log_log(LOG_DEBUG,"wrong nslcd version id (%d)",(int)tmpint32);
    return -1;
  }
  /* read the request type */
  READ(fp,action,sizeof(int32_t));
  return 0;
}

/* read a request message, returns <0 in case of errors,
   this function closes the socket */
static void handleconnection(int sock)
{
  FILE *fp;
  socklen_t alen;
  struct ucred client;
  int32_t action;

  /* look up process information from client */
  alen=sizeof(struct ucred);
  if (getsockopt(sock,SOL_SOCKET,SO_PEERCRED,&client,&alen) < 0)
  {
    log_log(LOG_ERR,"getsockopt(SO_PEERCRED) failed: %s",strerror(errno));
    if (close(sock))
      log_log(LOG_WARNING,"problem closing socket: %s",strerror(errno));
    return;
  }

  /* log connection */
  log_log(LOG_DEBUG,"connection from pid=%d uid=%d gid=%d",
                    (int)client.pid,(int)client.uid,(int)client.gid);

  /* create a stream object */
  if ((fp=fdopen(sock,"w+"))==NULL)
  {
    log_log(LOG_WARNING,"cannot create stream for writing: %s",strerror(errno));
    close(sock);
    return;
  }

  /* read request */
  if (read_header(fp,&action))
  {
    fclose(fp);
    return;
  }

  /* handle request */
  switch (action)
  {
    case NSLCD_ACTION_ALIAS_BYNAME:     nslcd_alias_byname(fp); break;
    case NSLCD_ACTION_ALIAS_ALL:        nslcd_alias_all(fp); break;
    case NSLCD_ACTION_ETHER_BYNAME:     nslcd_ether_byname(fp); break;
    case NSLCD_ACTION_ETHER_BYETHER:    nslcd_ether_byether(fp); break;
    case NSLCD_ACTION_ETHER_ALL:        nslcd_ether_all(fp); break;
    case NSLCD_ACTION_GROUP_BYNAME:     nslcd_group_byname(fp); break;
    case NSLCD_ACTION_GROUP_BYGID:      nslcd_group_bygid(fp); break;
    case NSLCD_ACTION_GROUP_BYMEMBER:   nslcd_group_bymember(fp); break;
    case NSLCD_ACTION_GROUP_ALL:        nslcd_group_all(fp); break;
    case NSLCD_ACTION_HOST_BYNAME:      nslcd_host_byname(fp); break;
    case NSLCD_ACTION_HOST_BYADDR:      nslcd_host_byaddr(fp); break;
    case NSLCD_ACTION_HOST_ALL:         nslcd_host_all(fp); break;
    case NSLCD_ACTION_NETGROUP_BYNAME:  nslcd_netgroup_byname(fp); break;
    case NSLCD_ACTION_NETWORK_BYNAME:   nslcd_network_byname(fp); break;
    case NSLCD_ACTION_NETWORK_BYADDR:   nslcd_network_byaddr(fp); break;
    case NSLCD_ACTION_NETWORK_ALL:      nslcd_network_all(fp); break;
    case NSLCD_ACTION_PASSWD_BYNAME:    nslcd_passwd_byname(fp); break;
    case NSLCD_ACTION_PASSWD_BYUID:     nslcd_passwd_byuid(fp); break;
    case NSLCD_ACTION_PASSWD_ALL:       nslcd_passwd_all(fp); break;
    case NSLCD_ACTION_PROTOCOL_BYNAME:  nslcd_protocol_byname(fp); break;
    case NSLCD_ACTION_PROTOCOL_BYNUMBER:nslcd_protocol_bynumber(fp); break;
    case NSLCD_ACTION_PROTOCOL_ALL:     nslcd_protocol_all(fp); break;
    case NSLCD_ACTION_RPC_BYNAME:       nslcd_rpc_byname(fp); break;
    case NSLCD_ACTION_RPC_BYNUMBER:     nslcd_rpc_bynumber(fp); break;
    case NSLCD_ACTION_RPC_ALL:          nslcd_rpc_all(fp); break;
    case NSLCD_ACTION_SERVICE_BYNAME:   nslcd_service_byname(fp); break;
    case NSLCD_ACTION_SERVICE_BYNUMBER: nslcd_service_bynumber(fp); break;
    case NSLCD_ACTION_SERVICE_ALL:      nslcd_service_all(fp); break;
    case NSLCD_ACTION_SHADOW_BYNAME:    nslcd_shadow_byname(fp); break;
    case NSLCD_ACTION_SHADOW_ALL:       nslcd_shadow_all(fp); break;
    default:
      log_log(LOG_WARNING,"invalid request id: %d",(int)action);
      break;
  }

  /* we're done with the request */
  fclose(fp);
  return;
}

/* accept a connection on the socket */
static void acceptconnection(void)
{
  int csock;
  int j;
  struct sockaddr_storage addr;
  socklen_t alen;

  /* accept a new connection */
  alen=(socklen_t)sizeof(struct sockaddr_storage);
  csock=accept(nslcd_serversocket,(struct sockaddr *)&addr,&alen);
  if (csock<0)
  {
    if ((errno==EINTR)||(errno==EAGAIN)||(errno==EWOULDBLOCK))
    {
      log_log(LOG_DEBUG,"debug: accept() failed (ignored): %s",strerror(errno));
      return;
    }
    log_log(LOG_ERR,"accept() failed: %s",strerror(errno));
    return;
  }

  /* make sure O_NONBLOCK is not inherited */
  if ((j=fcntl(csock,F_GETFL,0))<0)
  {
    log_log(LOG_ERR,"fctnl(F_GETFL) failed: %s",strerror(errno));
    if (close(csock))
      log_log(LOG_WARNING,"problem closing socket: %s",strerror(errno));
    return;
  }
  if (fcntl(csock,F_SETFL,j&~O_NONBLOCK)<0)
  {
    log_log(LOG_ERR,"fctnl(F_SETFL,~O_NONBLOCK) failed: %s",strerror(errno));
    if (close(csock))
      log_log(LOG_WARNING,"problem closing socket: %s",strerror(errno));
    return;
  }

  /* handle the connection */
  handleconnection(csock);
}


/* write the current process id to the specified file */
static void write_pidfile(const char *filename)
{
  FILE *fp;
  if (filename!=NULL)
  {
    if ((fp=fopen(filename,"w"))==NULL)
    {
      log_log(LOG_ERR,"cannot open pid file (%s): %s",filename,strerror(errno));
      exit(1);
    }
    if (fprintf(fp,"%d\n",(int)getpid())<=0)
    {
      log_log(LOG_ERR,"error writing pid file (%s)",filename);
      exit(1);
    }
    if (fclose(fp))
    {
      log_log(LOG_ERR,"error writing pid file (%s): %s",filename,strerror(errno));
      exit(1);
    }
  }
}


/* try to install signal handler and check result */
static void install_sighandler(int signum,RETSIGTYPE (*handler) (int))
{
  struct sigaction act;
  memset(&act,0,sizeof(struct sigaction));
  act.sa_handler=handler;
  sigemptyset(&act.sa_mask);
  act.sa_flags=SA_RESTART|SA_NOCLDSTOP;
  if (sigaction(signum,&act,NULL)!=0)
  {
    log_log(LOG_ERR,"error installing signal handler for '%s': %s",signame(signum),strerror(errno));
    exit(1);
  }
}

static void *worker(void *arg)
{
  /* start waiting for incoming connections */
  while (nslcd_exitsignal==0)
  {
    /* wait for a new connection */
    acceptconnection();
  }
  return NULL;
}


/* the main program... */
int main(int argc,char *argv[])
{
  gid_t mygid=-1;
  uid_t myuid=-1;
  int i;

  /* parse the command line */
  parse_cmdline(argc,argv);

  /* clear the environment */
  /* TODO:implement */

  /* check if we are already running */
  /* FIXME: implement (maybe pass along options or commands) */

  /* disable ldap lookups of host names to avoid lookup loop
     and fall back to files dns (a sensible default) */
  if (__nss_configure_lookup("hosts","files dns"))
    log_log(LOG_ERR,"unable to override hosts lookup method: %s",strerror(errno));

  /* daemonize */
  if ((!nslcd_debugging)&&(daemon(0,0)<0))
  {
    log_log(LOG_ERR,"unable to daemonize: %s",strerror(errno));
    exit(1);
  }

  /* set default mode for pidfile and socket */
  umask(0022);

  /* intilialize logging */
  if (!nslcd_debugging)
    log_startlogging();
  log_log(LOG_INFO,"version %s starting",VERSION);

  /* install handler to close stuff off on exit and log notice */
  atexit(exithandler);

  /* write pidfile */
  write_pidfile(NSLCD_PIDFILE);

  /* create socket */
  nslcd_serversocket=open_socket();

#ifdef HAVE_SETGROUPS
  /* drop all supplemental groups */
  if (setgroups(0,NULL)<0)
  {
    log_log(LOG_WARNING,"cannot setgroups(0,NULL) (ignored): %s",strerror(errno));
  }
  else
  {
    log_log(LOG_DEBUG,"debug: setgroups(0,NULL) done");
  }
#else /* HAVE_SETGROUPS */
  log_log(LOG_DEBUG,"debug: setgroups() not available");
#endif /* not HAVE_SETGROUPS */

#ifdef USE_CAPABILITIES
  /* if we are using capbilities, set them to be kept
     across setuid() calls so we can limit them later on */
  if (prctl(PR_SET_KEEPCAPS,1))
  {
    log_log(LOG_ERR,"cannot prctl(PR_SET_KEEPCAPS,1): %s",strerror(errno));
    exit(1);
  }
  log_log(LOG_DEBUG,"debug: prctl(PR_SET_KEEPCAPS,1) done");
  /* dump the current capabilities */
  caps=cap_get_proc();
  log_log(LOG_DEBUG,"debug: current capabilities: %s",cap_to_text(caps,NULL));
  cap_free(caps);
#endif /* USE_CAPABILITIES */

  /* change to nslcd gid */
  if (mygid!=((gid_t)-1))
  {
    if (setgid(mygid)!=0)
    {
      log_log(LOG_ERR,"cannot setgid(%d): %s",(int)mygid,strerror(errno));
      exit(1);
    }
    log_log(LOG_DEBUG,"debug: setgid(%d) done",mygid);
  }

  /* change to nslcd uid */
  if (myuid!=((uid_t)-1))
  {
    if (setuid(myuid)!=0)
    {
      log_log(LOG_ERR,"cannot setuid(%d): %s",(int)myuid,strerror(errno));
      exit(1);
    }
    log_log(LOG_DEBUG,"debug: setuid(%d) done",myuid);
  }

#ifdef USE_CAPABILITIES
  /* limit the capabilities */
  if (cap_set_proc(mycapabilities)!=0)
  {
    log_log(LOG_ERR,"cannot cap_set_proc(%s): %s",cap_to_text(mycapabilities,NULL),strerror(errno));
    exit(1);
  }
  log_log(LOG_DEBUG,"debug: cap_set_proc(%2) done",cap_to_text(mycapabilities,NULL));
  /* we no longer need this so we should free it */
  cap_free(mycapabilities);
  /* dump the current capabilities */
  caps=cap_get_proc();
  log_log(LOG_DEBUG,"debug: current capabilities: %s",cap_to_text(caps,NULL));
  cap_free(caps);
#endif /* USE_CAPABILITIES */

  /* install signalhandlers for some signals */
  install_sighandler(SIGHUP, sigexit_handler);
  install_sighandler(SIGINT, sigexit_handler);
  install_sighandler(SIGQUIT,sigexit_handler);
  install_sighandler(SIGABRT,sigexit_handler);
  install_sighandler(SIGPIPE,SIG_IGN);
  install_sighandler(SIGTERM,sigexit_handler);
  install_sighandler(SIGUSR1,sigexit_handler);
  install_sighandler(SIGUSR2,sigexit_handler);
  /* TODO: install signal handlers for reloading configuration */

  log_log(LOG_INFO,"accepting connections");
  
  /* start worker threads */
  for (i=0;i<NUM_THREADS;i++)
  {
    if (pthread_create(&nslcd_threads[i],NULL,worker,NULL))
    {
      log_log(LOG_ERR,"unable to start worker thread %d: %s",i,strerror(errno));
      exit(1);
    }
  }
  
  /* wait for all threads to die */
  for (i=0;i<NUM_THREADS;i++)
  {
    if (pthread_join(nslcd_threads[i],NULL))
    {
      log_log(LOG_ERR,"unable to wait for worker thread %d: %s",i,strerror(errno));
      exit(1);
    }
  }

  /* print something about received signals */
  if (nslcd_exitsignal!=0)
  {
    log_log(LOG_INFO,"caught signal %s (%d), shutting down",
                 signame(nslcd_exitsignal),nslcd_exitsignal);
  }

  return 1;
}
