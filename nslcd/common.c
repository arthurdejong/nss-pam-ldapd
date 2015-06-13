/*
   common.c - common server code routines
   This file is part of the nss-pam-ldapd library.

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013 Arthur de Jong

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

#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <strings.h>
#include <limits.h>
#include <netdb.h>
#include <string.h>
#include <regex.h>
#include <stdlib.h>
#include <signal.h>

#include "nslcd.h"
#include "common.h"
#include "log.h"
#include "attmap.h"
#include "cfg.h"

/* simple wrapper around snptintf() to return non-zero in case
   of any failure (but always keep string 0-terminated) */
int mysnprintf(char *buffer, size_t buflen, const char *format, ...)
{
  int res;
  va_list ap;
  /* do snprintf */
  va_start(ap, format);
  res = vsnprintf(buffer, buflen, format, ap);
  va_end(ap);
  /* NULL-terminate the string just to be on the safe side */
  buffer[buflen - 1] = '\0';
  /* check if the string was completely written */
  return ((res < 0) || (((size_t)res) >= buflen));
}

/* get a name of a signal with a given signal number */
const char *signame(int signum)
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

/* return the fully qualified domain name of the current host */
const char *getfqdn(void)
{
  static char *fqdn = NULL;
  char hostname[BUFLEN_HOSTNAME];
  int hostnamelen;
  int i;
  struct hostent *host = NULL;
  /* if we already have a fqdn return that */
  if (fqdn != NULL)
    return fqdn;
  /* get system hostname */
  if (gethostname(hostname, sizeof(hostname)) < 0)
  {
    log_log(LOG_ERR, "gethostname() failed: %s", strerror(errno));
    return NULL;
  }
  hostnamelen = strlen(hostname);
  /* lookup hostent */
  host = gethostbyname(hostname);
  if (host == NULL)
  {
    log_log(LOG_ERR, "gethostbyname(%s): %s", hostname, hstrerror(h_errno));
    /* fall back to hostname */
    fqdn = strdup(hostname);
    return fqdn;
  }
  /* check h_name for fqdn starting with our hostname */
  if ((strncasecmp(hostname, host->h_name, hostnamelen) == 0) &&
      (host->h_name[hostnamelen] == '.') &&
      (host->h_name[hostnamelen + 1] != '\0'))
  {
    fqdn = strdup(host->h_name);
    return fqdn;
  }
  /* also check h_aliases */
  for (i = 0; host->h_aliases[i] != NULL; i++)
  {
    if ((strncasecmp(hostname, host->h_aliases[i], hostnamelen) == 0) &&
        (host->h_aliases[i][hostnamelen] == '.') &&
        (host->h_aliases[i][hostnamelen + 1] != '\0'))
    {
      fqdn = strdup(host->h_aliases[i]);
      return fqdn;
    }
  }
  /* fall back to h_name if it has a dot in it */
  if (strchr(host->h_name, '.') != NULL)
  {
    fqdn = strdup(host->h_name);
    return fqdn;
  }
  /* also check h_aliases */
  for (i = 0; host->h_aliases[i] != NULL; i++)
  {
    if (strchr(host->h_aliases[i], '.') != NULL)
    {
      fqdn = strdup(host->h_aliases[i]);
      return fqdn;
    }
  }
  /* nothing found, fall back to hostname */
  fqdn = strdup(hostname);
  return fqdn;
}

const char *get_userpassword(MYLDAP_ENTRY *entry, const char *attr,
                             char *buffer, size_t buflen)
{
  const char *tmpvalue;
  /* get the value */
  tmpvalue = attmap_get_value(entry, attr, buffer, buflen);
  if (tmpvalue == NULL)
    return NULL;
  /* go over the entries and return the remainder of the value if it
     starts with {crypt} or crypt$ */
  if (strncasecmp(tmpvalue, "{crypt}", 7) == 0)
    return tmpvalue + 7;
  if (strncasecmp(tmpvalue, "crypt$", 6) == 0)
    return tmpvalue + 6;
  /* just return the first value completely */
  return tmpvalue;
  /* TODO: support more password formats e.g. SMD5
     (which is $1$ but in a different format)
     (any code for this is more than welcome) */
}

/* Checks if the specified name seems to be a valid user or group name. */
int isvalidname(const char *name)
{
  return regexec(&nslcd_cfg->validnames, name, 0, NULL, 0) == 0;
}

/* this writes a single address to the stream */
int write_address(TFILE *fp, MYLDAP_ENTRY *entry, const char *attr,
                  const char *addr)
{
  int32_t tmpint32;
  struct in_addr ipv4addr;
  struct in6_addr ipv6addr;
  /* try to parse the address as IPv4 first, fall back to IPv6 */
  if (inet_pton(AF_INET, addr, &ipv4addr) > 0)
  {
    /* write address type */
    WRITE_INT32(fp, AF_INET);
    /* write the address length */
    WRITE_INT32(fp, sizeof(struct in_addr));
    /* write the address itself (in network byte order) */
    WRITE(fp, &ipv4addr, sizeof(struct in_addr));
  }
  else if (inet_pton(AF_INET6, addr, &ipv6addr) > 0)
  {
    /* write address type */
    WRITE_INT32(fp, AF_INET6);
    /* write the address length */
    WRITE_INT32(fp, sizeof(struct in6_addr));
    /* write the address itself (in network byte order) */
    WRITE(fp, &ipv6addr, sizeof(struct in6_addr));
  }
  else
  {
    /* failure, log but write simple invalid address
       (otherwise the address list is messed up) */
    /* TODO: have error message in correct format */
    log_log(LOG_WARNING, "%s: %s: \"%s\" unparsable",
            myldap_get_dn(entry), attr, addr);
    /* write an illegal address type */
    WRITE_INT32(fp, -1);
    /* write an emtpy address */
    WRITE_INT32(fp, 0);
  }
  /* we're done */
  return 0;
}

int read_address(TFILE *fp, char *addr, int *addrlen, int *af)
{
  int32_t tmpint32;
  int len;
  /* read address family */
  READ_INT32(fp, *af);
  if ((*af != AF_INET) && (*af != AF_INET6))
  {
    log_log(LOG_WARNING, "incorrect address family specified: %d", *af);
    return -1;
  }
  /* read address length */
  READ_INT32(fp, len);
  if ((len > *addrlen) || (len <= 0))
  {
    log_log(LOG_WARNING, "address length incorrect: %d", len);
    return -1;
  }
  *addrlen = len;
  /* read address */
  READ(fp, addr, len);
  /* we're done */
  return 0;
}

/* convert the provided string representation of a sid
   (e.g. S-1-5-21-1936905831-823966427-12391542-23578)
   to a format that can be used to search the objectSid property with */
char *sid2search(const char *sid)
{
  const char *tmpsid = sid;
  char *res, *tmp;
  int i = 0;
  unsigned long int l;
  /* check the beginning of the string */
  if (strncasecmp(sid, "S-", 2) != 0)
  {
    log_log(LOG_ERR, "error in SID %s", sid);
    exit(EXIT_FAILURE);
  }
  /* count the number of dashes in the sid */
  while (tmpsid != NULL)
  {
    i++;
    tmpsid = strchr(tmpsid + 1, '-');
  }
  i -= 2; /* number of security ids plus one because we add the uid later */
  /* allocate memory */
  res = malloc(3 + 3 + 6 * 3 + i * 4 * 3 + 1);
  if (res == NULL)
  {
    log_log(LOG_CRIT, "malloc() failed to allocate memory");
    exit(1);
  }
  /* build the first part */
  l = strtoul(sid + 2, &tmp, 10);
  sprintf(res, "\\%02x\\%02x", (unsigned int)l & 0xff, (unsigned int)i);
  /* build authority part (we only handle 32 of the 48 bits) */
  l = strtoul(tmp + 1, &tmp, 10);
  sprintf(res + strlen(res), "\\00\\00\\%02x\\%02x\\%02x\\%02x",
          (unsigned int)((l >> 24) & 0xff),
          (unsigned int)((l >> 16) & 0xff),
          (unsigned int)((l >> 8) & 0xff),
          (unsigned int)(l & 0xff));
  /* go over the rest of the bits */
  while (*tmp != '\0')
  {
    l = strtoul(tmp + 1, &tmp, 10);
    sprintf(res + strlen(res), "\\%02x\\%02x\\%02x\\%02x",
            (unsigned int)(l & 0xff),
            (unsigned int)((l >> 8) & 0xff),
            (unsigned int)((l >> 16) & 0xff),
            (unsigned int)((l >> 24) & 0xff));
  }
  return res;
}

/* return the last security identifier of the binary sid */
unsigned long int binsid2id(const char *binsid)
{
  int i;
  /* find the position of the last security id */
  i = 2 + 6 + ((((unsigned int)binsid[1]) & 0xff) - 1) * 4;
  return (((unsigned long int)binsid[i]) & 0xff) |
         ((((unsigned long int)binsid[i + 1]) & 0xff) << 8) |
         ((((unsigned long int)binsid[i + 2]) & 0xff) << 16) |
         ((((unsigned long int)binsid[i + 3]) & 0xff) << 24);
}

#ifdef WANT_STRTOUI
/* provide a strtoui() implementation, similar to strtoul() but returning
   an range-checked unsigned int instead */
unsigned int strtoui(const char *nptr, char **endptr, int base)
{
  unsigned long val;
  val = strtoul(nptr, endptr, base);
  if (val > UINT_MAX)
  {
    errno = ERANGE;
    return UINT_MAX;
  }
  /* If errno was set by strtoul, we'll pass it back as-is */
  return (unsigned int)val;
}
#endif /* WANT_STRTOUI */
