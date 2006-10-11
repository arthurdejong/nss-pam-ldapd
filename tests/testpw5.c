
/* $Id: testpw5.c,v 1.2 2001/01/09 00:21:22 lukeh Exp $ */

/* This program just tests getpwent/getpwnam. You want to have nss_ldap
 * plugged in, so to speak, to test anything useful.
 */

#include "config.h"

#ifdef _REENTRANT
#ifdef HAVE_THREAD_H
#include <thread.h>
#else
#include <pthread.h>
#endif
#endif
#include <stdio.h>
#include <pwd.h>
#include <stdlib.h>

#if NeXT
#define uid_t int
#else
#include <dlfcn.h>		/* why? */
#endif

void test_passwd (void);

int ARGC;
char **ARGV;

#define MAX_THREADS  16

void
main (int argc, char **argv)
{
#ifdef _REENTRANT
  int i;
#endif
  ARGC = argc;
  ARGV = argv;

#ifdef _REENTRANT
  for (i = 0; i < MAX_THREADS; i++)
    {
      thread_t tid;
      thr_create (NULL, 0, test_passwd, NULL, 0, &tid);
      thr_continue (tid);
    }
  while (thr_join (NULL, NULL, NULL) == 0);
#else
  test_passwd ();
#endif
  exit (0);
}

#ifdef _REENTRANT
static void
ret (int status)
{
  thr_exit (&status);
}
#else
#define ret exit
#endif

void
test_passwd (void)
{
  struct passwd *pw;
  uid_t uid;
#ifdef _REENTRANT
  char buf[1024];
  struct passwd pbuf;
#endif



  printf (">>>>>> setpwent()\n");
  setpwent ();

  printf (">>>>>> getpwent()\n");
  scan_passwd ();

  printf (">>>>>> endpwent()\n");
  endpwent ();

  ret (0);
}

scan_passwd ()
{
  int i = 1;
  struct passwd *p;
#ifdef _REENTRANT
  char buf[1024];
  struct passwd pbuf;
  while ((p = getpwent_r (&pbuf, buf, sizeof (buf))) != NULL)
#else
  while ((p = getpwent ()) != NULL)
#endif
    {
      printf ("%s:%s:%d:%d:%s:%s:%s\n",
	      p->pw_name,
	      p->pw_passwd,
	      p->pw_uid, p->pw_gid, p->pw_gecos, p->pw_dir, p->pw_shell);

      if (p == NULL)
	ret (1);

#ifdef _REENTRANT
      p = getpwnam_r (p->pw_name, &pbuf, buf, sizeof (buf));
#else
      p = getpwnam (p->pw_name);
#endif

      if (p == NULL)
	ret (2);

      printf ("%s:%s:%d:%d:%s:%s:%s\n",
	      p->pw_name,
	      p->pw_passwd,
	      p->pw_uid, p->pw_gid, p->pw_gecos, p->pw_dir, p->pw_shell);

      i++;
    }
}
