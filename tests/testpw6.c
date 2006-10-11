
/* $Id: testpw6.c,v 1.2 2006/01/10 18:06:39 lukeh Exp $ */

/* This program just tests getpwent/getpwnam. You want to have nss_ldap
 * plugged in, so to speak, to test anything useful.
 */

#include "config.h"

#ifdef _REENTRANT
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#else
#include <thread.h>
#endif /* _REENTRANT */

#endif /* HAVE_PTHREAD_H */
#include <stdio.h>
#include <pwd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void test_passwd (void);
void scan_passwd (void);

int ARGC;
char **ARGV;

#define MAX_THREADS 8

void
main (int argc, char **argv)
{
#ifdef _REENTRANT
  int i;
#ifdef HAVE_PTHREAD_H
  pthread_t tids[MAX_THREADS];
#endif
#endif
  pid_t pid;
  ARGC = argc;
  ARGV = argv;

  /* PRIME */
  scan_passwd();

   pid = fork();
   if (pid == 0) {
	printf("IN CHILD\n");
   } else {
	printf("IN PARENT\n");
   }

#ifdef _REENTRANT
  for (i = 0; i < MAX_THREADS; i++)
    {
#ifdef HAVE_PTHREAD_H
      pthread_create(&tids[i], NULL, test_passwd, NULL);
#else
      thread_t tid;
      thr_create (NULL, 0, test_passwd, NULL, 0, &tid);
      thr_continue (tid);
#endif /* HAVE_PTHREAD_H */
    }
#ifdef HAVE_PTHREAD_H
  for (i = 0; i < MAX_THREADS; i++) pthread_join(tids[i], NULL);
#else
  while (thr_join (NULL, NULL, NULL) == 0);
#endif
#else
  test_passwd ();
#endif
  exit (0);
}

#ifdef _REENTRANT
static void
ret (int status)
{
#ifdef HAVE_PTHREAD_H
  pthread_exit(&status);
#else
  thr_exit (&status);
#endif
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
  int pid;

  printf (">>>>>> getpwnam(\"%s\")\n", ARGC > 1 ? ARGV[1] : "testuser");
#ifdef _REENTRANT
#if GETHOSTBYNAME_R_ARGS == 6
  if (getpwnam_r (ARGC > 1 ? ARGV[1] : "testuser", &pbuf, buf, sizeof (buf), &pw) != 0) pw = NULL;
#else
  pw = getpwnam_r (ARGC > 1 ? ARGV[1] : "testuser", &pbuf, buf, sizeof (buf));
#endif
#else
  pw = getpwnam (ARGC > 1 ? ARGV[1] : "testuser");
#endif

  if (!pw)
    ret (1);

  printf ("%s:%s:%d:%d:%s:%s:%s\n", pw->pw_name, pw->pw_passwd, pw->pw_uid,
	  pw->pw_gid, pw->pw_gecos, pw->pw_dir, pw->pw_shell);
  uid = pw->pw_uid;


  printf (">>>>>> getpwuid(%d)\n", uid);

#ifdef _REENTRANT
#if GETHOSTBYNAME_R_ARGS == 6
  if (getpwuid_r (uid, &pbuf, buf, sizeof(buf), &pw) != 0) pw = NULL;
#else
  pw = getpwuid_r (uid, &pbuf, buf, sizeof (buf));
#endif
#else
  pw = getpwuid (uid);
#endif

  if (!pw)
    ret (1);


  printf ("%s:%s:%d:%d:%s:%s:%s\n", pw->pw_name, pw->pw_passwd, pw->pw_uid,
	  pw->pw_gid, pw->pw_gecos, pw->pw_dir, pw->pw_shell);

  if (ARGC > 2 && !strcmp (ARGV[2], "no"))
    {
      printf (">>>>>> Enumeration skipped.\n");
    }
  else
    {
      printf (">>>>>> setpwent()\n");
      setpwent ();

      printf (">>>>>> getpwent()\n");
      scan_passwd ();

      printf (">>>>>> endpwent()\n");
      endpwent ();
    }

  ret (0);
}

void
scan_passwd (void)
{
  int i = 1;
  struct passwd *p;
#ifdef _REENTRANT
  char buf[1024];
  struct passwd pbuf;
#endif


#ifdef _REENTRANT
#if GETHOSTBYNAME_R_ARGS == 6
  while (getpwent_r (&pbuf, buf, sizeof (buf), &p) == 0 && p != NULL)
#else
  while ((p = getpwent_r (&pbuf, buf, sizeof (buf))) != NULL)
#endif
#else
  while ((p = getpwent ()) != NULL)
#endif
    {
      printf ("%s:%s:%d:%d:%s:%s:%s\n",
	      p->pw_name,
	      p->pw_passwd,
	      p->pw_uid, p->pw_gid, p->pw_gecos, p->pw_dir, p->pw_shell);
      i++;
    }
}
