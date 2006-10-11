/* test IRS, independently of getpwnam et al. */

#include <stdio.h>
#include <pwd.h>
#include <bsd/netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "irs-nss.h"

static const char *testhost = "davinci.eng.sun.com";
static char rcsid[] = "$Id: testpw4.c,v 1.2 2001/01/09 00:21:22 lukeh Exp $";

void
main (void)
{

  struct irs_pw *irs;
  struct irs_ho *irs2;
  struct passwd *pwd;
  struct hostent *h;

  int i;

  i = 0;

  printf ("Testing irs_pw enumeration...\n");

  /* test users */
  irs = irs_ldap_pw (NULL);

  (irs->rewind) (irs);
  while ((pwd = (irs->next) (irs)))
    {
      printf ("%s:%s:%d:%d:%s:%s:%s\n",
	      pwd->pw_name,
	      pwd->pw_passwd,
	      pwd->pw_uid,
	      pwd->pw_gid, pwd->pw_gecos, pwd->pw_dir, pwd->pw_shell);
      i++;
    }
  (irs->close) (irs);
  free (irs);

  fprintf (stderr, ">>>>>>> %d entries\n", i);

  /* test hosts */

  printf ("Testing irs_ho enumeration...\n");

  irs2 = irs_ldap_ho (NULL);
  i = 0;

  (irs2->rewind) (irs2);
  while ((h = (irs2->next) (irs2)))
    {
      struct in_addr addr;
      bcopy (h->h_addr, &addr.s_addr, h->h_length);
      printf ("%s\t%s\n", (char *) inet_ntoa (addr), h->h_name);
      i++;
    }
  (irs2->close) (irs2);
  fprintf (stderr, ">>>>>>> %d entries\n", i);

  printf ("Testing irs_ho byname...\n");

  h = (irs2->byname) (irs2, testhost);
  if (h != NULL)
    {
      struct in_addr addr;
      bcopy (h->h_addr, &addr.s_addr, h->h_length);
      printf ("%s\t%s\n", (char *) inet_ntoa (addr), h->h_name);
    }

  free (irs);

  exit (0);
}
