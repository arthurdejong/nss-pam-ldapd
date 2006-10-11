#include <stdio.h>
#include <pwd.h>

void
main (int argc, char **argv)
{
  scan_passwd ();

  exit (0);
}
scan_passwd ()
{
  struct passwd p;
  char buf[1024];
  int i = 1;

#ifdef WEIRD_GETPWENT
  FILE *fp = NULL;
#endif
  memset (buf, 0xFF, sizeof (buf));

#ifdef WEIRD_GETPWENT
  setpwent_r (&fp);
#else
  setpwent_r ();
#endif

#ifdef WEIRD_GETPWENT
  while (getpwent_r (&p, buf, (int) sizeof (buf), &fp) == 0)
#else
  while (getpwent_r (&p, buf, (int) sizeof (buf)) == 0)
#endif
    {
      printf ("%s:%s:%d:%d:%s:%s:%s\n",
	      p.pw_name,
	      p.pw_passwd,
	      p.pw_uid, p.pw_gid, p.pw_gecos, p.pw_dir, p.pw_shell);
      i++;
    }

#ifdef WEIRD_GETPWENT
  endpwent_r (&fp);
#else
  endpwent_r ();
#endif
  fprintf (stderr, ">>>>>>> %d\n", i);

}
