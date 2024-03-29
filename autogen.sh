#! /bin/sh

# run this to generate all initial .in files etc

# copy some files from automake/autoconf into place
[ -r /usr/share/misc/config.sub ] && \
  cp -f /usr/share/misc/config.sub config.sub
[ -r /usr/share/misc/config.guess ] && \
  cp -f /usr/share/misc/config.guess config.guess
automake_libdir="`automake --print-libdir`"
for fname in INSTALL ar-lib compile depcomp install-sh missing \
             mkinstalldirs py-compile test-driver
do
  [ -r "$automake_libdir/$fname" ] && \
    cp -f "$automake_libdir/$fname" "$fname"
done

# generate aclocal.m4 from configure.ac
aclocal -I m4

# generate config.h.in from configure.ac
autoheader --warnings=all --force

# generate Makefile.in from Makefile.am and configure.ac
automake --warnings=all --add-missing --copy --force-missing

# generate configure from configure.ac
autoconf --warnings=all --force
