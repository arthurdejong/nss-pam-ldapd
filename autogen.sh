#! /bin/sh

# run this to generate all initial .in files etc

# copy some files from automake/autoconf into place
[ -r /usr/share/misc/config.sub ] && \
  cp -f /usr/share/misc/config.sub config.sub
[ -r /usr/share/misc/config.guess ] && \
  cp -f /usr/share/misc/config.guess config.guess
[ -r /usr/share/automake-1.10/mkinstalldirs ] && \
  cp -f /usr/share/automake-1.10/mkinstalldirs mkinstalldirs
[ -r /usr/share/automake-1.10/missing ] && \
  cp -f /usr/share/automake-1.10/missing missing
[ -r /usr/share/automake-1.10/install-sh ] && \
  cp -f /usr/share/automake-1.10/install-sh install-sh
[ -r /usr/share/automake-1.10/depcomp ] && \
  cp -f /usr/share/automake-1.10/depcomp depcomp
[ -r /usr/share/automake-1.10/INSTALL ] && \
  cp -f /usr/share/automake-1.10/INSTALL INSTALL

# generate aclocal.m4 from configure.ac
aclocal-1.10 -I m4

# generate config.h.in from configure.ac
autoheader --warnings=all --force

# generate Makefile.in from Makefile.am and configure.ac
automake-1.10 --warnings=all --add-missing --copy --force-missing

# generate configure from configure.ac
autoconf --warnings=all --force
