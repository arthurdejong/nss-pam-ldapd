#! /bin/sh

# run this to generate all initial .in files etc

# copy some files from automake/autoconf into place
[ -r /usr/share/misc/config.sub ] && \
  cp -f /usr/share/misc/config.sub config.sub
[ -r /usr/share/misc/config.guess ] && \
  cp -f /usr/share/misc/config.guess config.guess
[ -r /usr/share/automake-1.11/mkinstalldirs ] && \
  cp -f /usr/share/automake-1.11/mkinstalldirs mkinstalldirs
[ -r /usr/share/automake-1.11/missing ] && \
  cp -f /usr/share/automake-1.11/missing missing
[ -r /usr/share/automake-1.11/install-sh ] && \
  cp -f /usr/share/automake-1.11/install-sh install-sh
[ -r /usr/share/automake-1.11/depcomp ] && \
  cp -f /usr/share/automake-1.11/depcomp depcomp
[ -r /usr/share/automake-1.11/INSTALL ] && \
  cp -f /usr/share/automake-1.11/INSTALL INSTALL

# generate aclocal.m4 from configure.ac
aclocal-1.11 -I m4

# generate config.h.in from configure.ac
autoheader --warnings=all --force

# generate Makefile.in from Makefile.am and configure.ac
automake-1.11 --warnings=all --add-missing --copy --force-missing

# generate configure from configure.ac
autoconf --warnings=all --force
