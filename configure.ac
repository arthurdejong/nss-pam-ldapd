# configure.ac - process this file with autoconf to produce configure
#
# Copyright (C) 2006 Luke Howard
# Copyright (C) 2006 West Consulting
# Copyright (C) 2006, 2007 Arthur de Jong
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301 USA

AC_PREREQ(2.59)
AC_COPYRIGHT(
[Copyright (C) 2006 Luke Howard
Copyright (C) 2006 West Consulting
Copyright (C) 2006, 2007 Arthur de Jong

This configure script is derived from configure.ac which is free software;
you can redistribute it and/or modify it under the terms of the GNU Lesser
General Public License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version. See the
configure.ac file for more details.])

# initialize and set version and bugreport address
AC_INIT([nss-ldapd],[0.2],[arthur@ch.tudelft.nl])
RELEASE_MONTH="Jun 2007"
AC_SUBST(RELEASE_MONTH)
AC_CONFIG_SRCDIR([nslcd.h])

AC_CANONICAL_TARGET
AC_PREFIX_DEFAULT()

# display notice and initialize automake
AC_MSG_NOTICE([configuring AC_PACKAGE_TARNAME AC_PACKAGE_VERSION])
AM_INIT_AUTOMAKE(AC_PACKAGE_TARNAME,AC_PACKAGE_VERSION)

# create a config.h file (Automake will add -DHAVE_CONFIG_H)
AC_CONFIG_HEADERS([config.h])

# check for programs
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_RANLIB

# start with default options
nss_ldap_so_LIBS=
nslcd_LIBS=

# check for debugging options
AC_ARG_ENABLE(debug,
              AS_HELP_STRING([--enable-debug],
                             [enable extensive debugging and logging]),
              [if test "x$enableval" != "xno" ; then CFLAGS="-g -DDEBUG $CFLAGS" ; fi])

# Check for extra compiler warnings
AC_ARG_ENABLE(warnings,
              AS_HELP_STRING([--enable-warnings],
                             [enable extra compiler warnings (gcc)]),
              [if test "x$enableval" != "no" ; then CFLAGS="$CFLAGS -pedantic -Wall -Wshadow -Wpointer-arith -Wcast-qual -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wnested-externs -Waggregate-return -Wmissing-declarations -Wunused -Wformat=2 -Wswitch-default -Wswitch-enum -Wfloat-equal -Wdeclaration-after-statement -Wextra -Wpointer-arith -Wbad-function-cast -Wunreachable-code -Wredundant-decls -Wredundant-decls" ; fi])

dnl
dnl --enable-paged-results is now deprecated; if this option is set,
dnl then paged results will be enabled by default. However, it can
dnl now always be enabled at runtime (as long as the underlying LDAP
dnl library supports ldap_search_ext()) with the nss_paged_results
dnl keyword. See nss_ldap(5) for more information
dnl
AC_ARG_ENABLE(paged-results,
              AS_HELP_STRING([--enable-paged-results],
                             [use paged results control by default]),
              [AC_DEFINE(PAGE_RESULTS,1,[Define to enable paged results control.])])

dnl
dnl XXX TODO make configurable-krb5-ccname-* configurable at runtime
dnl
AC_ARG_ENABLE(configurable-krb5-ccname-env,
              AS_HELP_STRING([--enable-configurable-krb5-ccname-env],
                             [enable configurable Kerberos V credentials cache name (putenv method)]),
              [ AC_DEFINE(CONFIGURE_KRB5_CCNAME,1,[Define to enable configurable Kerberos credentials cache.])
                AC_DEFINE(CONFIGURE_KRB5_CCNAME_ENV,1,[Define to enable configurable Kerberos credentials cache (putenv method).]) ])

AC_ARG_ENABLE(configurable-krb5-ccname-gssapi,
              AS_HELP_STRING([--enable-configurable-krb5-ccname-gssapi],
                             [enable configurable Kerberos V credentials cache name (gssapi method)]),
              [ AC_DEFINE(CONFIGURE_KRB5_CCNAME)
                AC_DEFINE(CONFIGURE_KRB5_CCNAME_GSSAPI,1,[Define to enable configurable Kerberos credentials cache (gssapi method).]) ])

AC_ARG_WITH(ldap-lib,
            AS_HELP_STRING([--with-ldap-lib=TYPE],
                           [select ldap library (auto|netscape5|netscape4|netscape3|umich|openldap) @<:@auto@:>@]))
if test -z "$with_ldap_lib"; then
  with_ldap_lib=auto
fi

AC_ARG_WITH(ldap-conf-file,
            AS_HELP_STRING([--with-ldap-conf-file=PATH],
                           [path to LDAP configuration file @<:@/etc/nss-ldapd.conf@:>@]),
            [ NSS_LDAP_PATH_CONF="$with_ldap_conf_file" ],
            [ NSS_LDAP_PATH_CONF="/etc/nss-ldapd.conf" ])
AC_DEFINE_UNQUOTED(NSS_LDAP_PATH_CONF,"$NSS_LDAP_PATH_CONF",[Path to LDAP configuration file.])
AC_SUBST(NSS_LDAP_PATH_CONF)

AC_ARG_WITH(ldap-secret-file,
            AS_HELP_STRING([--with-ldap-secret-file=PATH],
                           [path to LDAP root secret file @<:@/etc/nss-ldapd.secret@:>@]),
            [ NSS_LDAP_PATH_ROOTPASSWD="$with_ldap_secret_file" ],
            [ NSS_LDAP_PATH_ROOTPASSWD="/etc/nss-ldapd.secret" ])
AC_DEFINE_UNQUOTED(NSS_LDAP_PATH_ROOTPASSWD,"$NSS_LDAP_PATH_ROOTPASSWD",[Path to LDAP root secret file.])
AC_SUBST(NSS_LDAP_PATH_ROOTPASSWD)

AC_ARG_WITH(nslcd-pidfile,
            AS_HELP_STRING([--with-nslcd-pidfile=PATH],
                           [path to pidfile @<:@/var/run/nslcd/nslcd.pid@:>@]),
            [ NSLCD_PIDFILE="$with_nslcd_pidfile" ],
            [ NSLCD_PIDFILE="/var/run/nslcd/nslcd.pid" ])
AC_DEFINE_UNQUOTED(NSLCD_PIDFILE,"$NSLCD_PIDFILE",[The location of the pidfile used for checking availability of the nslcd.])
AC_SUBST(NSLCD_PIDFILE)

AC_ARG_WITH(nslcd-socket,
            AS_HELP_STRING([--with-nslcd-socket=PATH],
                           [path to socket @<:@/var/run/nslcd/socket@:>@]),
            [ NSLCD_SOCKET="$with_nslcd_socket" ],
            [ NSLCD_SOCKET="/var/run/nslcd/socket" ])
AC_DEFINE_UNQUOTED(NSLCD_SOCKET,"$NSLCD_SOCKET",[The location of the socket used for communicating.])
AC_SUBST(NSLCD_SOCKET)

AC_ARG_WITH(gssapi-dir,
            AS_HELP_STRING([--with-gssapi-dir=PATH],
                           [base directory of gssapi SDK]))

ldap_nss_ngroups=64
AC_ARG_WITH(ngroups,
            AS_HELP_STRING([--with-ngroups=NUM],
                           [average group size hint, experts only]),
            [ldap_nss_ngroups=$with_ngroups])
AC_DEFINE_UNQUOTED(LDAP_NSS_NGROUPS,$ldap_nss_ngroups,[Maximum number of group members in static buffer.])


# checks for availability of header files
AC_CHECK_HEADERS(lber.h)
AC_CHECK_HEADERS(ldap.h,,AC_MSG_ERROR([could not locate <ldap.h>]))
AC_CHECK_HEADERS(ldap_ssl.h)
AC_CHECK_HEADERS(nss.h)
AC_CHECK_HEADERS(nsswitch.h)
AC_CHECK_HEADERS(irs.h)
AC_CHECK_HEADERS(thread.h)
AC_CHECK_HEADERS(pthread.h)
AC_CHECK_HEADERS(synch.h)
AC_CHECK_HEADERS(malloc.h)
AC_CHECK_HEADERS(shadow.h)
AC_CHECK_HEADERS(prot.h)
AC_CHECK_HEADERS(port_before.h)
AC_CHECK_HEADERS(port_after.h)
AC_CHECK_HEADERS(aliases.h)
AC_CHECK_HEADERS(net/route.h)
AC_CHECK_HEADERS(netinet/if_ether.h)
AC_CHECK_HEADERS(netinet/ether.h)
AC_CHECK_HEADERS(ctype.h)
AC_CHECK_HEADERS(getopt.h)
AC_CHECK_HEADERS(alignof.h)
AC_CHECK_HEADERS(rpc/rpcent.h)
AC_CHECK_HEADERS(sys/byteorder.h)
AC_CHECK_HEADERS(sys/un.h)
AC_CHECK_HEADERS(libc-lock.h)
AC_CHECK_HEADERS(bits/libc-lock.h)
AC_CHECK_HEADERS(sasl.h sasl/sasl.h)
AC_CHECK_HEADERS(strings.h)
AC_CHECK_HEADERS(gssldap.h)
AC_CHECK_HEADERS(gsssasl.h)
AC_CHECK_HEADERS(gssapi/gssapi_krb5.h gssapi.h)
AC_CHECK_HEADERS(grp.h)

# checks for availability of system libraries for nslcd
save_LIBS="$LIBS"
LIBS="$nslcd_LIBS"
AC_SEARCH_LIBS(gethostbyname,nsl socket)
AC_SEARCH_LIBS(socket,socket)
AC_CHECK_LIB(resolv,main)
AC_SEARCH_LIBS(daemon,bsd)
nslcd_LIBS="$LIBS"
LIBS="$save_LIBS"

# check for availability of system libraries for nss part
save_LIBS="$LIBS"
LIBS="$nss_ldap_so_LIBS"
AC_SEARCH_LIBS(socket,socket)
nss_ldap_so_LIBS="$LIBS"
LIBS="$save_LIBS"

# TODO: simplify the above since we need a correct LIBS for the following
#       tests

# checks for availability of functions
AC_CHECK_FUNCS(strtok_r)
AC_CHECK_FUNCS(sigaction)
AC_CHECK_FUNCS(sigset)
AC_CHECK_FUNCS(res_search)
AC_CHECK_FUNCS(dn_expand)
AC_CHECK_FUNCS(snprintf)
AC_CHECK_FUNCS(gethostbyname)
AC_CHECK_FUNCS(nsdispatch)
AC_CHECK_FUNCS(ether_aton)
AC_CHECK_FUNCS(ether_ntoa)
AC_CHECK_FUNCS(setgroups)

# checks for types
AC_C_CONST
AC_TYPE_SIGNAL
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T

# check for support for the __thread keyword
AC_CACHE_CHECK([whether $CC supports '__thread'], [mn_cv_c___thread_supported],
               [AC_COMPILE_IFELSE(AC_LANG_PROGRAM([[static __thread i;]], []),
                       [mn_cv_c___thread_supported=yes],
                       [mn_cv_c___thread_supported=no])])
if test $mn_cv_c___thread_supported != yes
then
  AC_MSG_ERROR([$CC does not support '__thread' keyword])
fi

# check for support for the struct ether_addr structure
AC_MSG_CHECKING(for struct ether_addr)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <sys/types.h>
        #include <sys/socket.h>
        #include <net/if.h>
        #include <netinet/in.h>
        #include <netinet/if_ether.h>]], [[struct ether_addr x;]])],[
                AC_MSG_RESULT(yes)
                AC_DEFINE(HAVE_STRUCT_ETHER_ADDR,1,[Define to enable struct ether_addr definition.])
        ],[AC_MSG_RESULT(no)])

AC_MSG_CHECKING(for socklen_t)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <sys/types.h>
        #include <sys/socket.h>]], [[socklen_t len;]])],[
                AC_MSG_RESULT(yes)
                AC_DEFINE(HAVE_SOCKLEN_T, 1, [Define to enable socklen_t definition.])
        ],[AC_MSG_RESULT(no)])

# check to see if socklen_t is defined
AC_CHECK_TYPE(socklen_t,,
    AC_DEFINE(socklen_t, size_t,
    [Define to `size_t' if not defined elswhere.]),
    [
#include <sys/types.h>
#include <sys/socket.h>])

# check to see if struct sockaddr_storage is defined
AC_CHECK_TYPE(struct sockaddr_storage,,
    AC_DEFINE(sockaddr_storage,sockaddr_in,
    [Define to 'sockaddr_in' if not defined elsewhere.]),
    [
#include <sys/types.h>
#include <sys/socket.h>])

# checks for LDAP library
save_LIBS="$LIBS"
LIBS="$nslcd_LIBS"
save_CFLAGS="$CFLAGS"

# check threading stuff
ACX_PTHREAD(,AC_MSG_ERROR([no support for pthreads]))
AC_CHECK_FUNCS(pthread_atfork)

LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

AC_CHECK_LIB(gssapi, gss_krb5_ccache_name,[LIBS="-lgssapi $LIBS" found_gssapi_lib=yes],,$LIBS)
if test -z "$found_gssapi_lib"; then
  AC_CHECK_LIB(gssapi_krb5, gss_krb5_ccache_name,[LIBS="-lgssapi_krb5 $LIBS"],,$LIBS)
fi

if test -z "$found_ldap_lib" -a \( $with_ldap_lib = auto -o $with_ldap_lib = umich -o $with_ldap_lib = openldap \); then
  AC_CHECK_LIB(lber, main)
  AC_CHECK_LIB(ldap, main, [LIBS="-lldap_r $LIBS" found_ldap_lib=yes],,$LIBS)
fi
if test -z "$found_ldap_lib" -a \( $with_ldap_lib = auto -o $with_ldap_lib = netscape5 \); then
AC_CHECK_LIB(ldap50, main, LIBS="-lldap50 -lssldap50 -lssl3 -lnss3 -lnspr4 -lprldap50 -lplc4 -lplds4 $LIBS" found_ldap_lib=yes need_pthread=yes,, -lpthread)
fi
if test -z "$found_ldap_lib" -a \( $with_ldap_lib = auto -o $with_ldap_lib = netscape4 \); then
  AC_CHECK_LIB(ldapssl41, main, LIBS="-lldapssl41 -lplc3 -lplds3 -lnspr3 $LIBS" found_ldap_lib=yes need_pthread=yes,, -lpthread)
  if test -z "$found_ldap_lib"; then
    AC_CHECK_LIB(ldapssl40, main, LIBS="-lldapssl40 $LIBS" found_ldap_lib=yes need_pthread=yes,, -lpthread)
  fi
  if test -z "$found_ldap_lib"; then
    AC_CHECK_LIB(ldap41, main, LIBS="-lldap41 $LIBS" found_ldap_lib=yes need_pthread=no,,)
  fi
  if test -z "$found_ldap_lib"; then
    AC_CHECK_LIB(ldap40, main, LIBS="-lldap40 $LIBS" found_ldap_lib=yes need_pthread=no,,)
  fi
fi
if test -z "$found_ldap_lib" -a \( $with_ldap_lib = auto -o $with_ldap_lib = netscape3 \); then
  AC_CHECK_LIB(ldapssl30, main, LIBS="-lldapssl30 $LIBS" found_ldap_lib=yes need_pthread=yes,, -lpthread)
fi
if test -z "$found_ldap_lib"; then
  AC_MSG_ERROR(could not locate a valid LDAP library)
fi
if test "$need_pthread" = "yes"; then
  AC_CHECK_LIB(pthread, main)
fi
AC_CHECK_LIB(gssldap, ldap_gss_bind,[LIBS="-lgssldap $LIBS"],,$LIBS)

AC_CHECK_FUNCS(sasl_auxprop_request)
AC_CHECK_FUNCS(ldap_init ldap_get_lderrno ldap_parse_result ldap_memfree ldap_controls_free)
AC_CHECK_FUNCS(ldap_ld_free ldap_explode_rdn ldap_set_option ldap_get_option)
AC_CHECK_FUNCS(ldap_sasl_interactive_bind_s ldap_initialize ldap_search_ext)
AC_CHECK_FUNCS(ldap_create_control ldap_create_page_control ldap_parse_page_control)
AC_CHECK_FUNCS(ldap_set_rebind_proc)
AC_CACHE_CHECK(whether ldap_set_rebind_proc takes 3 arguments, nss_ldap_cv_ldap_set_rebind_proc, [
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <lber.h>
#include <ldap.h>]], [[ldap_set_rebind_proc(0, 0, 0);]])],[nss_ldap_cv_ldap_set_rebind_proc=3],[nss_ldap_cv_ldap_set_rebind_proc=2]) ])
AC_DEFINE_UNQUOTED(LDAP_SET_REBIND_PROC_ARGS, $nss_ldap_cv_ldap_set_rebind_proc,[Define to the number of arguments to ldap_set_rebindproc.])

CFLAGS="$save_CFLAGS"
nslcd_LIBS="$LIBS"
LIBS="$save_LIBS"

AC_SUBST(nss_ldap_so_LIBS)
AC_SUBST(nslcd_LIBS)

# generate files
AC_CONFIG_FILES([Makefile common/Makefile nss/Makefile nslcd/Makefile tests/Makefile tests/dict/Makefile tests/tio/Makefile])
AC_OUTPUT
