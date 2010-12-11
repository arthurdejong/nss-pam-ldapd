# configure.ac - process this file with autoconf to produce configure
#
# Copyright (C) 2006 Luke Howard
# Copyright (C) 2006 West Consulting
# Copyright (C) 2006, 2007, 2008, 2009, 2010 Arthur de Jong
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

AC_PREREQ(2.61)
AC_COPYRIGHT(
[Copyright (C) 2006 Luke Howard
Copyright (C) 2006 West Consulting
Copyright (C) 2006, 2007, 2008, 2009, 2010 Arthur de Jong

This configure script is derived from configure.ac which is free software;
you can redistribute it and/or modify it under the terms of the GNU Lesser
General Public License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version. See the
configure.ac file for more details.])

# initialize and set version and bugreport address
AC_INIT([nss-pam-ldapd],[0.7.13],[nss-pam-ldapd-users@lists.arthurdejong.org])
RELEASE_MONTH="Dec 2010"
AC_SUBST(RELEASE_MONTH)
AC_CONFIG_SRCDIR([nslcd.h])

# some initialisation
AC_CANONICAL_TARGET
AC_PREFIX_DEFAULT()
AC_CONFIG_LIBOBJ_DIR([compat])

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
AM_PROG_CC_C_O
AC_USE_SYSTEM_EXTENSIONS

# checks for tool to convert docbook to man
AC_PATH_PROGS(DOCBOOK2X_MAN, docbook2x-man)
if test "x${DOCBOOK2X_MAN}" = x
then
  AC_MSG_WARN([docbook2x-man not found: not generating man pages])
fi
AM_CONDITIONAL([GENMAN], [test "x${DOCBOOK2X_MAN}" != x])

# check for debugging options
AC_ARG_ENABLE(debug,
              AS_HELP_STRING([--enable-debug],
                             [enable extensive debugging and logging]),
              [if test "x$enableval" != "xno" ; then CFLAGS="-g -DDEBUG $CFLAGS" ; fi])

DESIRED_CFLAGS=""

# check for extra compiler warnings
AC_ARG_ENABLE(warnings,
              AS_HELP_STRING([--enable-warnings],
                             [enable extra compiler warnings (gcc)]),
              [if test "x$enableval" != "no"
               then
                 CFLAGS="$CFLAGS -pedantic -Wall -Wshadow -Wpointer-arith -Wcast-qual -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wnested-externs -Waggregate-return -Wmissing-declarations -Wunused -Wformat=2 -Wswitch-default -Wswitch-enum -Wfloat-equal -Wbad-function-cast -Wredundant-decls"
                 DESIRED_CFLAGS="$DESIRED_CFLAGS -Wextra -Wdeclaration-after-statement -Werror-implicit-function-declaration"
               fi])
test_gcc_flag() {
  AC_LANG_CONFTEST([int main() {}])
  $CC -c conftest.c $CFLAGS $@ > /dev/null 2> /dev/null
  ret=$?
  rm -f conftest.o
  return $ret
}
for flag in $DESIRED_CFLAGS
do
  AC_MSG_CHECKING([whether $CC accepts $flag])
  if test_gcc_flag $flag
  then
    CFLAGS="$CFLAGS $flag"
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
  fi
done

# add --disable-maintainer-mode option
AM_MAINTAINER_MODE([enable])

# check whether the NSS module should be built
AC_MSG_CHECKING([whether to build the NSS module])
AC_ARG_ENABLE(nss,
              AS_HELP_STRING([--disable-nss],
                             [build the NSS module [[default=enabled]]]),,
              [enable_nss="yes"])
AC_MSG_RESULT($enable_nss)
AM_CONDITIONAL([ENABLE_NSS], [test "x$enable_nss" = "xyes"])

# check whether the PAM module should be built
AC_MSG_CHECKING([whether to build the PAM module])
AC_ARG_ENABLE(pam,
              AS_HELP_STRING([--disable-pam],
                             [build the PAM module [[default=enabled]]]),,
              [enable_pam="yes"])
AC_MSG_RESULT($enable_pam)
AM_CONDITIONAL([ENABLE_PAM], [test "x$enable_pam" = "xyes"])

# check whether the nslcd daemon should be built
AC_MSG_CHECKING([whether to build the nslcd server])
AC_ARG_ENABLE(nslcd,
              AS_HELP_STRING([--disable-nslcd],
                             [build the nslcd server [[default=enabled]]]),,
              [enable_nslcd="yes"])
AC_MSG_RESULT($enable_nslcd)
AM_CONDITIONAL([ENABLE_NSLCD], [test "x$enable_nslcd" = "xyes"])

# check whether SASL support should be enabled
AC_MSG_CHECKING([whether to enable SASL support])
AC_ARG_ENABLE(sasl,
              AS_HELP_STRING([--disable-sasl],
                             [disable SASL support [[default=enabled]]]),
              [enable_sasl=$enableval],
              [enable_sasl="yes"])
AC_MSG_RESULT($enable_sasl)

# check whether Kerberos support should be enabled
AC_MSG_CHECKING([whether to enable Kerberos support])
AC_ARG_ENABLE(kerberos,
              AS_HELP_STRING([--disable-kerberos],
                             [disable Kerberos support [[default=enabled]]]),
              [enable_kerberos=$enableval],
              [enable_kerberos="yes"])
AC_MSG_RESULT($enable_kerberos)

# check whether configfile options should be checked
AC_MSG_CHECKING([whether to check configfile options])
AC_ARG_ENABLE(configfile_checking,
              AS_HELP_STRING([--disable-configfile-checking],
                             [check configfile options [[default=enabled]]]),
              [configfile_checking=$enableval],
              [configfile_checking="yes"])
AC_MSG_RESULT($configfile_checking)
if test "x$configfile_checking" = "xyes"
then
  AC_DEFINE(ENABLE_CONFIGFILE_CHECKING,1,[Whether to check configfile options.])
fi

# check the name of the configuration file
AC_ARG_WITH(ldap-conf-file,
            AS_HELP_STRING([--with-ldap-conf-file=PATH],
                           [path to nslcd configuration file @<:@/etc/nslcd.conf@:>@]),
            [ NSLCD_CONF_PATH="$with_ldap_conf_file" ],
            [ NSLCD_CONF_PATH="/etc/nslcd.conf" ])
AC_DEFINE_UNQUOTED(NSLCD_CONF_PATH,"$NSLCD_CONF_PATH",[Path to nslcd configuration file.])
AC_SUBST(NSLCD_CONF_PATH)

# check the name of the file with a bindpw value
AC_ARG_WITH(bindpw-file,
            AS_HELP_STRING([--with-bindpw-file=PATH],
                           [path to file with value for bindpw @<:@disabled@:>@]),
            [ NSLCD_BINDPW_PATH="$with_bindpw_file"
              AC_DEFINE_UNQUOTED(NSLCD_BINDPW_PATH,"$NSLCD_BINDPW_PATH",[Path to bindpw value.])
              AC_SUBST(NSLCD_BINDPW_PATH)
            ])

# where should the pidfile be written
AC_ARG_WITH(nslcd-pidfile,
            AS_HELP_STRING([--with-nslcd-pidfile=PATH],
                           [path to pidfile @<:@/var/run/nslcd/nslcd.pid@:>@]),
            [ NSLCD_PIDFILE="$with_nslcd_pidfile" ],
            [ NSLCD_PIDFILE="/var/run/nslcd/nslcd.pid" ])
AC_DEFINE_UNQUOTED(NSLCD_PIDFILE,"$NSLCD_PIDFILE",[The location of the pidfile used for checking availability of the nslcd.])
AC_SUBST(NSLCD_PIDFILE)

# where is the socket used for communication
AC_ARG_WITH(nslcd-socket,
            AS_HELP_STRING([--with-nslcd-socket=PATH],
                           [path to socket @<:@/var/run/nslcd/socket@:>@]),
            [ NSLCD_SOCKET="$with_nslcd_socket" ],
            [ NSLCD_SOCKET="/var/run/nslcd/socket" ])
AC_DEFINE_UNQUOTED(NSLCD_SOCKET,"$NSLCD_SOCKET",[The location of the socket used for communicating.])
AC_SUBST(NSLCD_SOCKET)

# the SONAME to use for the NSS module
AC_ARG_WITH(nss-ldap-soname,
            AS_HELP_STRING([--with-nss-ldap-soname=SONAME],
                           [name of NSS module @<:@libnss_ldap.so.2@:>@]),
            [ NSS_LDAP_SONAME="$with_nss_ldap_soname" ],
            [ NSS_LDAP_SONAME="libnss_ldap.so.2" ])
AC_DEFINE_UNQUOTED(NSS_LDAP_SONAME,"$NSS_LDAP_SONAME",[The SONAME of the NSS library module.])
AC_SUBST(NSS_LDAP_SONAME)

# checks for availability of header files
AC_CHECK_HEADERS([ctype.h strings.h pthread.h fcntl.h limits.h])
AC_CHECK_HEADERS([nss.h nss_common.h grp.h shadow.h aliases.h netdb.h rpc/rpcent.h])
AC_CHECK_HEADERS([netinet/ether.h arpa/inet.h netinet/in.h])
AC_CHECK_HEADERS([sys/socket.h sys/un.h sys/ucred.h ucred.h sys/param.h sys/time.h])
AC_CHECK_HEADERS([getopt.h syslog.h])

# other general checks
AC_C_INLINE
AC_C_CONST

# checks for availability of common functions
AC_CHECK_FUNCS([sigaction snprintf])
AC_CHECK_FUNCS(gethostbyname)
AC_SEARCH_LIBS(socket,socket)
AC_CHECK_FUNCS([strcasecmp strncasecmp strchr strcspn strspn strtol])
AC_CHECK_FUNCS([malloc realloc])
AC_FUNC_FORK

# checks for types
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_INT32_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# check for support for the __thread keyword
AC_CACHE_CHECK([whether $CC supports '__thread'], [mn_cv_c___thread_supported],
               [AC_COMPILE_IFELSE(AC_LANG_PROGRAM([[static __thread i;]], []),
                       [mn_cv_c___thread_supported=yes],
                       [mn_cv_c___thread_supported=no])])
if test $mn_cv_c___thread_supported != yes
then
  AC_MSG_WARN([$CC does not support '__thread' keyword])
  AC_DEFINE(__thread,,[Define to empty if compiler does not support `__thread' keyword.])
fi

# check how to pass a symbol map to the linker
AC_MSG_CHECKING([how linker wants the symbol map])
if $CC -Wl,--help 2>&1 | grep -- --version-script >/dev/null
then
  VERSION_SCRIPT_FLAG="-Wl,--version-script,"
  AC_SUBST(VERSION_SCRIPT_FLAG)
  AC_MSG_RESULT([--version-script])
elif $CC -Wl,--help 2>&1 | grep -- '-M mapfile' >/dev/null
then
  VERSION_SCRIPT_FLAG="-Wl,-M,"
  AC_SUBST(VERSION_SCRIPT_FLAG)
  AC_MSG_RESULT([-M])
else
  AC_MSG_RESULT([unknown, not passing symbol map])
fi
AM_CONDITIONAL([HAVE_VERSION_SCRIPT_FLAG], [test "x${VERSION_SCRIPT_FLAG}" != x])

# check for support for the struct ether_addr structure
AC_CHECK_TYPES(struct ether_addr,,,[
    #include <sys/socket.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #include <netinet/if_ether.h>
    #ifdef HAVE_NETINET_ETHER_H
    #include <netinet/ether.h>
    #endif])

# check to see if socklen_t is defined
AC_CHECK_TYPE(socklen_t,,
    AC_DEFINE(socklen_t,size_t,[Define to `size_t' if not defined elswhere.]),[
    #include <sys/types.h>
    #include <sys/socket.h>])

# NSS module-specific tests
if test "x$enable_nss" = "xyes"
then
  # save CFLAGS and LIBS to restore later
  nss_save_CFLAGS="$CFLAGS"
  nss_save_LIBS="$LIBS"

  # check for a definition of struct aliasent
  AC_CHECK_TYPES(struct aliasent,,,[
      #ifdef HAVE_ALIASES_H
      #include <aliases.h>
      #endif])

  # check for a definition of struct etherent
  AC_CHECK_TYPES(struct etherent,,,[
    #include <sys/socket.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #include <netinet/if_ether.h>
    #ifdef HAVE_NETINET_ETHER_H
    #include <netinet/ether.h>
    #endif])

  # check for a definition of struct rpcent
  AC_CHECK_TYPES(struct rpcent,,,[
      #include <netdb.h>
      #ifdef HAVE_RPC_RPCENT_H
      #include <rpc/rpcent.h>
      #endif])

  # check for a definition of enum nss_status
  AC_CHECK_TYPES(enum nss_status,,,[
      #ifdef HAVE_NSS_H
      #include <nss.h>
      #endif
      #ifdef HAVE_NSS_COMMON_H
      #include <nss_common.h>
      #endif])

  # restore CFLAGS and LIBS
  CFLAGS="$nss_save_CFLAGS"
  LIBS="$nss_save_LIBS"
fi

# PAM module-specific tests
if test "x$enable_pam" = "xyes"
then
  # save CFLAGS and LIBS to restore later
  pam_save_CFLAGS="$CFLAGS"
  pam_save_LIBS="$LIBS"

  # check for headers
  AC_CHECK_HEADERS(security/pam_appl.h)
  AC_CHECK_HEADERS(security/pam_modules.h,,,[
      #ifdef HAVE_SECURITY_PAM_APPL_H
      #include <security/pam_appl.h>
      #endif
      ])
  AC_CHECK_HEADERS(pam/pam_modules.h)
  AC_CHECK_HEADERS(security/pam_ext.h)
  AC_CHECK_HEADERS(security/pam_modutil.h)

  # at least one of security/pam_modules.h or pam/pam_modules.h is required
  if test "x$ac_cv_header_security_pam_modules_h" != "xyes" && \
     test "x$ac_cv_header_pam_pam_modules_h" != "xyes"
  then
    AC_MSG_ERROR(PAM header files are missing)
  fi

  # find pam library
  AC_SEARCH_LIBS(pam_get_data,pam,,AC_MSG_ERROR(no PAM library available))

  # replace some PAM functions if they are unavailable
  AC_REPLACE_FUNCS(pam_get_authtok pam_prompt)
  AC_CHECK_FUNCS(pam_modutil_getpwnam pam_syslog)

  # restore CFLAGS and LIBS
  CFLAGS="$pam_save_CFLAGS"
  LIBS="$pam_save_LIBS"
fi

# nslcd daemon-specific tests
if test "x$enable_nslcd" = "xyes"
then
  # save CFLAGS and LIBS to restore later
  nslcd_save_CFLAGS="$CFLAGS"
  nslcd_save_LIBS="$LIBS"

  # check header files
  AC_CHECK_HEADERS(lber.h)
  AC_CHECK_HEADERS(ldap.h,, test "x$enable_nslcd" = "xyes" && AC_MSG_ERROR([could not locate <ldap.h>]),[
      #if HAVE_LBER_H
      #include <lber.h>
      #endif
      ])
  AC_CHECK_HEADERS(ldap_ssl.h)
  AC_CHECK_HEADERS(gssldap.h)
  if test "x$enable_sasl" = "xyes"
  then
    AC_CHECK_HEADERS(sasl.h sasl/sasl.h)
    AC_CHECK_HEADERS(gsssasl.h)
  fi
  if test "x$enable_kerberos" = "xyes"
  then
    AC_CHECK_HEADERS(gssapi/gssapi.h gssapi/gssapi_generic.h gssapi/gssapi_krb5.h gssapi.h)
  fi

  # checks for availability of system libraries for nslcd
  AC_SEARCH_LIBS(gethostbyname,nsl socket)
  AC_SEARCH_LIBS(socket,socket)
  AC_SEARCH_LIBS(dlopen,dl)

  # check for availability of functions
  AC_CHECK_FUNCS(setgroups)
  AC_CHECK_FUNCS(getpeereid)
  AC_CHECK_FUNCS(getpeerucred)
  AC_CHECK_FUNCS(__nss_configure_lookup)
  AC_CHECK_FUNCS(getenv putenv clearenv)
  AC_CHECK_FUNCS(dlopen dlsym dlerror)

  # replace getopt_long() function if it is not on the system
  AC_REPLACE_FUNCS(getopt_long)

  # replace daemon() function if it is not on the system
  AC_SEARCH_LIBS(daemon,bsd)
  AC_REPLACE_FUNCS(daemon)

  # replace ether_ntoa_r() and ether_aton_r() if they are not found
  AC_CHECK_FUNCS(ether_aton_r ether_ntoa_r,,[AC_CHECK_FUNCS(ether_aton ether_ntoa)
                                             AC_LIBOBJ(ether)])

  # check to see if struct sockaddr_storage is defined
  AC_CHECK_TYPE(struct sockaddr_storage,,
      AC_DEFINE(sockaddr_storage,sockaddr_in,[Define to `sockaddr_in' if not defined elsewhere.]),[
      #include <sys/types.h>
      #include <sys/socket.h>])

  # check for support for the struct ucred structure
  AC_CHECK_TYPE(struct ucred,
      AC_DEFINE(HAVE_STRUCT_UCRED,1,[Define to 1 if you have a `struct ucred' definition.]),,[
      #include <sys/socket.h>
      #include <sys/un.h>
      #include <sys/types.h>])

  # check threading stuff
  AX_PTHREAD(,AC_MSG_ERROR([no support for pthreads]))
  AC_CHECK_FUNCS(pthread_mutex_lock)

  # search for an LDAP library (only OpenLDAP is tested)
  AC_ARG_WITH(ldap-lib,
              AS_HELP_STRING([--with-ldap-lib=TYPE],
                             [select ldap library (auto|netscape5|netscape4|netscape3|umich|openldap) @<:@auto@:>@]))
  if test -z "$with_ldap_lib"
  then
    with_ldap_lib=auto
  fi
  if test -z "$found_ldap_lib" -a \( $with_ldap_lib = auto -o $with_ldap_lib = umich -o $with_ldap_lib = openldap \)
  then
    AC_SEARCH_LIBS(ldap_search_ext,[ldap_r ldap],found_ldap_lib=yes,,)
  fi
  if test -z "$found_ldap_lib" -a \( $with_ldap_lib = auto -o $with_ldap_lib = netscape5 \)
  then
    AC_CHECK_LIB(ldap50, main, LIBS="-lldap50 -lssldap50 -lssl3 -lnss3 -lnspr4 -lprldap50 -lplc4 -lplds4 $LIBS" found_ldap_lib=yes,, -lpthread)
  fi
  if test -z "$found_ldap_lib" -a \( $with_ldap_lib = auto -o $with_ldap_lib = netscape4 \)
  then
    AC_CHECK_LIB(ldapssl41, main, LIBS="-lldapssl41 -lplc3 -lplds3 -lnspr3 $LIBS" found_ldap_lib=yes,, -lpthread)
    if test -z "$found_ldap_lib"
    then
      AC_CHECK_LIB(ldapssl40, main, LIBS="-lldapssl40 $LIBS" found_ldap_lib=yes,, -lpthread)
    fi
    if test -z "$found_ldap_lib"
    then
      AC_CHECK_LIB(ldap41, main, LIBS="-lldap41 $LIBS" found_ldap_lib=yes,,)
    fi
    if test -z "$found_ldap_lib"
    then
      AC_CHECK_LIB(ldap40, main, LIBS="-lldap40 $LIBS" found_ldap_lib=yes,,)
    fi
  fi
  if test -z "$found_ldap_lib" -a \( $with_ldap_lib = auto -o $with_ldap_lib = netscape3 \)
  then
    AC_CHECK_LIB(ldapssl30, main, LIBS="-lldapssl30 $LIBS" found_ldap_lib=yes,, -lpthread)
  fi
  AC_CHECK_FUNCS(ldap_search_ext,,AC_MSG_ERROR([could not locate a valid LDAP library]))

  # see if we need a BER library
  AC_SEARCH_LIBS(ber_bvfree,lber)

  # check for extra SASL libraries
  if test "$enable_sasl" = "yes"
  then
    AC_CHECK_TYPE(sasl_interact_t,
        AC_DEFINE(HAVE_SASL_INTERACT_T,1,[Define to 1 if you have a `sasl_interact_t' definition.]),,[
        #ifdef HAVE_SASL_SASL_H
        #include <sasl/sasl.h>
        #elif defined(HAVE_SASL_H)
        #include <sasl.h>
        #endif])
    AC_SEARCH_LIBS(sasl_client_init,sasl2)
    AC_CHECK_FUNCS(sasl_auxprop_request ldap_sasl_interactive_bind_s)
  fi

  # check for extra Kerberos libraries
  if test "$enable_kerberos" = "yes"
  then
    AC_SEARCH_LIBS(gss_krb5_ccache_name,gssapi gssapi_krb5)
    AC_SEARCH_LIBS(ldap_gss_bind,gssldap)
    AC_CHECK_FUNCS(gss_krb5_ccache_name)
  fi

  # check for ldap function availability
  AC_CHECK_FUNCS(ldap_parse_result ldap_memfree ldap_controls_free ldap_control_free)
  AC_CHECK_FUNCS(ldap_explode_dn ldap_explode_rdn ldap_set_option ldap_get_option)
  AC_CHECK_FUNCS(ldap_abandon ldap_simple_bind_s ldap_unbind ldap_set_rebind_proc)
  AC_CHECK_FUNCS(ldap_initialize ldap_search_ext)
  AC_CHECK_FUNCS(ldap_create_control ldap_extended_operation_s)
  AC_CHECK_FUNCS(ldap_domain2hostlist ldap_domain2dn)
  AC_CHECK_FUNCS(ldap_get_values ldap_value_free ldap_get_dn)
  AC_CHECK_FUNCS(ldap_err2string ldap_msgfree ldap_result)
  AC_CHECK_FUNCS(ber_bvfree ber_free ber_set_option)

  # replace ldap_create_page_control() and ldap_parse_page_control()
  AC_CHECK_FUNCS(ldap_create_page_control ldap_parse_page_control,,[AC_LIBOBJ(pagectrl)])

  # replace other ldap functions
  AC_REPLACE_FUNCS(ldap_passwd_s)
  AC_REPLACE_FUNCS(ldap_initialize)

  # check the number of arguments that ldap_set_rebind_proc() uses
  AC_CACHE_CHECK(
      [number of arguments to ldap_set_rebind_proc],
      nss_ldapd_cv_ldap_set_rebind_proc_args,
      [AC_COMPILE_IFELSE(
          [AC_LANG_PROGRAM([[
              #include <lber.h>
              #include <ldap.h>
              ]],[[
              ldap_set_rebind_proc(0,0,0);
              ]])],
          [nss_ldapd_cv_ldap_set_rebind_proc_args=3],
          [nss_ldapd_cv_ldap_set_rebind_proc_args=2]) ])
  AC_DEFINE_UNQUOTED(LDAP_SET_REBIND_PROC_ARGS,$nss_ldapd_cv_ldap_set_rebind_proc_args,
                     [Define to the number of arguments to ldap_set_rebindproc.])

  # check the return type of ldap_set_rebind_proc()
  AC_CACHE_CHECK(
      [return type of ldap_set_rebind_proc],
      nss_ldapd_cv_ldap_set_rebind_proc_type,
      [AC_COMPILE_IFELSE(
          [AC_LANG_PROGRAM([[
              #include <lber.h>
              #include <ldap.h>
              ]],[[
              #if LDAP_SET_REBIND_PROC_ARGS == 3
              return ldap_set_rebind_proc(0,0,0);
              #else
              return ldap_set_rebind_proc(0,0);
              #endif
              ]])],
          [nss_ldapd_cv_ldap_set_rebind_proc_type=int],
          [nss_ldapd_cv_ldap_set_rebind_proc_type=void]) ])
  if test "x$nss_ldapd_cv_ldap_set_rebind_proc_type" = "xvoid"
  then
    AC_DEFINE(LDAP_SET_REBIND_PROC_RETURNS_VOID,1,
              [Define to 1 if ldap_set_rebind_proc() returns void.])
  fi

  # save nslcd LIBS and CFLAGS and restore originals
  nslcd_CFLAGS="$CFLAGS"
  nslcd_LIBS="$LIBS"
  CFLAGS="$nslcd_save_CFLAGS"
  LIBS="$nslcd_save_LIBS"

  AC_SUBST(nslcd_LIBS)
fi

# generate files
AC_CONFIG_FILES([Makefile compat/Makefile common/Makefile nss/Makefile
                 pam/Makefile nslcd/Makefile man/Makefile tests/Makefile])
AC_OUTPUT
