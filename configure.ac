# configure.ac - process this file with autoconf to produce configure
#
# Copyright (C) 2006 Luke Howard
# Copyright (C) 2006 West Consulting
# Copyright (C) 2006-2017 Arthur de Jong
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
Copyright (C) 2006-2017 Arthur de Jong

This configure script is derived from configure.ac which is free software;
you can redistribute it and/or modify it under the terms of the GNU Lesser
General Public License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version. See the
configure.ac file for more details.])

# initialize and set version and bugreport address
AC_INIT([nss-pam-ldapd],
        [0.9.8],
        [nss-pam-ldapd-users@lists.arthurdejong.org],,
        [https://arthurdejong.org/nss-pam-ldapd/])
RELEASE_MONTH="Jun 2017"
AC_SUBST(RELEASE_MONTH)
AC_CONFIG_SRCDIR([nslcd.h])
AC_CONFIG_MACRO_DIR([m4])

# some initialisation
AC_CANONICAL_TARGET
AC_PREFIX_DEFAULT()
AC_CONFIG_LIBOBJ_DIR([compat])

# display notice and initialize automake
AC_MSG_NOTICE([configuring AC_PACKAGE_TARNAME AC_PACKAGE_VERSION])
AM_INIT_AUTOMAKE([1.11.2 check-news gnu std-options color-tests --warnings=all])

# create a config.h file (Automake will add -DHAVE_CONFIG_H)
AC_CONFIG_HEADERS([config.h])

# check for programs
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_RANLIB
AM_PROG_CC_C_O
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_LN_S
AM_PROG_AR

# checks for tool to convert docbook to man
genman="no"
AC_PATH_PROGS(DOCBOOK2X_MAN, docbook2x-man)
AC_MSG_CHECKING([for tool to (re)generate man pages])
if test "x${DOCBOOK2X_MAN}" != x
then
  genman="${DOCBOOK2X_MAN}"
fi
AC_MSG_RESULT($genman)
AM_CONDITIONAL([GENMAN], [test "x${genman}" != "xno"])
if test "x${genman}" = "xno"
then
  AC_MSG_WARN([docbook2x-man not found: not (re)generating man pages])
fi

# check whether to install manual pages
AC_MSG_CHECKING([whether to install man pages])
instman="no"
if [test "x${genman}" != "xno" || ls  "${srcdir}/man/"*.? > /dev/null 2>&1]
then
  instman="yes"
fi
AC_MSG_RESULT($instman)
AM_CONDITIONAL([INSTMAN], [test "x${instman}" != "xno"])
if test "x${instman}" = "xno"
then
  AC_MSG_WARN([not installing man pages (no generator and not pre-generated)])
fi

# check for Python and modules
AM_PATH_PYTHON(2.5,, [:])
AM_CONDITIONAL([HAVE_PYTHON], [test "$PYTHON" != ":"])
if test "x$PYTHON" != "x:"
then
  AX_PYTHON_MODULE(argparse)
fi

# check for debugging options
AC_ARG_ENABLE(debug,
              AS_HELP_STRING([--enable-debug],
                             [enable extensive debugging and logging]),
              [if test "x$enableval" != "xno" ; then CFLAGS="-g -DDEBUG $CFLAGS" ; fi])

# check for extra compiler warnings
DESIRED_CFLAGS=""
AC_ARG_ENABLE(warnings,
              AS_HELP_STRING([--enable-warnings],
                             [enable extra compiler warnings (gcc)]),
              [if test "x$enableval" != "no"
               then
                 CFLAGS="$CFLAGS -pedantic -Wall -Wshadow -Wpointer-arith -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wnested-externs -Waggregate-return -Wmissing-declarations -Wunused -Wformat=2 -Wswitch-default -Wswitch-enum -Wfloat-equal -Wbad-function-cast -Wredundant-decls"
                 DESIRED_CFLAGS="$DESIRED_CFLAGS -Wextra -Wdeclaration-after-statement -Werror-implicit-function-declaration -Werror=implicit"
               fi])
test_gcc_flag() {
  AC_LANG_CONFTEST([AC_LANG_PROGRAM()])
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

# check for Position Independent Code compiler option
PIC_CFLAGS=""
if test "$ac_cv_c_compiler_gnu" = "yes"
then
  PIC_CFLAGS="-fPIC"
else
  case "$target_os" in
    sysv5*) PIC_CFLAGS="-KPIC" ;;
  esac
fi
AC_SUBST(PIC_CFLAGS)

# add --disable-maintainer-mode option
AM_MAINTAINER_MODE([enable])

# check whether the NSS module should be built
AC_MSG_CHECKING([whether to build the NSS module])
AC_ARG_ENABLE(nss,
              AS_HELP_STRING([--disable-nss],
                             [build the NSS module @<:@enabled@:>@]),,
              [enable_nss="yes"])
AC_MSG_RESULT($enable_nss)
AM_CONDITIONAL([ENABLE_NSS], [test "x$enable_nss" = "xyes"])

# check whether the PAM module should be built
AC_MSG_CHECKING([whether to build the PAM module])
AC_ARG_ENABLE(pam,
              AS_HELP_STRING([--disable-pam],
                             [build the PAM module @<:@enabled@:>@]),,
              [enable_pam="yes"])
AC_MSG_RESULT($enable_pam)
AM_CONDITIONAL([ENABLE_PAM], [test "x$enable_pam" = "xyes"])

# check whether command-line utilities should be built
AC_MSG_CHECKING([whether to build the command-line utilities])
AC_ARG_ENABLE(utils,
              AS_HELP_STRING([--disable-utils],
                             [build the the command-line utilities @<:@auto@:>@]),,
              [enable_utils="auto"])
if test "x$enable_utils" = "xauto"
then
  if test "x$PYTHON" != "x:" && test "$HAVE_PYMOD_ARGPARSE" = "yes"
  then
    enable_utils="yes"
  else
    enable_utils="no"
  fi
fi
AC_MSG_RESULT($enable_utils)
AM_CONDITIONAL([ENABLE_UTILS], [test "x$enable_utils" = "xyes"])

# check whether the nslcd daemon should be built
AC_MSG_CHECKING([whether to build the nslcd daemon])
AC_ARG_ENABLE(nslcd,
              AS_HELP_STRING([--disable-nslcd],
                             [build the nslcd daemon @<:@enabled@:>@]),,
              [enable_nslcd="yes"])
AC_MSG_RESULT($enable_nslcd)
AM_CONDITIONAL([ENABLE_NSLCD], [test "x$enable_nslcd" = "xyes"])

# check whether the Python version of the nslcd daemon should be built
AC_MSG_CHECKING([whether to build the pynslcd daemon])
AC_ARG_ENABLE(pynslcd,
              AS_HELP_STRING([--enable-pynslcd],
                             [build the pynslcd daemon @<:@disabled@:>@]),,
              [enable_pynslcd="no"])
AC_MSG_RESULT($enable_pynslcd)
AM_CONDITIONAL([ENABLE_PYNSLCD], [test "x$enable_pynslcd" = "xyes"])
if test "x$enable_pynslcd" = "xyes"
then
  AC_MSG_WARN([the pynslcd daemon is experimental])
fi

# check whether SASL support should be enabled
AC_MSG_CHECKING([whether to enable SASL support])
AC_ARG_ENABLE(sasl,
              AS_HELP_STRING([--disable-sasl],
                             [disable SASL support @<:@enabled@:>@]),
              [enable_sasl=$enableval],
              [enable_sasl="yes"])
AC_MSG_RESULT($enable_sasl)

# check whether Kerberos support should be enabled
AC_MSG_CHECKING([whether to enable Kerberos support])
AC_ARG_ENABLE(kerberos,
              AS_HELP_STRING([--disable-kerberos],
                             [disable Kerberos support @<:@enabled@:>@]),
              [enable_kerberos=$enableval],
              [enable_kerberos="yes"])
AC_MSG_RESULT($enable_kerberos)

# check whether configfile options should be checked
AC_MSG_CHECKING([whether to check configfile options])
AC_ARG_ENABLE(configfile_checking,
              AS_HELP_STRING([--disable-configfile-checking],
                             [check configfile options @<:@enabled@:>@]),
              [configfile_checking=$enableval],
              [configfile_checking="yes"])
AC_MSG_RESULT($configfile_checking)
if test "x$configfile_checking" = "xyes"
then
  AC_DEFINE(ENABLE_CONFIGFILE_CHECKING, 1 ,[Whether to check configfile options.])
fi

# check the name of the configuration file
AC_ARG_WITH(ldap-conf-file,
            AS_HELP_STRING([--with-ldap-conf-file=PATH],
                           [path to nslcd configuration file @<:@/etc/nslcd.conf@:>@]),
            [ NSLCD_CONF_PATH="$with_ldap_conf_file" ],
            [ NSLCD_CONF_PATH="/etc/nslcd.conf" ])
AC_DEFINE_UNQUOTED(NSLCD_CONF_PATH, "$NSLCD_CONF_PATH", [Path to nslcd configuration file.])
AC_SUBST(NSLCD_CONF_PATH)

# check the name of the file with a bindpw value
AC_ARG_WITH(bindpw-file,
            AS_HELP_STRING([--with-bindpw-file=PATH],
                           [path to file with value for bindpw @<:@disabled@:>@]),
            [ NSLCD_BINDPW_PATH="$with_bindpw_file"
              AC_DEFINE_UNQUOTED(NSLCD_BINDPW_PATH, "$NSLCD_BINDPW_PATH", [Path to bindpw value.])
              AC_SUBST(NSLCD_BINDPW_PATH)
            ])

# where should the pidfile be written
AC_ARG_WITH(nslcd-pidfile,
            AS_HELP_STRING([--with-nslcd-pidfile=PATH],
                           [path to pidfile @<:@/var/run/nslcd/nslcd.pid@:>@]),
            [ NSLCD_PIDFILE="$with_nslcd_pidfile" ],
            [ NSLCD_PIDFILE="/var/run/nslcd/nslcd.pid" ])
AC_DEFINE_UNQUOTED(NSLCD_PIDFILE, "$NSLCD_PIDFILE", [The location of the pidfile used for checking availability of the nslcd.])
AC_SUBST(NSLCD_PIDFILE)

# where is the socket used for communication
AC_ARG_WITH(nslcd-socket,
            AS_HELP_STRING([--with-nslcd-socket=PATH],
                           [path to socket @<:@/var/run/nslcd/socket@:>@]),
            [ NSLCD_SOCKET="$with_nslcd_socket" ],
            [ NSLCD_SOCKET="/var/run/nslcd/socket" ])
AC_DEFINE_UNQUOTED(NSLCD_SOCKET, "$NSLCD_SOCKET", [The location of the socket used for communicating.])
AC_SUBST(NSLCD_SOCKET)

# the directory PAM librabries are expected to be placed into
AC_MSG_CHECKING([location for PAM module])
AC_ARG_WITH(pam-seclib-dir,
            AS_HELP_STRING([--with-pam-seclib-dir=PAM_SECLIB_DIR],
                           [path to PAM security library @<:@auto@:>@]),
            [ PAM_SECLIB_DIR="$with_pam_seclib_dir" ],
            [ PAM_SECLIB_DIR="auto" ])
if test "x$PAM_SECLIB_DIR" = "xauto"
then
  case "$target_os" in
    solaris*) PAM_SECLIB_DIR="/usr/lib/security" ;;
    freebsd*|dragonfly*) PAM_SECLIB_DIR="/usr/lib" ;;
    *)        PAM_SECLIB_DIR="/lib/security" ;;
  esac
fi
AC_MSG_RESULT($PAM_SECLIB_DIR)
AC_DEFINE_UNQUOTED(PAM_SECLIB_DIR, "$PAM_SECLIB_DIR", [path to PAM security library])
AC_SUBST(PAM_SECLIB_DIR)

# the name to use for the NSS module
AC_MSG_CHECKING([name of NSS and PAM modules])
AC_ARG_WITH(module-name,
            AS_HELP_STRING([--with-module-name=NAME],
                           [name of NSS and PAM modules @<:@ldap@:>@]),
            [ MODULE_NAME="$with_module_name" ],
            [ MODULE_NAME="ldap" ])
            # FIXME: this does not work
AC_MSG_RESULT($MODULE_NAME)
AC_DEFINE_UNQUOTED(MODULE_NAME, "$MODULE_NAME", [The name of the NSS and PAM modules.])
AC_DEFINE_UNQUOTED(NSS_NAME(NAME), [_nss_${MODULE_NAME}_##NAME], [Expand to NSS symbol name.])
AC_DEFINE_UNQUOTED(PAM_NAME(NAME), [_pam_${MODULE_NAME}_##NAME], [Expand to PAM symbol name.])
AC_SUBST(MODULE_NAME)

# the SONAME to use for the NSS module
AC_MSG_CHECKING([soname of NSS module])
AC_ARG_WITH(nss-ldap-soname,
            AS_HELP_STRING([--with-nss-ldap-soname=SONAME],
                           [name of NSS module @<:@auto@:>@]),
            [ NSS_LDAP_SONAME="$with_nss_ldap_soname" ],
            [ NSS_LDAP_SONAME="auto" ])
if test "x$NSS_LDAP_SONAME" = "xauto"
then
  case "$target_os" in
    solaris*) NSS_LDAP_SONAME="nss_$MODULE_NAME.so.1" ;;
    freebsd*|dragonfly*) NSS_LDAP_SONAME="nss_$MODULE_NAME.so.1" ;;
    *)        NSS_LDAP_SONAME="libnss_$MODULE_NAME.so.2" ;;
  esac
fi
AC_MSG_RESULT($NSS_LDAP_SONAME)
AC_DEFINE_UNQUOTED(NSS_LDAP_SONAME, "$NSS_LDAP_SONAME", [The SONAME of the NSS library module.])
AC_SUBST(NSS_LDAP_SONAME)

# the SONAME to use for the PAM module
AC_MSG_CHECKING([soname of PAM module])
AC_ARG_WITH(pam-ldap-soname,
            AS_HELP_STRING([--with-pam-ldap-soname=SONAME],
                           [name of PAM module @<:@auto@:>@]),
            [ PAM_LDAP_SONAME="$with_pam_ldap_soname" ],
            [ PAM_LDAP_SONAME="auto" ])
if test "x$PAM_LDAP_SONAME" = "xauto"
then
  case "$target_os" in
    solaris*) PAM_LDAP_SONAME="pam_$MODULE_NAME.so.1" ;;
    *)        PAM_LDAP_SONAME="pam_$MODULE_NAME.so" ;;
  esac
fi
AC_MSG_RESULT($PAM_LDAP_SONAME)
AC_SUBST(PAM_LDAP_SONAME)

# check which modules should be build
AC_ARG_WITH(nss-maps,
            AS_HELP_STRING([--with-nss-maps=MAP LIST],
                           [comma separated list of NSS maps to build @<:@all@:>@]),,
            [ with_nss_maps="all" ])

# checks for availability of header files
AC_CHECK_HEADERS([ctype.h strings.h pthread.h pthread_np.h fcntl.h limits.h])
AC_CHECK_HEADERS([nss.h nss_common.h grp.h shadow.h aliases.h netdb.h rpc/rpcent.h])
AC_CHECK_HEADERS([netinet/ether.h arpa/inet.h netinet/in.h])
AC_CHECK_HEADERS([nsswitch.h nss_dbdefs.h])
AC_CHECK_HEADERS([sys/socket.h sys/un.h sys/ucred.h ucred.h sys/param.h sys/time.h])
AC_CHECK_HEADERS([getopt.h syslog.h stddef.h])

# other general checks
AC_C_INLINE
AC_C_CONST

# checks for availability of common functions
AC_CHECK_FUNCS([sigaction snprintf])
AC_SEARCH_LIBS(socket, socket)
AC_CHECK_FUNCS([strcasecmp strncasecmp strchr strcspn strspn strtol strtoul strtoull strndup])
AC_CHECK_FUNCS([malloc realloc atexit])
AC_FUNC_FORK
AC_CHECK_FUNCS(__assert_fail)
AC_SEARCH_LIBS(clock_gettime, rt)
AC_CHECK_FUNCS([setusershell getusershell endusershell getgrouplist])
AC_CHECK_DECLS([setusershell, getusershell, endusershell])

# checks for types
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_INT32_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned long int)
AC_CHECK_SIZEOF(unsigned long long int)
AC_CHECK_SIZEOF(uid_t)
AC_CHECK_SIZEOF(gid_t)
AX_TLS()
AC_CHECK_TYPES(suseconds_t)

# check for support for the struct ether_addr structure
AC_CHECK_TYPES(struct ether_addr,,, [
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #include <netinet/if_ether.h>
    #ifdef HAVE_NETINET_ETHER_H
    #include <netinet/ether.h>
    #endif])

# check for ether_aton and ether_ntoa functions
AC_CHECK_FUNCS(ether_aton ether_ntoa ether_aton_r ether_ntoa_r)
AC_CHECK_DECLS([ether_aton, ether_ntoa],,, [
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #include <netinet/if_ether.h>
    #ifdef HAVE_NETINET_ETHER_H
    #include <netinet/ether.h>
    #endif])

# check to see if socklen_t is defined
AC_CHECK_TYPE(socklen_t,,
    AC_DEFINE(socklen_t, size_t, [Define to `size_t' if not defined elswhere.]), [
    #include <sys/types.h>
    #include <sys/socket.h>])

# check the return type of setnetgrent()
AC_CACHE_CHECK(
    [return type of setnetgrent],
    nss_pam_ldapd_cv_setnetgrent_type,
    [AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([[
            #include <netdb.h>
            ]], [[
            return setnetgrent(0);
            ]])],
        [nss_pam_ldapd_cv_setnetgrent_type=int],
        [nss_pam_ldapd_cv_setnetgrent_type=void]) ])
if test "x$nss_pam_ldapd_cv_setnetgrent_type" = "xvoid"
then
  AC_DEFINE(SETNETGRENT_RETURNS_VOID, 1,
            [Define to 1 if setnetgrent() returns void.])
fi

# NSS module-specific tests
if test "x$enable_nss" = "xyes"
then
  # save CFLAGS and LIBS to restore later
  nss_save_CFLAGS="$CFLAGS"
  nss_save_LIBS="$LIBS"

  # check for a definition of struct aliasent
  AC_CHECK_TYPES(struct aliasent,,, [
      #ifdef HAVE_ALIASES_H
      #include <aliases.h>
      #endif])

  # check for a definition of struct etherent
  AC_CHECK_TYPES(struct etherent,,, [
    #include <sys/socket.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #include <netinet/if_ether.h>
    #ifdef HAVE_NETINET_ETHER_H
    #include <netinet/ether.h>
    #endif])

  # check if struct passwd has a pw_class member
  AC_CHECK_MEMBERS([struct passwd.pw_class],,, [
      #include <pwd.h>])

  # check for a definition of struct rpcent
  AC_CHECK_TYPES(struct rpcent,,, [
      #include <netdb.h>
      #ifdef HAVE_RPC_RPCENT_H
      #include <rpc/rpcent.h>
      #endif])

  # check for a definition of struct spwd
  AC_CHECK_TYPES(struct spwd,,, [
      #ifdef HAVE_NSS_H
      #include <nss.h>
      #endif
      #ifdef HAVE_NSS_COMMON_H
      #include <nss_common.h>
      #endif
      #include <pwd.h>
      #ifdef HAVE_SHADOW_H
      #include <shadow.h>
      #endif])

  # check for a definition of enum nss_status and nss_backend_t
  AC_CHECK_TYPES([enum nss_status, nss_backend_t],,, [
      #ifdef HAVE_NSS_H
      #include <nss.h>
      #endif
      #ifdef HAVE_NSS_COMMON_H
      #include <nss_common.h>
      #endif
      #ifdef HAVE_NSS_DBDEFS_H
      #include <nss_dbdefs.h>
      #endif
      #ifdef HAVE_NSSWITCH_H
      #include <nsswitch.h>
      #endif])

  # check if struct nss_XbyY_args has a returnlen attribute
  AC_CHECK_MEMBERS([struct nss_XbyY_args.returnlen],,, [[
      #ifdef HAVE_NSS_H
      #include <nss.h>
      #endif
      #ifdef HAVE_NSS_COMMON_H
      #include <nss_common.h>
      #endif
      #ifdef HAVE_NSS_DBDEFS_H
      #include <nss_dbdefs.h>
      #endif
      #ifdef HAVE_NSSWITCH_H
      #include <nsswitch.h>
      #endif]])

  # check which NSS flavour to build
  AC_MSG_CHECKING([which NSS flavour to build])
  AC_ARG_WITH(nss-flavour,
              AS_HELP_STRING([--with-nss-flavour=auto|glibc|solaris|freebsd],
                             [the libc flavour to build our NSS module for @<:@auto@:>@]),,
              with_nss_flavour=auto)
  if test "x$with_nss_flavour" = "xauto"
  then
    # do the guessing game
    case "$target_os" in
      solaris*) with_nss_flavour=solaris ;;
      freebsd*|dragonfly*) with_nss_flavour=freebsd ;;
      *)        with_nss_flavour=glibc ;;
    esac
  fi
  AC_MSG_RESULT($with_nss_flavour)
  case "$with_nss_flavour" in
    glibc)   AC_DEFINE(NSS_FLAVOUR_GLIBC, 1, [Whether to use the Glibc NSS interface flavour.]) ;;
    solaris) AC_DEFINE(NSS_FLAVOUR_SOLARIS, 1, [Whether to use the Solaris NSS interface flavour.]) ;;
    freebsd) AC_DEFINE(NSS_FLAVOUR_FREEBSD, 1, [Whether to use the FreeBSD NSS interface flavour.]) ;;
  esac
  NSS_FLAVOUR="$with_nss_flavour"
  AC_SUBST(NSS_FLAVOUR)

  # check which module source files to use
  AC_MSG_CHECKING([which NSS maps to build])
  if test "x$with_nss_maps" = "xall"
  then
    case "$with_nss_flavour" in
      glibc)   with_nss_maps="aliases,ethers,group,hosts,netgroup,networks,passwd,protocols,rpc,services,shadow" ;;
      solaris) with_nss_maps="ethers,group,hosts,netgroup,networks,passwd,protocols,rpc,services,shadow" ;;
      freebsd) with_nss_maps="group,hosts,passwd,netgroup" ;;
    esac
  fi
  AC_MSG_RESULT($with_nss_maps)
  NSS_MODULE_OBJS="$(echo "$with_nss_maps " | sed 's/,/ /g;s/  */.$(OBJEXT) /g')"
  AC_SUBST(NSS_MODULE_OBJS)

  # find out how to link the library
  nss_ldap_so_LINK="\$(CCLD) \$(AM_CFLAGS) \$(CFLAGS) \$(nss_ldap_so_LDFLAGS) \$(LDFLAGS) -o \$@"
  case "$target_os" in
  solaris*)
    if test "x$GCC" = xyes
    then
      nss_ldap_so_LINK="/usr/ccs/bin/ld -Bdirect -z nodelete -Bdynamic -M exports.map -G -o \$@"
    else
      nss_ldap_so_LDFLAGS="-Wl,-Bdirect -Wl,-z,nodelete -Wl,-Bdynamic -Wl,-M,exports.map -Wl,-G"
    fi
    ;;
  *)
    nss_ldap_so_LDFLAGS="-shared -Wl,-h,\$(NSS_LDAP_SONAME) -Wl,--version-script,exports.map"
    ;;
  esac
  AC_SUBST(nss_ldap_so_LDFLAGS)
  AC_SUBST(nss_ldap_so_LINK)

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
  AC_CHECK_HEADERS(security/pam_modules.h,,, [
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
  AC_SEARCH_LIBS(pam_get_data, pam,, AC_MSG_ERROR(no PAM library available))

  # replace some PAM functions if they are unavailable
  AC_REPLACE_FUNCS(pam_get_authtok pam_prompt)
  AC_CHECK_FUNCS(pam_modutil_getpwnam pam_syslog)
  AC_CHECK_DECLS([pam_info, pam_error],,, [
     #ifdef HAVE_SECURITY_PAM_APPL_H
     #include <security/pam_appl.h>
     #endif
     #ifndef HAVE_PAM_PAM_MODULES_H
     #include <security/pam_modules.h>
     #ifdef HAVE_SECURITY_PAM_EXT_H
     #include <security/pam_ext.h>
     #endif
     #else
     #include <pam/pam_modules.h>
     #endif
     #ifdef HAVE_SECURITY_PAM_MODUTIL_H
     #include <security/pam_modutil.h>
     #endif])

  # find out how to link the library
  pam_ldap_so_LINK="\$(CCLD) \$(AM_CFLAGS) \$(CFLAGS) \$(pam_ldap_so_LDFLAGS) \$(LDFLAGS) -o \$@"
  case "$target_os" in
  solaris*)
    if test "x$GCC" = xyes
    then
      pam_ldap_so_LINK="/usr/ccs/bin/ld -Bdirect -z nodelete -Bdynamic -M \$(srcdir)/pam_ldap.map -G -o \$@"
    else
      pam_ldap_so_LDFLAGS="-shared -Wl,-Bdirect -Wl,-z,nodelete -Wl,-Bdynamic -Wl,-M,\$(srcdir)/pam_ldap.map -Wl,-G"
    fi
    ;;
  *)
    pam_ldap_so_LDFLAGS="-shared -Wl,--version-script,\$(srcdir)/pam_ldap.map"
    ;;
  esac
  AC_SUBST(pam_ldap_so_LDFLAGS)
  AC_SUBST(pam_ldap_so_LINK)

  # check argument type of pam_get_item()
  AC_CACHE_CHECK(
      [argument type of pam_get_item],
      nss_pam_ldapd_cv_pam_get_item_arg3_type,
      [AC_COMPILE_IFELSE(
          [AC_LANG_PROGRAM([[
              #ifdef HAVE_SECURITY_PAM_APPL_H
              #include <security/pam_appl.h>
              #endif
              #ifndef HAVE_PAM_PAM_MODULES_H
              #include <security/pam_modules.h>
              #ifdef HAVE_SECURITY_PAM_EXT_H
              #include <security/pam_ext.h>
              #endif
              #else
              #include <pam/pam_modules.h>
              #endif
              #ifdef HAVE_SECURITY_PAM_MODUTIL_H
              #include <security/pam_modutil.h>
              #endif
              extern int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item);
              ]], [])],
          [nss_pam_ldapd_cv_pam_get_item_arg3_type="const void **"],
          [nss_pam_ldapd_cv_pam_get_item_arg3_type="void **"]) ])
  PAM_ITEM_CONST=""
  if test "$nss_pam_ldapd_cv_pam_get_item_arg3_type" = "const void **"
  then
    PAM_ITEM_CONST="const"
  fi
  AC_DEFINE_UNQUOTED(PAM_ITEM_CONST, [$PAM_ITEM_CONST],
                     [Define to empty if pam_get_item() doesn't take `const` parameter.])

  # restore CFLAGS and LIBS
  CFLAGS="$pam_save_CFLAGS"
  LIBS="$pam_save_LIBS"
fi

# utils-specific tests
if test "x$enable_utils" = "xyes"
then
  # check Python interpreter
  AM_PATH_PYTHON(2.5,, AC_MSG_ERROR([Python is required]))
  AX_PYTHON_MODULE(argparse)
  if test "x$HAVE_PYMOD_ARGPARSE" != "xyes"
  then
    AC_MSG_WARN(Required Python modules missing)
  fi
fi

# nslcd daemon-specific tests
if test "x$enable_nslcd" = "xyes"
then
  # save CFLAGS and LIBS to restore later
  nslcd_save_CFLAGS="$CFLAGS"
  nslcd_save_LIBS="$LIBS"

  # check header files
  AC_CHECK_HEADERS(lber.h)
  AC_CHECK_HEADERS(ldap.h,, test "x$enable_nslcd" = "xyes" && AC_MSG_ERROR([could not locate <ldap.h>]), [
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
    AC_CHECK_HEADERS(gssapi/gssapi.h gssapi/gssapi_generic.h gssapi/gssapi_krb5.h gssapi.h krb5.h)
  fi
  AC_CHECK_HEADERS(regex.h)

  # checks for availability of system libraries for nslcd
  AC_SEARCH_LIBS(gethostbyname, nsl socket)
  AC_SEARCH_LIBS(hstrerror, resolv)
  AC_SEARCH_LIBS(dlopen, dl)

  # check for availability of functions
  AC_CHECK_FUNCS(initgroups setgroups execvp execvpe)
  AC_CHECK_FUNCS(getpeereid)
  AC_CHECK_FUNCS(getpeerucred)
  AC_CHECK_FUNCS(__nss_configure_lookup)
  AC_CHECK_FUNCS(getenv putenv clearenv)
  AC_CHECK_FUNCS(dlopen dlsym dlerror)
  AC_CHECK_FUNCS(regcomp regexec regerror)
  AC_CHECK_FUNCS(hstrerror)

  # replace some functions if they are not on the system
  AC_REPLACE_FUNCS(getopt_long)
  AC_REPLACE_FUNCS(strndup)

  # replace ether_aton_r() if not found
  AC_CHECK_FUNCS(ether_aton_r,, [AC_LIBOBJ(ether)])

  # check to see if struct sockaddr_storage is defined
  AC_CHECK_TYPE(struct sockaddr_storage,,
      AC_DEFINE(sockaddr_storage, sockaddr_in, [Define to `sockaddr_in' if not defined elsewhere.]), [
      #include <sys/types.h>
      #include <sys/socket.h>])

  # check for support for the struct ucred structure
  AC_CHECK_TYPE(struct ucred,
      AC_DEFINE(HAVE_STRUCT_UCRED, 1, [Define to 1 if you have a `struct ucred' definition.]),, [
      #include <sys/socket.h>
      #include <sys/un.h>
      #include <sys/types.h>])

  # check threading stuff
  AX_PTHREAD(, AC_MSG_ERROR([no support for pthreads]))
  pthread_save_CFLAGS="$CFLAGS"
  pthread_save_LIBS="$LIBS"
  CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
  LIBS="$LIBS $PTHREAD_LIBS"
  AC_CHECK_FUNCS([pthread_mutex_lock pthread_join pthread_timedjoin_np pthread_atfork])
  CFLAGS="$pthread_save_CFLAGS"
  LIBS="$pthread_save_LIBS"

  # also use deprecated LDAP functions
  AC_DEFINE(LDAP_DEPRECATED, 1, Define to activate deprecated features in OpenLDAP)
  # for compatibility on Solaris
  AC_DEFINE(LDAP_REFERRALS, 1, Define to get some functions on Solaris)

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
    AC_SEARCH_LIBS(ldap_search_ext, [ldap_r ldap], found_ldap_lib=yes,, )
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
      AC_CHECK_LIB(ldap41, main, LIBS="-lldap41 $LIBS" found_ldap_lib=yes,, )
    fi
    if test -z "$found_ldap_lib"
    then
      AC_CHECK_LIB(ldap40, main, LIBS="-lldap40 $LIBS" found_ldap_lib=yes,, )
    fi
  fi
  if test -z "$found_ldap_lib" -a \( $with_ldap_lib = auto -o $with_ldap_lib = netscape3 \)
  then
    AC_CHECK_LIB(ldapssl30, main, LIBS="-lldapssl30 $LIBS" found_ldap_lib=yes,, -lpthread)
  fi
  AC_CHECK_FUNCS(ldap_search_ext,, AC_MSG_ERROR([could not locate a valid LDAP library]))

  # see if we need a BER library
  AC_SEARCH_LIBS(ber_bvfree, lber)

  # check for extra SASL libraries
  if test "$enable_sasl" = "yes"
  then
    AC_CHECK_TYPE(sasl_interact_t,
        AC_DEFINE(HAVE_SASL_INTERACT_T, 1, [Define to 1 if you have a `sasl_interact_t' definition.]),, [
        #ifdef HAVE_SASL_SASL_H
        #include <sasl/sasl.h>
        #elif defined(HAVE_SASL_H)
        #include <sasl.h>
        #endif])
    AC_SEARCH_LIBS(ldap_sasl_interactive_bind_s, sasl2)
    AC_CHECK_FUNCS(ldap_sasl_interactive_bind_s)
  fi

  # check for extra Kerberos libraries
  if test "$enable_kerberos" = "yes"
  then
    AC_SEARCH_LIBS(gss_krb5_ccache_name, gssapi gssapi_krb5)
    AC_CHECK_FUNCS(gss_krb5_ccache_name)

    # save CFLAGS and LIBS to restore later
    krb5_save_CFLAGS="$CFLAGS"
    krb5_save_LIBS="$LIBS"

    # find library that contains krb5_is_thread_safe
    AC_SEARCH_LIBS(krb5_sendauth, [krb5 'krb5 -lcrypto -ldes -lasn1 -lroken'])
    AC_CHECK_FUNCS(krb5_is_thread_safe)

    # see if krb5 is thread safe
    if test "x$ac_cv_func_krb5_is_thread_safe" == "xyes"
    then
      AC_CACHE_CHECK(
          [krb5 thread safety],
          nslcd_cv_krb5_is_thread_safe,
              [AC_RUN_IFELSE(
                  [AC_LANG_PROGRAM([[
                      #include <krb5.h>
                      ]], [[
                      if (!krb5_is_thread_safe())
                        return 1;
                      ]])],
                  [nslcd_cv_krb5_is_thread_safe=yes],
                  [nslcd_cv_krb5_is_thread_safe=no],
                  [nslcd_cv_krb5_is_thread_safe=unknown])])
      if test "x$nslcd_cv_krb5_is_thread_safe" == "xno"
      then
        AC_MSG_WARN([krb5 is NOT thread safe])
      fi
    fi

    # restore CFLAGS and LIBS because we don't directly use krb5
    CFLAGS="$krb5_save_CFLAGS"
    LIBS="$krb5_save_LIBS"

  fi

  # check for ldap function availability
  AC_CHECK_FUNCS(ber_bvfree ber_free ber_set_option ber_get_enum)
  AC_CHECK_FUNCS(ldap_initialize ldap_start_tls_s)
  AC_CHECK_FUNCS(ldap_get_option ldap_set_option ldap_set_rebind_proc)
  AC_CHECK_FUNCS(ldap_simple_bind_s ldap_sasl_bind ldap_sasl_bind_s ldap_unbind)
  AC_CHECK_FUNCS(ldap_search_ext ldap_modify_ext_s ldap_extended_operation_s)
  AC_CHECK_FUNCS(ldap_explode_dn ldap_explode_rdn)
  AC_CHECK_FUNCS(ldap_domain2hostlist ldap_domain2dn)
  AC_CHECK_FUNCS(ldap_result ldap_parse_result ldap_msgfree ldap_memfree)
  AC_CHECK_FUNCS(ldap_get_dn ldap_first_attribute ldap_next_attribute)
  AC_CHECK_FUNCS(ldap_get_values ldap_value_free)
  AC_CHECK_FUNCS(ldap_get_values_len ldap_count_values_len ldap_value_free_len)
  AC_CHECK_FUNCS(ldap_err2string ldap_abandon)
  AC_CHECK_FUNCS(ldap_control_create ldap_create_control ldap_control_find)
  AC_CHECK_FUNCS(ldap_controls_free ldap_control_free ldap_get_entry_controls)
  AC_CHECK_FUNCS(ldap_parse_passwordpolicy_control ldap_passwordpolicy_err2txt)
  AC_CHECK_FUNCS(ldap_create_deref_control ldap_create_deref_control_value)
  AC_CHECK_FUNCS(ldap_parse_deref_control ldap_derefresponse_free)

  # replace ldap_create_page_control() and ldap_parse_page_control()
  AC_CHECK_FUNCS(ldap_create_page_control ldap_parse_page_control,, [AC_LIBOBJ(pagectrl)])
  AC_CHECK_DECLS(ldap_extended_operation_s,,, [
      #if HAVE_LBER_H
      #include <lber.h>
      #endif
      #include <ldap.h>])

  # replace other ldap functions
  AC_REPLACE_FUNCS(ldap_passwd_s)
  AC_REPLACE_FUNCS(ldap_initialize)
  AC_REPLACE_FUNCS(ldap_parse_passwordpolicy_control)
  AC_REPLACE_FUNCS(ldap_passwordpolicy_err2txt)

  # check the number of arguments that ldap_set_rebind_proc() uses
  AC_CACHE_CHECK(
      [number of arguments to ldap_set_rebind_proc],
      nss_ldapd_cv_ldap_set_rebind_proc_args,
      [AC_COMPILE_IFELSE(
          [AC_LANG_PROGRAM([[
              #include <lber.h>
              #include <ldap.h>
              ]], [[
              ldap_set_rebind_proc(0, 0, 0);
              ]])],
          [nss_ldapd_cv_ldap_set_rebind_proc_args=3],
          [nss_ldapd_cv_ldap_set_rebind_proc_args=2]) ])
  AC_DEFINE_UNQUOTED(LDAP_SET_REBIND_PROC_ARGS, $nss_ldapd_cv_ldap_set_rebind_proc_args,
                     [Define to the number of arguments to ldap_set_rebindproc.])

  # check the return type of ldap_set_rebind_proc()
  AC_CACHE_CHECK(
      [return type of ldap_set_rebind_proc],
      nss_ldapd_cv_ldap_set_rebind_proc_type,
      [AC_COMPILE_IFELSE(
          [AC_LANG_PROGRAM([[
              #include <lber.h>
              #include <ldap.h>
              ]], [[
              #if LDAP_SET_REBIND_PROC_ARGS == 3
              return ldap_set_rebind_proc(0, 0, 0);
              #else
              return ldap_set_rebind_proc(0, 0);
              #endif
              ]])],
          [nss_ldapd_cv_ldap_set_rebind_proc_type=int],
          [nss_ldapd_cv_ldap_set_rebind_proc_type=void]) ])
  if test "x$nss_ldapd_cv_ldap_set_rebind_proc_type" = "xvoid"
  then
    AC_DEFINE(LDAP_SET_REBIND_PROC_RETURNS_VOID, 1,
              [Define to 1 if ldap_set_rebind_proc() returns void.])
  fi

  # check for broken implementations of ldap_create_deref_control()
  if test "x$ac_cv_func_ldap_create_deref_control" = "xyes"
  then
    # this bug cannot be determined on compile time so we run a
    # small test program
    AC_CACHE_CHECK(
        [ldap_create_deref_control() implementation],
        nslcd_cv_ldap_create_deref_control_working,
            [AC_RUN_IFELSE(
                [AC_LANG_PROGRAM([[
                    #include <stdio.h>
                    #include <lber.h>
                    #include <ldap.h>
                    ]], [[
                    int rc;
                    LDAP *ld;
                    LDAPControl *ctrls[2] = {NULL, NULL};
                    struct LDAPDerefSpec ds[2];
                    char *attrs[2] = {"uid", NULL};
                    ld = ldap_init("localhost", LDAP_PORT);
                    if (ld == NULL)
                    {
                      fprintf(stderr, "ldap_init() failed\n");
                      return 2;
                    }
                    ds[0].derefAttr = "member";
                    ds[0].attributes = attrs;
                    ds[1].derefAttr = NULL;
                    rc = ldap_create_deref_control(ld, ds, 0, &ctrls[0]);
                    if (rc != LDAP_SUCCESS)
                    {
                      fprintf(stderr, "ldap_create_deref_control() failed: %s\n",
                              ldap_err2string(rc));
                      return 2;
                    }
                    if (ldap_control_find(LDAP_CONTROL_X_DEREF, ctrls, NULL) != NULL)
                      return 0;
                    if (ldap_control_find(LDAP_CONTROL_PAGEDRESULTS, ctrls, NULL) != NULL)
                    {
                      fprintf(stderr, "ldap_create_deref_control() created LDAP_CONTROL_PAGEDRESULTS control\n");
                      return 3;
                    }
                    fprintf(stderr, "ldap_create_deref_control() created unknown control\n");
                    return 2;
                    ]])],
                [nslcd_cv_ldap_create_deref_control_working=ok],
                [if test "$?" -eq 3; then nslcd_cv_ldap_create_deref_control_working=broken
                 else nslcd_cv_ldap_create_deref_control_working=unknown; fi],
                [nslcd_cv_ldap_create_deref_control_working=cross])])
    if test "x$nslcd_cv_ldap_create_deref_control_working" != "xok"
    then
      AC_MSG_NOTICE([using replacement ldap_create_deref_control()])
      AC_LIBOBJ(derefctrl)
      AC_DEFINE(REPLACE_LDAP_CREATE_DEREF_CONTROL, 1,
                [Define to 1 if ldap_create_deref_control() is broken.])
    fi
  fi

  # save nslcd LIBS and CFLAGS and restore originals
  nslcd_CFLAGS="$CFLAGS"
  nslcd_LIBS="$LIBS"
  CFLAGS="$nslcd_save_CFLAGS"
  LIBS="$nslcd_save_LIBS"

  AC_SUBST(nslcd_LIBS)
fi

# pynslcd-specific tests
if test "x$enable_pynslcd" = "xyes"
then
  # check Python interpreter
  AM_PATH_PYTHON(2.5,, AC_MSG_ERROR([Python is required]))
  AX_PYTHON_MODULE(daemon)
  AX_PYTHON_MODULE(fcntl)
  AX_PYTHON_MODULE(fnmatch)
  AX_PYTHON_MODULE(ldap)
  AX_PYTHON_MODULE(sqlite3)
  # required by ldap.controls.ppolicy:
  AX_PYTHON_MODULE(pyasn1)
  AX_PYTHON_MODULE(pyasn1_modules)
  if test "x$HAVE_PYMOD_DAEMON" != "xyes" || \
     test "x$HAVE_PYMOD_FCNTL" != "xyes" || \
     test "x$HAVE_PYMOD_FNMATCH" != "xyes" || \
     test "x$HAVE_PYMOD_LDAP" != "xyes" || \
     test "x$HAVE_PYMOD_SQLITE3" != "xyes" || \
     test "x$HAVE_PYMOD_PYASN1" != "xyes" || \
     test "x$HAVE_PYMOD_PYASN1_MODULES" != "xyes"
  then
    AC_MSG_WARN(Required Python modules missing)
  fi
  # optional modules
  AX_PYTHON_MODULE(setproctitle)
fi

AM_CONDITIONAL([NSS_FLAVOUR_GLIBC], [test "x${with_nss_flavour}" = xglibc])
AM_CONDITIONAL([NSS_FLAVOUR_SOLARIS], [test "x${with_nss_flavour}" = xsolaris])
AM_CONDITIONAL([NSS_FLAVOUR_FREEBSD], [test "x${with_nss_flavour}" = xfreebsd])

# generate files
AC_CONFIG_FILES([Makefile compat/Makefile common/Makefile nss/Makefile
                 pam/Makefile utils/Makefile nslcd/Makefile pynslcd/Makefile
                 man/Makefile tests/Makefile])
AC_CONFIG_FILES([pynslcd/constants.py], [[
(
  echo ''
  echo '# The following is automatically generated from nslcd.h.'
  echo '# See that file for details.'
  echo ''
  sed -n 's| */\*.*\*/ *||;s/^.define  *\(NSLCD_[A-Z_]*\)  */\1 = /p' "$srcdir"/nslcd.h
) >> pynslcd/constants.py]])
AC_OUTPUT
