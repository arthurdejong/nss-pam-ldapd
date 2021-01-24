/*
   prototypes.h - all functions exported by the NSS library

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006-2015 Arthur de Jong

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301 USA
*/

#ifndef NSS__PROTOTYPES_H
#define NSS__PROTOTYPES_H 1

#include "compat/nss_compat.h"

/* flag to globally disable lookups (all _nss_ldap_*() functions will return
   NSS_STATUS_UNAVAIL */
extern int NSS_NAME(enablelookups);

#if defined(NSS_FLAVOUR_FREEBSD) || defined(NSS_FLAVOUR_NETBSD)

/* for FreeBSD we want the GlibC prototypes and functions to be built
   (we provide some wrappers in freebsdnss.c and netbsdnss.c) */
#define NSS_FLAVOUR_GLIBC 1

/* FreeBSD specific register function */
ns_mtab *nss_module_register(const char *source, unsigned int *mtabsize,
                             nss_module_unregister_fn *unreg);

#endif /* NSS_FLAVOUR_FREEBSD || NSS_FLAVOUR_NETBSD */

#ifdef NSS_FLAVOUR_GLIBC

/*
   These are prototypes for functions exported from the ldap NSS module.
   For more complete definitions of these functions check the GLIBC
   documentation.

   Other services than those mentioned here are currently not implemented.

   These definitions partially came from examining the GLIBC source code
   as no complete documentation of the NSS interface is available.
   This however is a useful pointer:
   http://www.gnu.org/software/libc/manual/html_node/Name-Service-Switch.html
*/

/* aliases - mail aliases */
nss_status_t NSS_NAME(getaliasbyname_r)(const char *name, struct aliasent *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(setaliasent)(void);
nss_status_t NSS_NAME(getaliasent_r)(struct aliasent *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(endaliasent)(void);

/* ethers - ethernet numbers */
nss_status_t NSS_NAME(gethostton_r)(const char *name, struct etherent *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(getntohost_r)(const struct ether_addr *addr, struct etherent *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(setetherent)(int stayopen);
nss_status_t NSS_NAME(getetherent_r)(struct etherent *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(endetherent)(void);

/* group - groups of users */
nss_status_t NSS_NAME(getgrnam_r)(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(getgrgid_r)(gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(initgroups_dyn)(const char *user, gid_t skipgroup, long int *start, long int *size, gid_t **groupsp, long int limit, int *errnop);
nss_status_t NSS_NAME(setgrent)(int stayopen);
nss_status_t NSS_NAME(getgrent_r)(struct group *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(endgrent)(void);

/* hosts - host names and numbers */
nss_status_t NSS_NAME(gethostbyname_r)(const char *name, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop);
nss_status_t NSS_NAME(gethostbyname2_r)(const char *name, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop);
nss_status_t NSS_NAME(gethostbyaddr_r)(const void *addr, socklen_t len, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop);
nss_status_t NSS_NAME(sethostent)(int stayopen);
nss_status_t NSS_NAME(gethostent_r)(struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop);
nss_status_t NSS_NAME(endhostent)(void);

/* netgroup - list of host and users */
nss_status_t NSS_NAME(setnetgrent)(const char *group, struct __netgrent *result);
nss_status_t NSS_NAME(getnetgrent_r)(struct __netgrent *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(endnetgrent)(struct __netgrent *result);

/* networks - network names and numbers */
nss_status_t NSS_NAME(getnetbyname_r)(const char *name, struct netent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop);
nss_status_t NSS_NAME(getnetbyaddr_r)(uint32_t addr, int af, struct netent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop);
nss_status_t NSS_NAME(setnetent)(int stayopen);
nss_status_t NSS_NAME(getnetent_r)(struct netent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop);
nss_status_t NSS_NAME(endnetent)(void);

/* passwd - user database and passwords */
nss_status_t NSS_NAME(getpwnam_r)(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(getpwuid_r)(uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(setpwent)(int stayopen);
nss_status_t NSS_NAME(getpwent_r)(struct passwd *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(endpwent)(void);

/* protocols - network protocols */
nss_status_t NSS_NAME(getprotobyname_r)(const char *name, struct protoent *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(getprotobynumber_r)(int number, struct protoent *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(setprotoent)(int stayopen);
nss_status_t NSS_NAME(getprotoent_r)(struct protoent *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(endprotoent)(void);

/* rpc - remote procedure call names and numbers */
nss_status_t NSS_NAME(getrpcbyname_r)(const char *name, struct rpcent *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(getrpcbynumber_r)(int number, struct rpcent *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(setrpcent)(int stayopen);
nss_status_t NSS_NAME(getrpcent_r)(struct rpcent *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(endrpcent)(void);

/* services - network services */
nss_status_t NSS_NAME(getservbyname_r)(const char *name, const char *protocol, struct servent *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(getservbyport_r)(int port, const char *protocol, struct servent *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(setservent)(int stayopen);
nss_status_t NSS_NAME(getservent_r)(struct servent *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(endservent)(void);

/* shadow - extended user information */
nss_status_t NSS_NAME(getspnam_r)(const char *name, struct spwd *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(setspent)(int stayopen);
nss_status_t NSS_NAME(getspent_r)(struct spwd *result, char *buffer, size_t buflen, int *errnop);
nss_status_t NSS_NAME(endspent)(void);

#endif /* NSS_FLAVOUR_GLIBC */

#ifdef NSS_FLAVOUR_SOLARIS

/* helper macros to do casts */
#define NSS_ARGS(args) ((nss_XbyY_args_t *)args)
#define LDAP_BE(be) ((struct nss_ldap_backend*)(be))

/* these are the constructors we provide */
nss_backend_t *NSS_NAME(ethers_constr)(const char *db_name, const char *src_name, const char *cfg_args);
nss_backend_t *NSS_NAME(group_constr)(const char *db_name, const char *src_name, const char *cfg_args);
nss_backend_t *NSS_NAME(hosts_constr)(const char *db_name, const char *src_name, const char *cfg_args);
nss_backend_t *NSS_NAME(netgroup_constr)(const char *db_name, const char *src_name, const char *cfg_args);
nss_backend_t *NSS_NAME(networks_constr)(const char *db_name, const char *src_name, const char *cfg_args);
nss_backend_t *NSS_NAME(passwd_constr)(const char *db_name, const char *src_name, const char *cfg_args);
nss_backend_t *NSS_NAME(protocols_constr)(const char *db_name, const char *src_name, const char *cfg_args);
nss_backend_t *NSS_NAME(rpc_constr)(const char *db_name, const char *src_name, const char *cfg_args);
nss_backend_t *NSS_NAME(services_constr)(const char *db_name, const char *src_name, const char *cfg_args);
nss_backend_t *NSS_NAME(shadow_constr)(const char *db_name, const char *src_name, const char *cfg_args);

#endif /* NSS_FLAVOUR_SOLARIS */

#endif /* not NSS__PROTOTYPES_H */
