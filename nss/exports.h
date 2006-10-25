/* nss.h -all functions exported by the library */

#ifndef _NSS_EXPORTS_H
#define _NSS_EXPORTS_H 1

#include <nss.h>
#include <aliases.h>
#include <netinet/ether.h>
#include <sys/types.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <shadow.h>

/*
   These are prototypes for functions exported from the ldap nss module.
   For more complete definitions of these functions check the GLIBC
   documentation.
   
   Other services than those mentioned here are currently not implemented.
   Contributions are welcome.
*/

/* aliases - mail aliases */
enum nss_status _nss_ldap_getaliasbyname_r(const char *name,struct aliasent *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_setaliasent(void);
enum nss_status _nss_ldap_getaliasent_r(struct aliasent *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_endaliasent(void);

/* automount - automounter maps */
enum nss_status _nss_ldap_getautomntbyname_r(void *private,const char *key,const char **canon_key,const char **value,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_setautomntent(const char *mapname,void **private);
enum nss_status _nss_ldap_getautomntent_r(void *private,const char **key,const char **value,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_endautomntent(void **private);

/* ethers - ethernet numbers */
enum nss_status _nss_ldap_gethostton_r(const char *name,struct ether_addr *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_getntohost_r(struct ether_addr *addr,struct ether_addr *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_setetherent(void);
enum nss_status _nss_ldap_getetherent_r(struct ether_addr *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_endetherent(void);

/* group - groups of users */
enum nss_status _nss_ldap_getgrnam_r(const char *name,struct group *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_getgrgid_r(gid_t gid,struct group *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_setgrent(void);
enum nss_status _nss_ldap_getgrent_r(struct group *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_endgrent(void);
enum nss_status _nss_ldap_initgroups(const char *user,gid_t group,long int *start,long int *size,gid_t *groups,long int limit,int *errnop);
enum nss_status _nss_ldap_initgroups_dyn(const char *user,gid_t group,long int *start,long int *size,gid_t **groupsp,long int limit,int *errnop);

/* hosts - host names and numbers */
enum nss_status _nss_ldap_gethostbyname_r(const char *name,struct hostent *result,char *buffer,size_t buflen,int *errnop,int *h_errnop);
enum nss_status _nss_ldap_gethostbyname2_r(const char *name,int af,struct hostent *result,char *buffer,size_t buflen,int *errnop,int *h_errnop);
enum nss_status _nss_ldap_gethostbyaddr_r(struct in_addr *addr,int len,int type,struct hostent *result,char *buffer,size_t buflen,int *errnop,int *h_errnop);
enum nss_status _nss_ldap_sethostent(void);
enum nss_status _nss_ldap_gethostent_r(struct hostent *result,char *buffer,size_t buflen,int *errnop,int *h_errnop);
enum nss_status _nss_ldap_endhostent(void);

/* netgroup - list of host and users */
/* DISABLED FOR NOW
enum nss_status _nss_ldap_setnetgrent(char *group,struct __netgrent *result);
enum nss_status _nss_ldap_getnetgrent_r(struct __netgrent *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_endnetgrent(struct __netgrent *result);
*/

/* networks - network names and numbers */
enum nss_status _nss_ldap_getnetbyname_r(const char *name,struct netent *result,char *buffer,size_t buflen,int *errnop,int *herrnop);
enum nss_status _nss_ldap_getnetbyaddr_r(unsigned long addr,int type,struct netent *result,char *buffer,size_t buflen,int *errnop,int *herrnop);
enum nss_status _nss_ldap_setnetent(void);
enum nss_status _nss_ldap_getnetent_r(struct netent *result,char *buffer,size_t buflen,int *errnop,int *herrnop);
enum nss_status _nss_ldap_endnetent(void);

/* passwd - user database and passwords */
enum nss_status _nss_ldap_getpwnam_r(const char *name,struct passwd *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_getpwuid_r(uid_t uid,struct passwd *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_setpwent(void);
enum nss_status _nss_ldap_getpwent_r(struct passwd *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_endpwent(void);

/* protocols - network protocols */
enum nss_status _nss_ldap_getprotobyname_r(const char *name,struct protoent *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_getprotobynumber_r(int number,struct protoent *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_setprotoent(void);
enum nss_status _nss_ldap_getprotoent_r(struct protoent *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_endprotoent(void);

/* rpc - remote procedure call names and numbers */
enum nss_status _nss_ldap_getrpcbyname_r(const char *name,struct rpcent *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_getrpcbynumber_r(int number,struct rpcent *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_setrpcent(void);
enum nss_status _nss_ldap_getrpcent_r(struct rpcent *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_endrpcent(void);

/* services - network services */
enum nss_status _nss_ldap_getservbyname_r(const char *name,const char *proto,struct servent *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_getservbyport_r(int port,const char *proto,struct servent *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_setservent(void);
enum nss_status _nss_ldap_getservent_r(struct servent *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_endservent(void);

/* shadow - extended user information */
enum nss_status _nss_ldap_getspnam_r(const char *name,struct spwd *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_setspent(void);
enum nss_status _nss_ldap_getspent_r(struct spwd *result,char *buffer,size_t buflen,int *errnop);
enum nss_status _nss_ldap_endspent(void);

#endif /* not NSS_EXPORTS */
