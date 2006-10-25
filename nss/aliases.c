
#include "exports.h"

enum nss_status _nss_ldap_getaliasbyname_r(const char *name,struct aliasent *result,char *buffer,size_t buflen,int *errnop)
{}

enum nss_status _nss_ldap_setaliasent(void)
{}

enum nss_status _nss_ldap_getaliasent_r(struct aliasent *result,char *buffer,size_t buflen,int *errnop)
{}

enum nss_status _nss_ldap_endaliasent(void)
{}
