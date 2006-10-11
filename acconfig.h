/* Define to the number of arguments to ldap_set_rebindproc */
#undef LDAP_SET_REBIND_PROC_ARGS

/* define to the number of args to gethostbyname_r */
#undef GETHOSTBYNAME_R_ARGS

/* define to set RFC2307BIS support */
#undef RFC2307BIS

/* define to enable debug code */
#undef DEBUG

/* define to enable attribute/objectclass mapping */
#undef AT_OC_MAP

/* define to enable proxy authentication for AIX */
#undef PROXY_AUTH

/* define to enable paged results control */
#undef PAGE_RESULTS

/* define to enable configurable Kerberos credentials cache */
#undef CONFIGURE_KRB5_CCNAME

/* define to enable configurable Kerberos credentials cache (putenv method) */
#undef CONFIGURE_KRB5_CCNAME_ENV

/* define to enable configurable Kerberos credentials cache (gssapi method) */
#undef CONFIGURE_KRB5_CCNAME_GSSAPI

/* Define to 1 if you have the <gssapi/gssapi_krb5.h> header file. */
#undef HAVE_GSSAPI_GSSAPI_KRB5_H

/* define to enable struct ether_addr definition */
#undef HAVE_STRUCT_ETHER_ADDR

/* define to enable socklen_t definition */
#undef HAVE_SOCKLEN_T

/* define if struct passwd has a pw_change member */
#undef HAVE_PASSWD_PW_CHANGE

/* define if struct passwd has a pw_expire member */
#undef HAVE_PASSWD_PW_EXPIRE

/* path to LDAP configuration file */
#define NSS_LDAP_PATH_CONF              "/etc/ldap.conf"

/* path to LDAP root secret file */
#define NSS_LDAP_PATH_ROOTPASSWD        "/etc/ldap.secret"

/* maximum number of group members in static buffer */
#define LDAP_NSS_NGROUPS	 64

