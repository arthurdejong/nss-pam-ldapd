
#import <lber.h>
#import <ldap.h>
#import "ldap-nss.h"
#import "util.h"
#import "dnsconfig.h"

void
printcf (ldap_config_t * cf)
{
  printf ("host %s\n", cf->ldc_host);
  printf ("port %d\n", cf->ldc_port);
  printf ("base %s\n", cf->ldc_base);
#if 0
  char *ldc_host;
  int ldc_port;
  char *ldc_base;
  int ldc_scope;
  char *ldc_binddn;
  char *ldc_bindpw;
  struct ldap_config *ldc_next;
#endif
}

void
main (void)
{
/*
   NSS_STATUS _nss_ldap_readconfigfromdns(
   ldap_config_t *result,
   char *buf,
   size_t buflen
 */
  ldap_config_t cf;
  char buf[1024];

  _nss_ldap_readconfigfromdns (&cf, buf, sizeof (buf));
  printcf (&cf);
  printcf (cf.ldc_next);
  exit (0);
}
