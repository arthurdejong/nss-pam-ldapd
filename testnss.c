
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "nss/exports.h"

static char *nssstatus(enum nss_status retv)
{
  switch(retv)
  {
    case NSS_STATUS_TRYAGAIN: return "NSS_STATUS_TRYAGAIN";
    case NSS_STATUS_UNAVAIL:  return "NSS_STATUS_UNAVAIL"; 
    case NSS_STATUS_NOTFOUND: return "NSS_STATUS_NOTFOUND";
    case NSS_STATUS_SUCCESS:  return "NSS_STATUS_SUCCESS";
    case NSS_STATUS_RETURN:   return "NSS_STATUS_RETURN";
    default:                   return "NSS_STATUS_**ILLEGAL**";
  }
}

static void printpasswd(struct passwd *pw)
{
  printf("struct passwd {\n"
         "  pw_name=\"%s\",\n"
         "  pw_passwd=\"%s\",\n"
         "  pw_uid=%d,\n"
         "  pw_gid=%d,\n"
         "  pw_gecos=\"%s\",\n"
         "  pw_dir=\"%s\",\n"
         "  pw_shell=\"%s\"\n"
         "}\n", pw->pw_name, pw->pw_passwd,
         (int)(pw->pw_uid),(int)(pw->pw_gid),
         pw->pw_gecos,pw->pw_dir,pw->pw_shell);
} 

/* the main program... */
int main(int argc,char *argv[])
{
  struct passwd result;
  char buffer[1024];
  enum nss_status res;
  int errnocp;

  /* test getpwnam() */
  printf("TEST getpwnam()\n");
  res=_nss_ldap_getpwnam_r("arthur",&result,buffer,1024,&errnocp);
  printf("errno=%d:%s\n",(int)errno,strerror(errno));
  printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  printf("status=%s\n",nssstatus(res));
  printpasswd(&result);

  /* test getpwuid() */
  printf("TEST getpwuid()\n");
  res=_nss_ldap_getpwuid_r(180,&result,buffer,1024,&errnocp);
  printf("errno=%d:%s\n",(int)errno,strerror(errno));
  printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  printf("status=%s\n",nssstatus(res));
  printpasswd(&result);

  /* test {set,get,end}pwent() */
  printf("TEST {set,get,end}pwent()\n");
  _nss_ldap_setpwent();
  while ((res=_nss_ldap_getpwent_r(&result,buffer,1024,&errnocp))==NSS_STATUS_SUCCESS)
  {
    printf("errno=%d:%s\n",(int)errno,strerror(errno));
    printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
    printf("status=%s\n",nssstatus(res));
    printpasswd(&result);
  }
  printf("errno=%d:%s\n",(int)errno,strerror(errno));
  printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  printf("status=%s\n",nssstatus(res));
  _nss_ldap_endpwent();

  return 0;
}
