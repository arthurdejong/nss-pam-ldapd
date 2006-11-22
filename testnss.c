/*
   testnss.c - simple tests of developed nss code

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006 Arthur de Jong

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
   MA 02110-1301 USA
*/

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "nss/prototypes.h"

static char *nssstatus(enum nss_status retv)
{
  switch(retv)
  {
    case NSS_STATUS_TRYAGAIN: return "NSS_STATUS_TRYAGAIN";
    case NSS_STATUS_UNAVAIL:  return "NSS_STATUS_UNAVAIL";
    case NSS_STATUS_NOTFOUND: return "NSS_STATUS_NOTFOUND";
    case NSS_STATUS_SUCCESS:  return "NSS_STATUS_SUCCESS";
    case NSS_STATUS_RETURN:   return "NSS_STATUS_RETURN";
    default:                  return "NSS_STATUS_**ILLEGAL**";
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
         "}\n",pw->pw_name,pw->pw_passwd,
         (int)(pw->pw_uid),(int)(pw->pw_gid),
         pw->pw_gecos,pw->pw_dir,pw->pw_shell);
}

static void printalias(struct aliasent *alias)
{
  int i;
  printf("struct alias {\n"
         "  alias_name=\"%s\",\n"
         "  alias_members_len=%d,\n",
         alias->alias_name,(int)alias->alias_members_len);
  for (i=0;i<(int)alias->alias_members_len;i++)
    printf("  alias_members[%d]=\"%s\",\n",
           i,alias->alias_members[i]);
  printf("  alias_local=%d\n"
         "}\n",(int)alias->alias_local);
}

static void printgroup(struct group *group)
{
  int i;
  printf("struct group {\n"
         "  gr_name=\"%s\",\n"
         "  gr_passwd=\"%s\",\n"
         "  gr_gid=%d,\n",
         group->gr_name,group->gr_passwd,(int)group->gr_gid);
  for (i=0;group->gr_mem[i]!=NULL;i++)
    printf("  gr_mem[%d]=\"%s\",\n",
           i,group->gr_mem[i]);
  printf("  gr_mem[%d]=NULL\n"
         "}\n",i);
}

static void printhost(struct hostent *host)
{
  int i,j;
  char buffer[1024];
  const char *res;
  printf("struct hostent {\n"
         "  h_name=\"%s\",\n",
         host->h_name);
  for (i=0;host->h_aliases[i]!=NULL;i++)
    printf("  h_aliases[%d]=\"%s\",\n",
           i,host->h_aliases[i]);
  printf("  h_aliases[%d]=NULL,\n",i);
  if (host->h_addrtype==AF_INET)
    printf("  h_addrtype=AF_INET,\n");
  else if (host->h_addrtype==AF_INET6)
    printf("  h_addrtype=AF_INET6,\n");
  else
    printf("  h_addrtype=%d,\n",host->h_addrtype);
  printf("  h_length=%d,\n",host->h_length);
  for (i=0;host->h_addr_list[i]!=NULL;i++)
  {
    res=inet_ntop(host->h_addrtype,host->h_addr_list[i],
                  buffer,host->h_length);
    if (res!=NULL)
    {
      printf("  h_addr_list[%d]=%s,\n",i,buffer);
    }
    else
    {
      printf("  h_addr_list[%d]=",i);
      for (j=0;j<host->h_length;j++)
        printf("%02x",(int)host->h_addr_list[i][j]);
      printf(",\n");
    }
  }
  printf("  h_addr_list[%d]=NULL\n",i);
}

static void printether(struct etherent *ether)
{
  printf("struct etherent {\n"
         "  e_name=\"%s\",\n"
         "  e_addr=%s\n"
         "}\n",
         ether->e_name,ether_ntoa(&(ether->e_addr)));
}

static void printshadow(struct spwd *shadow)
{
  printf("struct spwd {\n"
         "  sp_namp=\"%s\",\n"
         "  sp_pwdp=\"%s\",\n"
         "  sp_lstchg=%ld,\n"
         "  sp_min=%ld,\n"
         "  sp_max=%ld,\n"
         "  sp_warn=%ld,\n"
         "  sp_inact=%ld,\n"
         "  sp_expire=%ld,\n"
         "  sp_flag=%lu\n"
         "}\n",
         shadow->sp_namp,shadow->sp_pwdp,shadow->sp_lstchg,
         shadow->sp_min,shadow->sp_max,shadow->sp_warn,
         shadow->sp_inact,shadow->sp_expire,shadow->sp_flag);
}

static void printnetgroup(struct __netgrent *netgroup)
{
  printf("struct __netgrent {\n");
  if (netgroup->type==triple_val)
  {
    printf("  type=triple_val,\n");
    if (netgroup->val.triple.host==NULL)
      printf("  val.triple.host=NULL,\n");
    else
      printf("  val.triple.host=\"%s\",\n",netgroup->val.triple.host);
    if (netgroup->val.triple.user==NULL)
      printf("  val.triple.user=NULL,\n");
    else
      printf("  val.triple.user=\"%s\",\n",netgroup->val.triple.user);
    if (netgroup->val.triple.domain==NULL)
      printf("  val.triple.domain=NULL,\n");
    else
      printf("  val.triple.domain=\"%s\",\n",netgroup->val.triple.domain);
  }
  else
  {
    printf("  type=triple_val,\n"
           "  val.group=\"%s\",\n",
           netgroup->val.group);
  }
  printf("  ...\n"
         "}\n");
}

/* the main program... */
int main(int argc,char *argv[])
{
  struct passwd passwdresult;
  struct aliasent aliasresult;
  struct group groupresult;
  struct hostent hostresult;
  struct etherent etherresult;
  struct spwd shadowresult;
  struct __netgrent netgroupresult;
  char buffer[1024];
  enum nss_status res;
  int errnocp,h_errnocp;
  long int start,size=40;
  gid_t *gidlist=(gid_t *)buffer;
  char address[1024];

  /* test getpwnam() */
  printf("\nTEST getpwnam()\n");
  res=_nss_ldap_getpwnam_r("arthur",&passwdresult,buffer,1024,&errnocp);
  printf("status=%s\n",nssstatus(res));
  if (res==NSS_STATUS_SUCCESS)
    printpasswd(&passwdresult);
  else
  {
    printf("errno=%d:%s\n",(int)errno,strerror(errno));
    printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  }

  /* test getpwnam() with non-existing user */
  printf("\nTEST getpwnam() with non-existing user\n");
  res=_nss_ldap_getpwnam_r("nonexist",&passwdresult,buffer,1024,&errnocp);
  printf("status=%s\n",nssstatus(res));
  if (res==NSS_STATUS_SUCCESS)
    printpasswd(&passwdresult);
  else
  {
    printf("errno=%d:%s\n",(int)errno,strerror(errno));
    printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  }

  /* test getpwuid() */
  printf("\nTEST getpwuid()\n");
  res=_nss_ldap_getpwuid_r(180,&passwdresult,buffer,1024,&errnocp);
  printf("status=%s\n",nssstatus(res));
  if (res==NSS_STATUS_SUCCESS)
    printpasswd(&passwdresult);
  else
  {
    printf("errno=%d:%s\n",(int)errno,strerror(errno));
    printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  }

  /* test {set,get,end}pwent() */
  printf("\nTEST {set,get,end}pwent()\n");
  res=_nss_ldap_setpwent(1);
  printf("status=%s\n",nssstatus(res));
  while ((res=_nss_ldap_getpwent_r(&passwdresult,buffer,1024,&errnocp))==NSS_STATUS_SUCCESS)
  {
    printf("status=%s\n",nssstatus(res));
    printpasswd(&passwdresult);
  }
  printf("status=%s\n",nssstatus(res));
  printf("errno=%d:%s\n",(int)errno,strerror(errno));
  printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  res=_nss_ldap_endpwent();
  printf("status=%s\n",nssstatus(res));

  /* test getaliasbyname() */
  printf("\nTEST getaliasbyname()\n");
  res=_nss_ldap_getaliasbyname_r("techstaff",&aliasresult,buffer,1024,&errnocp);
  printf("status=%s\n",nssstatus(res));
  if (res==NSS_STATUS_SUCCESS)
    printalias(&aliasresult);
  else
  {
    printf("errno=%d:%s\n",(int)errno,strerror(errno));
    printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  }

  /* test {set,get,end}aliasent() */
  printf("\nTEST {set,get,end}aliasent()\n");
  res=_nss_ldap_setaliasent();
  printf("status=%s\n",nssstatus(res));
  while ((res=_nss_ldap_getaliasent_r(&aliasresult,buffer,1024,&errnocp))==NSS_STATUS_SUCCESS)
  {
    printf("status=%s\n",nssstatus(res));
    printalias(&aliasresult);
  }
  printf("status=%s\n",nssstatus(res));
  printf("errno=%d:%s\n",(int)errno,strerror(errno));
  printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  res=_nss_ldap_endaliasent();
  printf("status=%s\n",nssstatus(res));

  /* test getgrnam() */
  printf("\nTEST getgrnam()\n");
  res=_nss_ldap_getgrnam_r("testgroup",&groupresult,buffer,1024,&errnocp);
  printf("status=%s\n",nssstatus(res));
  if (res==NSS_STATUS_SUCCESS)
    printgroup(&groupresult);
  else
  {
    printf("errno=%d:%s\n",(int)errno,strerror(errno));
    printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  }

  /* test getgrgid() */
  printf("\nTEST getgrgid()\n");
  res=_nss_ldap_getgrgid_r(100,&groupresult,buffer,1024,&errnocp);
  printf("status=%s\n",nssstatus(res));
  if (res==NSS_STATUS_SUCCESS)
    printgroup(&groupresult);
  else
  {
    printf("errno=%d:%s\n",(int)errno,strerror(errno));
    printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  }

  /* test initgroups() */
  printf("\nTEST initgroups()\n");
  res=_nss_ldap_initgroups_dyn("arthur",10,&start,&size,&gidlist,size,&errnocp);
  printf("status=%s\n",nssstatus(res));
  if (res==NSS_STATUS_SUCCESS)
  {
    for (size=0;size<start;size++)
    {
      printf("gidlist[%d]=%d\n",(int)size,(int)gidlist[size]);
    }
  }
  else
  {
    printf("errno=%d:%s\n",(int)errno,strerror(errno));
    printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  }

  /* test {set,get,end}grent() */
  printf("\nTEST {set,get,end}grent()\n");
  res=_nss_ldap_setgrent(1);
  printf("status=%s\n",nssstatus(res));
  while ((res=_nss_ldap_getgrent_r(&groupresult,buffer,1024,&errnocp))==NSS_STATUS_SUCCESS)
  {
    printf("status=%s\n",nssstatus(res));
    printgroup(&groupresult);
  }
  printf("status=%s\n",nssstatus(res));
  printf("errno=%d:%s\n",(int)errno,strerror(errno));
  printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  res=_nss_ldap_endgrent();
  printf("status=%s\n",nssstatus(res));

  /* test gethostbyname2(AF_INET) */
  printf("\nTEST gethostbyname2(AF_INET)\n");
  res=_nss_ldap_gethostbyname2_r("oostc",AF_INET,&hostresult,buffer,1024,&errnocp,&h_errnocp);
  printf("status=%s\n",nssstatus(res));
  if (res==NSS_STATUS_SUCCESS)
    printhost(&hostresult);
  else
  {
    printf("errno=%d:%s\n",(int)errno,strerror(errno));
    printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
    printf("h_errno=%d:%s\n",(int)h_errno,hstrerror(h_errno));
    printf("h_errnocp=%d:%s\n",(int)h_errnocp,hstrerror(h_errnocp));
  }

  /* test gethostbyname2(AF_INET6) */
  printf("\nTEST gethostbyname2(AF_INET6)\n");
  res=_nss_ldap_gethostbyname2_r("oostc",AF_INET6,&hostresult,buffer,1024,&errnocp,&h_errnocp);
  printf("status=%s\n",nssstatus(res));
  if (res==NSS_STATUS_SUCCESS)
    printhost(&hostresult);
  else
  {
    printf("errno=%d:%s\n",(int)errno,strerror(errno));
    printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
    printf("h_errno=%d:%s\n",(int)h_errno,hstrerror(h_errno));
    printf("h_errnocp=%d:%s\n",(int)h_errnocp,hstrerror(h_errnocp));
  }

  /* test gethostbyaddr(AF_INET) */
  printf("\nTEST gethostbyaddr(AF_INET)\n");
  inet_pton(AF_INET,"192.43.210.81",address);
  res=_nss_ldap_gethostbyaddr_r((void *)address,sizeof(struct in_addr),AF_INET,
                                &hostresult,buffer,1024,&errnocp,&h_errnocp);
  printf("status=%s\n",nssstatus(res));
  if (res==NSS_STATUS_SUCCESS)
    printhost(&hostresult);
  else
  {
    printf("errno=%d:%s\n",(int)errno,strerror(errno));
    printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
    printf("h_errno=%d:%s\n",(int)h_errno,hstrerror(h_errno));
    printf("h_errnocp=%d:%s\n",(int)h_errnocp,hstrerror(h_errnocp));
  }

  /* test gethostbyaddr(AF_INET6) */
  printf("\nTEST gethostbyaddr(AF_INET6)\n");
  inet_pton(AF_INET6,"2001:200:0:8002:203:47ff:fea5:3085",address);
  res=_nss_ldap_gethostbyaddr_r((void *)address,sizeof(struct in6_addr),AF_INET6,
                                &hostresult,buffer,1024,&errnocp,&h_errnocp);
  printf("status=%s\n",nssstatus(res));
  if (res==NSS_STATUS_SUCCESS)
    printhost(&hostresult);
  else
  {
    printf("errno=%d:%s\n",(int)errno,strerror(errno));
    printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
    printf("h_errno=%d:%s\n",(int)h_errno,hstrerror(h_errno));
    printf("h_errnocp=%d:%s\n",(int)h_errnocp,hstrerror(h_errnocp));
  }

  /* test {set,get,end}hostent() */
  printf("\nTEST {set,get,end}hostent()\n");
  res=_nss_ldap_sethostent(1);
  printf("status=%s\n",nssstatus(res));
  while ((res=_nss_ldap_gethostent_r(&hostresult,buffer,1024,&errnocp,&h_errnocp))==NSS_STATUS_SUCCESS)
  {
    printf("status=%s\n",nssstatus(res));
    printhost(&hostresult);
  }
  printf("status=%s\n",nssstatus(res));
  printf("errno=%d:%s\n",(int)errno,strerror(errno));
  printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  printf("h_errno=%d:%s\n",(int)h_errno,hstrerror(h_errno));
  printf("h_errnocp=%d:%s\n",(int)h_errnocp,hstrerror(h_errnocp));
  res=_nss_ldap_endhostent();
  printf("status=%s\n",nssstatus(res));

  /* test ether_hostton() */
  printf("\nTEST ether_hostton()\n");
  res=_nss_ldap_gethostton_r("appelscha",&etherresult,buffer,1024,&errnocp);
  printf("status=%s\n",nssstatus(res));
  if (res==NSS_STATUS_SUCCESS)
    printether(&etherresult);
  else
  {
    printf("errno=%d:%s\n",(int)errno,strerror(errno));
    printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  }

  /* test ether_ntohost() */
  printf("\nTEST ether_ntohost()\n");
  res=_nss_ldap_getntohost_r(ether_aton("0:13:72:a4:39:c7"),
                             &etherresult,buffer,1024,&errnocp);
  printf("status=%s\n",nssstatus(res));
  if (res==NSS_STATUS_SUCCESS)
    printether(&etherresult);
  else
  {
    printf("errno=%d:%s\n",(int)errno,strerror(errno));
    printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  }

  /* test {set,get,end}etherent() */
  printf("\nTEST {set,get,end}etherent()\n");
  res=_nss_ldap_setetherent(1);
  printf("status=%s\n",nssstatus(res));
  while ((res=_nss_ldap_getetherent_r(&etherresult,buffer,1024,&errnocp))==NSS_STATUS_SUCCESS)
  {
    printf("status=%s\n",nssstatus(res));
    printether(&etherresult);
  }
  printf("status=%s\n",nssstatus(res));
  printf("errno=%d:%s\n",(int)errno,strerror(errno));
  printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  res=_nss_ldap_endetherent();
  printf("status=%s\n",nssstatus(res));

  /* test getspnam() */
  printf("\nTEST getspnam()\n");
  res=_nss_ldap_getspnam_r("arthur",&shadowresult,buffer,1024,&errnocp);
  printf("status=%s\n",nssstatus(res));
  if (res==NSS_STATUS_SUCCESS)
    printshadow(&shadowresult);
  else
  {
    printf("errno=%d:%s\n",(int)errno,strerror(errno));
    printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  }

  /* test {set,get,end}spent() */
  printf("\nTEST {set,get,end}spent()\n");
  res=_nss_ldap_setspent(1);
  printf("status=%s\n",nssstatus(res));
  while ((res=_nss_ldap_getspent_r(&shadowresult,buffer,1024,&errnocp))==NSS_STATUS_SUCCESS)
  {
    printf("status=%s\n",nssstatus(res));
    printshadow(&shadowresult);
  }
  printf("status=%s\n",nssstatus(res));
  printf("errno=%d:%s\n",(int)errno,strerror(errno));
  printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  res=_nss_ldap_endspent();
  printf("status=%s\n",nssstatus(res));

  /* test {set,get,end}netgrent() */
  printf("\nTEST {set,get,end}netgrent()\n");
  res=_nss_ldap_setnetgrent("westcomp",&netgroupresult);
  printf("status=%s\n",nssstatus(res));
  while ((_nss_ldap_getnetgrent_r(&netgroupresult,buffer,1024,&errnocp))==NSS_STATUS_SUCCESS)
  {
    printf("status=%s\n",nssstatus(res));
    printnetgroup(&netgroupresult);
  }
  printf("status=%s\n",nssstatus(res));
  printf("errno=%d:%s\n",(int)errno,strerror(errno));
  printf("errnocp=%d:%s\n",(int)errnocp,strerror(errnocp));
  res=_nss_ldap_endnetgrent(&netgroupresult);
  printf("status=%s\n",nssstatus(res));

  return 0;
}
