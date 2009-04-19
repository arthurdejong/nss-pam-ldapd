/*
   pam.c - pam processing routines

   Copyright (C) 2009 Howard Chu
   Copyright (C) 2009 Arthur de Jong

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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif /* HAVE_STDINT_H */

#include "common.h"
#include "log.h"
#include "myldap.h"
#include "cfg.h"

/* for PAM status codes */
#include <security/pam_modules.h>

/* check authentication credentials of the user */
int nslcd_pam_authc(TFILE *fp,MYLDAP_SESSION *session)
{
  /* define common variables */
  int32_t tmpint32;
  MYLDAP_SEARCH *search;
  MYLDAP_ENTRY *entry;
  int rc=PAM_AUTH_ERR;
  char uid[256];
  char svc[256];
  char pwd[256];
  char userdn[256];
  /* read request parameters */
  READ_STRING_BUF2(fp,uid,sizeof(uid));
  if (!isvalidname(uid)) {
    log_log(LOG_WARNING,"nslcd_pam_authc(%s): invalid user name",uid);
    /* write a response message anyway */
    /* TODO: probably just write NSLCD_RESULT_END to indicate failure */
    WRITE_INT32(fp,NSLCD_VERSION);
    WRITE_INT32(fp,NSLCD_ACTION_PAM_AUTHC);
    WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
    WRITE_INT32(fp,PAM_USER_UNKNOWN); /* authok */
    WRITE_INT32(fp,PAM_SUCCESS);  /* authz */
    WRITE_STRING(fp,"");    /* dn */
    WRITE_STRING(fp,"");    /* authzmsg */
    WRITE_STRING(fp,"");    /* tmpluser */
    return -1;
  }
  READ_STRING_BUF2(fp,svc,sizeof(svc));
  READ_STRING_BUF2(fp,pwd,sizeof(pwd));
  /* log call */
  log_log(LOG_DEBUG,"nslcd_pam_authc(%s,%s,passwd)",uid,svc);
  /* write the response header */
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PAM_AUTHC);
  /* set up a new connection */

  /* FIXME: implement setting up connection, perform uid->DN expansion
            and bind with DN and pwd */

  /* maye use existing session for uid2dn lookup and make new connection
     just for binding, also be sure to clean up session (probably set up a
     session here, call another function to get the results, etc) */

  /* perform uid to DN translation */
  if (uid2dn(session,uid,userdn,sizeof(userdn))==NULL)
  {
    log_log(LOG_WARNING,"nslcd_pam_authc(%s): user not found",uid);
    /* return error to client */
    /* FIXME: probably return NSLCD_RESULT_END instead */
    WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
    WRITE_INT32(fp,PAM_USER_UNKNOWN); /* authok */
    WRITE_INT32(fp,PAM_SUCCESS);  /* authz */
    WRITE_STRING(fp,"");          /* dn */
    WRITE_STRING(fp,"");    /* authzmsg */
    WRITE_STRING(fp,"");    /* tmpluser */
    return -1;
  }

  /* TODO: perform bind

  switch(rs.sr_err) {
  case LDAP_SUCCESS: rc = PAM_SUCCESS; break;
  case LDAP_INVALID_CREDENTIALS: rc = PAM_AUTH_ERR; break;
  default: rc = PAM_AUTH_ERR; break;
  }*/

  WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
  WRITE_INT32(fp,rc); /* authok */
  WRITE_INT32(fp,PAM_SUCCESS);  /* authz */
  WRITE_STRING(fp,userdn); /* dn */
  WRITE_STRING(fp,"");    /* authzmsg */
  WRITE_STRING(fp,"");    /* tmpluser */

  return 0;
}

/* check authorisation of the user */
int nslcd_pam_authz(TFILE *fp,MYLDAP_SESSION *session)
{
/*
  struct berval dn, svc;
  struct berval authzmsg = BER_BVNULL;
  int32_t tmpint32;
  char dnc[1024];
  char svcc[256];

  READ_STRING_BUF2(fp,dnc,sizeof(dnc));
  dn.bv_val = dnc;
  dn.bv_len = tmpint32;
  READ_STRING_BUF2(fp,svcc,sizeof(svcc));
  svc.bv_val = svcc;
  svc.bv_len = tmpint32;

  Debug(LDAP_DEBUG_TRACE,"nssov_pam_authz(%s)\n",dn.bv_val,0,0);

  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PAM_AUTHZ);
  WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
  WRITE_INT32(fp,PAM_SUCCESS);
  WRITE_BERVAL(fp,&authzmsg);
*/
  return 0;
}

int nslcd_pam_sess_o(TFILE *fp,MYLDAP_SESSION *session)
{
/*
  struct berval dn, svc;
  int32_t tmpint32;
  char dnc[1024];
  char svcc[256];

  READ_STRING_BUF2(fp,dnc,sizeof(dnc));
  dn.bv_val = dnc;
  dn.bv_len = tmpint32;
  READ_STRING_BUF2(fp,svcc,sizeof(svcc));
  svc.bv_val = svcc;
  svc.bv_len = tmpint32;

  Debug(LDAP_DEBUG_TRACE,"nssov_pam_sess_o(%s)\n",dn.bv_val,0,0);

  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PAM_SESS_O);
  WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
*/
  return 0;
}

int nslcd_pam_sess_c(TFILE *fp,MYLDAP_SESSION *session)
{
/*
  struct berval dn, svc;
  int32_t tmpint32;
  char dnc[1024];
  char svcc[256];

  READ_STRING_BUF2(fp,dnc,sizeof(dnc));
  dn.bv_val = dnc;
  dn.bv_len = tmpint32;
  READ_STRING_BUF2(fp,svcc,sizeof(svcc));
  svc.bv_val = svcc;
  svc.bv_len = tmpint32;

  Debug(LDAP_DEBUG_TRACE,"nssov_pam_sess_c(%s)\n",dn.bv_val,0,0);

  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PAM_SESS_C);
  WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
*/
  return 0;
}

int nslcd_pam_pwmod(TFILE *fp,MYLDAP_SESSION *session)
{
/*
  struct berval dn, uid, opw, npw;
  int32_t tmpint32;
  char dnc[1024];
  char uidc[256];
  char opwc[256];
  char npwc[256];

  READ_STRING_BUF2(fp,dnc,sizeof(dnc));
  dn.bv_val = dnc;
  dn.bv_len = tmpint32;
  READ_STRING_BUF2(fp,uidc,sizeof(uidc));
  uid.bv_val = uidc;
  uid.bv_len = tmpint32;
  READ_STRING_BUF2(fp,opwc,sizeof(opwc));
  opw.bv_val = opwc;
  opw.bv_len = tmpint32;
  READ_STRING_BUF2(fp,npwc,sizeof(npwc));
  npw.bv_val = npwc;
  npw.bv_len = tmpint32;

  Debug(LDAP_DEBUG_TRACE,"nssov_pam_pwmod(%s), %s\n",dn.bv_val,uid.bv_val,0);

  BER_BVZERO(&npw);
  WRITE_INT32(fp,NSLCD_VERSION);
  WRITE_INT32(fp,NSLCD_ACTION_PAM_PWMOD);
  WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
  WRITE_INT32(fp,PAM_SUCCESS);
  WRITE_BERVAL(fp,&npw);
*/
  return 0;
}
