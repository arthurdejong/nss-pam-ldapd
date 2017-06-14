/*
   usermod.c - routines for changing user information such as full name,
               login shell, etc

   Copyright (C) 2013-2017 Arthur de Jong

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
#include <unistd.h>
#include <sys/stat.h>

#include "common.h"
#include "log.h"
#include "myldap.h"
#include "cfg.h"
#include "attmap.h"
#include "compat/shell.h"

/* ensure that both userdn and username are filled in from the entry,
   returns an LDAP result code */
static MYLDAP_ENTRY *validate_user(MYLDAP_SESSION *session,
                                   char *username, int *rcp)
{
  int rc;
  MYLDAP_ENTRY *entry = NULL;
  /* check username for validity */
  if (!isvalidname(username))
  {
    log_log(LOG_WARNING, "request denied by validnames option");
    *rcp = LDAP_NO_SUCH_OBJECT;
    return NULL;
  }
  /* get the user entry based on the username */
  entry = uid2entry(session, username, &rc);
  if (entry == NULL)
  {
    if (rc == LDAP_SUCCESS)
      rc = LDAP_NO_SUCH_OBJECT;
    log_log(LOG_DEBUG, "\"%s\": user not found: %s", username, ldap_err2string(rc));
    *rcp = rc;
    return NULL;
  }
  return entry;
}

static int is_valid_homedir(const char *homedir)
{
  struct stat sb;
  /* should be absolute path */
  if (homedir[0] != '/')
    return 0;
  /* get directory status */
  if (stat(homedir, &sb))
  {
    log_log(LOG_DEBUG, "cannot stat() %s: %s", homedir, strerror(errno));
    return 0;
  }
  /* check if a directory */
  if (!S_ISDIR(sb.st_mode))
  {
    log_log(LOG_DEBUG, "%s: not a directory", homedir);
    return 0;
  }
  /* FIXME: check ownership */
  return 1;
}

static int is_valid_shell(const char *shell)
{
  int valid = 0;
  char *l;
  setusershell();
  while ((l = getusershell()) != NULL)
  {
    if (strcmp(l, shell) == 0)
    {
      valid = 1;
      break;
    }
  }
  endusershell();
  return valid;
}

static MYLDAP_SESSION *get_session(const char *binddn, const char *password,
                                   int *rcp)
{
  MYLDAP_SESSION *session;
  /* set up a new connection */
  session = myldap_create_session();
  if (session == NULL)
  {
    *rcp = LDAP_UNAVAILABLE;
    return NULL;
  }
  /* check that we can bind */
  *rcp = myldap_bind(session, binddn, password, NULL, NULL);
  if (*rcp != LDAP_SUCCESS)
  {
    myldap_session_close(session);
    return NULL;
  }
  return session;
}

#define ADD_MOD(attribute, value)                                           \
  if ((value != NULL) && (attribute[0] != '"'))                             \
  {                                                                         \
    strvals[i * 2] = (char *)value;                                         \
    strvals[i * 2 + 1] = NULL;                                              \
    mods[i].mod_op = LDAP_MOD_REPLACE;                                      \
    mods[i].mod_type = (char *)attribute;                                   \
    mods[i].mod_values = strvals + (i * 2);                                 \
    modsp[i] = mods + i;                                                    \
    i++;                                                                    \
  }

static int change(MYLDAP_SESSION *session, const char *userdn,
                  const char *homedir, const char *shell)
{
  #define NUMARGS 2
  char *strvals[(NUMARGS + 1) * 2];
  LDAPMod mods[(NUMARGS + 1)], *modsp[(NUMARGS + 1)];
  int i = 0;
  /* build the list of modifications */
  ADD_MOD(attmap_passwd_homeDirectory, homedir);
  ADD_MOD(attmap_passwd_loginShell, shell);
  /* terminate the list of modifications */
  modsp[i] = NULL;
  /* execute the update */
  return myldap_modify(session, userdn, modsp);
}

int nslcd_usermod(TFILE *fp, MYLDAP_SESSION *session, uid_t calleruid)
{
  int32_t tmpint32;
  int rc = LDAP_SUCCESS;
  char username[BUFLEN_NAME];
  int asroot, isroot;
  char password[BUFLEN_PASSWORD];
  int32_t param;
  char buffer[4096];
  size_t buflen = sizeof(buffer);
  size_t bufptr = 0;
  const char *value = NULL;
  const char *fullname = NULL, *roomnumber = NULL, *workphone = NULL;
  const char *homephone = NULL, *other = NULL, *homedir = NULL;
  const char *shell = NULL;
  const char *binddn = NULL; /* the user performing the modification */
  MYLDAP_ENTRY *entry;
  MYLDAP_SESSION *newsession;
  char errmsg[BUFLEN_MESSAGE];
  /* read request parameters */
  READ_STRING(fp, username);
  READ_INT32(fp, asroot);
  READ_STRING(fp, password);
  /* read the usermod parameters */
  while (1)
  {
    READ_INT32(fp, param);
    if (param == NSLCD_USERMOD_END)
      break;
    READ_BUF_STRING(fp, value);
    switch (param)
    {
      case NSLCD_USERMOD_FULLNAME:   fullname = value; break;
      case NSLCD_USERMOD_ROOMNUMBER: roomnumber = value; break;
      case NSLCD_USERMOD_WORKPHONE:  workphone = value; break;
      case NSLCD_USERMOD_HOMEPHONE:  homephone = value; break;
      case NSLCD_USERMOD_OTHER:      other = value; break;
      case NSLCD_USERMOD_HOMEDIR:    homedir = value; break;
      case NSLCD_USERMOD_SHELL:      shell = value; break;
      default: /* other parameters are silently ignored */ break;
    }
  }
  /* log call */
  log_setrequest("usermod=\"%s\"", username);
  log_log(LOG_DEBUG, "nslcd_usermod(\"%s\",%s,\"%s\")",
          username, asroot ? "asroot" : "asuser", *password ? "***" : "");
  if (fullname != NULL)
    log_log(LOG_DEBUG, "nslcd_usermod(fullname=\"%s\")", fullname);
  if (roomnumber != NULL)
    log_log(LOG_DEBUG, "nslcd_usermod(roomnumber=\"%s\")", roomnumber);
  if (workphone != NULL)
    log_log(LOG_DEBUG, "nslcd_usermod(workphone=\"%s\")", workphone);
  if (homephone != NULL)
    log_log(LOG_DEBUG, "nslcd_usermod(homephone=\"%s\")", homephone);
  if (other != NULL)
    log_log(LOG_DEBUG, "nslcd_usermod(other=\"%s\")", other);
  if (homedir != NULL)
    log_log(LOG_DEBUG, "nslcd_usermod(homedir=\"%s\")", homedir);
  if (shell != NULL)
    log_log(LOG_DEBUG, "nslcd_usermod(shell=\"%s\")", shell);
  /* write the response header */
  WRITE_INT32(fp, NSLCD_VERSION);
  WRITE_INT32(fp, NSLCD_ACTION_USERMOD);
  /* validate request */
  entry = validate_user(session, username, &rc);
  if (entry == NULL)
  {
    /* for user not found we just say no result, otherwise break the protocol */
    if (rc == LDAP_NO_SUCH_OBJECT)
    {
      WRITE_INT32(fp, NSLCD_RESULT_END);
    }
    return -1;
  }
  /* check if it is a modification as root */
  isroot = (calleruid == 0) && asroot;
  if (asroot)
  {
    if (nslcd_cfg->rootpwmoddn == NULL)
    {
      log_log(LOG_NOTICE, "rootpwmoddn not configured");
      /* we break the protocol */
      return -1;
    }
    binddn = nslcd_cfg->rootpwmoddn;
    /* check if rootpwmodpw should be used */
    if ((*password == '\0') && isroot && (nslcd_cfg->rootpwmodpw != NULL))
    {
      if (strlen(nslcd_cfg->rootpwmodpw) >= sizeof(password))
      {
        log_log(LOG_ERR, "nslcd_pam_pwmod(): rootpwmodpw will not fit in password");
        return -1;
      }
      strcpy(password, nslcd_cfg->rootpwmodpw);
    }
  }
  else
    binddn = myldap_get_dn(entry);
  WRITE_INT32(fp, NSLCD_RESULT_BEGIN);
  /* home directory change requires either root or valid directory */
  if ((homedir != NULL) && (!isroot) && !is_valid_homedir(homedir))
  {
    log_log(LOG_NOTICE, "invalid directory: %s", homedir);
    WRITE_INT32(fp, NSLCD_USERMOD_HOMEDIR);
    WRITE_STRING(fp, "invalid directory");
    homedir = NULL;
  }
  /* shell change requires either root or a valid shell */
  if ((shell != NULL) && (!isroot) && !is_valid_shell(shell))
  {
    log_log(LOG_NOTICE, "invalid shell: %s", shell);
    WRITE_INT32(fp, NSLCD_USERMOD_SHELL);
    WRITE_STRING(fp, "invalid shell");
    shell = NULL;
  }
  /* perform requested changes */
  newsession = get_session(binddn, password, &rc);
  if (newsession != NULL)
  {
    rc = change(newsession, myldap_get_dn(entry), homedir, shell);
    myldap_session_close(newsession);
  }
  /* return response to caller */
  if (rc != LDAP_SUCCESS)
  {
    log_log(LOG_WARNING, "%s: modification failed: %s",
            myldap_get_dn(entry), ldap_err2string(rc));
    mysnprintf(errmsg, sizeof(errmsg) - 1, "change failed: %s", ldap_err2string(rc));
    WRITE_INT32(fp, NSLCD_USERMOD_RESULT);
    WRITE_STRING(fp, errmsg);
    WRITE_INT32(fp, NSLCD_USERMOD_END);
    WRITE_INT32(fp, NSLCD_RESULT_END);
    return 0;
  }
  log_log(LOG_NOTICE, "changed information for %s", myldap_get_dn(entry));
  WRITE_INT32(fp, NSLCD_USERMOD_END);
  WRITE_INT32(fp, NSLCD_RESULT_END);
  return 0;
}
