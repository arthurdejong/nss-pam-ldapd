/*
   util.c - LDAP utility functions
   This file was part of the nss_ldap library which has been
   forked into the nss-ldapd library.

   Copyright (C) 1997-2005 Luke Howard
   Copyright (C) 2006, 2007 West Consulting
   Copyright (C) 2006, 2007 Arthur de Jong

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
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <stdlib.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <netdb.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif
#if defined(HAVE_THREAD_H)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include "ldap-nss.h"
#include "util.h"
#include "common.h"
#include "log.h"
#include "cfg.h"
#include "attmap.h"


static void *__cache = NULL;

NSS_LDAP_DEFINE_LOCK (__cache_lock);

#define cache_lock()     NSS_LDAP_LOCK(__cache_lock)
#define cache_unlock()   NSS_LDAP_UNLOCK(__cache_lock)

struct ldap_datum
{
  void *data;
  size_t size;
};

#define NSS_LDAP_DATUM_ZERO(d)  do { \
                (d)->data = NULL; \
                (d)->size = 0; \
        } while (0)

#define NSS_LDAP_DB_NORMALIZE_CASE      0x1

struct ldap_dictionary
{
  struct ldap_datum key;
  struct ldap_datum value;
  struct ldap_dictionary *next;
};

static struct ldap_dictionary *old_dict_new(void)
{
  struct ldap_dictionary *dict;
  dict = malloc(sizeof(struct ldap_dictionary));
  if (dict==NULL)
  {
    return NULL;
  }
  NSS_LDAP_DATUM_ZERO(&dict->key);
  NSS_LDAP_DATUM_ZERO(&dict->value);
  dict->next=NULL;
  return dict;
}

static struct ldap_dictionary *
do_find_last (struct ldap_dictionary *dict)
{
  struct ldap_dictionary *p;

  for (p = dict; p->next != NULL; p = p->next)
    ;

  return p;
}

static enum nss_status
do_dup_datum (struct ldap_datum * dst, const struct ldap_datum * src)
{
  dst->data = malloc (src->size);
  if (dst->data == NULL)
    return NSS_STATUS_TRYAGAIN;

  memcpy (dst->data, src->data, src->size);
  dst->size = src->size;

  return NSS_STATUS_SUCCESS;
}

static void
do_free_datum (struct ldap_datum * datum)
{
  if (datum->data != NULL)
    {
      free (datum->data);
      datum->data = NULL;
    }
  datum->size = 0;
}

static void
do_free_dictionary (struct ldap_dictionary *dict)
{
  do_free_datum (&dict->key);
  do_free_datum (&dict->value);
  free (dict);
}

static enum nss_status old_dict_put(
                struct ldap_dictionary *db,
                const struct ldap_datum *key,
                const struct ldap_datum *value)
{
  struct ldap_dictionary *dict = (struct ldap_dictionary *) db;
  struct ldap_dictionary *p, *q;

  assert(key!=NULL);
  assert(key->data!=NULL);

  if (dict->key.data==NULL)
  {
    /* uninitialized */
    q=dict;
    p=NULL;
  }
  else
  {
    p=do_find_last(dict);
    assert(p!=NULL);
    assert(p->next==NULL);
    q=old_dict_new();
    if (q==NULL)
      return NSS_STATUS_TRYAGAIN;
  }

  if (do_dup_datum(&q->key,key)!=NSS_STATUS_SUCCESS)
  {
    do_free_dictionary(q);
    return NSS_STATUS_TRYAGAIN;
  }

  if (do_dup_datum(&q->value,value)!=NSS_STATUS_SUCCESS)
  {
    do_free_dictionary(q);
    return NSS_STATUS_TRYAGAIN;
  }

  if (p!=NULL)
    p->next=q;

  return NSS_STATUS_SUCCESS;
}

static enum nss_status old_dict_get(
                struct ldap_dictionary *db,
                unsigned flags,
                const struct ldap_datum *key,
                struct ldap_datum *value)
{
  struct ldap_dictionary *p;
  for (p=db;p!=NULL;p=p->next)
  {
    int cmp;
    if (p->key.size != key->size)
      continue;
    if (flags & NSS_LDAP_DB_NORMALIZE_CASE)
      cmp=strncasecmp((char *)p->key.data,(char *)key->data,key->size);
    else
      cmp=memcmp(p->key.data,key->data,key->size);
    if (cmp==0)
    {
      value->data=p->value.data;
      value->size=p->value.size;
      return NSS_STATUS_SUCCESS;
    }
  }
  return NSS_STATUS_NOTFOUND;
}

static enum nss_status
dn2uid_cache_put (const char *dn, const char *uid)
{
  enum nss_status status;
  struct ldap_datum key, val;

  cache_lock ();

  if (__cache == NULL)
    {
      __cache = (void *)old_dict_new();
      if (__cache == NULL)
        {
          cache_unlock ();
          return NSS_STATUS_TRYAGAIN;
        }
    }

  key.data = (const void *) dn;
  key.size = strlen (dn);
  val.data = (const void *) uid;
  val.size = strlen (uid);

  status = old_dict_put (__cache, &key, &val);

  cache_unlock ();

  return status;
}

static enum nss_status
dn2uid_cache_get (const char *dn, char **uid, char **buffer, size_t * buflen)
{
  struct ldap_datum key, val;
  enum nss_status status;

  cache_lock ();

  if (__cache == NULL)
    {
      cache_unlock ();
      return NSS_STATUS_NOTFOUND;
    }

  key.data = (const void *) dn;
  key.size = strlen (dn);

  status = old_dict_get (__cache, 0, &key, &val);
  if (status != NSS_STATUS_SUCCESS)
    {
      cache_unlock ();
      return status;
    }

  if (*buflen <= val.size)
    {
      cache_unlock ();
      return NSS_STATUS_TRYAGAIN;
    }

  *uid = *buffer;
  memcpy (*uid, (const char *) val.data, val.size);
  (*uid)[val.size] = '\0';
  *buffer += val.size + 1;
  *buflen -= val.size + 1;

  cache_unlock ();
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ldap_dn2uid(const char *dn,char **uid,char **buffer,
                                 size_t * buflen,int *pIsNestedGroup,
                                 LDAPMessage **pRes)
{
  enum nss_status status;

  log_log(LOG_DEBUG,"==> _nss_ldap_dn2uid");

  *pIsNestedGroup = 0;

  status = dn2uid_cache_get (dn, uid, buffer, buflen);
  if (status == NSS_STATUS_NOTFOUND)
    {
      const char *attrs[4];
      LDAPMessage *res;

      attrs[0] = attmap_passwd_uid;
      attrs[1] = attmap_group_uniqueMember;
      attrs[2] = attmap_objectClass;
      attrs[3] = NULL;

      if (_nss_ldap_read (dn, attrs, &res) == NSS_STATUS_SUCCESS)
        {
          LDAPMessage *e = _nss_ldap_first_entry (res);
          if (e != NULL)
            {
              if (has_objectclass(e,attmap_group_objectClass))
                {
                  *pIsNestedGroup = 1;
                  *pRes = res;
                  log_log(LOG_DEBUG,"<== _nss_ldap_dn2uid (nested group)");
                  return NSS_STATUS_SUCCESS;
                }

              status =
                _nss_ldap_assign_attrval (e, attmap_passwd_uid, uid,
                                          buffer, buflen);
              if (status == NSS_STATUS_SUCCESS)
                dn2uid_cache_put (dn, *uid);
            }
        }
      ldap_msgfree (res);
    }

  log_log(LOG_DEBUG,"<== _nss_ldap_dn2uid");

  return status;
}

static enum nss_status
do_getrdnvalue (const char *dn,
                const char *rdntype,
                char **rval, char **buffer, size_t * buflen)
{
  char **exploded_dn;
  char *rdnvalue = NULL;
  char rdnava[64];
  int rdnlen = 0, rdnavalen;

  snprintf (rdnava, sizeof rdnava, "%s=", rdntype);
  rdnavalen = strlen (rdnava);

  exploded_dn = ldap_explode_dn (dn, 0);

  if (exploded_dn != NULL)
    {
      /*
       * attempt to get the naming attribute's principal
       * value by parsing the RDN. We need to support
       * multivalued RDNs (as they're essentially mandated
       * for services)
       */
#ifdef HAVE_LDAP_EXPLODE_RDN
      /*
       * use ldap_explode_rdn() API, as it's cleaner than
       * strtok(). This code has not been tested!
       */
      char **p, **exploded_rdn;

      exploded_rdn = ldap_explode_rdn (*exploded_dn, 0);
      if (exploded_rdn != NULL)
        {
          for (p = exploded_rdn; *p != NULL; p++)
            {
              if (strncasecmp (*p, rdnava, rdnavalen) == 0)
                {
                  char *r = *p + rdnavalen;

                  rdnlen = strlen (r);
                  if (*buflen <= rdnlen)
                    {
                      ldap_value_free (exploded_rdn);
                      ldap_value_free (exploded_dn);
                      return NSS_STATUS_TRYAGAIN;
                    }
                  rdnvalue = *buffer;
                  strncpy (rdnvalue, r, rdnlen);
                  break;
                }
            }
          ldap_value_free (exploded_rdn);
        }
#else /* HAVE_LDAP_EXPLODE_RDN */
      /*
       * we don't have Netscape's ldap_explode_rdn() API,
       * so we fudge it with strtok(). Note that this will
       * not handle escaping properly.
       */
      char *p, *r = *exploded_dn;
#ifdef HAVE_STRTOK_R
      char *st = NULL;
#endif /* HAVE_STRTOK_R */

#ifndef HAVE_STRTOK_R
      for (p = strtok (r, "+");
#else /* HAVE_STRTOK_R */
      for (p = strtok_r (r, "+", &st);
#endif /* not HAVE_STRTOK_R */
           p != NULL;
#ifndef HAVE_STRTOK_R
           p = strtok (NULL, "+"))
#else /* HAVE_STRTOK_R */
           p = strtok_r (NULL, "+", &st))
#endif /* not HAVE_STRTOK_R */
      {
        if (strncasecmp (p, rdnava, rdnavalen) == 0)
          {
            p += rdnavalen;
            rdnlen = strlen (p);
            if (*buflen <= rdnlen)
              {
                ldap_value_free (exploded_dn);
                return NSS_STATUS_TRYAGAIN;
              }
            rdnvalue = *buffer;
            strncpy (rdnvalue, p, rdnlen);
            break;
          }
        if (r != NULL)
          r = NULL;
      }
#endif /* not HAVE_LDAP_EXPLODE_RDN */
    }

  if (exploded_dn != NULL)
    {
      ldap_value_free (exploded_dn);
    }

  if (rdnvalue != NULL)
    {
      rdnvalue[rdnlen] = '\0';
      *buffer += rdnlen + 1;
      *buflen -= rdnlen + 1;
      *rval = rdnvalue;
      return NSS_STATUS_SUCCESS;
    }

  return NSS_STATUS_NOTFOUND;
}

enum nss_status
_nss_ldap_getrdnvalue (LDAPMessage * entry,
                       const char *rdntype,
                       char **rval, char **buffer, size_t * buflen)
{
  char *dn;
  enum nss_status status;

  dn = _nss_ldap_get_dn (entry);
  if (dn == NULL)
    {
      return NSS_STATUS_NOTFOUND;
    }

  status = do_getrdnvalue (dn, rdntype, rval, buffer, buflen);
#ifdef HAVE_LDAP_MEMFREE
  ldap_memfree (dn);
#else /* HAVE_LDAP_MEMFREE */
  free (dn);
#endif /* not HAVE_LDAP_MEMFREE */

  /*
   * If examining the DN failed, then pick the nominal first
   * value of cn as the canonical name (recall that attributes
   * are sets, not sequences)
   */
  if (status == NSS_STATUS_NOTFOUND)
    {
      char **vals;

      vals = _nss_ldap_get_values (entry, rdntype);

      if (vals != NULL)
        {
          int rdnlen = strlen (*vals);
          if (*buflen > rdnlen)
            {
              char *rdnvalue = *buffer;
              strncpy (rdnvalue, *vals, rdnlen);
              rdnvalue[rdnlen] = '\0';
              *buffer += rdnlen + 1;
              *buflen -= rdnlen + 1;
              *rval = rdnvalue;
              status = NSS_STATUS_SUCCESS;
            }
          else
            {
              status = NSS_STATUS_TRYAGAIN;
            }
          ldap_value_free (vals);
        }
    }

  return status;
}

int _nss_ldap_write_rndvalue(TFILE *fp,LDAPMessage *entry,const char *rdntype)
{
  char *dn;
  int status=456;
  char **vals;
  int32_t tmpint32;
  char **exploded_dn;
  char **exploded_rdn;
  char rdnava[64];
  int rdnavalen;
  int i;
  /* log call */
  log_log(LOG_DEBUG,"_nss_ldap_write_rndvalue(%s)",rdntype);
  /* get the dn from the entry */
  dn=_nss_ldap_get_dn(entry);
  if (dn==NULL)
    return NSLCD_RESULT_NOTFOUND;
  /* append a `=' to the rdntype */
  snprintf(rdnava,sizeof(rdnava),"%s=",rdntype);
  rdnavalen=strlen(rdnava);
  /* explode dn */
  exploded_dn=ldap_explode_dn(dn,0);
  if (exploded_dn!=NULL)
  {
    /*
     * attempt to get the naming attribute's principal
     * value by parsing the RDN. We need to support
     * multivalued RDNs (as they're essentially mandated
     * for services)
     */
    exploded_rdn=ldap_explode_rdn(exploded_dn[0],0);
    if (exploded_rdn!=NULL)
    {
      for (i=0;exploded_rdn[i]!=NULL;i++)
      {
        /* if the values begins with rndava */
        if (strncasecmp(exploded_rdn[i],rdnava,rdnavalen)==0)
        {
          /* FIXME: handle case where WRITE fails */
          WRITE_STRING(fp,exploded_rdn[i]+rdnavalen);
          status=0;
          break;
        }
      }
      ldap_value_free(exploded_rdn);
    }
    ldap_value_free(exploded_dn);
  }
  ldap_memfree(dn);
  /*
   * If examining the DN failed, then pick the nominal first
   * value of cn as the canonical name (recall that attributes
   * are sets, not sequences)
   */
  if (status==456)
  {
    vals=_nss_ldap_get_values(entry,rdntype);
    if (vals!=NULL)
    {
      /* write the first entry */
      WRITE_STRING(fp,vals[0]);
      status=NSS_STATUS_SUCCESS;
      ldap_value_free(vals);
      status=0;
    }
  }
  return status;
}

int _nss_ldap_escape_string(const char *src,char *buffer,size_t buflen)
{
  int pos=0;
  /* go over all characters in source string */
  for (;*src!='\0';src++)
  {
    /* check if char will fit */
    if (pos>=(buflen+4))
      return -1;
    /* do escaping for some characters */
    switch (*src)
    {
      case '*':
        strcpy(buffer+pos,"\\2a");
        pos+=3;
        break;
      case '(':
        strcpy(buffer+pos,"\\28");
        pos+=3;
        break;
      case ')':
        strcpy(buffer+pos,"\\29");
        pos+=3;
        break;
      case '\\':
        strcpy(buffer+pos,"\\5c");
        pos+=3;
        break;
      default:
        /* just copy character */
        buffer[pos++]=*src;
        break;
    }
  }
  /* terminate destination string */
  buffer[pos]='\0';
  return 0;
}
