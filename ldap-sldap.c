/* Copyright (C) 2006 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@padl.com>, 2006.

   The nss_ldap library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The nss_ldap library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the nss_ldap library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   $Id$
 */


static char rcsId[] =
  "$Id$";

#include "config.h"

#ifdef HAVE_PORT_BEFORE_H
#include <port_before.h>
#endif

#if defined(HAVE_THREAD_H) && !defined(_AIX)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <assert.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>
#endif
#include <net/if.h>
#include <netinet/in.h>

#include "ldap-nss.h"
#include "ldap-automount.h"
#include "ldap-sldap.h"
#include "util.h"

#ifdef HAVE_PORT_AFTER_H
#include <port_after.h>
#endif

#ifdef HAVE_NSSWITCH_H

/*
 * This implements enough of the Solaris libsldap interface in order
 * for the automounter to work.
 */

static ns_ldap_return_code __ns_ldap_initResult (ns_ldap_result_t ** pResult);
static ns_ldap_return_code __ns_ldap_initSearch (ns_ldap_cookie_t * cookie);
static ldap_map_selector_t __ns_ldap_str2selector (const char *map);
static ns_ldap_return_code __ns_ldap_unmapObjectClasses (ns_ldap_cookie_t *
							 cookie,
							 char **mappedClasses,
							 char
							 ***pOrigClasses);

#ifdef DEBUG
static const char *
NS_LDAP_ERR2STR (ns_ldap_return_code err)
{
  char *str = NULL;

  __ns_ldap_err2str (err, &str);

  return str;
}
#endif /* DEBUG */

static void **
__ns_ldap_makeStringParam (const char *string)
{
  void **p;

  p = (void **) malloc (2 * sizeof (void *));
  if (p == NULL)
    {
      return NULL;
    }
  p[0] = strdup (string);
  if (p[0] == NULL)
    {
      free (p);
      return NULL;
    }
  p[1] = NULL;

  return p;
}

char **
__ns_ldap_getMappedAttributes (const char *service, const char *attribute)
{
  const char *mapped;

  mapped = _nss_ldap_map_at (__ns_ldap_str2selector (service), attribute);
  if (mapped == NULL)
    {
      return NULL;
    }

  return (char **) __ns_ldap_makeStringParam (mapped);
}

char **
__ns_ldap_getMappedObjectClass (const char *service, const char *objectClass)
{
  const char *mapped;

  mapped = _nss_ldap_map_oc (__ns_ldap_str2selector (service), objectClass);
  if (mapped == NULL)
    {
      return NULL;
    }

  return (char **) __ns_ldap_makeStringParam (mapped);
}

static ns_ldap_return_code
__ns_ldap_mapError (NSS_STATUS error)
{
  ns_ldap_return_code code;

  switch (error)
    {
    case NSS_SUCCESS:
      code = NS_LDAP_SUCCESS;
      break;
    case NSS_TRYAGAIN:
      code = NS_LDAP_MEMORY;
      break;
    case NSS_NOTFOUND:
      code = NS_LDAP_NOTFOUND;
      break;
    case NSS_UNAVAIL:
    default:
      code = NS_LDAP_OP_FAILED;
      break;
    }

  return code;
}

static ns_ldap_return_code
__ns_ldap_mapErrorDetail (ns_ldap_return_code code, ns_ldap_error_t ** errorp)
{
  char *m = NULL;
  char *s = NULL;

  *errorp = (ns_ldap_error_t *) calloc (1, sizeof (ns_ldap_error_t));
  if (*errorp == NULL)
    {
      return NS_LDAP_MEMORY;
    }

  (*errorp)->status = _nss_ldap_get_ld_errno (&m, &s);
  (*errorp)->message = (m != NULL) ? strdup (m) : NULL;

  return code;
}

ns_ldap_return_code
__ns_ldap_freeError (ns_ldap_error_t ** errorp)
{
  if (errorp == NULL)
    {
      return NS_LDAP_INVALID_PARAM;
    }
  if (*errorp != NULL)
    {
      if ((*errorp)->message != NULL)
	{
	  free ((*errorp)->message);
	  (*errorp)->message = NULL;
	}
      free (*errorp);
      *errorp = NULL;
    }
  return NS_LDAP_SUCCESS;
}

ns_ldap_return_code
__ns_ldap_freeParam (void ***data)
{
  void **p;

  if (*data != NULL)
    {
      for (p = *data; *p != NULL; p++)
	{
	  free (*p);
	  *p = NULL;
	}
      free (*data);
      *data = NULL;
    }

  return NS_LDAP_SUCCESS;
}


ns_ldap_return_code
__ns_ldap_getParam (const ParamIndexType type, void ***data,
		    ns_ldap_error_t ** errorp)
{
  ns_ldap_return_code ret;

  *errorp = NULL;

  debug ("==> __ns_ldap_getParam (param=%d)", type);

  switch (type)
    {
    case NS_LDAP_FILE_VERSION_P:
      *data = __ns_ldap_makeStringParam (NS_LDAP_VERSION);
      ret = NS_LDAP_SUCCESS;
      break;
    default:
      ret = NS_LDAP_INVALID_PARAM;
      break;
    }

  debug ("<== __ns_ldap_getParam (ret=%s)", NS_LDAP_ERR2STR (ret));

  return ret;
}

ns_ldap_return_code
__ns_ldap_freeAttr (ns_ldap_attr_t ** pAttr)
{
  int i;
  ns_ldap_attr_t *attr = *pAttr;

  if (attr != NULL)
    {
      if (attr->attrname != NULL)
	{
	  free (attr->attrname);
	}
      if (attr->attrvalue != NULL)
	{
	  for (i = 0; i < attr->value_count; i++)
	    {
	      free (attr->attrvalue[i]);
	    }
	  free (attr->attrvalue);
	}
    }

  return NS_LDAP_SUCCESS;
}

ns_ldap_return_code
__ns_ldap_freeEntry (ns_ldap_entry_t ** pentry)
{
  int i;
  ns_ldap_entry_t *entry = *pentry;

  if (entry != NULL)
    {
      if (entry->attr_pair != NULL)
	{
	  for (i = 0; i < entry->attr_count; i++)
	    {
	      __ns_ldap_freeAttr (&entry->attr_pair[i]);
	    }
	  free (entry->attr_pair);
	}
      free (entry);
      *pentry = NULL;
    }

  return NS_LDAP_SUCCESS;
}

ns_ldap_return_code
__ns_ldap_freeResult (ns_ldap_result_t ** pResult)
{
  ns_ldap_result_t *result;
  ns_ldap_entry_t *entry, *next = NULL;

  if (pResult == NULL)
    {
      return NS_LDAP_INVALID_PARAM;
    }

  result = *pResult;
  if (result == NULL)
    {
      return NS_LDAP_SUCCESS;
    }

  entry = result->entry;

  while (entry != NULL)
    {
      next = entry->next;
      __ns_ldap_freeEntry (&entry);
      entry = next;
    }

  free (result);
  *pResult = NULL;

  return NS_LDAP_SUCCESS;
}

ns_ldap_return_code
__ns_ldap_allocAttr (ns_ldap_attr_t ** pAttr)
{
  ns_ldap_attr_t *attr;

  *pAttr = NULL;

  attr = (ns_ldap_attr_t *) malloc (sizeof (*attr));
  if (attr == NULL)
    {
      return NS_LDAP_MEMORY;
    }

  attr->attrname = NULL;
  attr->attrvalue = NULL;
  attr->value_count = 0;

  *pAttr = attr;

  return NS_LDAP_SUCCESS;
}

ns_ldap_return_code
__ns_ldap_parseAttr (ns_ldap_cookie_t * cookie,
		     LDAPMessage * entry,
		     const char *attribute, ns_ldap_attr_t ** pAttr)
{
  ns_ldap_attr_t *attr;
  const char *unmappedAttribute;
  ns_ldap_return_code ret;
  char **values;
  int freeValues = 1;

  ret = __ns_ldap_allocAttr (&attr);
  if (ret != NS_LDAP_SUCCESS)
    {
      return ret;
    }

  if ((cookie->flags & NS_LDAP_NOMAP) == 0)
    {
      unmappedAttribute = _nss_ldap_unmap_at (cookie->sel, attribute);
      if (unmappedAttribute == NULL)
	{
	  __ns_ldap_freeAttr (&attr);
	  return NS_LDAP_INVALID_PARAM;
	}
    }
  else
    {
      unmappedAttribute = attribute;
    }

  attr->attrname = strdup (unmappedAttribute);
  if (attr->attrname == NULL)
    {
      __ns_ldap_freeAttr (&attr);
      return NS_LDAP_MEMORY;
    }
  attr->attrvalue = NULL;

  values = _nss_ldap_get_values (entry, attribute);

  if ((cookie->flags & NS_LDAP_NOMAP) == 0)
    {
      if (strcasecmp (attribute, "objectClass") == 0)
	{
	  /* Map object class values */
	  ret =
	    __ns_ldap_unmapObjectClasses (cookie, values, &attr->attrvalue);
	  if (ret != NS_LDAP_SUCCESS)
	    {
	      __ns_ldap_freeAttr (&attr);
	      return ret;
	    }
	}
    }

  if (attr->attrvalue == NULL)
    {
      attr->attrvalue = values;
      freeValues = 0;
    }

  attr->value_count =
    (attr->attrvalue != NULL) ? ldap_count_values (attr->attrvalue) : 0;

  if (freeValues)
    {
      ldap_value_free (values);
    }

  *pAttr = attr;

  return NS_LDAP_SUCCESS;
}

ns_ldap_return_code
__ns_ldap_parseDn (ns_ldap_cookie_t * cookie, LDAPMessage * entry,
		   ns_ldap_attr_t ** pAttr)
{
  ns_ldap_attr_t *attr;
  ns_ldap_return_code ret;

  ret = __ns_ldap_allocAttr (&attr);
  if (ret != NS_LDAP_SUCCESS)
    {
      return ret;
    }

  attr->attrname = strdup ("dn");
  if (attr->attrname == NULL)
    {
      __ns_ldap_freeAttr (&attr);
      return NS_LDAP_MEMORY;
    }

  attr->value_count = 1;

  attr->attrvalue = (char **) malloc (1 * sizeof (char *));
  if (attr->attrvalue == NULL)
    {
      __ns_ldap_freeAttr (&attr);
      return NS_LDAP_MEMORY;
    }

  attr->attrvalue[0] = _nss_ldap_get_dn (entry);
  if (attr->attrvalue[0] == NULL)
    {
      __ns_ldap_freeAttr (&attr);
      return NS_LDAP_MEMORY;
    }

  *pAttr = attr;

  return NS_LDAP_SUCCESS;
}

NSS_STATUS
__ns_ldap_parseEntry (LDAPMessage * msg, ldap_state_t * state,
		      void *result, char *buffer, size_t buflen)
{
  ns_ldap_cookie_t *cookie = (ns_ldap_cookie_t *) result;
  char *attribute;
  BerElement *ber = NULL;
  ns_ldap_return_code ret = NS_LDAP_SUCCESS;
  ns_ldap_entry_t *entry;
  int attr_count;

#ifdef DEBUG
  {
    char *dn = _nss_ldap_get_dn (msg);
    debug ("==> __ns_ldap_parseEntry (%s)", dn);
    ldap_memfree (dn);
  }
#endif

  entry = (ns_ldap_entry_t *) malloc (sizeof (*entry));
  if (entry == NULL)
    {
      cookie->ret = NS_LDAP_MEMORY;
      debug ("<== __ns_ldap_parseEntry (no memory)");
      return NSS_NOTFOUND;
    }

  entry->attr_count = 0;
  entry->attr_pair = NULL;
  entry->next = NULL;

  attr_count = 1;		/* for DN */

  for (attribute = _nss_ldap_first_attribute (msg, &ber);
       attribute != NULL; attribute = _nss_ldap_next_attribute (msg, ber))
    {
      attr_count++;
#ifdef HAVE_LDAP_MEMFREE
      ldap_memfree (attribute);
#endif
    }

  if (ber != NULL)
    ber_free (ber, 0);

  entry->attr_pair =
    (ns_ldap_attr_t **) calloc (attr_count, sizeof (ns_ldap_attr_t *));
  if (entry->attr_pair == NULL)
    {
      __ns_ldap_freeEntry (&entry);
      cookie->ret = NS_LDAP_MEMORY;
      debug ("<== __ns_ldap_parseEntry (no memory)");
      return NSS_NOTFOUND;
    }

  ret = __ns_ldap_parseDn (cookie, msg, &entry->attr_pair[entry->attr_count]);
  if (ret != NS_LDAP_SUCCESS)
    {
      __ns_ldap_freeEntry (&entry);
      cookie->ret = ret;
      debug ("<== __ns_ldap_parseEntry (failed to parse DN)");
      return ret;
    }

  entry->attr_count++;

  for (attribute = _nss_ldap_first_attribute (msg, &ber);
       attribute != NULL; attribute = _nss_ldap_next_attribute (msg, ber))
    {
      ns_ldap_attr_t *attr;

      ret = __ns_ldap_parseAttr (cookie, msg, attribute, &attr);
#ifdef HAVE_LDAP_MEMFREE
      ldap_memfree (attribute);
#endif
      if (ret != NS_LDAP_SUCCESS)
	{
	  continue;
	}
      entry->attr_pair[entry->attr_count++] = attr;
    }

  if (ber != NULL)
    ber_free (ber, 0);

  if (ret == NS_LDAP_SUCCESS)
    {
      ns_ldap_entry_t *last;

      if (cookie->result == NULL)
	{
	  ret = __ns_ldap_initResult (&cookie->result);
	  if (ret != NS_LDAP_SUCCESS)
	    {
	      __ns_ldap_freeEntry (&entry);
	      cookie->ret = ret;
	      debug ("<== __ns_ldap_parseEntry (failed to init result: %s)",
		     NS_LDAP_ERR2STR (ret));
	      return __ns_ldap_mapError (ret);
	    }
	  cookie->result->entry = entry;
	}
      else
	{
	  assert (cookie->entry != NULL);

	  for (last = cookie->entry; last->next != NULL; last = last->next)
	    ;
	  last->next = entry;
	}

      cookie->entry = entry;

      if (cookie->callback != NULL)
	{
	  cookie->cb_ret = (*cookie->callback) (entry, cookie->userdata);
	}

      cookie->result->entries_count++;
    }
  else
    {
      __ns_ldap_freeEntry (&entry);
    }

  cookie->ret = ret;

  debug ("<== __ns_ldap_parseEntry (ret=%s)", NS_LDAP_ERR2STR (ret));

  return __ns_ldap_mapError (ret);
}

static ns_ldap_return_code
__ns_ldap_initResult (ns_ldap_result_t ** pResult)
{
  ns_ldap_result_t *result;

  result = (ns_ldap_result_t *) malloc (sizeof (ns_ldap_result_t));
  if (result == NULL)
    {
      return NS_LDAP_MEMORY;
    }

  result->entries_count = 0;
  result->entry = NULL;

  *pResult = result;

  return NS_LDAP_SUCCESS;
}

static ldap_map_selector_t
__ns_ldap_str2selector (const char *map)
{
  ldap_map_selector_t sel;

  if (map == NULL)
    {
      sel = LM_NONE;
    }
  else
    {
      sel = _nss_ldap_str2selector (map);

      if (strcmp (map, "automount") == 0)
	{
	  sel = LM_NONE;	/* for enumeration only */
	}
      else if (sel == LM_NONE && (strncmp (map, "auto_", 5)) == 0)
	{
	  sel = LM_AUTOMOUNT;
	}
      else
	{
	  sel = _nss_ldap_str2selector (map);
	}
    }

  return sel;
}

static ns_ldap_return_code
__ns_ldap_unmapObjectClasses (ns_ldap_cookie_t * cookie, char **mappedClasses,
			      char ***pOrigClasses)
{
  char **origClasses = NULL;
  int count, i;

  count = ldap_count_values (mappedClasses);
  origClasses = (char **) calloc (count + 1, sizeof (char *));
  if (origClasses == NULL)
    {
      return NS_LDAP_MEMORY;
    }

  for (i = 0; i < count; i++)
    {
      origClasses[i] =
	strdup (_nss_ldap_unmap_oc (cookie->sel, mappedClasses[i]));
      if (origClasses[i] == NULL)
	{
	  ldap_value_free (origClasses);
	  return NS_LDAP_MEMORY;
	}
    }
  origClasses[i] = NULL;
  *pOrigClasses = origClasses;

  return NS_LDAP_SUCCESS;
}

static ns_ldap_return_code
__ns_ldap_mapAttributes (ns_ldap_cookie_t * cookie, const char ***pAttributes)
{
  const char **attributes;
  int i;

  *pAttributes = NULL;

  if (cookie->attribute == NULL)
    {
      return NS_LDAP_SUCCESS;
    }

  for (i = 0; cookie->attribute[i] != NULL; i++)
    ;

  attributes = (const char **) calloc (i + 1, sizeof (char **));
  if (attributes == NULL)
    {
      return NS_LDAP_MEMORY;
    }

  for (i = 0; cookie->attribute[i] != NULL; i++)
    {
      attributes[i] = _nss_ldap_map_at (cookie->sel, cookie->attribute[i]);
      assert (attributes[i] != NULL);
    }
  attributes[i] = NULL;
  *pAttributes = attributes;

  return NS_LDAP_SUCCESS;
}

static ns_ldap_return_code
__ns_ldap_emitFilterString (char **pFilter, size_t * len, size_t * size,
			    const char *s)
{
  size_t slen = strlen (s);
  char *filter;

  if (*len + slen >= *size)
    {
      /* need some more space */
      size_t newSize = *size;
      char *newFilter;

      if (newSize == 0)
	newSize = NSS_BUFSIZ;
      else
	newSize *= 2;

      newFilter = realloc (*pFilter, newSize);
      if (newFilter == NULL)
	{
	  return NS_LDAP_MEMORY;
	}
      *pFilter = newFilter;
      *size = newSize;
    }

  filter = *pFilter;

  memcpy (&filter[*len], s, slen);
  filter[*len + slen] = '\0';

  *len += slen;

  return NS_LDAP_SUCCESS;
}


#define EMIT_STRING(_s)	do { \
		ns_ldap_return_code ret = __ns_ldap_emitFilterString(&filter, &len, &size, (_s)); \
		if (ret != NS_LDAP_SUCCESS) { \
			if (filter != NULL) free(filter); \
			return ret; \
		} \
	} while (0)

#define EMIT_CHAR(_c)	do { \
		char _s[2]; \
		ns_ldap_return_code ret; \
		_s[0] = _c; \
		_s[1] = '\0'; \
		ret = __ns_ldap_emitFilterString(&filter, &len, &size, (_s)); \
		if (ret != NS_LDAP_SUCCESS) { \
			if (filter != NULL) free(filter); \
			return ret; \
		} \
	} while (0)


static ns_ldap_return_code
__ns_ldap_mapFilter (ns_ldap_cookie_t * cookie, char **pFilter)
{
  enum
  { EXPECT_LHS, FOUND_LHS, EXPECT_RHS, FOUND_RHS } state;
  char *lhs = NULL;
  char *rhs = NULL;
  size_t len = 0, size = 0;
  char tmp;
  size_t i;
  char *filter = NULL;
  size_t filterLen = strlen (cookie->filter);

  state = EXPECT_LHS;

  for (i = 0; i <= filterLen; i++)
    {
      switch (state)
	{
	case EXPECT_LHS:
	  switch (cookie->filter[i])
	    {
	    case '(':
	    case ')':
	    case '&':
	    case '|':
	    case '!':
	      EMIT_CHAR (cookie->filter[i]);
	      break;
	    default:
	      state = FOUND_LHS;
	      lhs = &cookie->filter[i];
	      break;
	    }
	  break;
	case FOUND_LHS:
	  switch (cookie->filter[i])
	    {
	    case '<':
	    case '=':
	    case '>':
	    case '~':
	      state = EXPECT_RHS;
	      tmp = cookie->filter[i];
	      cookie->filter[i] = '\0';
	      /* map LHS (attribute type) */
	      EMIT_STRING (_nss_ldap_map_at (cookie->sel, lhs));
	      EMIT_CHAR (tmp);
	      break;
	    default:
	      break;
	    }
	  break;
	case EXPECT_RHS:
	  switch (cookie->filter[i])
	    {
	    case '<':
	    case '=':
	    case '>':
	    case '~':
	      EMIT_CHAR (cookie->filter[i]);
	      break;
	    default:
	      state = FOUND_RHS;
	      rhs = &cookie->filter[i];
	      break;
	    }
	  break;
	case FOUND_RHS:
	  switch (cookie->filter[i])
	    {
	    case '&':
	    case '|':
	    case '!':
	    case ')':
	    case '\0':
	      state = EXPECT_LHS;
	      tmp = cookie->filter[i];;
	      cookie->filter[i] = '\0';
	      if (strcasecmp (lhs, "objectClass") == 0)
		EMIT_STRING (_nss_ldap_map_oc (cookie->sel, rhs));
	      else
		EMIT_STRING (rhs);
	      if (strcasecmp (rhs, "automount") == 0)
		cookie->sel = LM_AUTOMOUNT;
	      EMIT_CHAR (tmp);
	      break;
	    default:
	      break;
	    }
	  break;
	}
    }

  *pFilter = filter;

  return NS_LDAP_SUCCESS;
}

static ns_ldap_return_code
__ns_ldap_freeCookie (ns_ldap_cookie_t ** pCookie)
{
  ns_ldap_cookie_t *cookie;

  cookie = *pCookie;

  if (cookie != NULL)
    {
      if (cookie->map != NULL)
	free (cookie->map);
      if (cookie->filter != NULL)
	free (cookie->filter);
      if (cookie->attribute != NULL)
	ldap_value_free (cookie->attribute);
      if (cookie->state != NULL)
	{
	  _nss_ldap_ent_context_release (cookie->state);
	  free (cookie->state);
	}
      if (cookie->mapped_filter != NULL)
	free (cookie->mapped_filter);
      if (cookie->mapped_attribute != NULL)
	free (cookie->mapped_attribute);
      _nss_ldap_am_context_free (&cookie->am_state);
      __ns_ldap_freeResult (&cookie->result);
      free (cookie);
    }

  *pCookie = NULL;

  return NS_LDAP_SUCCESS;
}

static ns_ldap_return_code
__ns_ldap_initCookie (const char *map,
		      const char *filter,
		      int (*init_filter_cb) (const ns_ldap_search_desc_t *
					     desc, char **realfilter,
					     const void *userdata),
		      const char *const *attribute, const ns_cred_t * cred,
		      const int flags, ns_ldap_cookie_t ** pCookie,
		      int (*callback) (const ns_ldap_entry_t * entry,
				       const void *userdata),
		      const void *userdata)
{
  ns_ldap_cookie_t *cookie;
  ns_ldap_return_code ret;
  size_t i;

  assert (pCookie != NULL && *pCookie == NULL);

  ret = __ns_ldap_mapError (_nss_ldap_init ());
  if (ret != NS_LDAP_SUCCESS)
    {
      return ret;
    }

  cookie = (ns_ldap_cookie_t *) calloc (1, sizeof (*cookie));
  if (cookie == NULL)
    {
      return NS_LDAP_MEMORY;
    }

  if (filter == NULL)
    {
      __ns_ldap_freeCookie (&cookie);
      return NS_LDAP_INVALID_PARAM;
    }

  if (map != NULL)
    {
      cookie->map = strdup (map);
      if (cookie->map == NULL)
	{
	  __ns_ldap_freeCookie (&cookie);
	  return NS_LDAP_MEMORY;
	}
    }

  cookie->filter = strdup (filter);
  if (cookie->filter == NULL)
    {
      __ns_ldap_freeCookie (&cookie);
      return NS_LDAP_MEMORY;
    }

  if (attribute != NULL)
    {
      for (i = 0; attribute[i] != NULL; i++)
	;

      cookie->attribute = (char **) calloc (i + 1, sizeof (char *));
      if (cookie->attribute == NULL)
	{
	  __ns_ldap_freeCookie (&cookie);
	  return NS_LDAP_MEMORY;
	}

      for (i = 0; attribute[i] != NULL; i++)
	{
	  cookie->attribute[i] = strdup (attribute[i]);
	  if (cookie->attribute[i] == NULL)
	    {
	      __ns_ldap_freeCookie (&cookie);
	      return NS_LDAP_MEMORY;
	    }
	}
      cookie->attribute[i] = NULL;
    }

  cookie->flags = flags;
  cookie->init_filter_cb = init_filter_cb;
  cookie->callback = callback;
  cookie->userdata = userdata;
  cookie->ret = -1;
  cookie->cb_ret = NS_LDAP_CB_NEXT;
  cookie->erange = 0;
  cookie->sel = __ns_ldap_str2selector (map);

  if (_nss_ldap_ent_context_init_locked (&cookie->state) == NULL)
    {
      __ns_ldap_freeCookie (&cookie);
      return NS_LDAP_INTERNAL;
    }

  cookie->result = NULL;
  cookie->entry = NULL;

  ret = __ns_ldap_initSearch (cookie);
  if (ret != NS_LDAP_SUCCESS)
    {
      __ns_ldap_freeCookie (&cookie);
      return ret;
    }

  *pCookie = cookie;

  return NS_LDAP_SUCCESS;
}

static ns_ldap_return_code
__ns_ldap_initSearch (ns_ldap_cookie_t * cookie)
{
  ns_ldap_return_code ret;
  NSS_STATUS stat;

  assert (cookie != NULL);
  assert (cookie->state != NULL);

  ret = __ns_ldap_mapAttributes (cookie, &cookie->mapped_attribute);
  if (ret != NS_LDAP_SUCCESS)
    {
      return ret;
    }

  ret = __ns_ldap_mapFilter (cookie, &cookie->mapped_filter);
  if (ret != NS_LDAP_SUCCESS)
    {
      return ret;
    }

  /*
   * In the automount case, we need to do a search for a list of
   * search bases
   */
  if (cookie->sel == LM_AUTOMOUNT)
    {
      assert (cookie->am_state == NULL);
      assert (cookie->map != NULL);

      stat = _nss_ldap_am_context_init (cookie->map, &cookie->am_state);
      if (stat != NSS_SUCCESS)
	{
	  return __ns_ldap_mapError (stat);
	}
    }

  return ret;
}

/*
 * Performs a search given an existing cookie
 *
 * If cookie->result != NULL then the entry will be appended to
 * the result list. Use this for implementing __ns_ldap_list().
 *
 * If cookie->result == NULL then a new result list will be
 * allocated. Use this for implementing __ns_ldap_nextEntry().
 *
 * cookie->entry always points to the last entry in cookie->result
 * 
 * Caller should acquire global lock
 */
static ns_ldap_return_code
__ns_ldap_search (ns_ldap_cookie_t * cookie)
{
  ldap_args_t a;
  NSS_STATUS stat;
  ldap_automount_context_t *am = cookie->am_state;

  LA_INIT (a);
  LA_TYPE (a) = LA_TYPE_NONE;

  if (cookie->sel == LM_AUTOMOUNT)
    {
      assert (am != NULL);
      assert (am->lac_dn_count > 0);

      LA_BASE (a) = am->lac_dn_list[am->lac_dn_index];
    }				/* XXX todo is support maps that are RDNs relative to default search base */

  assert (cookie->mapped_filter != NULL);

retry_search:
  cookie->ret = -1;

  stat = _nss_ldap_getent_ex (&a, &cookie->state, cookie,
			      NULL, 0, &cookie->erange,
			      cookie->mapped_filter,
			      cookie->sel,
			      cookie->mapped_attribute, __ns_ldap_parseEntry);

  if (stat == NSS_NOTFOUND &&
      cookie->sel == LM_AUTOMOUNT && am->lac_dn_index < am->lac_dn_count - 1)
    {
      am->lac_dn_index++;
      goto retry_search;
    }

  if (cookie->ret < 0)
    {
      cookie->ret = __ns_ldap_mapError (stat);
    }

  return cookie->ret;
}

ns_ldap_return_code
__ns_ldap_firstEntry (const char *service,
		      const char *filter,
		      int (*init_filter_cb) (const ns_ldap_search_desc_t *
					     desc, char **realfilter,
					     const void *userdata),
		      const char *const *attribute, const ns_cred_t * cred,
		      const int flags, void **pCookie,
		      ns_ldap_result_t ** result, ns_ldap_error_t ** errorp,
		      const void *userdata)
{
  ns_ldap_return_code ret;
  ns_ldap_cookie_t *cookie = NULL;

  *pCookie = NULL;
  *result = NULL;
  *errorp = NULL;

  debug ("==> __ns_ldap_firstEntry (map=%s filter=%s)",
	 service != NULL ? service : "(null)", filter);

  _nss_ldap_enter ();

  ret = __ns_ldap_initCookie (service, filter, init_filter_cb,
			      attribute, cred, flags, &cookie, NULL,
			      userdata);
  if (ret == NS_LDAP_SUCCESS)
    {
      ret = __ns_ldap_search (cookie);

      *result = cookie->result;
      cookie->result = NULL;
    }

  __ns_ldap_mapErrorDetail (ret, errorp);

  _nss_ldap_leave ();

  *pCookie = cookie;

  debug ("<== __ns_ldap_firstEntry ret=%s cookie=%p", NS_LDAP_ERR2STR (ret),
	 cookie);

  return ret;
}

ns_ldap_return_code
__ns_ldap_nextEntry (void *_cookie,
		     ns_ldap_result_t ** result, ns_ldap_error_t ** errorp)
{
  ns_ldap_return_code ret;
  ns_ldap_cookie_t *cookie;

  *result = NULL;
  *errorp = NULL;

  cookie = (ns_ldap_cookie_t *) _cookie;
  if (cookie == NULL)
    {
      return NS_LDAP_INVALID_PARAM;
    }

  debug ("==> __ns_ldap_nextEntry cookie=%p", cookie);

  _nss_ldap_enter ();

  ret = __ns_ldap_search (cookie);

  *result = cookie->result;
  cookie->result = NULL;

  __ns_ldap_mapErrorDetail (ret, errorp);

  _nss_ldap_leave ();

  debug ("<== __ns_ldap_nextEntry ret=%s", NS_LDAP_ERR2STR (ret));

  return ret;
}

ns_ldap_return_code
__ns_ldap_endEntry (void **pCookie, ns_ldap_error_t ** errorp)
{
  ns_ldap_cookie_t *cookie;

  _nss_ldap_enter ();

  cookie = (ns_ldap_cookie_t *) * pCookie;

  debug ("==> __ns_ldap_freeEntry cookie=%p", cookie);

  __ns_ldap_mapErrorDetail (cookie->ret, errorp);
  __ns_ldap_freeCookie (&cookie);

  *pCookie = NULL;

  _nss_ldap_leave ();

  debug ("<== __ns_ldap_freeEntry");

  return NS_LDAP_SUCCESS;
}

ns_ldap_return_code
__ns_ldap_list (const char *map,
		const char *filter,
		int (*init_filter_cb) (const ns_ldap_search_desc_t * desc,
				       char **realfilter,
				       const void *userdata),
		const char *const *attribute, const ns_cred_t * cred,
		const int flags, ns_ldap_result_t ** pResult,
		ns_ldap_error_t ** errorp,
		int (*callback) (const ns_ldap_entry_t * entry,
				 const void *userdata), const void *userdata)
{
  ns_ldap_cookie_t *cookie = NULL;
  ns_ldap_result_t *result = NULL;
  ns_ldap_return_code ret;

  debug ("==> __ns_ldap_list map=%s filter=%s",
	 map != NULL ? map : "(null)", filter);

  *pResult = NULL;
  *errorp = NULL;

  _nss_ldap_enter ();

  ret = __ns_ldap_initCookie (map, filter, init_filter_cb,
			      attribute, cred, flags, &cookie, callback,
			      userdata);

  while (ret == NS_LDAP_SUCCESS)
    {
      ret = __ns_ldap_search (cookie);

      if (result == NULL)
	{
	  result = cookie->result;
	}

      if (cookie->cb_ret != NS_LDAP_CB_NEXT)
	{
	  assert (cookie->callback != NULL);
	  break;
	}
    }

  if (cookie != NULL)
    {
      if (ret == NS_LDAP_NOTFOUND && cookie->entry != NULL)
	{
	  ret = NS_LDAP_SUCCESS;
	}

      *pResult = result;
      cookie->result = NULL;
    }

  __ns_ldap_freeCookie (&cookie);
  __ns_ldap_mapErrorDetail (ret, errorp);

  _nss_ldap_leave ();

  debug ("<== __ns_ldap_list ret=%s", NS_LDAP_ERR2STR (ret));

  return ret;
}

ns_ldap_return_code
__ns_ldap_err2str (ns_ldap_return_code err, char **strmsg)
{
  switch (err)
    {
    case NS_LDAP_SUCCESS:
    case NS_LDAP_SUCCESS_WITH_INFO:
      *strmsg = "Success";
      break;
    case NS_LDAP_OP_FAILED:
      *strmsg = "Operation failed";
      break;
    case NS_LDAP_NOTFOUND:
      *strmsg = "Not found";
      break;
    case NS_LDAP_MEMORY:
      *strmsg = "Out of memory";
      break;
    case NS_LDAP_CONFIG:
      *strmsg = "Configuration error";
      break;
    case NS_LDAP_PARTIAL:
      *strmsg = "Partial results received";
      break;
    case NS_LDAP_INTERNAL:
      *strmsg = "Internal LDAP error";
      break;
    case NS_LDAP_INVALID_PARAM:
      *strmsg = "Invalid parameter";
      break;
    default:
      *strmsg = "Unknown error";
      return NS_LDAP_INVALID_PARAM;
      break;
    }

  return NS_LDAP_SUCCESS;
}

#endif /* HAVE_NSSWITCH_H */
