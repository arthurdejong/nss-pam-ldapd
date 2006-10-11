/* Copyright (C) 1997-2005 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@padl.com>, 1997.

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
 */

static char rcsId[] = "$Id: ltf.c,v 2.29 2005/05/20 05:30:42 lukeh Exp $";

#include "config.h"

#ifdef HAVE_PORT_BEFORE_H
#include <port_before.h>
#endif

#if defined(HAVE_THREAD_H) && !defined(_AIX)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#include "ldap-nss.h"

#if defined(LDAP_OPT_THREAD_FN_PTRS) && (defined(HAVE_THREAD_H) || defined(HAVE_PTHREAD_H))

static void *ltf_mutex_alloc (void);
static void ltf_mutex_free (void *m);
static NSS_STATUS ltf_tsd_setup (void);
static void ltf_set_ld_error (int err, char *matched, char *errmsg,
			      void *dummy);
static int ltf_get_ld_error (char **matched, char **errmsg, void *dummy);
static void ltf_set_errno (int err);
static int ltf_get_errno (void);

#ifndef HAVE_THREAD_H		/* thus, pthreads */
/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-

 * The contents of this file are subject to the Netscape Public License
 * Version 1.0 (the "NPL"); you may not use this file except in
 * compliance with the NPL.  You may obtain a copy of the NPL at
 * http://www.mozilla.org/NPL/
 *
 * Software distributed under the NPL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the NPL
 * for the specific language governing rights and limitations under the
 * NPL.
 *
 * The Initial Developer of this code under the NPL is Netscape
 * Communications Corporation.  Portions created by Netscape are
 * Copyright (C) 1998 Netscape Communications Corporation.  All Rights
 * Reserved.
 */

static int ltf_mutex_lock (void *);
static int ltf_mutex_unlock (void *);

static pthread_key_t key;

NSS_STATUS _nss_ldap_ltf_thread_init (LDAP * ld)
{
  struct ldap_thread_fns tfns;

  /* set mutex pointers */
  memset (&tfns, '\0', sizeof (struct ldap_thread_fns));
  tfns.ltf_mutex_alloc = ltf_mutex_alloc;
  tfns.ltf_mutex_free = ltf_mutex_free;
  tfns.ltf_mutex_lock = ltf_mutex_lock;
  tfns.ltf_mutex_unlock = ltf_mutex_unlock;
  tfns.ltf_get_errno = ltf_get_errno;
  tfns.ltf_set_errno = ltf_set_errno;
  tfns.ltf_get_lderrno = ltf_get_ld_error;
  tfns.ltf_set_lderrno = ltf_set_ld_error;
  tfns.ltf_lderrno_arg = NULL;
  /* set ld_errno pointers */
  if (ldap_set_option (ld, LDAP_OPT_THREAD_FN_PTRS, (void *) &tfns) != 0)
    {
      return NSS_UNAVAIL;
    }

  return ltf_tsd_setup ();
}

static void *
ltf_mutex_alloc (void)
{
  pthread_mutex_t *mutexp;

  if ((mutexp = malloc (sizeof (pthread_mutex_t))) != NULL)
    {
      pthread_mutex_init (mutexp, NULL);
    }

  return (mutexp);
}

static void
ltf_mutex_free (void *mutexp)
{
  pthread_mutex_destroy ((pthread_mutex_t *) mutexp);
}

static int
ltf_mutex_lock (void *mutexp)
{
#if defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
  return __libc_lock_lock (*(pthread_mutex_t *) mutexp);
#elif defined(HPUX)
  return __thread_mutex_lock ((pthread_mutex_t *) mutexp);
#else
# ifdef _AIX
  if (__multi_threaded == 0)
    return 0;
# endif
  return pthread_mutex_lock ((pthread_mutex_t *) mutexp);
#endif /* HAVE_LIBC_LOCK_H || HAVE_BITS_LIBC_LOCK_H */
}

static int
ltf_mutex_unlock (void *mutexp)
{
#if defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
  return __libc_lock_unlock (*(pthread_mutex_t *) mutexp);
#elif defined(HPUX)
  return __thread_mutex_unlock ((pthread_mutex_t *) mutexp);
#else
# ifdef _AIX
  if (__multi_threaded == 0)
    return 0;
# endif
  return pthread_mutex_unlock ((pthread_mutex_t *) mutexp);
#endif /* HAVE_LIBC_LOCK_H || HAVE_BITS_LIBC_LOCK_H */
}

static NSS_STATUS
ltf_tsd_setup (void)
{
  void *tsd;

#if defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
  if (__libc_key_create (&key, free) != 0)
    {
      return NSS_UNAVAIL;
    }
  tsd = (void *) calloc (1, sizeof (struct ldap_error));
  __libc_setspecific (key, tsd);
#else
  if (pthread_key_create (&key, free) != 0)
    {
      return NSS_UNAVAIL;
    }
  tsd = pthread_getspecific (key);
  if (tsd != NULL)
    {
      pthread_exit (NULL);
    }
  tsd = (void *) calloc (1, sizeof (struct ldap_error));
  pthread_setspecific (key, tsd);
#endif /* HAVE_LIBC_LOCK_H || HAVE_BITS_LIBC_LOCK_H */

  return NSS_SUCCESS;
}

static void
ltf_set_ld_error (int err, char *matched, char *errmsg, void *dummy)
{
  struct ldap_error *le;

#if defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
  le = __libc_getspecific (key);
#else
  le = pthread_getspecific (key);
#endif /* HAVE_LIBC_LOCK_H || HAVE_BITS_LIBC_LOCK_H */

  le->le_errno = err;

  if (le->le_matched != NULL)
    ldap_memfree (le->le_matched);
  le->le_matched = matched;

  if (le->le_errmsg != NULL)
    ldap_memfree (le->le_errmsg);
  le->le_errmsg = errmsg;
}

static int
ltf_get_ld_error (char **matched, char **errmsg, void *dummy)
{
  struct ldap_error *le;

#if defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
  le = __libc_getspecific (key);
#else
  le = pthread_getspecific (key);
#endif /* HAVE_LIBC_LOCK_H || HAVE_BITS_LIBC_LOCK_H */
  if (le == NULL)
    return LDAP_LOCAL_ERROR;

  if (matched != NULL)
    *matched = le->le_matched;

  if (errmsg != NULL)
    *errmsg = le->le_errmsg;

  return (le->le_errno);
}

static void
ltf_set_errno (int err)
{
  errno = err;
}

static int
ltf_get_errno (void)
{
  return (errno);
}
#else
static thread_key_t ltf_key = 0;

static void *
ltf_mutex_alloc (void)
{
  mutex_t *m;

  m = (mutex_t *) malloc (sizeof (*m));
  if (m == NULL)
    return NULL;

  if (mutex_init (m, USYNC_THREAD, NULL) < 0)
    return NULL;

  return m;
}

static void
ltf_mutex_free (void *m)
{
  mutex_destroy ((mutex_t *) m);
/*      free(m); */
}

void
ltf_destr (void *tsd)
{
  free (tsd);
}

static NSS_STATUS
ltf_tsd_setup (void)
{
  void *tsd;

  (void) thr_keycreate (&ltf_key, ltf_destr);
  tsd = (void *) calloc (1, sizeof (ldap_error_t));
  thr_setspecific (ltf_key, tsd);
  return NSS_SUCCESS;
}

static void
ltf_set_ld_error (int err, char *matched, char *errmsg, void *dummy)
{
  ldap_error_t *le;

  (void) thr_getspecific (ltf_key, (void **) &le);
  if (le == NULL)
    return;

  le->le_errno = err;

  if (le->le_matched != NULL)
    ldap_memfree (le->le_matched);
  le->le_matched = matched;

  if (le->le_errmsg != NULL)
    ldap_memfree (le->le_errmsg);
  le->le_errmsg = errmsg;
}

static int
ltf_get_ld_error (char **matched, char **errmsg, void *dummy)
{
  ldap_error_t *le = NULL;

  (void) thr_getspecific (ltf_key, (void **) &le);
  if (le == NULL)
    return LDAP_LOCAL_ERROR;

  if (matched != NULL)
    *matched = le->le_matched;

  if (errmsg != NULL)
    *errmsg = le->le_errmsg;

  return le->le_errno;
}

static void
ltf_set_errno (int err)
{
  errno = err;
}

static int
ltf_get_errno (void)
{
  return errno;
}

NSS_STATUS _nss_ldap_ltf_thread_init (LDAP * ld)
{
  struct ldap_thread_fns tfns;

  memset (&tfns, '\0', sizeof (tfns));
  tfns.ltf_mutex_alloc = ltf_mutex_alloc;
  tfns.ltf_mutex_free = ltf_mutex_free;
  tfns.ltf_mutex_lock = (int (*)(void *)) mutex_lock;
  tfns.ltf_mutex_unlock = (int (*)(void *)) mutex_unlock;
  tfns.ltf_get_errno = ltf_get_errno;
  tfns.ltf_set_errno = ltf_set_errno;
  tfns.ltf_get_lderrno = ltf_get_ld_error;
  tfns.ltf_set_lderrno = ltf_set_ld_error;
  tfns.ltf_lderrno_arg = NULL;

  if (ldap_set_option (ld, LDAP_OPT_THREAD_FN_PTRS, (void *) &tfns) != 0)
    return NSS_UNAVAIL;

  return ltf_tsd_setup ();
}
#endif /* !HAVE_THREAD_H */
#endif /* LDAP_OPT_THREAD_FN_PTRS */
