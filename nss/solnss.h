/*
   solnss.h - common functions for NSS lookups on Solaris

   Copyright (C) 2012 Arthur de Jong

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

#ifndef NSS__SOLNSS_H
#define NSS__SOLNSS_H 1
#ifdef NSS_FLAVOUR_SOLARIS

/* extra definitions we need (Solaris NSS functions don't pass errno)
   also clear the output values */
#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN
#define NSS_EXTRA_DEFS                                                      \
  int *errnop = &(errno);                                                   \
  NSS_ARGS(args)->returnval = NULL;                                         \
  NSS_ARGS(args)->returnlen = 0;                                            \
  NSS_ARGS(args)->erange = 0;                                               \
  NSS_ARGS(args)->h_errno = 0;
#else /* not HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */
#define NSS_EXTRA_DEFS                                                      \
  int *errnop = &(errno);                                                   \
  NSS_ARGS(args)->returnval = NULL;                                         \
  NSS_ARGS(args)->erange = 0;                                               \
  NSS_ARGS(args)->h_errno = 0;
#endif /* not HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

/* check validity of passed buffer (Solaris flavour) */
#define NSS_BUFCHECK                                                        \
  if ((NSS_ARGS(args)->buf.buffer == NULL) ||                               \
      (NSS_ARGS(args)->buf.buflen <= 0))                                    \
  {                                                                         \
    NSS_ARGS(args)->erange = 1;                                             \
    return NSS_STATUS_TRYAGAIN;                                             \
  }

/* wrapper function body for read_xxxent that does the buffer handling,
   return code handling and conversion to strings for nscd
   (also see READ_RESULT_STRING below) */
#define READ_RESULT(ent, extra...)                                          \
  nss_status_t retv;                                                        \
  READ_RESULT_STRING(ent, ##extra)                                          \
  /* read the entry */                                                      \
  retv = read_##ent(fp, args->buf.result, args->buf.buffer,                 \
                    args->buf.buflen, ##extra);                             \
  if (retv != NSS_STATUS_SUCCESS)                                           \
    return retv;                                                            \
  args->returnval = args->buf.result;                                       \
  return NSS_STATUS_SUCCESS;

/* provide result handling for when libc (or nscd) expects the returned
   values to be in string format */
#ifdef HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN
#define READ_RESULT_STRING(ent, extra...)                                   \
  struct ent result;                                                        \
  char *buffer;                                                             \
  /* try to return in string format if requested */                         \
  if (args->buf.result == NULL)                                             \
  {                                                                         \
    /* read the entry into a temporary buffer */                            \
    buffer = (char *)malloc(args->buf.buflen);                              \
    if (buffer == NULL)                                                     \
      return NSS_STATUS_UNAVAIL;                                            \
    retv = read_##ent(fp, &result, buffer, args->buf.buflen, ##extra);      \
    /* format to string */                                                  \
    if (retv == NSS_STATUS_SUCCESS)                                         \
      if (ent##2str(&result, args->buf.buffer, args->buf.buflen) == NULL)   \
      {                                                                     \
        args->erange = 1;                                                   \
        retv = NSS_NOTFOUND;                                                \
      }                                                                     \
    /* clean up and return result */                                        \
    free(buffer);                                                           \
    if (retv != NSS_STATUS_SUCCESS)                                         \
      return retv;                                                          \
    args->returnval = args->buf.buffer;                                     \
    args->returnlen = strlen(args->returnval);                              \
    return NSS_STATUS_SUCCESS;                                              \
  }
#else /* not HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */
#define READ_RESULT_STRING(ent, extra...) ;
#endif /* not HAVE_STRUCT_NSS_XBYY_ARGS_RETURNLEN */

/* this is the backend structure for Solaris */
struct nss_ldap_backend {
  nss_backend_op_t *ops;  /* function-pointer table */
  int n_ops;              /* number of function pointers */
  TFILE *fp;              /* file pointer for {set,get,end}ent() functions */
};

/* constructor for LDAP backends */
nss_backend_t *nss_ldap_constructor(nss_backend_op_t *ops, size_t sizeofops);

/* destructor for LDAP backends */
nss_status_t nss_ldap_destructor(nss_backend_t *be, void UNUSED(*args));

#endif /* NSS_FLAVOUR_SOLARIS */
#endif /* not NSS__COMMON_H */
