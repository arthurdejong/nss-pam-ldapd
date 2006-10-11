/**************************************************************
 * Original:
 * Patrick Powell Tue Apr 11 09:48:21 PDT 1995
 * A bombproof version of doprnt (dopr) included.
 * Sigh. This sort of thing is always nasty do deal with. Note that
 * the version here does not include floating point...
 *
 * snprintf() is used instead of sprintf() as it does limit checks
 * for string length. This covers a nasty loophole.
 *
 * The other functions are there to prevent NULL pointers from
 * causing nast effects.
 **************************************************************/

/* keep namespace tidy */
#define vsnprintf	_nss_ldap_vsnprintf
#define snprintf	_nss_ldap_snprintf

#define HAVE_STDARG_H
#include <sys/types.h>
/* varargs declarations: */
/* you might have to hand force this by doing #define HAVE_STDARG_H */

#if defined(HAVE_STDARG_H)
#include <stdarg.h>
#define HAVE_STDARGS		/* let's hope that works everywhere (mj) */
#define VA_LOCAL_DECL va_list ap;
#define VA_START(f) va_start(ap, f)
#define VA_SHIFT(v,t) ;		/* no-op for ANSI */
#define VA_END va_end(ap)
#else
#if defined(HAVE_VARARGS_H)
#include <varargs.h>
#undef HAVE_STDARGS
#define VA_LOCAL_DECL va_list ap;
#define VA_START(f) va_start(ap)	/* f is ignored! */
#define VA_SHIFT(v,t) v = va_arg(ap,t)
#define VA_END va_end(ap)
#else
XX **NO VARARGS ** XX
#endif
#endif
/* you can have ANSI C definitions */
#ifdef HAVE_STDARGS
int snprintf (char *str, size_t count, const char *fmt, ...);
int vsnprintf (char *str, size_t count, const char *fmt, va_list arg);
void setproctitle (char *fmt, ...);
#else
int snprintf ();
int vsnprintf ();
void setproctitle ();
#endif
