
#include <nss.h>

/* translates a nslcd return code (as defined in nslcd.h) to
   a nss code (as defined in nss.h) */
enum nss_status nslcd2nss(int code);

/* macros for handling read and write problems, they are
   NSS specific due to the return codes */

#define ERROR_OUT_OPENERROR \
  *errnop=errno; \
  return NSS_STATUS_UNAVAIL;

#define ERROR_OUT_READERROR(fp) \
  fclose(fp); \
  *errnop=ENOENT; \
  return NSS_STATUS_UNAVAIL; \

#define ERROR_OUT_BUFERROR(fp) \
  fclose(fp); \
  *errnop=ERANGE; \
  return NSS_STATUS_TRYAGAIN; \

#define ERROR_OUT_WRITEERROR(fp) \
  ERROR_OUT_READERROR(fp)

#define ERROR_OUT_NOSUCCESS(fp,retv) \
  fclose(fp); \
  *errnop=ENOENT; \
  return nslcd2nss(retv);
