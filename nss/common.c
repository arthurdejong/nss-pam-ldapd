
#include <nss.h>

#include "nslcd-client.h"
#include "common.h"

/* translates a nsklcd return code (as defined in nslcd.h) to
   a nss code (as defined in nss.h) */
enum nss_status nslcd2nss(int code)
{
  switch (code)
  {
    case NSLCD_RS_UNAVAIL:  return NSS_STATUS_UNAVAIL;
    case NSLCD_RS_NOTFOUND: return NSS_STATUS_NOTFOUND;
    case NSLCD_RS_SUCCESS:  return NSS_STATUS_SUCCESS;
    case NSLCD_RS_SMALLBUF: return NSS_STATUS_TRYAGAIN;
    default:                return NSS_STATUS_UNAVAIL;
  }
}

