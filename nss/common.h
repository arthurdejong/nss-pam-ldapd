
#include <nss.h>

/* translates a nsklcd return code (as defined in nslcd.h) to
   a nss code (as defined in nss.h) */
enum nss_status nslcd2nss(int code);

/* Macros for reading and writing to sockets. */
#define OPEN_SOCK \
  if ((fp=nslcd_client_open())==NULL) \
  { \
    *errnop=errno; \
    return NSS_STATUS_UNAVAIL; \
  }

#define ERROR_OUT(status,errnoval) \
  { \
    fclose(fp); \
    *errnop=errnoval; \
    return (status); \
  }

#define READ(fp,ptr,size) \
  if (fread(ptr,size,1,fp)<1) \
    ERROR_OUT(NSS_STATUS_UNAVAIL,ENOENT);

#define LDF_STRING(field) \
  /* read the size of the string */ \
  READ(fp,&sz,sizeof(int32_t)); \
  /* FIXME: add error checking and sanity checking */ \
  /* check if read would fit */ \
  if ((bufptr+(size_t)sz+1)>buflen) \
    ERROR_OUT(NSS_STATUS_TRYAGAIN,ERANGE); /* will not fit */ \
  /* read string from the stream */ \
  READ(fp,buffer+bufptr,(size_t)sz); \
  /* TODO: check that string does not contain \0 */ \
  /* null-terminate string in buffer */ \
  buffer[bufptr+sz]='\0'; \
  /* prepare result */ \
  (field)=buffer+bufptr; \
  bufptr+=sz+1;

#define LDF_TYPE(field,type) \
  READ(fp,&(field),sizeof(type))
