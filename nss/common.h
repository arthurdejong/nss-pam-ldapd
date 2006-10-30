
#include <nss.h>

/* translates a nslcd return code (as defined in nslcd.h) to
   a nss code (as defined in nss.h) */
enum nss_status nslcd2nss(int code);

/* Macros for reading and writing to sockets. */

/* open a client socket */
#define OPEN_SOCK(fp) \
  if ((fp=nslcd_client_open())==NULL) \
  { \
    *errnop=errno; \
    return NSS_STATUS_UNAVAIL; \
  }

/* bail out of the function with the nss status and errno set,
   closing the socket */
#define ERROR_OUT(fp,status,errnoval) \
  { \
    fclose(fp); \
    *errnop=errnoval; \
    return (status); \
  }

/* read a buffer from the stream */
#define READ(fp,ptr,size) \
  if (fread(ptr,size,1,fp)<1) \
    ERROR_OUT(fp,NSS_STATUS_UNAVAIL,ENOENT);

/* read a string (lengt,buffer) from the stream, nul-terminating the string */
#define LDF_STRING(field) \
  /* read the size of the string */ \
  READ(fp,&sz,sizeof(int32_t)); \
  /* FIXME: add error checking and sanity checking */ \
  /* check if read would fit */ \
  if ((bufptr+(size_t)sz+1)>buflen) \
    ERROR_OUT(fp,NSS_STATUS_TRYAGAIN,ERANGE); /* will not fit */ \
  /* read string from the stream */ \
  READ(fp,buffer+bufptr,(size_t)sz); \
  /* TODO: check that string does not contain \0 */ \
  /* null-terminate string in buffer */ \
  buffer[bufptr+sz]='\0'; \
  /* prepare result */ \
  (field)=buffer+bufptr; \
  bufptr+=sz+1;

/* read a typed value from the stream */
#define LDF_TYPE(field,type) \
  READ(fp,&(field),sizeof(type))
