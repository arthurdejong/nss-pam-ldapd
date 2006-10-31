
/* common macros for reading and writing from streams */

#ifndef _NSLCD_COMMON_H
#define _NSLCD_COMMON_H 1

/* WRITE marcos, used for writing data, on write error they will
   call the ERROR_OUT_WRITEERROR macro
   these macros may require the availability of the following
   variables:
   int32_t tmpint32; - temporary variable
   */

#define WRITE(fp,ptr,size) \
  if (fwrite(ptr,size,1,fp)<1) \
    { ERROR_OUT_WRITEERROR(fp) }

#define WRITE_TYPE(fp,field,type) \
  WRITE(fp,&(field),sizeof(type))

#define WRITE_INT32(fp,i) \
  tmpint32=(int32_t)(i); \
  WRITE_TYPE(fp,tmpint32,int32_t)

#define WRITE_STRING(fp,str) \
  WRITE_INT32(fp,strlen(str)); \
  WRITE(fp,str,strlen(str));

#define WRITE_FLUSH(fp) \
  if (fflush(fp)<0) \
    { ERROR_OUT_WRITEERROR(fp) }

/* READ macros, used for reading data, on read error they will
   call the ERROR_OUT_READERROR or ERROR_OUT_BUFERROR macro
   these macros may require the availability of the following
   variables:
   int32_t tmpint32; - temporary variable
   char *buffer;     - pointer to a buffer for reading strings
   size_t buflen;    - the size of the buffer
   size_t bufptr;    - the current position in the buffer
   */

#define READ(fp,ptr,size) \
  if (fread(ptr,size,1,fp)<1) \
    { ERROR_OUT_READERROR(fp) }

#define READ_TYPE(fp,field,type) \
  READ(fp,&(field),sizeof(type))

#define READ_INT32(fp,i) \
  READ_TYPE(fp,tmpint32,int32_t); \
  i=tmpint32;

/* read string in the buffer (using buffer, buflen and bufptr)
   and store the actual location of the string in field */
#define READ_STRING_BUF(fp,field) \
  /* read the size of the string */ \
  READ_TYPE(fp,tmpint32,int32_t); \
  /* check if read would fit */ \
  if ((bufptr+(size_t)tmpint32+1)>buflen) \
    { ERROR_OUT_BUFERROR(fp) } /* will not fit */ \
  /* read string from the stream */ \
  READ(fp,buffer+bufptr,(size_t)tmpint32); \
  /* null-terminate string in buffer */ \
  buffer[bufptr+tmpint32]='\0'; \
  /* prepare result */ \
  (field)=buffer+bufptr; \
  bufptr+=tmpint32+1;

/* read a string from the stream dynamically allocating memory
   for the string (don't forget to call free() later on) */
#define READ_STRING_ALLOC(fp,field) \
  /* read the size of the string */ \
  READ_TYPE(fp,tmpint32,int32_t); \
  /* allocate memory */ \
  (field)=(char *)malloc((size_t)(tmpint32+1)); \
  if ((field)==NULL) \
    { ERROR_OUT_ALLOCERROR(fp) } /* problem allocating */ \
  /* read string from the stream */ \
  READ(fp,name,(size_t)tmpint32); \
  /* null-terminate string in buffer */ \
  (name)[tmpint32]='\0';

#endif /* not _NSLCD_COMMON_H */
