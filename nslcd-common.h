
/* common macros for reading and writing from streams */

#ifndef _NSLCD_COMMON_H
#define _NSLCD_COMMON_H 1

/* WRITE marcos, used for writing data, on write error they will
   call the ERROR_OUT_WRITEERROR macro
   these macros may require the availability of the following
   variables:
   int32_t tmpint32; - temporary variable
   */

#ifdef DEBUG_PROT
#define DEBUG_PRINT(args...) fprintf(stderr, ## args)
#else /* DEBUG_PROT */
#define DEBUG_PRINT(args...)
#endif /* not DEBUG_PROT */

#define WRITE(fp,ptr,size) \
  DEBUG_PRINT("WRITE()\n"); \
  if (fwrite(ptr,size,1,fp)<1) \
    { ERROR_OUT_WRITEERROR(fp) }

#define WRITE_TYPE(fp,field,type) \
  DEBUG_PRINT("WRITE_TYPE()\n"); \
  WRITE(fp,&(field),sizeof(type))

#define WRITE_INT32(fp,i) \
  DEBUG_PRINT("WRITE_INT32(%d)\n",(int)i); \
  tmpint32=(int32_t)(i); \
  WRITE_TYPE(fp,tmpint32,int32_t)

#define WRITE_STRING(fp,str) \
  DEBUG_PRINT("WRITE_STRING(\"%s\"=%d)\n",str,strlen(str)); \
  WRITE_INT32(fp,strlen(str)); \
  if (tmpint32>0) \
    { WRITE(fp,str,tmpint32); }

#define WRITE_FLUSH(fp) \
  DEBUG_PRINT("WRITE_FLUSH()\n"); \
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
    { ERROR_OUT_READERROR(fp) } \
  DEBUG_PRINT("READ()\n");

#define READ_TYPE(fp,field,type) \
  READ(fp,&(field),sizeof(type)) \
  DEBUG_PRINT("READ_TYPE()\n");

#define READ_INT32(fp,i) \
  READ_TYPE(fp,tmpint32,int32_t); \
  i=tmpint32; \
  DEBUG_PRINT("READ_INT32(%d)\n",(int)i);

/* read string in the buffer (using buffer, buflen and bufptr)
   and store the actual location of the string in field */
#define READ_STRING_BUF(fp,field) \
  /* read the size of the string */ \
  READ_TYPE(fp,tmpint32,int32_t); \
  /* check if read would fit */ \
  if ((bufptr+(size_t)tmpint32+1)>buflen) \
    { ERROR_OUT_BUFERROR(fp) } /* will not fit */ \
  /* read string from the stream */ \
  if (tmpint32>0) \
    { READ(fp,buffer+bufptr,(size_t)tmpint32); } \
  /* null-terminate string in buffer */ \
  buffer[bufptr+tmpint32]='\0'; \
  DEBUG_PRINT("READ_STRING_BUF(\"%s\"=%d)\n",buffer+bufptr,strlen(buffer+bufptr)); \
  /* prepare result */ \
  (field)=buffer+bufptr; \
  bufptr+=(size_t)tmpint32+1;

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
  if (tmpint32>0) \
    { READ(fp,name,(size_t)tmpint32); } \
  /* null-terminate string in buffer */ \
  (name)[tmpint32]='\0'; \
  DEBUG_PRINT("READ_STRING(\"%s\"=%d)\n",(name),strlen(name));

#endif /* not _NSLCD_COMMON_H */
