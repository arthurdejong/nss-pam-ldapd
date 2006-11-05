
/* common macros for reading and writing from streams */

#ifndef _NSLCD_COMMON_H
#define _NSLCD_COMMON_H 1

/* WRITE marcos, used for writing data, on write error they will
   call the ERROR_OUT_WRITEERROR macro
   these macros may require the availability of the following
   variables:
   int32_t tmpint32; - temporary variable
   */

#define DEBUG_PRINT_OLD(...) fprintf(stderr, ## args)
#ifdef DEBUG_PROT
#define DEBUG_PRINT(fmt,arg) fprintf(stderr,fmt,arg)
#else /* DEBUG_PROT */
#define DEBUG_PRINT(fmt,arg)
#endif /* not DEBUG_PROT */

#define WRITE(fp,ptr,size) \
  DEBUG_PRINT("WRITE: %d bytes\n",(int)size); \
  if (fwrite(ptr,size,1,fp)<1) \
    { ERROR_OUT_WRITEERROR(fp) }

#define WRITE_TYPE(fp,field,type) \
  WRITE(fp,&(field),sizeof(type))

#define WRITE_INT32(fp,i) \
  DEBUG_PRINT("WRITE: int32=%d\n",(int)i); \
  tmpint32=(int32_t)(i); \
  WRITE_TYPE(fp,tmpint32,int32_t)

#define WRITE_STRING(fp,str) \
  DEBUG_PRINT("WRITE: string=\"%s\"\n",str); \
  WRITE_INT32(fp,strlen(str)); \
  if (tmpint32>0) \
    { WRITE(fp,str,tmpint32); }

#define WRITE_FLUSH(fp) \
  if (fflush(fp)<0) \
    { ERROR_OUT_WRITEERROR(fp) }

#define WRITE_STRINGLIST_NUM(fp,arr,num) \
  /* write number of strings */ \
  WRITE_INT32(fp,num); \
  /* write strings */ \
  for (tmp2int32=0;tmp2int32<(num);tmp2int32++) \
  { \
    WRITE_STRING(fp,(arr)[tmp2int32]); \
  }

#define WRITE_STRINGLIST_NULLTERM(fp,arr) \
  /* first determin length of array */ \
  for (tmp3int32=0;(arr)[tmp3int32]!=NULL;tmp3int32++) \
    /*noting*/ ; \
  /* write number of strings */ \
  WRITE_TYPE(fp,tmp3int32,int32_t); \
  /* write strings */ \
  for (tmp2int32=0;tmp2int32<tmp3int32;tmp2int32++) \
  { \
    WRITE_STRING(fp,(arr)[tmp2int32]); \
  }

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
  DEBUG_PRINT("READ: %d bytes\n",(int)size);

#define READ_TYPE(fp,field,type) \
  READ(fp,&(field),sizeof(type))

#define READ_INT32(fp,i) \
  READ_TYPE(fp,tmpint32,int32_t); \
  i=tmpint32; \
  DEBUG_PRINT("READ: int32=%d\n",(int)i);

/* current position in the buffer */
#define BUF_CUR \
  (buffer+bufptr)

/* check that the buffer has sz bytes left in it */
#define BUF_CHECK(fp,sz) \
  if ((bufptr+(size_t)(sz))>buflen) \
    { ERROR_OUT_BUFERROR(fp) } /* will not fit */ \

/* move the buffer pointer */
#define BUF_SKIP(sz) \
  bufptr+=(size_t)(sz);

/* read string in the buffer (using buffer, buflen and bufptr)
   and store the actual location of the string in field */
#define READ_STRING_BUF(fp,field) \
  /* read the size of the string */ \
  READ_TYPE(fp,tmpint32,int32_t); \
  /* check if read would fit */ \
  BUF_CHECK(fp,tmpint32+1); \
  /* read string from the stream */ \
  if (tmpint32>0) \
    { READ(fp,BUF_CUR,(size_t)tmpint32); } \
  /* null-terminate string in buffer */ \
  BUF_CUR[tmpint32]='\0'; \
  DEBUG_PRINT("READ: string=\"%s\"\n",BUF_CUR); \
  /* prepare result */ \
  (field)=BUF_CUR; \
  BUF_SKIP(tmpint32+1);

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
  /* null-terminate string */ \
  (name)[tmpint32]='\0'; \
  DEBUG_PRINT("READ: string=\"%s\"\n",(name));

/* read an array from a stram and store the length of the
   array in num (size for the array is allocated) */
#define READ_STRINGLIST_NUM(fp,arr,num) \
  /* read the number of entries */ \
  READ_INT32(fp,(num)); \
  /* allocate room for *char[num] */ \
  tmpint32*=sizeof(char *); \
  BUF_CHECK(fp,tmpint32); \
  (arr)=(char **)BUF_CUR; \
  BUF_SKIP(tmpint32); \
  for (tmp2int32=0;tmp2int32<(num);tmp2int32++) \
  { \
    READ_STRING_BUF(fp,(arr)[tmp2int32]); \
  }

/* read an array from a stram and store it as a null-terminated
   array list (size for the array is allocated) */
#define READ_STRINGLIST_NULLTERM(fp,arr) \
  /* read the number of entries */ \
  READ_TYPE(fp,tmp3int32,int32_t); \
  /* allocate room for *char[num+1] */ \
  tmp2int32=(tmp3int32+1)*sizeof(char *); \
  BUF_CHECK(fp,tmp2int32); \
  (arr)=(char **)BUF_CUR; \
  BUF_SKIP(tmp2int32); \
  /* read all entries */ \
  for (tmp2int32=0;tmp2int32<tmp3int32;tmp2int32++) \
  { \
    READ_STRING_BUF(fp,(arr)[tmp2int32]); \
  } \
  /* set last entry to NULL */ \
  (arr)[tmp2int32]=NULL;

/* skip a number of bytes foreward */
#define SKIP(fp,sz) \
  if (fseek(fp,(long)sz,SEEK_CUR)) \
    { ERROR_OUT_READERROR(fp) }

/* read a string from the stream but don't do anything with the result */
#define SKIP_STRING(fp) \
  /* read the size of the string */ \
  READ_TYPE(fp,tmpint32,int32_t); \
  /* seek in the stream past the string contents */ \
  SKIP(fp,tmpint32); \
  DEBUG_PRINT("READ: skip %d bytes\n",(int)tmpint32);

/* skip a loop of strings */
#define SKIP_STRINGLIST(fp) \
  /* read the number of entries */ \
  READ_TYPE(fp,tmp3int32,int32_t); \
  /* read all entries */ \
  for (tmp2int32=0;tmp2int32<tmp3int32;tmp2int32++) \
  { \
    SKIP_STRING(fp); \
  }

#endif /* not _NSLCD_COMMON_H */
