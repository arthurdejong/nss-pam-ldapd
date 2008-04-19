/*
   dict.c - dictionary functions
   This file is part of the nss-ldapd library.

   Copyright (C) 2007, 2008 Arthur de Jong

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

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdint.h>

#include "dict.h"

/*
   This module uses a hashtable to store it's key to value mappings. The
   structure is basically as follows:

   [struct dictionary]
     \- holds an array of pointers to a linked list of [struct dict_entry]
          \- each entry has a key/value mapping

   The hashmap can be resized when the total number of elements in the hashmap
   exceeds a certain load factor.

   All the keys are copied in a separate linked list of buffers where each new
   buffer that is allocated is larger than the previous one. The first buffer
   in the linked list is always the current one.

   Note that the initial sizes of hashtable and the loadfactor still need to
   be tuned to the use in this application.
*/

/* an entry stores one key/value pair */
struct dict_entry {
  uint32_t hash;      /* used for quick matching and rehashing */
  const char *key;    /* a reference to a copy of the key */
  void *value;        /* the stored value */
  struct dict_entry *next;
};

/* initial size allocated for the key strings */
#define KEYSTORAGE_INITSIZE 100

/* the initial size of the hashtable */
#define DICT_INITSIZE 7

/* load factor at which point to grow hashtable */
#define DICT_LOADPERCENTAGE 400

/* storage for key strings */
struct dict_keystorage {
  size_t size;      /* the number of bytes allocated */
  size_t off;       /* where in the buffer we can begin storing */
  char *buf;        /* storage for strings */
  /* newly allocated keystorages should be put in front of the list */
  struct dict_keystorage *next;
};

/* the dictionary is a hashtable */
struct dictionary {
  int size;                      /* size of the hashtable */
  int num;                       /* total number of keys stored */
  struct dict_entry **table;     /* the hashtable */
  struct dict_keystorage *keys;  /* for storing key strings */
  int loop_idx;                  /* for looping */
  struct dict_entry *loop_entry; /* for looping */
};

/* Simple hash function that computes the hash value of a lower-cased
   string. */
static uint32_t stringhash(const char *str)
{
  uint32_t hash=0;
  while (*str!='\0')
    hash=3*hash+tolower(*str++);
  return hash;
}

/* Grow the hashtable. */
static void growhashtable(DICT *dict)
{
  int i;
  int newsize;
  struct dict_entry **newtable;
  struct dict_entry *entry,*tmp;
  newsize=dict->size*3+1;
  /* allocate room for new hashtable */
  newtable=(struct dict_entry **)malloc(newsize*sizeof(struct dict_entry *));
  if (newtable==NULL)
    return; /* allocating memory failed continue to fill the existing table */
  /* clear new table */
  for (i=0;i<newsize;i++)
    newtable[i]=NULL;
  /* copy old hashtable into new table */
  for (i=0;i<dict->size;i++)
  {
    /* go over elements in linked list */
    entry=dict->table[i];
    while (entry!=NULL)
    {
      tmp=entry;
      entry=entry->next;
      /* put in new position */
      tmp->next=newtable[tmp->hash%newsize];
      newtable[tmp->hash%newsize]=tmp;
    }
  }
  /* free the old hashtable */
  free(dict->table);
  /* put new hashtable in place */
  dict->size=newsize;
  dict->table=newtable;
}

DICT *dict_new(void)
{
  char *buf;
  struct dictionary *dict;
  int i;
  /* allocate room for dictionary information */
  buf=(char *)malloc(sizeof(struct dictionary)+sizeof(struct dict_keystorage)+KEYSTORAGE_INITSIZE);
  if (buf==NULL)
    return NULL;
  /* set up toplevel structs and buffers */
  dict=(struct dictionary *)buf;
  dict->size=DICT_INITSIZE;
  dict->num=0;
  dict->keys=(struct dict_keystorage *)(buf+sizeof(struct dictionary));
  dict->keys->size=KEYSTORAGE_INITSIZE;
  dict->keys->off=0;
  dict->keys->buf=buf+sizeof(struct dictionary)+sizeof(struct dict_keystorage);
  dict->keys->next=NULL;
  /* allocate initial hashtable */
  dict->table=(struct dict_entry **)malloc(DICT_INITSIZE*sizeof(struct dict_entry *));
  if (dict->table==NULL)
  {
    free(buf);
    return NULL;
  }
  /* clear the hashtable */
  for (i=0;i<DICT_INITSIZE;i++)
    dict->table[i]=NULL;
  /* we're done */
  return dict;
}

/* Copy the key to the storage. Returns the copy of the key in the storage. */
static const char *storekey(DICT *dict,const char *key)
{
  size_t l;
  size_t newsize;
  char *buf;
  struct dict_keystorage *newkeys;
  l=strlen(key)+1;
  /* ensure that we have enough space */
  if (l>=(dict->keys->size-dict->keys->off))
  {
    newsize=((dict->keys->size+l)*3)/2;
    buf=(char *)malloc(sizeof(struct dict_keystorage)+newsize);
    if (buf==NULL)
      return NULL;
    newkeys=(struct dict_keystorage *)buf;
    newkeys->size=newsize;
    newkeys->off=0;
    newkeys->buf=(char *)(buf+sizeof(struct dict_keystorage));
    newkeys->next=dict->keys;
    /* put new keystorage in front of linked list */
    dict->keys=newkeys;
  }
  /* add the value to the buffer */
  buf=dict->keys->buf+dict->keys->off;
  strcpy(buf,key);
  dict->keys->off+=l;
  return buf;
}

void dict_free(DICT *dict)
{
  struct dict_entry *entry,*etmp;
  struct dict_keystorage *keys,*ktmp;
  int i;
  /* free hashtable entries */
  for (i=0;i<dict->size;i++)
  {
    entry=dict->table[i];
    while (entry!=NULL)
    {
      etmp=entry;
      entry=entry->next;
      free(etmp);
    }
  }
  /* free the hashtable */
  free(dict->table);
  /* free key storage
     (except last which was allocated with the dict) */
  keys=dict->keys;
  while (keys->next!=NULL)
  {
    ktmp=keys;
    keys=keys->next;
    free(ktmp);
  }
  /* free dictionary struct itself */
  free(dict);
}

void *dict_get(DICT *dict,const char *key)
{
  uint32_t hash;
  struct dict_entry *entry;
  /* calculate the hash */
  hash=stringhash(key);
  /* loop over the linked list in the hashtable */
  for (entry=dict->table[hash%dict->size];entry!=NULL;entry=entry->next)
  {
    if ( (entry->hash==hash) &&
         (strcasecmp(entry->key,key)==0) )
      return entry->value;
  }
  /* no matches found */
  return NULL;
}

int dict_put(DICT *dict,const char *key,void *value)
{
  uint32_t hash;
  int idx;
  struct dict_entry *entry,*prev;
  /* check if we should grow the hashtable */
  if ( dict->num >= ((dict->size*DICT_LOADPERCENTAGE)/100) )
    growhashtable(dict);
  /* calculate the hash and position in the hashtable */
  hash=stringhash(key);
  idx=hash%dict->size;
  /* check if the entry is already present */
  for (entry=dict->table[idx],prev=NULL;
       entry!=NULL;
       prev=entry,entry=entry->next)
  {
    if ( (entry->hash==hash) &&
         (strcasecmp(entry->key,key)==0) )
    {
      /* check if we should unset the entry */
      if (value==NULL)
      {
        /* remove from linked list */
        if (prev==NULL)
          dict->table[idx]=entry->next;
        else
          prev->next=entry->next;
        /* free entry memory and register removal */
        free(entry);
        dict->num--;
        return 0;
      }
      /* just set the new value */
      entry->value=value;
      return 0;
    }
  }
  /* if entry should be unset we're done */
  if (value==NULL)
    return 0;
  /* entry is not present, make new entry */
  entry=(struct dict_entry *)malloc(sizeof(struct dict_entry));
  if (entry==NULL)
    return -1;
  entry->hash=hash;
  entry->key=storekey(dict,key);
  if (entry->key==NULL)
  {
    free(entry);
    return -1; /* problem duplicating key */
  }
  entry->value=value;
  /* insert into hashtable/linked list */
  entry->next=dict->table[idx];
  dict->table[idx]=entry;
  /* increment number of stored items */
  dict->num++;
  return 0;
}

void dict_loop_first(DICT *dict)
{
  dict->loop_idx=0;
  dict->loop_entry=dict->table[dict->loop_idx];
}

const char *dict_loop_next(DICT *dict,const char **key,void **value)
{
  struct dict_entry *entry;
  /* find non-empty entry */
  while ( (dict->loop_idx<dict->size) && (dict->loop_entry==NULL) )
    dict->loop_entry=dict->table[dict->loop_idx++];
  if (dict->loop_entry==NULL)
    return NULL; /* no more entries to check */
  /* save current result and go to next entry */
  entry=dict->loop_entry;
  dict->loop_entry=entry->next;
  /* return results */
  if (key!=NULL)
    *key=entry->key;
  if (value!=NULL)
    *value=entry->value;
  return entry->key;
}
