/*
   dict.c - dictionary functions
   This file is part of the nss-ldapd library.

   Copyright (C) 2007 Arthur de Jong

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "dict.h"

struct dict_entry {
  const char *key;
  void *value;
  struct dict_entry *next;
};

struct dictionary {
  struct dict_entry *head;
  struct dict_entry *ptr; /* for searching */
};

static struct dict_entry *dict_entry_new(const char *key)
{
  struct dict_entry *entry;
  entry=(struct dict_entry *)malloc(sizeof(struct dict_entry));
  if (entry==NULL)
    return NULL;
  entry->key=strdup(key);
  if (entry->key==NULL)
  {
    free(entry);
    return NULL;
  }
  entry->value=NULL;
  return entry;
}

static void dict_entry_free(struct dict_entry *entry)
{
  /* free key */
  free((void *)entry->key);
  /* free entry */
  free(entry);
}

static struct dict_entry *dict_entry_find(
        DICT *dict,const char *key)
{
  struct dict_entry *ptr;
  for (ptr=dict->head;ptr!=NULL;ptr=ptr->next)
  {
    if (strcasecmp(ptr->key,key)==0)
      return ptr;
  }
  return NULL;
}

DICT *dict_new(void)
{
  struct dictionary *dict;
  dict=(struct dictionary *)malloc(sizeof(struct dictionary));
  if (dict==NULL)
    return NULL;
  dict->head=NULL;
  dict->ptr=NULL;
  return dict;
}

int dict_put(DICT *dict,const char *key,void *value)
{
  struct dict_entry *entry;
  /* ignore setting of value to NULL */
  if (value==NULL)
    return 0; /* probably do dict_del(dict,key) */
  entry=dict_entry_find(dict,key);
  if (entry==NULL)
  {
    /* create new entry and insert it in the list */
    entry=dict_entry_new(key);
    if (entry==NULL)
      return -1;
    /* insert entry in list */
    entry->next=dict->head;
    dict->head=entry;
  }
  /* set value */
  entry->value=value;
  return 0;
}

void *dict_get(DICT *dict,const char *key)
{
  struct dict_entry *entry;
  entry=dict_entry_find(dict,key);
  if (entry==NULL)
    return NULL;
  return entry->value;
}

void dict_free(DICT *dict)
{
  struct dict_entry *ptr,*nxt;
  /* free all entries */
  ptr=dict->head;
  while (ptr!=NULL)
  {
    nxt=ptr->next;
    dict_entry_free(ptr);
    ptr=nxt;
  }
  /* clear some references */
  dict->head=NULL;
  dict->ptr=NULL;
  /* free struct itself */
  free(dict);
}

void dict_values_first(DICT *dict)
{
  dict->ptr=dict->head;
}

void *dict_values_next(DICT *dict)
{
  struct dict_entry *ptr;
  ptr=dict->ptr;
  if (dict->ptr!=NULL)
    dict->ptr=dict->ptr->next;
  return ptr;
}
