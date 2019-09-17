/*
   expr.c - limited shell-like expression parsing functions
   This file is part of the nss-pam-ldapd library.

   Copyright (C) 2009-2016 Arthur de Jong
   Copyright (c) 2012 Thorsten Glaser <t.glaser@tarent.de>
   Copyright (c) 2016 Giovanni Mascellani <gio@debian.org>

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
#include <stdio.h>
#include <errno.h>

#include "expr.h"
#include "compat/attrs.h"

/* the maximum length of a variable name */
#define MAXVARLENGTH 30

static inline int my_isalpha(const char c)
{
  return ((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z'));
}

static inline int my_isdigit(const char c)
{
  return (c >= '0') && (c <= '9');
}

static inline int my_isalphanum(const char c)
{
  return my_isalpha(c) || ((c >= '0') && (c <= '9'));
}

/* return the part of the string that is a valid name */
MUST_USE static const char *parse_name(const char *str, int *ptr,
                                       char *buffer, size_t buflen)
{
  int i = 0;
  /* clear the buffer */
  buffer[i] = '\0';
  /* look for an alpha + alphanumeric* string */
  if (!my_isalpha(str[*ptr]))
    return NULL;
  while (my_isalphanum(str[*ptr]) || (str[*ptr] == ';'))
  {
    if ((size_t)i >= buflen)
      return NULL;
    buffer[i++] = str[(*ptr)++];
  }
  /* NULL-terminate the string */
  if ((size_t)i >= buflen)
    return NULL;
  buffer[i++] = '\0';
  return buffer;
}

/* dummy expander function to always return an empty string */
static const char *empty_expander(const char UNUSED(*name),
                                  void UNUSED(*expander_arg))
{
  return "";
}

/* definition of the parse functions (they call each other) */
MUST_USE static const char *parse_dollar_expression(
              const char *str, int *ptr, char *buffer, size_t buflen,
              expr_expander_func expander, void *expander_arg);
MUST_USE static const char *parse_expression(
              const char *str, int *ptr, int endat, char *buffer, size_t buflen,
              expr_expander_func expander, void *expander_arg);

/* handle ${attr:-word} expressions */
MUST_USE static const char *parse_dollar_default(
              const char *str, int *ptr, char *buffer, size_t buflen,
              expr_expander_func expander, void *expander_arg,
              const char *varvalue)
{
  if ((varvalue != NULL) && (*varvalue != '\0'))
  {
    /* value is set, skip rest of expression and use value */
    if (parse_expression(str, ptr, '}', buffer, buflen, empty_expander, NULL) == NULL)
      return NULL;
    if (strlen(varvalue) >= buflen)
      return NULL;
    strcpy(buffer, varvalue);
  }
  else
  {
    /* value is not set, evaluate rest of expression */
    if (parse_expression(str, ptr, '}', buffer, buflen, expander, expander_arg) == NULL)
      return NULL;
  }
  return buffer;
}

/* handle ${attr:+word} expressions */
MUST_USE static const char *parse_dollar_alternative(
              const char *str, int *ptr, char *buffer, size_t buflen,
              expr_expander_func expander, void *expander_arg,
              const char *varvalue)
{
  if ((varvalue != NULL) && (*varvalue != '\0'))
  {
    /* value is set, evaluate rest of expression */
    if (parse_expression(str, ptr, '}', buffer, buflen, expander, expander_arg) == NULL)
      return NULL;
  }
  else
  {
    /* value is not set, skip rest of expression and blank */
    if (parse_expression(str, ptr, '}', buffer, buflen, empty_expander, NULL) == NULL)
      return NULL;
    buffer[0] = '\0';
  }
  return buffer;
}

/* handle ${attr:offset:length} expressions */
MUST_USE static const char *parse_dollar_substring(
              const char *str, int *ptr, char *buffer, size_t buflen,
              const char *varvalue)
{
  char *tmp;
  unsigned long int offset, length;
  size_t varlen;
  /* parse input */
  tmp = (char *)str + *ptr;
  if (!my_isdigit(*tmp))
    return NULL;
  errno = 0;
  offset = strtoul(tmp, &tmp, 10);
  if ((*tmp != ':') || (errno != 0))
    return NULL;
  tmp += 1;
  errno = 0;
  length = strtoul(tmp, &tmp, 10);
  if ((*tmp != '}') || (errno != 0))
    return NULL;
  /* don't skip closing '}' here, because it will be skipped later */
  *ptr += tmp - (str + *ptr);
  varlen = strlen(varvalue);
  if (offset > varlen)
    offset = varlen;
  if (offset + length > varlen)
    length = varlen - offset;
  if (length >= buflen)
    return NULL;
  /* everything's ok, copy data; we use memcpy instead of strncpy
     because we already know the exact length in play */
  memcpy(buffer, varvalue + offset, length);
  buffer[length] = '\0';
  return buffer;
}

/* handle ${attr#word} expressions */
MUST_USE static const char *parse_dollar_match(
              const char *str, int *ptr, char *buffer, size_t buflen,
              const char *varvalue)
{
  char c;
  const char *cp, *vp;
  int ismatch;
  size_t vallen;
  cp = str + *ptr;
  vp = varvalue;
  ismatch = 1;
  while (((c = *cp++) != '\0') && (c != '}'))
  {
    if (ismatch && (*vp =='\0'))
      ismatch = 0; /* varvalue shorter than trim string */
    if (c == '?')
    {
      /* match any one character */
      vp++;
      continue;
    }
    if (c == '\\')
    {
      if ((c = *cp++) == '\0')
        return NULL; /* end of input: syntax error */
      /* escape the next character c */
    }
    if (ismatch && (*vp != c))
      ismatch = 0; /* they differ */
    vp++;
  }
  if (c == '\0')
    return NULL; /* end of input: syntax error */
  /* at this point, cp points to after the closing } */
  (*ptr) = cp - str - 1;
  /* if ismatch, vp points to the beginning of the
     data after trimming, otherwise vp is invalid */
  if (!ismatch)
    vp = varvalue;
  /* now copy the (trimmed or not) value to the buffer */
  if ((vallen = strlen(vp) + 1) > buflen)
    return NULL;
  memcpy(buffer, vp, vallen);
  return buffer;
}

MUST_USE static const char *parse_dollar_expression(
              const char *str, int *ptr, char *buffer, size_t buflen,
              expr_expander_func expander, void *expander_arg)
{
  char varname[MAXVARLENGTH];
  const char *varvalue;
  if ((buflen <= 0) || (buffer == NULL) || (str == NULL) || (ptr == NULL))
    return NULL;
  if (str[*ptr] == '{')
  {
    (*ptr)++;
    /* the first part is always a variable name */
    if (parse_name(str, ptr, varname, sizeof(varname)) == NULL)
      return NULL;
    varvalue = expander(varname, expander_arg);
    if (varvalue == NULL)
      varvalue = "";
    if (str[*ptr] == '}')
    {
      /* simple substitute */
      if (strlen(varvalue) >= buflen)
        return NULL;
      strcpy(buffer, varvalue);
    }
    else if (strncmp(str + *ptr, ":-", 2) == 0)
    {
      /* if variable is not set or empty, substitute remainder */
      (*ptr) += 2;
      if (parse_dollar_default(str, ptr, buffer, buflen, expander, expander_arg, varvalue) == NULL)
        return NULL;
    }
    else if (strncmp(str + *ptr, ":+", 2) == 0)
    {
      /* if variable is set, substitute remainder */
      (*ptr) += 2;
      if (parse_dollar_alternative(str, ptr, buffer, buflen, expander, expander_arg, varvalue) == NULL)
        return NULL;
    }
    else if (str[*ptr] == ':')
    {
      /* substitute substring of variable */
      (*ptr) += 1;
      if (parse_dollar_substring(str, ptr, buffer, buflen, varvalue) == NULL)
        return NULL;
    }
    else if (str[*ptr] == '#')
    {
      /* try to strip the remainder value from variable beginning */
      (*ptr) += 1;
      if (parse_dollar_match(str, ptr, buffer, buflen, varvalue) == NULL)
        return NULL;
    }
    else
      return NULL;
    (*ptr)++; /* skip closing } */
  }
  else
  {
    /* it is a simple reference to a variable, like $uidNumber */
    if (parse_name(str, ptr, varname, sizeof(varname)) == NULL)
      return NULL;
    varvalue = expander(varname, expander_arg);
    if (varvalue == NULL)
      varvalue = "";
    if (strlen(varvalue) >= buflen)
      return NULL;
    strcpy(buffer, varvalue);
  }
  return buffer;
}

MUST_USE static const char *parse_expression(
              const char *str, int *ptr, int endat, char *buffer, size_t buflen,
              expr_expander_func expander, void *expander_arg)
{
  int j = 0;
  /* go over string */
  while ((str[*ptr] != endat) && (str[*ptr] != '\0'))
  {
    switch (str[*ptr])
    {
      case '$': /* beginning of an expression */
        (*ptr)++;
        if ((size_t)j >= buflen)
          return NULL;
        if (parse_dollar_expression(str, ptr, buffer + j, buflen - j,
                                    expander, expander_arg) == NULL)
          return NULL;
        j = strlen(buffer);
        break;
      case '\\': /* escaped character, unescape */
        (*ptr)++;
        FALLTHROUGH; /* no break needed here */
      default: /* just copy the text */
        if ((size_t)j >= buflen)
          return NULL;
        buffer[j++] = str[*ptr];
        (*ptr)++;
    }
  }
  /* NULL-terminate buffer */
  if ((size_t)j >= buflen)
    return NULL;
  buffer[j++] = '\0';
  return buffer;
}

MUST_USE const char *expr_parse(const char *str, char *buffer, size_t buflen,
                                expr_expander_func expander, void *expander_arg)
{
  int i = 0;
  return parse_expression(str, &i, '\0', buffer, buflen,
                          expander, expander_arg);
}

SET *expr_vars(const char *str, SET *set)
{
  char varname[MAXVARLENGTH];
  int i = 0;
  /* allocate set if needed */
  if (set == NULL)
    set = set_new();
  if (set == NULL)
    return NULL;
  /* go over string */
  while (str[i] != '\0')
  {
    switch (str[i])
    {
      case '$': /* beginning of a $-expression */
        i++;
        if (str[i] == '{')
          i++;
        /* the rest should start with a variable name */
        if (parse_name(str, &i, varname, sizeof(varname)) != NULL)
          set_add(set, varname);
        break;
      case '\\': /* escaped character, unescape */
        i++;
        FALLTHROUGH; /* no break needed here */
      default: /* just skip */
        i++;
    }
  }
  return set;
}
