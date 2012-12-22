/*
   expr.h - limited shell-like expression parsing functions
   This file is part of the nss-pam-ldapd library.

   Copyright (C) 2009, 2012 Arthur de Jong

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

#ifndef COMMON__EXPR_H
#define COMMON__EXPR_H 1

#include "compat/attrs.h"
#include "common/set.h"

typedef const char *(*expr_expander_func) (const char *name, void *expander_arg);

/* Parse the expression and store the result in buffer, using the
   expander function to expand variable names to values. If the expression
   is invalid or the result didn't fit in the buffer NULL is returned. */
MUST_USE const char *expr_parse(const char *expr, char *buffer, size_t buflen,
                                expr_expander_func expander, void *expander_arg);

/* Return the variable names that are used in expr. If set is NULL a new one
   is allocated, otherwise the passed set is added to. */
SET *expr_vars(const char *expr, SET *set);

#endif /* not _COMMON__ */
