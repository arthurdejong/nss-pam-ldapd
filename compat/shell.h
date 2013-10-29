/*
   shell.h - ethernet definitions for systems lacking those

   Copyright (C) 2013 Arthur de Jong

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

#ifndef COMPAT__SHELL_H
#define COMPAT__SHELL_H 1

#ifdef HAVE_GETUSERSHELL
#if !HAVE_DECL_GETUSERSHELL
/* we define getusershell() here because on some platforms the function is
   undefined */
extern char *getusershell(void);
#endif /* not HAVE_DECL_GETUSERSHELL */
#endif /* HAVE_GETUSERSHELL */

#ifdef HAVE_SETUSERSHELL
#if !HAVE_DECL_SETUSERSHELL
/* we define setusershell() here because on some platforms the function is
   undefined */
extern char *setusershell(void);
#endif /* not HAVE_DECL_SETUSERSHELL */
#endif /* HAVE_SETUSERSHELL */

#ifdef HAVE_ENDUSERSHELL
#if !HAVE_DECL_ENDUSERSHELL
/* we define getusershell() here because on some platforms the function is
   undefined */
extern char *endusershell(void);
#endif /* not HAVE_DECL_ENDUSERSHELL */
#endif /* HAVE_ENDUSERSHELL */

#endif /* not COMPAT__SHELL_H */
