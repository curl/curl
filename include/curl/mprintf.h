/*************************************************************************
 *
 * $Id$
 *
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/ 
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License. 
 *
 * The Original Code is Triacle.
 *
 * The Initial Developers of the Original Code are Bjorn Reese and
 * Daniel Stenberg.
 *
 * Portions created by Initial Developers are
 *
 *   Copyright (C) 1998 Bjorn Reese and Daniel Stenberg.
 *   All Rights Reserved. 
 *
 * Contributor(s):
 *
 *************************************************************************
 *
 * Preliminary documentation
 *
 * printf conversions:
 *
 *  conversion ::= '%%' | '%' [position] ( number | float | string )
 *  position ::= digits '$'
 *  number ::= [number-flags] ( 'd' | 'i' | 'o' | 'x' | 'X' | 'u')
 *  number-flags ::= 'h' | 'l' | 'L' ...
 *  float ::= [float-flags] ( 'f' | 'e' | 'E' | 'g' | 'G' )
 *  string ::= [string-flags] 's'
 *  string-flags ::= padding | '#'
 *  digits ::= (digit)+
 *  digit ::= 0-9
 *
 *  c
 *  p
 *  n
 *
 * qualifiers
 *
 *  -     : left adjustment
 *  +     : show sign
 *  SPACE : padding
 *  #     : alterative
 *  .     : precision
 *  *     : width
 *  0     : padding / size
 *  1-9   : size
 *  h     : short
 *  l     : long
 *  ll    : longlong
 *  L     : long double
 *  Z     : long / longlong
 *  q     : longlong
 *
 ************************************************************************/

#ifndef H_MPRINTF
#define H_MPRINTF

#include <stdarg.h>

int mprintf(const char *format, ...);
int mfprintf(FILE *fd, const char *format, ...);
int msprintf(char *buffer, const char *format, ...);
int msnprintf(char *buffer, size_t maxlength, const char *format, ...);
int mvprintf(const char *format, va_list args);
int mvfprintf(FILE *fd, const char *format, va_list args);
int mvsprintf(char *buffer, const char *format, va_list args);
int mvsnprintf(char *buffer, size_t maxlength, const char *format, va_list args);
char *maprintf(const char *format, ...);
char *mvaprintf(const char *format, va_list args);

#ifdef _MPRINTF_REPLACE
# define printf mprintf
# define fprintf mfprintf
# define sprintf msprintf
# define snprintf msnprintf
# define vprintf mvprintf
# define vfprintf mvfprintf
# define vsprintf mvsprintf
# define vsnprintf mvsnprintf
#endif

#endif /* H_MPRINTF */
