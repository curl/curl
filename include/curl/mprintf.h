/*************************************************************************
 *
 * $Id$
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE AUTHORS AND
 * CONTRIBUTORS ACCEPT NO RESPONSIBILITY IN ANY CONCEIVABLE MANNER.
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
