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
#include <stdio.h> /* needed for FILE */

int curl_mprintf(const char *format, ...);
int curl_mfprintf(FILE *fd, const char *format, ...);
int curl_msprintf(char *buffer, const char *format, ...);
int curl_msnprintf(char *buffer, size_t maxlength, const char *format, ...);
int curl_mvprintf(const char *format, va_list args);
int curl_mvfprintf(FILE *fd, const char *format, va_list args);
int curl_mvsprintf(char *buffer, const char *format, va_list args);
int curl_mvsnprintf(char *buffer, size_t maxlength, const char *format, va_list args);
char *curl_maprintf(const char *format, ...);
char *curl_mvaprintf(const char *format, va_list args);

#ifdef _MPRINTF_REPLACE
# define printf curl_mprintf
# define fprintf curl_mfprintf
# define sprintf curl_msprintf
# define snprintf curl_msnprintf
# define vprintf curl_mvprintf
# define vfprintf curl_mvfprintf
# define vsprintf curl_mvsprintf
# define vsnprintf curl_mvsnprintf
# define aprintf curl_maprintf
# define vaprintf curl_mvaprintf
#endif

#endif /* H_MPRINTF */
