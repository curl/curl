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

int Curl_mprintf(const char *format, ...);
int Curl_mfprintf(FILE *fd, const char *format, ...);
int Curl_msprintf(char *buffer, const char *format, ...);
int Curl_msnprintf(char *buffer, size_t maxlength, const char *format, ...);
int Curl_mvprintf(const char *format, va_list args);
int Curl_mvfprintf(FILE *fd, const char *format, va_list args);
int Curl_mvsprintf(char *buffer, const char *format, va_list args);
int Curl_mvsnprintf(char *buffer, size_t maxlength, const char *format, va_list args);
char *Curl_maprintf(const char *format, ...);
char *Curl_mvaprintf(const char *format, va_list args);

#ifdef _MPRINTF_REPLACE
# define printf Curl_mprintf
# define fprintf Curl_mfprintf
# define sprintf Curl_msprintf
# define snprintf Curl_msnprintf
# define vprintf Curl_mvprintf
# define vfprintf Curl_mvfprintf
# define vsprintf Curl_mvsprintf
# define vsnprintf Curl_mvsnprintf
# define aprintf Curl_maprintf
# define vaprintf Curl_mvaprintf
#endif

#endif /* H_MPRINTF */
