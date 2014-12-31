/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#include "endian.h"

/*
 * This function converts from the little endian format used in the incoming
 * package to whatever endian format we're using natively. Argument is a
 * pointer to a 2 byte buffer.
 */
unsigned short readshort_le(unsigned char *buf)
{
  return (unsigned short)(((unsigned short)buf[0]) |
                          ((unsigned short)buf[1] << 8));
}

/*
 * This function converts from the little endian format used in the
 * incoming package to whatever endian format we're using natively.
 * Argument is a pointer to a 4 byte buffer.
 */
unsigned int readint_le(unsigned char *buf)
{
  return ((unsigned int)buf[0]) | ((unsigned int)buf[1] << 8) |
         ((unsigned int)buf[2] << 16) | ((unsigned int)buf[3] << 24);
}

void write32_le(const int value, unsigned char *buffer)
{
  buffer[0] = (char)(value & 0x000000FF);
  buffer[1] = (char)((value & 0x0000FF00) >> 8);
  buffer[2] = (char)((value & 0x00FF0000) >> 16);
  buffer[3] = (char)((value & 0xFF000000) >> 24);
}

#if (CURL_SIZEOF_CURL_OFF_T > 4)
#if defined(HAVE_LONGLONG)
void write64_le(const long long value, unsigned char *buffer)
#else
void write64_le(const __int64 value, unsigned char *buffer)
#endif
{
  write32_le((int)value, buffer);
  write32_le((int)(value >> 32), buffer + 4);
}
#endif
