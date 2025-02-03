#ifndef HEADER_FETCH_STRTOOFFT_H
#define HEADER_FETCH_STRTOOFFT_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"

/*
 * Determine which string to integral data type conversion function we use
 * to implement string conversion to our fetch_off_t integral data type.
 *
 * Notice that fetch_off_t might be 64 or 32 bits wide, and that it might use
 * an underlying data type which might be 'long', 'int64_t', 'long long' or
 * '__int64' and more remotely other data types.
 *
 * On systems where the size of fetch_off_t is greater than the size of 'long'
 * the conversion function to use is strtoll() if it is available, otherwise,
 * we emulate its functionality with our own clone.
 *
 * On systems where the size of fetch_off_t is smaller or equal than the size
 * of 'long' the conversion function to use is strtol().
 */

typedef enum
{
  FETCH_OFFT_OK,   /* parsed fine */
  FETCH_OFFT_FLOW, /* over or underflow */
  FETCH_OFFT_INVAL /* nothing was parsed */
} FETCHofft;

FETCHofft fetchx_strtoofft(const char *str, char **endp, int base,
                           fetch_off_t *num);

#endif /* HEADER_FETCH_STRTOOFFT_H */
