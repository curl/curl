/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2009, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include <curl/curl.h>

#include "curl_rand.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/* Private pseudo-random number seed. Unsigned integer >= 32bit. Threads
   mutual exclusion is not implemented to acess it since we do not require
   high quality random numbers (only used in form boudary generation). */

static unsigned int randseed;

/* Pseudo-random number support. */

unsigned int Curl_rand(void)
{
  unsigned int r;
  /* Return an unsigned 32-bit pseudo-random number. */
  r = randseed = randseed * 1103515245 + 12345;
  return (r << 16) | ((r >> 16) & 0xFFFF);
}

void Curl_srand(void)
{
  /* Randomize pseudo-random number sequence. */

  randseed = (unsigned int) time(NULL);
  Curl_rand();
  Curl_rand();
  Curl_rand();
}

