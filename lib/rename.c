/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "rename.h"

#include "curl_setup.h"

#if (!defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)) ||  \
  defined(USE_ALTSVC)

#include "timeval.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* return 0 on success, 1 on error */
int Curl_rename(const char *oldpath, const char *newpath)
{
#ifdef WIN32
  /* rename() on Windows doesn't overwrite, so we can't use it here.
     MoveFileExA() will overwrite and is usually atomic, however it fails
     when there are open handles to the file. */
  const int max_wait_ms = 1000;
  struct curltime start = Curl_now();
  for(;;) {
    timediff_t diff;
    if(MoveFileExA(oldpath, newpath, MOVEFILE_REPLACE_EXISTING))
      break;
    diff = Curl_timediff(Curl_now(), start);
    if(diff < 0 || diff > max_wait_ms)
      return 1;
    Sleep(1);
  }
#else
  if(rename(oldpath, newpath))
    return 1;
#endif
  return 0;
}

#endif
