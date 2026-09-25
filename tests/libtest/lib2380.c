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
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "first.h"
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h> /* RLIMIT_FSIZE */
#endif
#include <signal.h>  /* SIGXFSZ */

#if defined(HAVE_GETRLIMIT) && defined(HAVE_SETRLIMIT) &&       \
  defined(RLIMIT_FSIZE) && defined(SIGXFSZ)
/* set a tiny limit to trigger easily */
#define T2380_FSIZE_LIMIT 50
#endif

static CURLcode test_lib2380(const char *URL)
{
  CURLcode result = CURLE_OK;
#ifdef T2380_FSIZE_LIMIT
  struct rlimit rl_orig;
  struct rlimit rl;
  FILE *f;

  if(getrlimit(RLIMIT_FSIZE, &rl_orig)) {
    curl_mfprintf(stderr, "getrlimit() failed\n");
    goto test_cleanup;
  }
  signal(SIGXFSZ, SIG_IGN);
  rl = rl_orig;
  rl.rlim_cur = T2380_FSIZE_LIMIT;
  if(setrlimit(RLIMIT_FSIZE, &rl)) {
    curl_mfprintf(stderr, "setrlimit() failed\n");
    goto test_cleanup;
  }

  f = curlx_fopen(URL, "wb");
  if(f) {
    int i;
    int n;

    /* switch off stream buffering */
    setvbuf(f, NULL, _IONBF, 0);

    /* this should fail already in lap 1 */
    for(i = 0; i < 4; i++) {
      n = curl_mfprintf(f,
                        "012345678901234567890123456789012345678901234567\n");
      if(n == -1) {
        curl_mfprintf(stderr, "error on lap %d\n", i);
        break;
      }
    }
    curlx_fclose(f);
  }

  /* restore the original value */
  setrlimit(RLIMIT_FSIZE, &rl_orig);

test_cleanup:
#else
  (void)URL; /* unused */
#endif
  return result;
}
