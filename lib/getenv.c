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
#include "curl_setup.h"

#if defined(_WIN32) && defined(UNICODE)
#include "curlx/multibyte.h"
#endif

char *curl_getenv(const char *variable)
{
#if defined(CURL_WINDOWS_UWP) || \
  defined(__ORBIS__) || defined(__PROSPERO__) /* PlayStation 4 and 5 */
  (void)variable;
  return NULL;
#elif defined(_WIN32)
  /* This uses Windows API instead of C runtime getenv() to get the environment
     variable since some changes are not always visible to the latter. #4774 */
#ifdef UNICODE
  wchar_t *buf = NULL;
  wchar_t *tmp;
  wchar_t *name = curlx_convert_UTF8_to_wchar(variable);
#else
  char *buf = NULL;
  char *tmp;
  const char *name = variable;
#endif
  char *result = NULL;
  DWORD bufsize;
  DWORD rc = 1;
  const DWORD max = 32768; /* max env var size from MSCRT source */

#ifdef UNICODE
  if(!name)
    return NULL;
#endif

  for(;;) {
    tmp = curlx_realloc(buf, rc * sizeof(*buf));
    if(!tmp) {
      break;
    }

    buf = tmp;
    bufsize = rc;

    /* it is possible for rc to be 0 if the variable was found but empty.
       Since getenv does not make that distinction we ignore it as well. */
#ifdef UNICODE
    rc = GetEnvironmentVariableW(name, buf, bufsize);
#else
    rc = GetEnvironmentVariableA(name, buf, bufsize);
#endif
    if(!rc || rc == bufsize || rc > max)
      break;

    /* if rc < bufsize then rc excludes the terminating null */
    if(rc < bufsize) {
#ifdef UNICODE
      result = curlx_convert_wchar_to_UTF8(buf);
#else
      result = buf;
      buf = NULL;
#endif
      break;
    }

    /* else rc is characters needed, try again */
  }

  curlx_free(buf);
#ifdef UNICODE
  curlx_free(name);
#endif
  return result;
#else
  char *env = getenv(variable);
  return (env && env[0]) ? curlx_strdup(env) : NULL;
#endif
}
