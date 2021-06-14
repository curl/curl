/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

#include "curl_setup.h"

#include <curl/curl.h>
#include "curl_memory.h"

#include "memdebug.h"

#ifdef WIN32
static TCHAR *GetEnvWin32(const TCHAR *variable)
{
  /* This uses Windows API instead of C runtime getenv() to get the environment
     variable since some changes aren't always visible to the latter. #4774 */
  TCHAR *buf = NULL;
  TCHAR *tmp;
  DWORD bufsize;
  DWORD rc = 1;
  const DWORD max = 32768; /* max env var size from MSCRT source */

  for(;;) {
    tmp = (TCHAR*)realloc(buf, rc * sizeof(TCHAR));
    if(!tmp) {
      free(buf);
      return NULL;
    }

    buf = tmp;
    bufsize = rc;

    /* It's possible for rc to be 0 if the variable was found but empty.
       Since getenv doesn't make that distinction we ignore it as well. */
    rc = GetEnvironmentVariable(variable, buf, bufsize);
    if(!rc || rc == bufsize || rc > max) {
      free(buf);
      return NULL;
    }

    /* if rc < bufsize then rc is bytes written not including null */
    if(rc < bufsize) {
      return buf;
    }
    /* else rc is bytes needed, try again */
  }
}
#endif

static char *GetEnv(const char *variable)
{
#if defined(_WIN32_WCE) || defined(CURL_WINDOWS_APP)
  (void)variable;
  return NULL;
#elif defined(WIN32)
#ifdef UNICODE
  char *value = NULL;
  wchar_t *variable_w = curlx_convert_UTF8_to_wchar(variable);
  if(variable_w) {
    wchar_t *value_w = GetEnvWin32(variable_w);
    if(value_w) {
      value = curlx_convert_wchar_to_UTF8(value_w);
      free(value_w);
    }
    free(variable_w);
  }
  return value;
#else
  return GetEnvWin32(variable);
#endif
#else
  char *env = getenv(variable);
  return (env && env[0])?strdup(env):NULL;
#endif
}

char *curl_getenv(const char *v)
{
  return GetEnv(v);
}
