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

#include "getenv.h"
#include "curlx.h"

#ifdef BUILDING_LIBCURL
#include "curl_memory.h"
#endif
#include "memdebug.h"

#ifdef WIN32
/*
This function returns the environment variable value in the current locale or
Unicode UTF-8.

If 'utf8' is true then 'variable' and the returned value are Unicode UTF-8
instead of the current locale. That should only be true for Windows Unicode
builds, since Windows does not allow setting the current locale to UTF-8.

Windows API GetEnvironmentVariableW is used instead of C runtime getenv()
since some changes aren't always visible to the latter (#4774) and also
because getenv cannot retrieve Unicode.

The API function is called in a loop because the environment can be
modified by a different thread and have a different size between calls.
*/
static char *win32_getenv(const char *variable, bool utf8)
{
  WCHAR *tmp;
  WCHAR *w_var = NULL;
  WCHAR *buf = NULL;
  DWORD bufsize; /* size of buf in chars */
  DWORD rc = 256; /* number of chars to resize buf, 256 to start */
  const DWORD maxsize = 32768; /* max env var chars from MSCRT source */

#ifndef _UNICODE
  /* utf-8 in non-unicode builds is unexpected, assume it's a mistake */
  DEBUGASSERT(!utf8);
#endif

  if(utf8)
    w_var = curlx_convert_UTF8_to_wchar(variable);
  else
    w_var = curlx_convert_ANSI_to_wchar(variable);

  if(!w_var)
    return NULL;

  for(;;) {
    tmp = realloc(buf, rc * sizeof(WCHAR));
    if(!tmp) {
      free(buf);
      curlx_unicodefree(w_var);
      return NULL;
    }

    buf = tmp;
    bufsize = rc;

    /* It's possible for rc to be 0 if the variable was found but empty.
       Since getenv doesn't make that distinction we ignore it as well. */
    rc = GetEnvironmentVariableW(w_var, buf, bufsize);
    if(!rc || rc == bufsize || rc > maxsize) {
      free(buf);
      curlx_unicodefree(w_var);
      return NULL;
    }

    /* if rc < bufsize then rc is chars written not including null */
    if(rc < bufsize) {
      char *convbuf;
      char *dupe = NULL;

      if(utf8)
        convbuf = curlx_convert_wchar_to_UTF8(buf);
      else
        convbuf = curlx_convert_wchar_to_ANSI(buf);

      if(convbuf)
        dupe = strdup(convbuf);

      free(buf);
      curlx_unicodefree(w_var);
      curlx_unicodefree(convbuf);

      return dupe;
    }

    /* else rc is chars needed, try again */
  }
}

#ifdef _UNICODE
char *Curl_getenv_utf8(const char *variable)
{
  return win32_getenv(variable, true);
}
bool Curl_env_exist_utf8(const char *variable)
{
  char *p = Curl_getenv_utf8(variable);
  free(p);
  return p ? true : false;
}
#endif /* _UNICODE */
#endif /* WIN32 */

char *Curl_getenv_local(const char *variable)
{
#if defined(_WIN32_WCE) || defined(CURL_WINDOWS_APP)
  (void)variable;
  return NULL;
#elif defined(WIN32)
  return win32_getenv(variable, false);
#else
  /* !checksrc! disable BANNEDFUNC 1 */
  char *env = getenv(variable);
  return (env && env[0])?strdup(env):NULL;
#endif
}

bool Curl_env_exist_local(const char *variable)
{
  char *p = Curl_getenv_local(variable);
  free(p);
  return p ? true : false;
}

#ifdef BUILDING_LIBCURL
/* !checksrc! disable BANNEDFUNC 1 */
char *curl_getenv(const char *v)
{
  return Curl_getenv_local(v);
}
#endif
