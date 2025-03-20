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
#include <curl/curl.h>
#include "testutil.h"
#include "memdebug.h"

#ifdef _WIN32
HMODULE win32_load_system_library(const TCHAR *filename)
{
#if defined(CURL_WINDOWS_UWP) || defined(UNDER_CE)
  (void)filename;
  return NULL;
#else
  size_t filenamelen = _tcslen(filename);
  size_t systemdirlen = GetSystemDirectory(NULL, 0);
  size_t written;
  TCHAR *path;

  if(!filenamelen || filenamelen > 32768 ||
     !systemdirlen || systemdirlen > 32768)
    return NULL;

  /* systemdirlen includes null character */
  path = malloc(sizeof(TCHAR) * (systemdirlen + 1 + filenamelen));
  if(!path)
    return NULL;

  /* if written >= systemdirlen then nothing was written */
  written = GetSystemDirectory(path, (unsigned int)systemdirlen);
  if(!written || written >= systemdirlen)
    return NULL;

  if(path[written - 1] != _T('\\'))
    path[written++] = _T('\\');

  _tcscpy(path + written, filename);

  return LoadLibrary(path);
#endif
}
#endif
