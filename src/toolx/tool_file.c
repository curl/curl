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
#include "tool_file.h"

#ifdef _WIN32
#include "curlx/multibyte.h"

#include <direct.h>

int toolx_win32_mkdir(const char *path)
{
  int result = -1;

#ifdef _UNICODE
  wchar_t *path_w = curlx_convert_UTF8_to_wchar(path);
  if(path_w) {
    result = _wmkdir(path_w);
    curlx_free(path_w);
  }
  else
    /* !checksrc! disable ERRNOVAR 1 */
    errno = EINVAL;
#else
  result = _mkdir(path);
#endif

  return result;
}
#endif /* _WIN32 */
