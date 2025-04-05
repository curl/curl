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
#ifndef CURL_DISABLE_FTP
#include "strdup.h"
#include "fileinfo.h"
#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

struct fileinfo *Curl_fileinfo_alloc(void)
{
  return CALLOC(1, sizeof(struct fileinfo));
}

void Curl_fileinfo_cleanup(struct fileinfo *finfo)
{
  if(!finfo)
    return;

  Curl_dyn_free(&finfo->buf);
  FREE(finfo);
}
#endif
