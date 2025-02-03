#ifndef HEADER_FETCH_FORMDATA_H
#define HEADER_FETCH_FORMDATA_H
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

#ifndef FETCH_DISABLE_FORM_API

/* used by FormAdd for temporary storage */
struct FormInfo
{
  char *name;
  size_t namelength;
  char *value;
  fetch_off_t contentslength;
  char *contenttype;
  long flags;
  char *buffer; /* pointer to existing buffer used for file upload */
  size_t bufferlength;
  char *showfilename; /* The filename to show. If not set, the actual
                         filename will be used */
  char *userp;        /* pointer for the read callback */
  struct fetch_slist *contentheader;
  struct FormInfo *more;
  bool name_alloc;
  bool value_alloc;
  bool contenttype_alloc;
  bool showfilename_alloc;
};

FETCHcode Curl_getformdata(FETCH *data,
                           fetch_mimepart *,
                           struct fetch_httppost *post,
                           fetch_read_callback fread_func);
#endif /* FETCH_DISABLE_FORM_API */

#endif /* HEADER_FETCH_FORMDATA_H */
