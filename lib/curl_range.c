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
#include "curl_range.h"
#include "sendf.h"
#include "strparse.h"

/* Only include this function if one or more of FTP, FILE are enabled. */
#if !defined(CURL_DISABLE_FTP) || !defined(CURL_DISABLE_FILE)

 /*
  Check if this is a range download, and if so, set the internal variables
  properly.
 */
CURLcode Curl_range(struct Curl_easy *data)
{
  if(data->state.use_range && data->state.range) {
    curl_off_t from, to;
    bool first_num = TRUE;
    const char *p = data->state.range;
    if(Curl_str_number(&p, &from, CURL_OFF_T_MAX))
      first_num = FALSE;

    if(Curl_str_single(&p, '-'))
      /* no leading dash or after the first number is an error */
      return CURLE_RANGE_ERROR;

    if(Curl_str_number(&p, &to, CURL_OFF_T_MAX)) {
      /* no second number */
      /* X - */
      data->state.resume_from = from;
      DEBUGF(infof(data, "RANGE %" FMT_OFF_T " to end of file", from));
    }
    else if(!first_num) {
      /* -Y */
      if(!to)
        /* "-0" is just wrong */
        return CURLE_RANGE_ERROR;

      data->req.maxdownload = to;
      data->state.resume_from = -to;
      DEBUGF(infof(data, "RANGE the last %" FMT_OFF_T " bytes", to));
    }
    else {
      /* X-Y */
      curl_off_t totalsize;

      /* Ensure the range is sensible - to should follow from. */
      if(from > to)
        return CURLE_RANGE_ERROR;

      totalsize = to - from;
      if(totalsize == CURL_OFF_T_MAX)
        return CURLE_RANGE_ERROR;

      data->req.maxdownload = totalsize + 1; /* include last byte */
      data->state.resume_from = from;
      DEBUGF(infof(data, "RANGE from %" FMT_OFF_T
                   " getting %" FMT_OFF_T " bytes",
                   from, data->req.maxdownload));
    }
    DEBUGF(infof(data, "range-download from %" FMT_OFF_T
                 " to %" FMT_OFF_T ", totally %" FMT_OFF_T " bytes",
                 from, to, data->req.maxdownload));
  }
  else
    data->req.maxdownload = -1;
  return CURLE_OK;
}

#endif
