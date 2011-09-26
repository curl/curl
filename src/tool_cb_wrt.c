/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "setup.h"

#include <curl/curl.h>

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_msgs.h"
#include "tool_cb_wrt.h"

#include "memdebug.h" /* keep this as LAST include */

/*
** callback for CURLOPT_WRITEFUNCTION
*/

size_t tool_write_cb(void *buffer, size_t sz, size_t nmemb, void *userdata)
{
  size_t rc;
  struct OutStruct *out = userdata;
  struct Configurable *config = out->config;

  /*
   * Once that libcurl has called back tool_write_cb() the returned value
   * is checked against the amount that was intended to be written, if
   * it does not match then it fails with CURLE_WRITE_ERROR. So at this
   * point returning a value different from sz*nmemb indicates failure.
   */
  const size_t err_rc = (sz * nmemb) ? 0 : 1;

  if(!out->stream) {
    out->bytes = 0; /* nothing written yet */
    if(!out->filename) {
      warnf(config, "Remote filename has no length!\n");
      return err_rc; /* Failure */
    }

    if(config->content_disposition) {
      /* don't overwrite existing files */
      FILE* f = fopen(out->filename, "r");
      if(f) {
        fclose(f);
        warnf(config, "Refusing to overwrite %s: %s\n", out->filename,
              strerror(EEXIST));
        return err_rc; /* Failure */
      }
    }

    /* open file for writing */
    out->stream = fopen(out->filename, "wb");
    if(!out->stream) {
      warnf(config, "Failed to create the file %s: %s\n", out->filename,
            strerror(errno));
      return err_rc; /* failure */
    }
  }

  rc = fwrite(buffer, sz, nmemb, out->stream);

  if((sz * nmemb) == rc)
    /* we added this amount of data to the output */
    out->bytes += (sz * nmemb);

  if(config->readbusy) {
    config->readbusy = FALSE;
    curl_easy_pause(config->easy, CURLPAUSE_CONT);
  }

  if(config->nobuffer) {
    /* disable output buffering */
    int res = fflush(out->stream);
    if(res) {
      /* return a value that isn't the same as sz * nmemb */
      return err_rc; /* failure */
    }
  }

  return rc;
}

