/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "tool_setup.h"

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
  struct OutStruct *outs = userdata;
  struct Configurable *config = outs->config;

  /*
   * Once that libcurl has called back tool_write_cb() the returned value
   * is checked against the amount that was intended to be written, if
   * it does not match then it fails with CURLE_WRITE_ERROR. So at this
   * point returning a value different from sz*nmemb indicates failure.
   */
  const size_t failure = (sz * nmemb) ? 0 : 1;

  if(!config)
    return failure;

#ifdef DEBUGBUILD
  if(config->include_headers) {
    if(sz * nmemb > (size_t)CURL_MAX_HTTP_HEADER) {
      warnf(config, "Header data size exceeds single call write limit!\n");
      return failure;
    }
  }
  else {
    if(sz * nmemb > (size_t)CURL_MAX_WRITE_SIZE) {
      warnf(config, "Data size exceeds single call write limit!\n");
      return failure;
    }
  }

  {
    /* Some internal congruency checks on received OutStruct */
    bool check_fails = FALSE;
    if(outs->filename) {
      /* regular file */
      if(!*outs->filename)
        check_fails = TRUE;
      if(!outs->s_isreg)
        check_fails = TRUE;
      if(outs->fopened && !outs->stream)
        check_fails = TRUE;
      if(!outs->fopened && outs->stream)
        check_fails = TRUE;
      if(!outs->fopened && outs->bytes)
        check_fails = TRUE;
    }
    else {
      /* standard stream */
      if(!outs->stream || outs->s_isreg || outs->fopened)
        check_fails = TRUE;
      if(outs->alloc_filename || outs->is_cd_filename || outs->init)
        check_fails = TRUE;
    }
    if(check_fails) {
      warnf(config, "Invalid output struct data for write callback\n");
      return failure;
    }
  }
#endif

  if(!outs->stream) {
    FILE *file;

    if(!outs->filename || !*outs->filename) {
      warnf(config, "Remote filename has no length!\n");
      return failure;
    }

    if(outs->is_cd_filename) {
      /* don't overwrite existing files */
      file = fopen(outs->filename, "rb");
      if(file) {
        fclose(file);
        warnf(config, "Refusing to overwrite %s: %s\n", outs->filename,
              strerror(EEXIST));
        return failure;
      }
    }

    /* open file for writing */
    file = fopen(outs->filename, "wb");
    if(!file) {
      warnf(config, "Failed to create the file %s: %s\n", outs->filename,
            strerror(errno));
      return failure;
    }
    outs->s_isreg = TRUE;
    outs->fopened = TRUE;
    outs->stream = file;
    outs->bytes = 0;
    outs->init = 0;
  }

  rc = fwrite(buffer, sz, nmemb, outs->stream);

  if((sz * nmemb) == rc)
    /* we added this amount of data to the output */
    outs->bytes += (sz * nmemb);

  if(config->readbusy) {
    config->readbusy = FALSE;
    curl_easy_pause(config->easy, CURLPAUSE_CONT);
  }

  if(config->nobuffer) {
    /* output buffering disabled */
    int res = fflush(outs->stream);
    if(res)
      return failure;
  }

  return rc;
}

