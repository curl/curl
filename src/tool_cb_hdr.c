/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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

#include "strcase.h"

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_doswin.h"
#include "tool_msgs.h"
#include "tool_cb_hdr.h"

#include "memdebug.h" /* keep this as LAST include */

static char *parse_filename(const char *ptr, size_t len);

/*
** callback for CURLOPT_HEADERFUNCTION
*/

size_t tool_header_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
  struct HdrCbData *hdrcbdata = userdata;
  struct OutStruct *outs = hdrcbdata->outs;
  struct OutStruct *heads = hdrcbdata->heads;
  const char *str = ptr;
  const size_t cb = size * nmemb;
  const char *end = (char *)ptr + cb;
  char *url = NULL;

  /*
   * Once that libcurl has called back tool_header_cb() the returned value
   * is checked against the amount that was intended to be written, if
   * it does not match then it fails with CURLE_WRITE_ERROR. So at this
   * point returning a value different from sz*nmemb indicates failure.
   */
  size_t failure = (size * nmemb) ? 0 : 1;

  if(!heads->config)
    return failure;

#ifdef DEBUGBUILD
  if(size * nmemb > (size_t)CURL_MAX_HTTP_HEADER) {
    warnf(heads->config->global, "Header data exceeds single call write "
          "limit!\n");
    return failure;
  }
#endif

  /*
   * Write header data when curl option --dump-header (-D) is given.
   */

  if(heads->config->headerfile && heads->stream) {
    size_t rc = fwrite(ptr, size, nmemb, heads->stream);
    if(rc != cb)
      return rc;
    /* flush the stream to send off what we got earlier */
    (void)fflush(heads->stream);
  }

  /*
   * This callback sets the filename where output shall be written when
   * curl options --remote-name (-O) and --remote-header-name (-J) have
   * been simultaneously given and additionally server returns an HTTP
   * Content-Disposition header specifying a filename property.
   */

  if(hdrcbdata->honor_cd_filename &&
     (cb > 20) && checkprefix("Content-disposition:", str) &&
     !curl_easy_getinfo(outs->config->easy, CURLINFO_EFFECTIVE_URL, &url) &&
     url && (checkprefix("http://", url) || checkprefix("https://", url))) {
    const char *p = str + 20;

    /* look for the 'filename=' parameter
       (encoded filenames (*=) are not supported) */
    for(;;) {
      char *filename;
      size_t len;

      while(*p && (p < end) && !ISALPHA(*p))
        p++;
      if(p > end - 9)
        break;

      if(memcmp(p, "filename=", 9)) {
        /* no match, find next parameter */
        while((p < end) && (*p != ';'))
          p++;
        continue;
      }
      p += 9;

      /* this expression below typecasts 'cb' only to avoid
         warning: signed and unsigned type in conditional expression
      */
      len = (ssize_t)cb - (p - str);
      filename = parse_filename(p, len);
      if(filename) {
        outs->filename = filename;
        outs->alloc_filename = TRUE;
        outs->is_cd_filename = TRUE;
        outs->s_isreg = TRUE;
        outs->fopened = FALSE;
        outs->stream = NULL;
        hdrcbdata->honor_cd_filename = FALSE;
        break;
      }
      else
        return failure;
    }
  }

  return cb;
}

/*
 * Copies a file name part and returns an ALLOCATED data buffer.
 */
static char *parse_filename(const char *ptr, size_t len)
{
  char *copy;
  char *p;
  char *q;
  char  stop = '\0';

  /* simple implementation of strndup() */
  copy = malloc(len+1);
  if(!copy)
    return NULL;
  memcpy(copy, ptr, len);
  copy[len] = '\0';

  p = copy;
  if(*p == '\'' || *p == '"') {
    /* store the starting quote */
    stop = *p;
    p++;
  }
  else
    stop = ';';

  /* if the filename contains a path, only use filename portion */
  q = strrchr(copy, '/');
  if(q) {
    p = q + 1;
    if(!*p) {
      Curl_safefree(copy);
      return NULL;
    }
  }

  /* If the filename contains a backslash, only use filename portion. The idea
     is that even systems that don't handle backslashes as path separators
     probably want the path removed for convenience. */
  q = strrchr(p, '\\');
  if(q) {
    p = q + 1;
    if(!*p) {
      Curl_safefree(copy);
      return NULL;
    }
  }

  /* scan for the end letter and stop there */
  for(q = p; *q; ++q) {
    if(*q == stop) {
      *q = '\0';
      break;
    }
  }

  /* make sure the file name doesn't end in \r or \n */
  q = strchr(p, '\r');
  if(q)
    *q = '\0';

  q = strchr(p, '\n');
  if(q)
    *q = '\0';

  if(copy != p)
    memmove(copy, p, strlen(p) + 1);

#if defined(MSDOS) || defined(WIN32)
  {
    char *sanitized;
    SANITIZEcode sc = sanitize_file_name(&sanitized, copy, 0);
    Curl_safefree(copy);
    if(sc)
      return NULL;
    copy = sanitized;
  }
#endif /* MSDOS || WIN32 */

  /* in case we built debug enabled, we allow an evironment variable
   * named CURL_TESTDIR to prefix the given file name to put it into a
   * specific directory
   */
#ifdef DEBUGBUILD
  {
    char *tdir = curlx_getenv("CURL_TESTDIR");
    if(tdir) {
      char buffer[512]; /* suitably large */
      snprintf(buffer, sizeof(buffer), "%s/%s", tdir, copy);
      Curl_safefree(copy);
      copy = strdup(buffer); /* clone the buffer, we don't use the libcurl
                                aprintf() or similar since we want to use the
                                same memory code as the "real" parse_filename
                                function */
      curl_free(tdir);
    }
  }
#endif

  return copy;
}

