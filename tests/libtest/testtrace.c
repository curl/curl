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
#include "testtrace.h"

#include "memdebug.h"

struct libtest_trace_cfg debug_config;

static time_t epoch_offset; /* for test time tracing */
static int    known_offset; /* for test time tracing */

void debug_dump(const char *timebuf, const char *text,
                FILE *stream, const unsigned char *ptr,
                size_t size, bool nohex)
{
  size_t i;
  size_t c;

  unsigned int width = 0x10;

  if(nohex)
    /* without the hex output, we can fit more on screen */
    width = 0x40;

  curl_mfprintf(stream, "%s%s, %zu bytes (0x%zx)\n", timebuf, text,
                size, size);

  for(i = 0; i < size; i += width) {

    curl_mfprintf(stream, "%04zx: ", i);

    if(!nohex) {
      /* hex not disabled, show it */
      for(c = 0; c < width; c++)
        if(i + c < size)
          curl_mfprintf(stream, "%02x ", ptr[i + c]);
        else
          fputs("   ", stream);
    }

    for(c = 0; (c < width) && (i + c < size); c++) {
      /* check for 0D0A; if found, skip past and start a new line of output */
      if(nohex && (i + c + 1 < size) && ptr[i + c] == 0x0D &&
         ptr[i + c + 1] == 0x0A) {
        i += (c + 2 - width);
        break;
      }
      curl_mfprintf(stream, "%c",
                    ((ptr[i + c] >= 0x20) && (ptr[i + c] < 0x80)) ?
                    ptr[i + c] : '.');
      /* check again for 0D0A, to avoid an extra \n if it's at width */
      if(nohex && (i + c + 2 < size) && ptr[i + c + 1] == 0x0D &&
         ptr[i + c + 2] == 0x0A) {
        i += (c + 3 - width);
        break;
      }
    }
    fputc('\n', stream); /* newline */
  }
  fflush(stream);
}

int libtest_debug_cb(CURL *handle, curl_infotype type,
                     char *data, size_t size, void *userp)
{
  struct libtest_trace_cfg *trace_cfg = userp;
  const char *text;
  char timebuf[20];
  char *timestr;

  (void)handle;

  timebuf[0] = '\0';
  timestr = &timebuf[0];

  if(trace_cfg->tracetime) {
    struct tm *now;
    struct curltime tv;
    time_t secs;
    tv = curlx_now();
    if(!known_offset) {
      epoch_offset = time(NULL) - tv.tv_sec;
      known_offset = 1;
    }
    secs = epoch_offset + tv.tv_sec;
    /* !checksrc! disable BANNEDFUNC 1 */
    now = localtime(&secs);  /* not thread safe but we don't care */
    curl_msnprintf(timebuf, sizeof(timebuf), "%02d:%02d:%02d.%06ld ",
                   now->tm_hour, now->tm_min, now->tm_sec, (long)tv.tv_usec);
  }

  switch(type) {
  case CURLINFO_TEXT:
    curl_mfprintf(stderr, "%s== Info: %s", timestr, data);
    return 0;
  case CURLINFO_HEADER_OUT:
    text = "=> Send header";
    break;
  case CURLINFO_DATA_OUT:
    text = "=> Send data";
    break;
  case CURLINFO_SSL_DATA_OUT:
    text = "=> Send SSL data";
    break;
  case CURLINFO_HEADER_IN:
    text = "<= Recv header";
    break;
  case CURLINFO_DATA_IN:
    text = "<= Recv data";
    break;
  case CURLINFO_SSL_DATA_IN:
    text = "<= Recv SSL data";
    break;
  default: /* in case a new one is introduced to shock us */
    return 0;
  }

  debug_dump(timebuf, text, stderr, (const unsigned char *)data, size,
             trace_cfg->nohex);
  return 0;
}

static void log_line_start(FILE *log, const char *idsbuf, curl_infotype type)
{
  /*
   * This is the trace look that is similar to what libcurl makes on its
   * own.
   */
  static const char * const s_infotype[] = {
    "* ", "< ", "> ", "{ ", "} ", "{ ", "} "
  };
  if(idsbuf && *idsbuf)
    curl_mfprintf(log, "%s%s", idsbuf, s_infotype[type]);
  else
    fputs(s_infotype[type], log);
}

/* callback for CURLOPT_DEBUGFUNCTION (used in client tests) */
int cli_debug_cb(CURL *handle, curl_infotype type,
                 char *data, size_t size, void *userp)
{
  FILE *output = stderr;
  static int newl = 0;
  static int traced_data = 0;
  char idsbuf[60];
  curl_off_t xfer_id, conn_id;

  (void)handle;
  (void)userp;

  if(!curl_easy_getinfo(handle, CURLINFO_XFER_ID, &xfer_id) && xfer_id >= 0) {
    if(!curl_easy_getinfo(handle, CURLINFO_CONN_ID, &conn_id) &&
       conn_id >= 0) {
      curl_msnprintf(idsbuf, sizeof(idsbuf),
                     "[%" CURL_FORMAT_CURL_OFF_T "-"
                      "%" CURL_FORMAT_CURL_OFF_T "] ", xfer_id, conn_id);
    }
    else {
      curl_msnprintf(idsbuf, sizeof(idsbuf),
                     "[%" CURL_FORMAT_CURL_OFF_T "-x] ", xfer_id);
    }
  }
  else
    idsbuf[0] = 0;

  switch(type) {
  case CURLINFO_HEADER_OUT:
    if(size > 0) {
      size_t st = 0;
      size_t i;
      for(i = 0; i < size - 1; i++) {
        if(data[i] == '\n') { /* LF */
          if(!newl) {
            log_line_start(output, idsbuf, type);
          }
          (void)fwrite(data + st, i - st + 1, 1, output);
          st = i + 1;
          newl = 0;
        }
      }
      if(!newl)
        log_line_start(output, idsbuf, type);
      (void)fwrite(data + st, i - st + 1, 1, output);
    }
    newl = (size && (data[size - 1] != '\n')) ? 1 : 0;
    traced_data = 0;
    break;
  case CURLINFO_TEXT:
  case CURLINFO_HEADER_IN:
    if(!newl)
      log_line_start(output, idsbuf, type);
    (void)fwrite(data, size, 1, output);
    newl = (size && (data[size - 1] != '\n')) ? 1 : 0;
    traced_data = 0;
    break;
  case CURLINFO_DATA_OUT:
  case CURLINFO_DATA_IN:
  case CURLINFO_SSL_DATA_IN:
  case CURLINFO_SSL_DATA_OUT:
    if(!traced_data) {
      if(!newl)
        log_line_start(output, idsbuf, type);
      curl_mfprintf(output, "[%zu bytes data]\n", size);
      newl = 0;
      traced_data = 1;
    }
    break;
  default: /* nada */
    newl = 0;
    traced_data = 1;
    break;
  }

  return 0;
}
