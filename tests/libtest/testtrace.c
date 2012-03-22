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

#include "test.h"

#include "testutil.h"
#include "testtrace.h"
#include "memdebug.h"

struct libtest_trace_cfg libtest_debug_config;

static time_t epoch_offset; /* for test time tracing */
static int    known_offset; /* for test time tracing */

static 
void libtest_debug_dump(const char *timebuf, const char *text, FILE *stream,
                        const unsigned char *ptr, size_t size, int nohex)
{
  size_t i;
  size_t c;

  unsigned int width = 0x10;

  if(nohex)
    /* without the hex output, we can fit more on screen */
    width = 0x40;

  fprintf(stream, "%s%s, %d bytes (0x%x)\n", timebuf, text,
          (int)size, (int)size);

  for(i = 0; i < size; i += width) {

    fprintf(stream, "%04x: ", (int)i);

    if(!nohex) {
      /* hex not disabled, show it */
      for(c = 0; c < width; c++)
        if(i+c < size)
          fprintf(stream, "%02x ", ptr[i+c]);
        else
          fputs("   ", stream);
    }

    for(c = 0; (c < width) && (i+c < size); c++) {
      /* check for 0D0A; if found, skip past and start a new line of output */
      if(nohex &&
         (i+c+1 < size) && (ptr[i+c] == 0x0D) && (ptr[i+c+1] == 0x0A)) {
        i += (c+2-width);
        break;
      }
      fprintf(stream, "%c", ((ptr[i+c] >= 0x20) && (ptr[i+c] < 0x80)) ?
              ptr[i+c] : '.');
      /* check again for 0D0A, to avoid an extra \n if it's at width */
      if(nohex &&
         (i+c+2 < size) && (ptr[i+c+1] == 0x0D) && (ptr[i+c+2] == 0x0A)) {
        i += (c+3-width);
        break;
      }
    }
    fputc('\n', stream); /* newline */
  }
  fflush(stream);
}

int libtest_debug_cb(CURL *handle, curl_infotype type,
                     unsigned char *data, size_t size,
                     void *userp)
{

  struct libtest_trace_cfg *trace_cfg = userp;
  const char *text;
  struct timeval tv;
  struct tm *now;
  char timebuf[20];
  char *timestr;
  time_t secs;

  (void)handle;

  timebuf[0] = '\0';
  timestr = &timebuf[0];

  if(trace_cfg->tracetime) {
    tv = tutil_tvnow();
    if(!known_offset) {
      epoch_offset = time(NULL) - tv.tv_sec;
      known_offset = 1;
    }
    secs = epoch_offset + tv.tv_sec;
    now = localtime(&secs);  /* not thread safe but we don't care */
    snprintf(timebuf, sizeof(timebuf), "%02d:%02d:%02d.%06ld ",
             now->tm_hour, now->tm_min, now->tm_sec, (long)tv.tv_usec);
  }

  switch (type) {
  case CURLINFO_TEXT:
    fprintf(stderr, "%s== Info: %s", timestr, (char *)data);
  default: /* in case a new one is introduced to shock us */
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
  }

  libtest_debug_dump(timebuf, text, stderr, data, size, trace_cfg->nohex);
  return 0;
}

