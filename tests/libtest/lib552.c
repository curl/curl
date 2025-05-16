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
/* argv1 = URL
 * argv2 = proxy with embedded user+password
 */

#include "test.h"

#include "warnless.h"
#include "memdebug.h"

struct testdata {
  char trace_ascii; /* 1 or 0 */
};

static
void dump(const char *text,
          FILE *stream, unsigned char *ptr, size_t size,
          char nohex)
{
  size_t i;
  size_t c;

  unsigned int width = 0x10;

  if(nohex)
    /* without the hex output, we can fit more on screen */
    width = 0x40;

  curl_mfprintf(stream, "%s, %zu bytes (0x%zx)\n", text, size, size);

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
              (ptr[i + c] >= 0x20) && (ptr[i + c] < 0x80) ? ptr[i + c] : '.');
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

static
int my_trace(CURL *handle, curl_infotype type,
             char *data, size_t size,
             void *userp)
{
  struct testdata *config = (struct testdata *)userp;
  const char *text;
  (void)handle; /* prevent compiler warning */

  switch(type) {
  case CURLINFO_TEXT:
    curl_mfprintf(stderr, "== Info: %s", (char *)data);
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

  dump(text, stderr, (unsigned char *)data, size, config->trace_ascii);
  return 0;
}


static size_t current_offset = 0;
static char databuf[70000]; /* MUST be more than 64k OR
                               MAX_INITIAL_POST_SIZE */

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t  amount = nmemb * size; /* Total bytes curl wants */
  size_t  available = sizeof(databuf) - current_offset; /* What we have to
                                                           give */
  size_t  given = amount < available ? amount : available; /* What is given */
  (void)stream;
  memcpy(ptr, databuf + current_offset, given);
  current_offset += given;
  return given;
}


static size_t write_callback(char *ptr, size_t size, size_t nmemb,
                             void *stream)
{
  int amount = curlx_uztosi(size * nmemb);
  curl_mprintf("%.*s", amount, (char *)ptr);
  (void)stream;
  return size * nmemb;
}


static curlioerr ioctl_callback(CURL *handle, int cmd, void *clientp)
{
  (void)clientp;
  if(cmd == CURLIOCMD_RESTARTREAD) {
    curl_mprintf("APPLICATION received a CURLIOCMD_RESTARTREAD request\n");
    curl_mprintf("APPLICATION ** REWINDING! **\n");
    current_offset = 0;
    return CURLIOE_OK;
  }
  (void)handle;
  return CURLIOE_UNKNOWNCMD;
}



CURLcode test(char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;
  struct testdata config;
  size_t i;
  static const char fill[] = "test data";

  config.trace_ascii = 1; /* enable ASCII tracing */

  global_init(CURL_GLOBAL_ALL);
  easy_init(curl);

  test_setopt(curl, CURLOPT_DEBUGFUNCTION, my_trace);
  test_setopt(curl, CURLOPT_DEBUGDATA, &config);
  /* the DEBUGFUNCTION has no effect until we enable VERBOSE */
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* setup repeated data string */
  for(i = 0; i < sizeof(databuf); ++i)
    databuf[i] = fill[i % sizeof(fill)];

  /* Post */
  test_setopt(curl, CURLOPT_POST, 1L);

  /* Setup read callback */
  test_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) sizeof(databuf));
  test_setopt(curl, CURLOPT_READFUNCTION, read_callback);

  /* Write callback */
  test_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

  /* Ioctl function */
  test_setopt(curl, CURLOPT_IOCTLFUNCTION, ioctl_callback);

  test_setopt(curl, CURLOPT_PROXY, libtest_arg2);

  test_setopt(curl, CURLOPT_URL, URL);

  /* Accept any auth. But for this bug configure proxy with DIGEST, basic
     might work too, not NTLM */
  test_setopt(curl, CURLOPT_PROXYAUTH, (long)CURLAUTH_ANY);

  res = curl_easy_perform(curl);

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return res;
}
