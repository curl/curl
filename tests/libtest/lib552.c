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
 * are also available at https://fetch.se/docs/copyright.html.
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

  fprintf(stream, "%s, %zu bytes (0x%zx)\n", text, size, size);

  for(i = 0; i < size; i += width) {

    fprintf(stream, "%04zx: ", i);

    if(!nohex) {
      /* hex not disabled, show it */
      for(c = 0; c < width; c++)
        if(i + c < size)
          fprintf(stream, "%02x ", ptr[i + c]);
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
      fprintf(stream, "%c",
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
int my_trace(FETCH *handle, fetch_infotype type,
             char *data, size_t size,
             void *userp)
{
  struct testdata *config = (struct testdata *)userp;
  const char *text;
  (void)handle; /* prevent compiler warning */

  switch(type) {
  case FETCHINFO_TEXT:
    fprintf(stderr, "== Info: %s", (char *)data);
    return 0;
  case FETCHINFO_HEADER_OUT:
    text = "=> Send header";
    break;
  case FETCHINFO_DATA_OUT:
    text = "=> Send data";
    break;
  case FETCHINFO_SSL_DATA_OUT:
    text = "=> Send SSL data";
    break;
  case FETCHINFO_HEADER_IN:
    text = "<= Recv header";
    break;
  case FETCHINFO_DATA_IN:
    text = "<= Recv data";
    break;
  case FETCHINFO_SSL_DATA_IN:
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
  size_t  amount = nmemb * size; /* Total bytes fetch wants */
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
  int amount = fetchx_uztosi(size * nmemb);
  printf("%.*s", amount, (char *)ptr);
  (void)stream;
  return size * nmemb;
}


static fetchioerr ioctl_callback(FETCH *handle, int cmd, void *clientp)
{
  (void)clientp;
  if(cmd == FETCHIOCMD_RESTARTREAD) {
    printf("APPLICATION received a FETCHIOCMD_RESTARTREAD request\n");
    printf("APPLICATION ** REWINDING! **\n");
    current_offset = 0;
    return FETCHIOE_OK;
  }
  (void)handle;
  return FETCHIOE_UNKNOWNCMD;
}



FETCHcode test(char *URL)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;
  struct testdata config;
  size_t i;
  static const char fill[] = "test data";

  config.trace_ascii = 1; /* enable ASCII tracing */

  global_init(FETCH_GLOBAL_ALL);
  easy_init(fetch);

  test_setopt(fetch, FETCHOPT_DEBUGFUNCTION, my_trace);
  test_setopt(fetch, FETCHOPT_DEBUGDATA, &config);
  /* the DEBUGFUNCTION has no effect until we enable VERBOSE */
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);

  /* setup repeated data string */
  for(i = 0; i < sizeof(databuf); ++i)
    databuf[i] = fill[i % sizeof(fill)];

  /* Post */
  test_setopt(fetch, FETCHOPT_POST, 1L);

  /* Setup read callback */
  test_setopt(fetch, FETCHOPT_POSTFIELDSIZE, (long) sizeof(databuf));
  test_setopt(fetch, FETCHOPT_READFUNCTION, read_callback);

  /* Write callback */
  test_setopt(fetch, FETCHOPT_WRITEFUNCTION, write_callback);

  /* Ioctl function */
  FETCH_IGNORE_DEPRECATION(
    test_setopt(fetch, FETCHOPT_IOCTLFUNCTION, ioctl_callback);
  )

  test_setopt(fetch, FETCHOPT_PROXY, libtest_arg2);

  test_setopt(fetch, FETCHOPT_URL, URL);

  /* Accept any auth. But for this bug configure proxy with DIGEST, basic
     might work too, not NTLM */
  test_setopt(fetch, FETCHOPT_PROXYAUTH, (long)FETCHAUTH_ANY);

  res = fetch_easy_perform(fetch);

test_cleanup:

  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();
  return res;
}
