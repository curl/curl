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
/* <DESC>
 * multi interface and debug callback
 * </DESC>
 */
#include <stdio.h>
#include <string.h>

#include <curl/curl.h>

#define TRUE 1

static void dump(const char *text, FILE *stream, const unsigned char *ptr,
                 size_t size, char nohex)
{
  size_t i;
  size_t c;

  unsigned int width = 0x10;

  if(nohex)
    /* without the hex output, we can fit more on screen */
    width = 0x40;

  fprintf(stream, "%s, %10.10lu bytes (0x%8.8lx)\n",
          text, (unsigned long)size, (unsigned long)size);

  for(i = 0; i < size; i += width) {

    fprintf(stream, "%4.4lx: ", (unsigned long)i);

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
      /* check again for 0D0A, to avoid an extra \n if it is at width */
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

static int my_trace(CURL *curl, curl_infotype type,
                    unsigned char *data, size_t size,
                    void *userp)
{
  const char *text;

  (void)userp;
  (void)curl;

  switch(type) {
  case CURLINFO_TEXT:
    fprintf(stderr, "== Info: %s", data);
    return 0;
  case CURLINFO_HEADER_OUT:
    text = "=> Send header";
    break;
  case CURLINFO_DATA_OUT:
    text = "=> Send data";
    break;
  case CURLINFO_HEADER_IN:
    text = "<= Recv header";
    break;
  case CURLINFO_DATA_IN:
    text = "<= Recv data";
    break;
  default: /* in case a new one is introduced to shock us */
    return 0;
  }

  dump(text, stderr, data, size, TRUE);
  return 0;
}

/*
 * Simply download an HTTP file.
 */
int main(void)
{
  CURL *curl;

  CURLcode result = curl_global_init(CURL_GLOBAL_ALL);
  if(result)
    return (int)result;

  curl = curl_easy_init();
  if(curl) {

    CURLM *multi;

    /* set the options (I left out a few, you get the point anyway) */
    curl_easy_setopt(curl, CURLOPT_URL, "https://www.example.com/");

    curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, my_trace);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    /* init a multi stack */
    multi = curl_multi_init();
    if(multi) {

      int still_running = 0; /* keep number of running handles */

      /* add the individual transfers */
      curl_multi_add_handle(multi, curl);

      do {
        CURLMcode mresult = curl_multi_perform(multi, &still_running);

        if(still_running)
          /* wait for activity, timeout or "nothing" */
          mresult = curl_multi_poll(multi, NULL, 0, 1000, NULL);

        if(mresult)
          break;

      } while(still_running);

      curl_multi_cleanup(multi);
    }

    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return 0;
}
