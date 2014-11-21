/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/*
 * This example uses the "Streaming HTML parser" to extract the href pieces in
 * a streaming manner from a downloaded HTML. Kindly donated by Michał
 * Kowalczyk.
 *
 * The parser is found at
 * http://code.google.com/p/htmlstreamparser/
 */

#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <htmlstreamparser.h>

#ifndef EXIT_SUCCESS
#define EXIT_SUCCESS 0
#endif
#ifndef EXIT_FAILURE
#define EXIT_FAILURE 1
#endif


static size_t write_callback(void *buffer, size_t size, size_t nmemb,
                             void *hsp)
{
  size_t realsize = size * nmemb, p;
  for (p = 0; p < realsize; p++) {
    html_parser_char_parse(hsp, ((char *)buffer)[p]);
    if (html_parser_cmp_tag(hsp, "a", 1))
      if (html_parser_cmp_attr(hsp, "href", 4))
        if (html_parser_is_in(hsp, HTML_VALUE_ENDED)) {
          html_parser_val(hsp)[html_parser_val_length(hsp)] = '\0';
          printf("%s\n", html_parser_val(hsp));
        }
  }
  return realsize;
}

int main(int argc, char *argv[])
{
  char tag[1], attr[4], val[128];
  CURL *curl;
  HTMLSTREAMPARSER *hsp;

  /* Call curl_global_init immediately after the program starts, while it is
  still only one thread and before it uses libcurl at all. If the function
  returns non-zero, something went wrong and you cannot use the other curl
  functions. */
  if(curl_global_init(CURL_GLOBAL_ALL)) {
    fprintf(stderr, "Fatal: The initialization of libcurl has failed.\n");
    return EXIT_FAILURE;
  }

  /* Call curl_global_cleanup immediately before the program exits, when the
  program is again only one thread and after its last use of libcurl. For
  example, you can use atexit to ensure the cleanup will be called at exit. */
  if(atexit(curl_global_cleanup)) {
    fprintf(stderr, "Fatal: atexit failed to register curl_global_cleanup.\n");
    curl_global_cleanup();
    return EXIT_FAILURE;
  }

  if (argc != 2) {
    printf("Usage: %s URL\n", argv[0]);
    return EXIT_FAILURE;
  }

  curl = curl_easy_init();

  hsp = html_parser_init();

  html_parser_set_tag_to_lower(hsp, 1);
  html_parser_set_attr_to_lower(hsp, 1);
  html_parser_set_tag_buffer(hsp, tag, sizeof(tag));
  html_parser_set_attr_buffer(hsp, attr, sizeof(attr));
  html_parser_set_val_buffer(hsp, val, sizeof(val)-1);

  curl_easy_setopt(curl, CURLOPT_URL, argv[1]);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, hsp);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

  curl_easy_perform(curl);

  curl_easy_cleanup(curl);

  html_parser_cleanup(hsp);

  return EXIT_SUCCESS;
}
