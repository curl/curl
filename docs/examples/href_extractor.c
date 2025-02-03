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

/* <DESC>
 * Uses the "Streaming HTML parser" to extract the href pieces in a streaming
 * manner from a downloaded HTML.
 * </DESC>
 */
/*
 * The HTML parser is found at https://github.com/arjunc77/htmlstreamparser
 */

#include <stdio.h>
#include <fetch/fetch.h>
#include <htmlstreamparser.h>


static size_t write_callback(void *buffer, size_t size, size_t nmemb,
                             void *hsp)
{
  size_t realsize = size * nmemb, p;
  for(p = 0; p < realsize; p++) {
    html_parser_char_parse(hsp, ((char *)buffer)[p]);
    if(html_parser_cmp_tag(hsp, "a", 1))
      if(html_parser_cmp_attr(hsp, "href", 4))
        if(html_parser_is_in(hsp, HTML_VALUE_ENDED)) {
          html_parser_val(hsp)[html_parser_val_length(hsp)] = '\0';
          printf("%s\n", html_parser_val(hsp));
        }
  }
  return realsize;
}

int main(int argc, char *argv[])
{
  char tag[1], attr[4], val[128];
  FETCH *fetch;
  HTMLSTREAMPARSER *hsp;

  if(argc != 2) {
    printf("Usage: %s URL\n", argv[0]);
    return EXIT_FAILURE;
  }

  fetch = fetch_easy_init();

  hsp = html_parser_init();

  html_parser_set_tag_to_lower(hsp, 1);
  html_parser_set_attr_to_lower(hsp, 1);
  html_parser_set_tag_buffer(hsp, tag, sizeof(tag));
  html_parser_set_attr_buffer(hsp, attr, sizeof(attr));
  html_parser_set_val_buffer(hsp, val, sizeof(val)-1);

  fetch_easy_setopt(fetch, FETCHOPT_URL, argv[1]);
  fetch_easy_setopt(fetch, FETCHOPT_WRITEFUNCTION, write_callback);
  fetch_easy_setopt(fetch, FETCHOPT_WRITEDATA, hsp);
  fetch_easy_setopt(fetch, FETCHOPT_FOLLOWLOCATION, 1L);

  fetch_easy_perform(fetch);

  fetch_easy_cleanup(fetch);

  html_parser_cleanup(hsp);

  return EXIT_SUCCESS;
}
