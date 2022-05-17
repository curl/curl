/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * using the multi interface to do a multipart formpost without blocking
 * </DESC>
 */

#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include <curl/curl.h>

int main(void)
{
  CURL *curl;

  CURLM *multi_handle;
  int still_running = 0;

  curl_mime *form = NULL;
  curl_mimepart *field = NULL;
  struct curl_slist *headerlist = NULL;
  static const char buf[] = "Expect:";

  curl = curl_easy_init();
  multi_handle = curl_multi_init();

  if(curl && multi_handle) {
    /* Create the form */
    form = curl_mime_init(curl);

    /* Fill in the file upload field */
    field = curl_mime_addpart(form);
    curl_mime_name(field, "sendfile");
    curl_mime_filedata(field, "multi-post.c");

    /* Fill in the filename field */
    field = curl_mime_addpart(form);
    curl_mime_name(field, "filename");
    curl_mime_data(field, "multi-post.c", CURL_ZERO_TERMINATED);

    /* Fill in the submit field too, even if this is rarely needed */
    field = curl_mime_addpart(form);
    curl_mime_name(field, "submit");
    curl_mime_data(field, "send", CURL_ZERO_TERMINATED);

    /* initialize custom header list (stating that Expect: 100-continue is not
       wanted */
    headerlist = curl_slist_append(headerlist, buf);

    /* what URL that receives this POST */
    curl_easy_setopt(curl, CURLOPT_URL, "https://www.example.com/upload.cgi");
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);

    curl_multi_add_handle(multi_handle, curl);

    do {
      CURLMcode mc = curl_multi_perform(multi_handle, &still_running);

      if(still_running)
        /* wait for activity, timeout or "nothing" */
        mc = curl_multi_poll(multi_handle, NULL, 0, 1000, NULL);

      if(mc)
        break;
    } while(still_running);

    curl_multi_cleanup(multi_handle);

    /* always cleanup */
    curl_easy_cleanup(curl);

    /* then cleanup the form */
    curl_mime_free(form);

    /* free slist */
    curl_slist_free_all(headerlist);
  }
  return 0;
}
