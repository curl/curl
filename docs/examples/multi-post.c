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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
/* <DESC>
 * using the multi interface to do a multipart formpost without blocking
 * </DESC>
 */

#include <stdio.h>
#include <string.h>

#include <fetch/fetch.h>

int main(void)
{
  FETCH *fetch;

  FETCHM *multi_handle;
  int still_running = 0;

  fetch_mime *form = NULL;
  fetch_mimepart *field = NULL;
  struct fetch_slist *headerlist = NULL;
  static const char buf[] = "Expect:";

  fetch = fetch_easy_init();
  multi_handle = fetch_multi_init();

  if (fetch && multi_handle)
  {
    /* Create the form */
    form = fetch_mime_init(fetch);

    /* Fill in the file upload field */
    field = fetch_mime_addpart(form);
    fetch_mime_name(field, "sendfile");
    fetch_mime_filedata(field, "multi-post.c");

    /* Fill in the filename field */
    field = fetch_mime_addpart(form);
    fetch_mime_name(field, "filename");
    fetch_mime_data(field, "multi-post.c", FETCH_ZERO_TERMINATED);

    /* Fill in the submit field too, even if this is rarely needed */
    field = fetch_mime_addpart(form);
    fetch_mime_name(field, "submit");
    fetch_mime_data(field, "send", FETCH_ZERO_TERMINATED);

    /* initialize custom header list (stating that Expect: 100-continue is not
       wanted */
    headerlist = fetch_slist_append(headerlist, buf);

    /* what URL that receives this POST */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://www.example.com/upload.cgi");
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);

    fetch_easy_setopt(fetch, FETCHOPT_HTTPHEADER, headerlist);
    fetch_easy_setopt(fetch, FETCHOPT_MIMEPOST, form);

    fetch_multi_add_handle(multi_handle, fetch);

    do
    {
      FETCHMcode mc = fetch_multi_perform(multi_handle, &still_running);

      if (still_running)
        /* wait for activity, timeout or "nothing" */
        mc = fetch_multi_poll(multi_handle, NULL, 0, 1000, NULL);

      if (mc)
        break;
    } while (still_running);

    fetch_multi_cleanup(multi_handle);

    /* always cleanup */
    fetch_easy_cleanup(fetch);

    /* then cleanup the form */
    fetch_mime_free(form);

    /* free slist */
    fetch_slist_free_all(headerlist);
  }
  return 0;
}
