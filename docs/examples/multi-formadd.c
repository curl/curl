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
 * using the multi interface to do a multipart formpost without blocking
 * </DESC>
 */

/*
 * Warning: this example uses the deprecated form api. See "multi-post.c"
 *          for a similar example using the mime api.
 */

#include <stdio.h>
#include <string.h>

#include <fetch/fetch.h>

int main(void)
{
  FETCH *fetch;

  FETCHM *multi_handle;
  int still_running = 0;

  struct fetch_httppost *formpost = NULL;
  struct fetch_httppost *lastptr = NULL;
  struct fetch_slist *headerlist = NULL;
  static const char buf[] = "Expect:";

  FETCH_IGNORE_DEPRECATION(
      /* Fill in the file upload field. This makes libfetch load data from
         the given file name when fetch_easy_perform() is called. */
      fetch_formadd(&formpost,
                    &lastptr,
                    FETCHFORM_COPYNAME, "sendfile",
                    FETCHFORM_FILE, "multi-formadd.c",
                    FETCHFORM_END);

      /* Fill in the filename field */
      fetch_formadd(&formpost,
                    &lastptr,
                    FETCHFORM_COPYNAME, "filename",
                    FETCHFORM_COPYCONTENTS, "multi-formadd.c",
                    FETCHFORM_END);

      /* Fill in the submit field too, even if this is rarely needed */
      fetch_formadd(&formpost,
                    &lastptr,
                    FETCHFORM_COPYNAME, "submit",
                    FETCHFORM_COPYCONTENTS, "send",
                    FETCHFORM_END);)

  fetch = fetch_easy_init();
  multi_handle = fetch_multi_init();

  /* initialize custom header list (stating that Expect: 100-continue is not
     wanted */
  headerlist = fetch_slist_append(headerlist, buf);
  if (fetch && multi_handle)
  {

    /* what URL that receives this POST */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://www.example.com/upload.cgi");
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);

    fetch_easy_setopt(fetch, FETCHOPT_HTTPHEADER, headerlist);
    FETCH_IGNORE_DEPRECATION(
        fetch_easy_setopt(fetch, FETCHOPT_HTTPPOST, formpost);)

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

    FETCH_IGNORE_DEPRECATION(
        /* then cleanup the formpost chain */
        fetch_formfree(formpost);)

    /* free slist */
    fetch_slist_free_all(headerlist);
  }
  return 0;
}
