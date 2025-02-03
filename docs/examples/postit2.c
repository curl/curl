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
 * HTTP Multipart formpost with file upload and two additional parts.
 * </DESC>
 */
/* Example code that uploads a filename 'foo' to a remote script that accepts
 * "HTML form based" (as described in RFC 1738) uploads using HTTP POST.
 *
 * The imaginary form we fill in looks like:
 *
 * <form method="post" enctype="multipart/form-data" action="examplepost.cgi">
 * Enter file: <input type="file" name="sendfile" size="40">
 * Enter filename: <input type="text" name="filename" size="30">
 * <input type="submit" value="send" name="submit">
 * </form>
 *
 */

#include <stdio.h>
#include <string.h>

#include <fetch/fetch.h>

int main(int argc, char *argv[])
{
  FETCH *fetch;
  FETCHcode res;

  fetch_mime *form = NULL;
  fetch_mimepart *field = NULL;
  struct fetch_slist *headerlist = NULL;
  static const char buf[] = "Expect:";

  fetch_global_init(FETCH_GLOBAL_ALL);

  fetch = fetch_easy_init();
  if (fetch)
  {
    /* Create the form */
    form = fetch_mime_init(fetch);

    /* Fill in the file upload field */
    field = fetch_mime_addpart(form);
    fetch_mime_name(field, "sendfile");
    fetch_mime_filedata(field, "postit2.c");

    /* Fill in the filename field */
    field = fetch_mime_addpart(form);
    fetch_mime_name(field, "filename");
    fetch_mime_data(field, "postit2.c", FETCH_ZERO_TERMINATED);

    /* Fill in the submit field too, even if this is rarely needed */
    field = fetch_mime_addpart(form);
    fetch_mime_name(field, "submit");
    fetch_mime_data(field, "send", FETCH_ZERO_TERMINATED);

    /* initialize custom header list (stating that Expect: 100-continue is not
       wanted */
    headerlist = fetch_slist_append(headerlist, buf);
    /* what URL that receives this POST */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/examplepost.cgi");
    if ((argc == 2) && (!strcmp(argv[1], "noexpectheader")))
      /* only disable 100-continue header if explicitly requested */
      fetch_easy_setopt(fetch, FETCHOPT_HTTPHEADER, headerlist);
    fetch_easy_setopt(fetch, FETCHOPT_MIMEPOST, form);

    /* Perform the request, res gets the return code */
    res = fetch_easy_perform(fetch);
    /* Check for errors */
    if (res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));

    /* always cleanup */
    fetch_easy_cleanup(fetch);

    /* then cleanup the form */
    fetch_mime_free(form);
    /* free slist */
    fetch_slist_free_all(headerlist);
  }
  return 0;
}
