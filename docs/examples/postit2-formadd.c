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
 * HTTP Multipart formpost with file upload and two additional parts.
 * </DESC>
 */

/*
 * Example code that uploads a filename 'foo' to a remote script that accepts
 * "HTML form based" (as described in RFC 1738) uploads using HTTP POST.
 *
 * Warning: this example uses the deprecated form api. See "postit2.c"
 *          for a similar example using the mime api.
 *
 * The imaginary form we fill in looks like:
 *
 * <form method="post" enctype="multipart/form-data" action="examplepost.cgi">
 * Enter file: <input type="file" name="sendfile" size="40">
 * Enter filename: <input type="text" name="filename" size="30">
 * <input type="submit" value="send" name="submit">
 * </form>
 */

#include <stdio.h>
#include <string.h>

#include <fetch/fetch.h>

int main(int argc, char *argv[])
{
  FETCH *fetch;
  FETCHcode res;

  struct fetch_httppost *formpost = NULL;
  struct fetch_httppost *lastptr = NULL;
  struct fetch_slist *headerlist = NULL;
  static const char buf[] = "Expect:";

  fetch_global_init(FETCH_GLOBAL_ALL);

  FETCH_IGNORE_DEPRECATION(
      /* Fill in the file upload field */
      fetch_formadd(&formpost,
                    &lastptr,
                    FETCHFORM_COPYNAME, "sendfile",
                    FETCHFORM_FILE, "postit2-formadd.c",
                    FETCHFORM_END);

      /* Fill in the filename field */
      fetch_formadd(&formpost,
                    &lastptr,
                    FETCHFORM_COPYNAME, "filename",
                    FETCHFORM_COPYCONTENTS, "postit2-formadd.c",
                    FETCHFORM_END);

      /* Fill in the submit field too, even if this is rarely needed */
      fetch_formadd(&formpost,
                    &lastptr,
                    FETCHFORM_COPYNAME, "submit",
                    FETCHFORM_COPYCONTENTS, "send",
                    FETCHFORM_END);)

  fetch = fetch_easy_init();
  /* initialize custom header list (stating that Expect: 100-continue is not
     wanted */
  headerlist = fetch_slist_append(headerlist, buf);
  if (fetch)
  {
    /* what URL that receives this POST */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/examplepost.cgi");
    if ((argc == 2) && (!strcmp(argv[1], "noexpectheader")))
      /* only disable 100-continue header if explicitly requested */
      fetch_easy_setopt(fetch, FETCHOPT_HTTPHEADER, headerlist);
    FETCH_IGNORE_DEPRECATION(
        fetch_easy_setopt(fetch, FETCHOPT_HTTPPOST, formpost);)

    /* Perform the request, res gets the return code */
    res = fetch_easy_perform(fetch);
    /* Check for errors */
    if (res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));

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
