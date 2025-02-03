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
#include "test.h"

#include "memdebug.h"

FETCHcode test(char *URL)
{
   FETCHcode res;
   FETCH *fetch;
   char *newURL = NULL;
   struct fetch_slist *slist = NULL;

   if(fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK) {
     fprintf(stderr, "fetch_global_init() failed\n");
     return TEST_ERR_MAJOR_BAD;
   }

   fetch = fetch_easy_init();
   if(!fetch) {
     fprintf(stderr, "fetch_easy_init() failed\n");
     fetch_global_cleanup();
     return TEST_ERR_MAJOR_BAD;
   }

   /*
    * Begin with fetch set to use a single CWD to the URL's directory.
    */
   test_setopt(fetch, FETCHOPT_URL, URL);
   test_setopt(fetch, FETCHOPT_VERBOSE, 1L);
   test_setopt(fetch, FETCHOPT_FTP_FILEMETHOD, (long) FETCHFTPMETHOD_SINGLECWD);

   res = fetch_easy_perform(fetch);

   /*
    * Change the FTP_FILEMETHOD option to use full paths rather than a CWD
    * command. Use an innocuous QUOTE command, after which fetch will CWD to
    * ftp_conn->entrypath and then (on the next call to ftp_statemach_act)
    * find a non-zero ftpconn->dirdepth even though no directories are stored
    * in the ftpconn->dirs array (after a call to freedirs).
    */

   slist = fetch_slist_append(NULL, "SYST");
   if(!slist) {
     fetch_free(newURL);
     fetch_easy_cleanup(fetch);
     fetch_global_cleanup();
     return TEST_ERR_MAJOR_BAD;
   }

   test_setopt(fetch, FETCHOPT_URL, libtest_arg2);
   test_setopt(fetch, FETCHOPT_FTP_FILEMETHOD, (long) FETCHFTPMETHOD_NOCWD);
   test_setopt(fetch, FETCHOPT_QUOTE, slist);

   res = fetch_easy_perform(fetch);

test_cleanup:

   fetch_slist_free_all(slist);
   fetch_free(newURL);
   fetch_easy_cleanup(fetch);
   fetch_global_cleanup();

   return res;
}
