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
 * Upload to FTP, resuming failed transfers. Active mode.
 * </DESC>
 */

#include <stdlib.h>
#include <stdio.h>
#include <fetch/fetch.h>

/* parse headers for Content-Length */
static size_t getcontentlengthfunc(void *ptr, size_t size, size_t nmemb,
                                   void *stream)
{
  int r;
  long len = 0;

  r = sscanf(ptr, "Content-Length: %ld\n", &len);
  if(r)
    *((long *) stream) = len;

  return size * nmemb;
}

/* discard downloaded data */
static size_t discardfunc(void *ptr, size_t size, size_t nmemb, void *stream)
{
  (void)ptr;
  (void)stream;
  return size * nmemb;
}

/* read data to upload */
static size_t readfunc(char *ptr, size_t size, size_t nmemb, void *stream)
{
  FILE *f = stream;
  size_t n;

  if(ferror(f))
    return FETCH_READFUNC_ABORT;

  n = fread(ptr, size, nmemb, f) * size;

  return n;
}


static int upload(FETCH *fetchhandle, const char *remotepath,
                  const char *localpath, long timeout, long tries)
{
  FILE *f;
  long uploaded_len = 0;
  FETCHcode r = FETCHE_GOT_NOTHING;
  int c;

  f = fopen(localpath, "rb");
  if(!f) {
    perror(NULL);
    return 0;
  }

  fetch_easy_setopt(fetchhandle, FETCHOPT_UPLOAD, 1L);

  fetch_easy_setopt(fetchhandle, FETCHOPT_URL, remotepath);

  if(timeout)
    fetch_easy_setopt(fetchhandle, FETCHOPT_SERVER_RESPONSE_TIMEOUT, timeout);

  fetch_easy_setopt(fetchhandle, FETCHOPT_HEADERFUNCTION, getcontentlengthfunc);
  fetch_easy_setopt(fetchhandle, FETCHOPT_HEADERDATA, &uploaded_len);

  fetch_easy_setopt(fetchhandle, FETCHOPT_WRITEFUNCTION, discardfunc);

  fetch_easy_setopt(fetchhandle, FETCHOPT_READFUNCTION, readfunc);
  fetch_easy_setopt(fetchhandle, FETCHOPT_READDATA, f);

  /* enable active mode */
  fetch_easy_setopt(fetchhandle, FETCHOPT_FTPPORT, "-");

  /* allow the server no more than 7 seconds to connect back */
  fetch_easy_setopt(fetchhandle, FETCHOPT_ACCEPTTIMEOUT_MS, 7000L);

  fetch_easy_setopt(fetchhandle, FETCHOPT_FTP_CREATE_MISSING_DIRS, 1L);

  fetch_easy_setopt(fetchhandle, FETCHOPT_VERBOSE, 1L);

  for(c = 0; (r != FETCHE_OK) && (c < tries); c++) {
    /* are we resuming? */
    if(c) { /* yes */
      /* determine the length of the file already written */

      /*
       * With NOBODY and NOHEADER, libfetch issues a SIZE command, but the only
       * way to retrieve the result is to parse the returned Content-Length
       * header. Thus, getcontentlengthfunc(). We need discardfunc() above
       * because HEADER dumps the headers to stdout without it.
       */
      fetch_easy_setopt(fetchhandle, FETCHOPT_NOBODY, 1L);
      fetch_easy_setopt(fetchhandle, FETCHOPT_HEADER, 1L);

      r = fetch_easy_perform(fetchhandle);
      if(r != FETCHE_OK)
        continue;

      fetch_easy_setopt(fetchhandle, FETCHOPT_NOBODY, 0L);
      fetch_easy_setopt(fetchhandle, FETCHOPT_HEADER, 0L);

      fseek(f, uploaded_len, SEEK_SET);

      fetch_easy_setopt(fetchhandle, FETCHOPT_APPEND, 1L);
    }
    else { /* no */
      fetch_easy_setopt(fetchhandle, FETCHOPT_APPEND, 0L);
    }

    r = fetch_easy_perform(fetchhandle);
  }

  fclose(f);

  if(r == FETCHE_OK)
    return 1;
  else {
    fprintf(stderr, "%s\n", fetch_easy_strerror(r));
    return 0;
  }
}

int main(void)
{
  FETCH *fetchhandle = NULL;

  fetch_global_init(FETCH_GLOBAL_ALL);
  fetchhandle = fetch_easy_init();

  upload(fetchhandle, "ftp://user:pass@example.com/path/file", "C:\\file",
         0, 3);

  fetch_easy_cleanup(fetchhandle);
  fetch_global_cleanup();

  return 0;
}
