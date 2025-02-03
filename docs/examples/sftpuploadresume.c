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
 * Upload to SFTP, resuming a previously aborted transfer.
 * </DESC>
 */

#include <stdlib.h>
#include <stdio.h>
#include <fetch/fetch.h>

/* read data to upload */
static size_t readfunc(char *ptr, size_t size, size_t nmemb, void *stream)
{
  FILE *f = (FILE *)stream;
  size_t n;

  if(ferror(f))
    return FETCH_READFUNC_ABORT;

  n = fread(ptr, size, nmemb, f) * size;

  return n;
}

/*
 * sftpGetRemoteFileSize returns the remote file size in byte; -1 on error
 */
static fetch_off_t sftpGetRemoteFileSize(const char *i_remoteFile)
{
  FETCHcode result = FETCHE_GOT_NOTHING;
  fetch_off_t remoteFileSizeByte = -1;
  FETCH *fetchHandlePtr = fetch_easy_init();

  fetch_easy_setopt(fetchHandlePtr, FETCHOPT_VERBOSE, 1L);

  fetch_easy_setopt(fetchHandlePtr, FETCHOPT_URL, i_remoteFile);
  fetch_easy_setopt(fetchHandlePtr, FETCHOPT_NOPROGRESS, 1);
  fetch_easy_setopt(fetchHandlePtr, FETCHOPT_NOBODY, 1);
  fetch_easy_setopt(fetchHandlePtr, FETCHOPT_HEADER, 1);
  fetch_easy_setopt(fetchHandlePtr, FETCHOPT_FILETIME, 1);

  result = fetch_easy_perform(fetchHandlePtr);
  if(FETCHE_OK == result) {
    result = fetch_easy_getinfo(fetchHandlePtr,
                               FETCHINFO_CONTENT_LENGTH_DOWNLOAD_T,
                               &remoteFileSizeByte);
    if(result)
      return -1;
    printf("filesize: %lu\n", (unsigned long)remoteFileSizeByte);
  }
  fetch_easy_cleanup(fetchHandlePtr);

  return remoteFileSizeByte;
}


static int sftpResumeUpload(FETCH *fetchhandle, const char *remotepath,
                            const char *localpath)
{
  FILE *f = NULL;
  FETCHcode result = FETCHE_GOT_NOTHING;

  fetch_off_t remoteFileSizeByte = sftpGetRemoteFileSize(remotepath);
  if(-1 == remoteFileSizeByte) {
    printf("Error reading the remote file size: unable to resume upload\n");
    return -1;
  }

  f = fopen(localpath, "rb");
  if(!f) {
    perror(NULL);
    return 0;
  }

  fetch_easy_setopt(fetchhandle, FETCHOPT_UPLOAD, 1L);
  fetch_easy_setopt(fetchhandle, FETCHOPT_URL, remotepath);
  fetch_easy_setopt(fetchhandle, FETCHOPT_READFUNCTION, readfunc);
  fetch_easy_setopt(fetchhandle, FETCHOPT_READDATA, f);

#ifdef _WIN32
  _fseeki64(f, remoteFileSizeByte, SEEK_SET);
#else
  fseek(f, (long)remoteFileSizeByte, SEEK_SET);
#endif
  fetch_easy_setopt(fetchhandle, FETCHOPT_APPEND, 1L);
  result = fetch_easy_perform(fetchhandle);

  fclose(f);

  if(result == FETCHE_OK)
    return 1;
  else {
    fprintf(stderr, "%s\n", fetch_easy_strerror(result));
    return 0;
  }
}

int main(void)
{
  const char *remote = "sftp://user:pass@example.com/path/filename";
  const char *filename = "filename";
  FETCH *fetchhandle = NULL;

  fetch_global_init(FETCH_GLOBAL_ALL);
  fetchhandle = fetch_easy_init();

  if(!sftpResumeUpload(fetchhandle, remote, filename)) {
    printf("resumed upload using fetch %s failed\n", fetch_version());
  }

  fetch_easy_cleanup(fetchhandle);
  fetch_global_cleanup();

  return 0;
}
