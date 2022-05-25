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

#include "curl_setup.h"

#if !defined(CURL_DISABLE_COOKIES) || !defined(CURL_DISABLE_ALTSVC) ||  \
  !defined(CURL_DISABLE_HSTS)

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include "urldata.h"
#include "rand.h"
#include "fopen.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/*
 * Curl_fopen() opens a file for writing with a temp name, to be renamed
 * to the final name when completed. If there is an existing file using this
 * name at the time of the open, this function will clone the mode from that
 * file.  if 'tempname' is non-NULL, it needs a rename after the file is
 * written.
 */
CURLcode Curl_fopen(struct Curl_easy *data, const char *filename,
                    FILE **fh, char **tempname)
{
  CURLcode result = CURLE_WRITE_ERROR;
  unsigned char randsuffix[9];
  char *tempstore = NULL;
  struct_stat sb;
  int fd = -1;
  *tempname = NULL;

  if(stat(filename, &sb) == -1 || !S_ISREG(sb.st_mode)) {
    /* a non-regular file, fallback to direct fopen() */
    *fh = fopen(filename, FOPEN_WRITETEXT);
    if(*fh)
      return CURLE_OK;
    goto fail;
  }

  result = Curl_rand_hex(data, randsuffix, sizeof(randsuffix));
  if(result)
    goto fail;

  tempstore = aprintf("%s.%s.tmp", filename, randsuffix);
  if(!tempstore) {
    result = CURLE_OUT_OF_MEMORY;
    goto fail;
  }

  result = CURLE_WRITE_ERROR;
  fd = open(tempstore, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if(fd == -1)
    goto fail;

#ifdef HAVE_FCHMOD
  {
    struct_stat nsb;
    if((fstat(fd, &nsb) != -1) &&
       (nsb.st_uid == sb.st_uid) && (nsb.st_gid == sb.st_gid)) {
      /* if the user and group are the same, clone the original mode */
      if(fchmod(fd, sb.st_mode) == -1)
        goto fail;
    }
  }
#endif

  *fh = fdopen(fd, FOPEN_WRITETEXT);
  if(!*fh)
    goto fail;

  *tempname = tempstore;
  return CURLE_OK;

fail:
  if(fd != -1) {
    close(fd);
    unlink(tempstore);
  }

  free(tempstore);

  *tempname = NULL;
  return result;
}

#endif /* ! disabled */
