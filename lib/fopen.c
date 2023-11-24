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
  The dirslash() function breaks a null-terminated pathname string into
  directory and filename components then returns the directory component up
  to, *AND INCLUDING*, a final '/'.  If there is no directory in the path,
  this instead returns a "" string.

  This function returns a pointer to malloc'ed memory.

  The input path to this function is expected to have a file name part.
*/

#ifdef _WIN32
#define PATHSEP "\\"
#define IS_SEP(x) (((x) == '/') || ((x) == '\\'))
#elif defined(MSDOS) || defined(__EMX__) || defined(OS2)
#define PATHSEP "\\"
#define IS_SEP(x) ((x) == '\\')
#else
#define PATHSEP "/"
#define IS_SEP(x) ((x) == '/')
#endif

static char *dirslash(const char *path)
{
  size_t n;
  struct dynbuf out;
  DEBUGASSERT(path);
  Curl_dyn_init(&out, CURL_MAX_INPUT_LENGTH);
  n = strlen(path);
  if(n) {
    /* find the rightmost path separator, if any */
    while(n && !IS_SEP(path[n-1]))
      --n;
    /* skip over all the path separators, if any */
    while(n && IS_SEP(path[n-1]))
      --n;
  }
  if(Curl_dyn_addn(&out, path, n))
    return NULL;
  /* if there was a directory, append a single trailing slash */
  if(n && Curl_dyn_addn(&out, PATHSEP, 1))
    return NULL;
  return Curl_dyn_ptr(&out);
}

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
  unsigned char randbuf[41];
  char *tempstore = NULL;
  struct_stat sb;
  int fd = -1;
  char *dir = NULL;
  *tempname = NULL;

  *fh = fopen(filename, FOPEN_WRITETEXT);
  if(!*fh)
    goto fail;
  if(fstat(fileno(*fh), &sb) == -1 || !S_ISREG(sb.st_mode)) {
    return CURLE_OK;
  }
  fclose(*fh);
  *fh = NULL;

  result = Curl_rand_alnum(data, randbuf, sizeof(randbuf));
  if(result)
    goto fail;

  dir = dirslash(filename);
  if(dir) {
    /* The temp file name should not end up too long for the target file
       system */
    tempstore = aprintf("%s%s.tmp", dir, randbuf);
    free(dir);
  }

  if(!tempstore) {
    result = CURLE_OUT_OF_MEMORY;
    goto fail;
  }

  result = CURLE_WRITE_ERROR;
  fd = open(tempstore, O_WRONLY | O_CREAT | O_EXCL, 0600|sb.st_mode);
  if(fd == -1)
    goto fail;

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
  return result;
}

#endif /* ! disabled */
