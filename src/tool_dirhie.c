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
#include "tool_setup.h"

#include "tool_dirhie.h"
#include "tool_msgs.h"

#ifdef UNITTESTS
#  define toolx_mkdir(x, y) create_dir_hierarchy_trace_mkdir(x)
#elif defined(_WIN32)
#  include <direct.h>
#  define toolx_mkdir(x, y) _mkdir(x)
#elif defined(MSDOS) && !defined(__DJGPP__)
#  define toolx_mkdir(x, y) mkdir(x)
#else
#  define toolx_mkdir mkdir
#endif

#ifdef UNITTESTS
static struct dynbuf mkdir_results;

UNITTEST struct dynbuf *create_dir_hierarchy_trace_dynres(void)
{
  return &mkdir_results;
}

static int create_dir_hierarchy_trace_mkdir(const char *dir)
{
  if(curlx_dyn_add(&mkdir_results, dir) ||
     curlx_dyn_add(&mkdir_results, "|")) {
    /* !checksrc! disable ERRNOVAR 1 */
    errno = ENOMEM;
    return -1;
  }
  errno = 0;
  return 0;
}
#endif

static void show_dir_errno(const char *name)
{
  switch(errno) {
#ifdef EACCES
  /* !checksrc! disable ERRNOVAR 1 */
  case EACCES:
    errorf("You do not have permission to create %s", name);
    break;
#endif
#ifdef ENAMETOOLONG
  case ENAMETOOLONG:
    errorf("The directory name %s is too long", name);
    break;
#endif
#ifdef EROFS
  case EROFS:
    errorf("%s resides on a read-only file system", name);
    break;
#endif
#ifdef ENOSPC
  case ENOSPC:
    errorf("No space left on the file system that would "
           "contain the directory %s", name);
    break;
#endif
#ifdef EDQUOT
  case EDQUOT:
    errorf("Cannot create directory %s because you "
           "exceeded your quota", name);
    break;
#endif
  default:
    errorf("Error creating directory %s", name);
    break;
  }
}

/*
 * Create the needed directory hierarchy recursively in order to save
 *  multi-GETs in file output, ie:
 *  curl "http://example.org/dir[1-5]/file[1-5].txt" -o "dir#1/file#2.txt"
 *  should create all the dir* automagically
 */

#if defined(_WIN32) || defined(__DJGPP__)
/* systems that may use either or when specifying a path */
#define PATH_DELIMITERS "\\/"
#else
#define PATH_DELIMITERS DIR_CHAR
#endif

CURLcode create_dir_hierarchy(const char *outfile)
{
  CURLcode result = CURLE_OK;
  size_t outlen = strlen(outfile);
  struct dynbuf dirbuf;

  curlx_dyn_init(&dirbuf, outlen + 1);

  while(*outfile) {
    bool skip = FALSE;
    size_t seplen = strspn(outfile, PATH_DELIMITERS);
    size_t len = strcspn(&outfile[seplen], PATH_DELIMITERS);

    /* the last path component is the file and it ends with a null byte */
    if(!outfile[len + seplen])
      break;

#if defined(_WIN32) || defined(MSDOS)
    if(!curlx_dyn_len(&dirbuf)) {
      /* Skip creating a standalone Windows/MS-DOS drive letter 'X:', e.g.
         if outfile is X:\foo\bar\filename. Do create drive-relative
         directories e.g. in outfile X:foo\bar\filename. This logic takes into
         account unsupported drives !:, 1:, etc. */
      if(len == 2 && (outfile[1] == ':'))
        skip = TRUE;
    }
#endif
    /* insert the leading separators (possibly plural) plus the following
       directory name */
    result = curlx_dyn_addn(&dirbuf, outfile, seplen + len);
    if(result)
      return result;

    /* Create directory. Ignore access denied error to allow traversal. */
    /* !checksrc! disable ERRNOVAR 1 */
    if(!skip && (toolx_mkdir(curlx_dyn_ptr(&dirbuf), (mode_t)0000750) == -1) &&
       (errno != EACCES) && (errno != EEXIST)) {
      show_dir_errno(curlx_dyn_ptr(&dirbuf));
      result = CURLE_WRITE_ERROR;
      break; /* get out of loop */
    }
    outfile += len + seplen;
  }

  curlx_dyn_free(&dirbuf);

  return result;
}
