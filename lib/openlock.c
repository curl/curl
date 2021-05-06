/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2019 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

#include "curl_setup.h"

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <curl/curl.h>
#include "openlock.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/*
 * Curl_openlock() opens a file for writing text and waits for the adivsory
 * lock on it.
 */

#ifndef O_CLOEXEC
/* this doesn't exist everywhere */
#define O_CLOEXEC 0
#endif

CURLcode Curl_openlock(const char *file, struct openlock *o)
{
  int fd = -1;
  FILE *out = NULL;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(o);
  o->fd = -1;
  o->out = NULL;

  fd = open(file, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666);
  if(fd == -1) {
    result = CURLE_WRITE_ERROR;
    goto error;
  }

#ifdef HAVE_LOCKF
  /* wait for advisory lock on the whole file */
  if(lockf(fd, F_LOCK, 0)) {
    result = CURLE_WRITE_ERROR;
    goto error;
  }
#endif

  out = fdopen(fd, FOPEN_WRITETEXT);
  if(!out)
    result = CURLE_WRITE_ERROR;
  else {
    o->fd = fd;
    o->out = out;
    return CURLE_OK;
  }
  error:
  if(out)
    /* fclose() will close the fd as well after fdopen */
    fclose(out);
  else if(fd != -1)
    close(fd);
  return result;
}

/*
 * Truncate the file at the current position, then unlock and close it.
 */
void Curl_openunlock(struct openlock *o)
{
#ifdef HAVE_FTRUNCATE
  long pos = ftell(o->out);
  fflush(o->out);
  if(ftruncate(o->fd, (off_t)pos))
    /* ignoring the return code causes warnings ... */
    pos = 0;
#endif
#ifdef HAVE_LOCKF
  if(o->fd != -1) {
    if(lockf(o->fd, F_ULOCK, 0)) {
      o->fd = -1;
    }
  }
#endif
  if(o->out)
    fclose(o->out);
}
