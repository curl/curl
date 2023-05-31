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

#ifdef HAVE_FCNTL_H
/* for open() */
#include <fcntl.h>
#endif

#include <sys/stat.h>

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_msgs.h"
#include "tool_cb_wrt.h"
#include "tool_operate.h"

#include "memdebug.h" /* keep this as LAST include */

#ifndef O_BINARY
#define O_BINARY 0
#endif
#ifdef WIN32
#define OPENMODE S_IREAD | S_IWRITE
#else
#define OPENMODE S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH
#endif

/* create/open a local file for writing, return TRUE on success */
bool tool_create_output_file(struct OutStruct *outs,
                             struct OperationConfig *config)
{
  struct GlobalConfig *global;
  FILE *file = NULL;
  char *fname = outs->filename;
  char *aname = NULL;
  DEBUGASSERT(outs);
  DEBUGASSERT(config);
  global = config->global;
  if(!fname || !*fname) {
    warnf(global, "Remote filename has no length");
    return FALSE;
  }

  if(config->output_dir && outs->is_cd_filename) {
    aname = aprintf("%s/%s", config->output_dir, fname);
    if(!aname) {
      errorf(global, "out of memory");
      return FALSE;
    }
    fname = aname;
  }

  if(config->file_clobber_mode == CLOBBER_ALWAYS ||
     (config->file_clobber_mode == CLOBBER_DEFAULT &&
      !outs->is_cd_filename)) {
    /* open file for writing */
    file = fopen(fname, "wb");
  }
  else {
    int fd;
    do {
      fd = open(fname, O_CREAT | O_WRONLY | O_EXCL | O_BINARY, OPENMODE);
      /* Keep retrying in the hope that it isn't interrupted sometime */
    } while(fd == -1 && errno == EINTR);
    if(config->file_clobber_mode == CLOBBER_NEVER && fd == -1) {
      int next_num = 1;
      size_t len = strlen(fname);
      size_t newlen = len + 13; /* nul + 1-11 digits + dot */
      char *newname;
      /* Guard against wraparound in new filename */
      if(newlen < len) {
        free(aname);
        errorf(global, "overflow in filename generation");
        return FALSE;
      }
      newname = malloc(newlen);
      if(!newname) {
        errorf(global, "out of memory");
        free(aname);
        return FALSE;
      }
      memcpy(newname, fname, len);
      newname[len] = '.';
      while(fd == -1 && /* haven't successfully opened a file */
            (errno == EEXIST || errno == EISDIR) &&
            /* because we keep having files that already exist */
            next_num < 100 /* and we haven't reached the retry limit */ ) {
        curlx_msnprintf(newname + len + 1, 12, "%d", next_num);
        next_num++;
        do {
          fd = open(newname, O_CREAT | O_WRONLY | O_EXCL | O_BINARY, OPENMODE);
          /* Keep retrying in the hope that it isn't interrupted sometime */
        } while(fd == -1 && errno == EINTR);
      }
      outs->filename = newname; /* remember the new one */
      outs->alloc_filename = TRUE;
    }
    /* An else statement to not overwrite existing files and not retry with
       new numbered names (which would cover
       config->file_clobber_mode == CLOBBER_DEFAULT && outs->is_cd_filename)
       is not needed because we would have failed earlier, in the while loop
       and `fd` would now be -1 */
    if(fd != -1) {
      file = fdopen(fd, "wb");
      if(!file)
        close(fd);
    }
  }

  if(!file) {
    warnf(global, "Failed to open the file %s: %s", fname,
          strerror(errno));
    free(aname);
    return FALSE;
  }
  free(aname);
  outs->s_isreg = TRUE;
  outs->fopened = TRUE;
  outs->stream = file;
  outs->bytes = 0;
  outs->init = 0;
  return TRUE;
}

/*
** callback for CURLOPT_WRITEFUNCTION
*/

size_t tool_write_cb(char *buffer, size_t sz, size_t nmemb, void *userdata)
{
  size_t rc;
  struct per_transfer *per = userdata;
  struct OutStruct *outs = &per->outs;
  struct OperationConfig *config = per->config;
  size_t bytes = sz * nmemb;
  bool is_tty = config->global->isatty;
#ifdef WIN32
  CONSOLE_SCREEN_BUFFER_INFO console_info;
  intptr_t fhnd;
#endif

#ifdef DEBUGBUILD
  {
    char *tty = curlx_getenv("CURL_ISATTY");
    if(tty) {
      is_tty = TRUE;
      curl_free(tty);
    }
  }

  if(config->show_headers) {
    if(bytes > (size_t)CURL_MAX_HTTP_HEADER) {
      warnf(config->global, "Header data size exceeds single call write "
            "limit");
      return CURL_WRITEFUNC_ERROR;
    }
  }
  else {
    if(bytes > (size_t)CURL_MAX_WRITE_SIZE) {
      warnf(config->global, "Data size exceeds single call write limit");
      return CURL_WRITEFUNC_ERROR;
    }
  }

  {
    /* Some internal congruency checks on received OutStruct */
    bool check_fails = FALSE;
    if(outs->filename) {
      /* regular file */
      if(!*outs->filename)
        check_fails = TRUE;
      if(!outs->s_isreg)
        check_fails = TRUE;
      if(outs->fopened && !outs->stream)
        check_fails = TRUE;
      if(!outs->fopened && outs->stream)
        check_fails = TRUE;
      if(!outs->fopened && outs->bytes)
        check_fails = TRUE;
    }
    else {
      /* standard stream */
      if(!outs->stream || outs->s_isreg || outs->fopened)
        check_fails = TRUE;
      if(outs->alloc_filename || outs->is_cd_filename || outs->init)
        check_fails = TRUE;
    }
    if(check_fails) {
      warnf(config->global, "Invalid output struct data for write callback");
      return CURL_WRITEFUNC_ERROR;
    }
  }
#endif

  if(!outs->stream && !tool_create_output_file(outs, per->config))
    return CURL_WRITEFUNC_ERROR;

  if(is_tty && (outs->bytes < 2000) && !config->terminal_binary_ok) {
    /* binary output to terminal? */
    if(memchr(buffer, 0, bytes)) {
      warnf(config->global, "Binary output can mess up your terminal. "
            "Use \"--output -\" to tell curl to output it to your terminal "
            "anyway, or consider \"--output <FILE>\" to save to a file.");
      config->synthetic_error = TRUE;
      return CURL_WRITEFUNC_ERROR;
    }
  }

#ifdef WIN32
  fhnd = _get_osfhandle(fileno(outs->stream));
  if(isatty(fileno(outs->stream)) &&
     GetConsoleScreenBufferInfo((HANDLE)fhnd, &console_info)) {
    DWORD in_len = (DWORD)(sz * nmemb);
    wchar_t* wc_buf;
    DWORD wc_len;

    /* calculate buffer size for wide characters */
    wc_len = MultiByteToWideChar(CP_UTF8, 0, buffer, in_len,  NULL, 0);
    wc_buf = (wchar_t*) malloc(wc_len * sizeof(wchar_t));
    if(!wc_buf)
      return CURL_WRITEFUNC_ERROR;

    /* calculate buffer size for multi-byte characters */
    wc_len = MultiByteToWideChar(CP_UTF8, 0, buffer, in_len, wc_buf, wc_len);
    if(!wc_len) {
      free(wc_buf);
      return CURL_WRITEFUNC_ERROR;
    }

    if(!WriteConsoleW(
        (HANDLE) fhnd,
        wc_buf,
        wc_len,
        &wc_len,
        NULL)) {
      free(wc_buf);
      return CURL_WRITEFUNC_ERROR;
    }
    free(wc_buf);
    rc = bytes;
  }
  else
#endif
    rc = fwrite(buffer, sz, nmemb, outs->stream);

  if(bytes == rc)
    /* we added this amount of data to the output */
    outs->bytes += bytes;

  if(config->readbusy) {
    config->readbusy = FALSE;
    curl_easy_pause(per->curl, CURLPAUSE_CONT);
  }

  if(config->nobuffer) {
    /* output buffering disabled */
    int res = fflush(outs->stream);
    if(res)
      return CURL_WRITEFUNC_ERROR;
  }

  return rc;
}
