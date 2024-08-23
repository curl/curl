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

#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_msgs.h"
#include "tool_cb_wrt.h"
#include "tool_operate.h"

#include "memdebug.h" /* keep this as LAST include */

#ifndef O_BINARY
#define O_BINARY 0
#endif
#ifdef _WIN32
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
  DEBUGASSERT(outs);
  DEBUGASSERT(config);
  global = config->global;
  if(!fname || !*fname) {
    warnf(global, "Remote filename has no length");
    return FALSE;
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
      /* Keep retrying in the hope that it is not interrupted sometime */
    } while(fd == -1 && errno == EINTR);
    if(config->file_clobber_mode == CLOBBER_NEVER && fd == -1) {
      int next_num = 1;
      size_t len = strlen(fname);
      size_t newlen = len + 13; /* nul + 1-11 digits + dot */
      char *newname;
      /* Guard against wraparound in new filename */
      if(newlen < len) {
        errorf(global, "overflow in filename generation");
        return FALSE;
      }
      newname = malloc(newlen);
      if(!newname) {
        errorf(global, "out of memory");
        return FALSE;
      }
      memcpy(newname, fname, len);
      newname[len] = '.';
      while(fd == -1 && /* have not successfully opened a file */
            (errno == EEXIST || errno == EISDIR) &&
            /* because we keep having files that already exist */
            next_num < 100 /* and we have not reached the retry limit */ ) {
        msnprintf(newname + len + 1, 12, "%d", next_num);
        next_num++;
        do {
          fd = open(newname, O_CREAT | O_WRONLY | O_EXCL | O_BINARY, OPENMODE);
          /* Keep retrying in the hope that it is not interrupted sometime */
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
    return FALSE;
  }
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
#ifdef _WIN32
  CONSOLE_SCREEN_BUFFER_INFO console_info;
  intptr_t fhnd;
#endif

#ifdef DEBUGBUILD
  {
    char *tty = curl_getenv("CURL_ISATTY");
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

#ifdef _WIN32
  fhnd = _get_osfhandle(fileno(outs->stream));
  /* if Windows console then UTF-8 must be converted to UTF-16 */
  if(isatty(fileno(outs->stream)) &&
     GetConsoleScreenBufferInfo((HANDLE)fhnd, &console_info)) {
    wchar_t *wc_buf;
    DWORD wc_len, chars_written;
    unsigned char *rbuf = (unsigned char *)buffer;
    DWORD rlen = (DWORD)bytes;

#define IS_TRAILING_BYTE(x) (0x80 <= (x) && (x) < 0xC0)

    /* attempt to complete an incomplete UTF-8 sequence from previous call.
       the sequence does not have to be well-formed. */
    if(outs->utf8seq[0] && rlen) {
      bool complete = false;
      /* two byte sequence (lead byte 110yyyyy) */
      if(0xC0 <= outs->utf8seq[0] && outs->utf8seq[0] < 0xE0) {
        outs->utf8seq[1] = *rbuf++;
        --rlen;
        complete = true;
      }
      /* three byte sequence (lead byte 1110zzzz) */
      else if(0xE0 <= outs->utf8seq[0] && outs->utf8seq[0] < 0xF0) {
        if(!outs->utf8seq[1]) {
          outs->utf8seq[1] = *rbuf++;
          --rlen;
        }
        if(rlen && !outs->utf8seq[2]) {
          outs->utf8seq[2] = *rbuf++;
          --rlen;
          complete = true;
        }
      }
      /* four byte sequence (lead byte 11110uuu) */
      else if(0xF0 <= outs->utf8seq[0] && outs->utf8seq[0] < 0xF8) {
        if(!outs->utf8seq[1]) {
          outs->utf8seq[1] = *rbuf++;
          --rlen;
        }
        if(rlen && !outs->utf8seq[2]) {
          outs->utf8seq[2] = *rbuf++;
          --rlen;
        }
        if(rlen && !outs->utf8seq[3]) {
          outs->utf8seq[3] = *rbuf++;
          --rlen;
          complete = true;
        }
      }

      if(complete) {
        WCHAR prefix[3] = {0};  /* UTF-16 (1-2 WCHARs) + NUL */

        if(MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)outs->utf8seq, -1,
                               prefix, sizeof(prefix)/sizeof(prefix[0]))) {
          DEBUGASSERT(prefix[2] == L'\0');
          if(!WriteConsoleW(
              (HANDLE) fhnd,
              prefix,
              prefix[1] ? 2 : 1,
              &chars_written,
              NULL)) {
            return CURL_WRITEFUNC_ERROR;
          }
        }
        /* else: UTF-8 input was not well formed and OS is pre-Vista which
           drops invalid characters instead of writing U+FFFD to output.  */

        memset(outs->utf8seq, 0, sizeof(outs->utf8seq));
      }
    }

    /* suppress an incomplete utf-8 sequence at end of rbuf */
    if(!outs->utf8seq[0] && rlen && (rbuf[rlen - 1] & 0x80)) {
      /* check for lead byte from a two, three or four byte sequence */
      if(0xC0 <= rbuf[rlen - 1] && rbuf[rlen - 1] < 0xF8) {
        outs->utf8seq[0] = rbuf[rlen - 1];
        rlen -= 1;
      }
      else if(rlen >= 2 && IS_TRAILING_BYTE(rbuf[rlen - 1])) {
        /* check for lead byte from a three or four byte sequence */
        if(0xE0 <= rbuf[rlen - 2] && rbuf[rlen - 2] < 0xF8) {
          outs->utf8seq[0] = rbuf[rlen - 2];
          outs->utf8seq[1] = rbuf[rlen - 1];
          rlen -= 2;
        }
        else if(rlen >= 3 && IS_TRAILING_BYTE(rbuf[rlen - 2])) {
          /* check for lead byte from a four byte sequence */
          if(0xF0 <= rbuf[rlen - 3] && rbuf[rlen - 3] < 0xF8) {
            outs->utf8seq[0] = rbuf[rlen - 3];
            outs->utf8seq[1] = rbuf[rlen - 2];
            outs->utf8seq[2] = rbuf[rlen - 1];
            rlen -= 3;
          }
        }
      }
    }

    if(rlen) {
      /* calculate buffer size for wide characters */
      wc_len = (DWORD)MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)rbuf, (int)rlen,
                                          NULL, 0);
      if(!wc_len)
        return CURL_WRITEFUNC_ERROR;

      wc_buf = (wchar_t*) malloc(wc_len * sizeof(wchar_t));
      if(!wc_buf)
        return CURL_WRITEFUNC_ERROR;

      wc_len = (DWORD)MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)rbuf, (int)rlen,
                                          wc_buf, (int)wc_len);
      if(!wc_len) {
        free(wc_buf);
        return CURL_WRITEFUNC_ERROR;
      }

      if(!WriteConsoleW(
          (HANDLE) fhnd,
          wc_buf,
          wc_len,
          &chars_written,
          NULL)) {
        free(wc_buf);
        return CURL_WRITEFUNC_ERROR;
      }
      free(wc_buf);
    }

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
