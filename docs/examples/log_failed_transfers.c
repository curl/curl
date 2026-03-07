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
/* <DESC>
 * Save failed transfer verbose log to disk
 * </DESC>
 */
/*
 *
 * This example demonstrates per-transfer verbose logging to memory.
 * The transfer's log is written to disk only if the transfer fails.
 *
 */
#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS  /* for fopen(), strerror(), vsnprintf() */
#endif
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include <curl/curl.h>

#ifdef _WIN32
#include <windows.h>
#define unlink _unlink
#else
#include <strings.h>
#include <unistd.h>
#endif

struct mem {
  /* 'buf' points to memory contents that is always zero terminated so that it
     can be treated like a string if appropriate. 'recent' points to the most
     recent data written to 'buf'. */
  char *buf, *recent;
  /* 'len' and 'allocsize' are the length and allocated size of 'buf' */
  size_t len, allocsize;
};

struct transfer {
  const char *url, *bodyfile, *logfile;
  struct mem log;
  FILE *bodyfp;
  CURL *curl;
};

static void mem_reset(struct mem *mem)
{
  free(mem->buf);
  mem->buf = NULL;
  mem->recent = NULL;
  mem->len = 0;
  mem->allocsize = 0;
}

/* expand free buffer space to needed size. return -1 or 'needed'. */
static int mem_need(struct mem *mem, size_t needed)
{
  char *newbuf;
  size_t newsize;

  if(needed > (unsigned)INT_MAX)
    return -1;

  if(needed <= (mem->allocsize - mem->len))
    return (int)needed;

  /* min 4k makes reallocations much less frequent when lengths are small */
  newsize = needed < 4096 ? 4096 : needed;

  newsize += mem->len;

  if(newsize < mem->len || newsize > (unsigned)INT_MAX)
    return -1;

  newbuf = realloc(mem->buf, newsize);

  if(!newbuf)
    return -1;

  if(mem->recent && mem->buf != newbuf)
    mem->recent = newbuf + (mem->recent - mem->buf);

  mem->buf = newbuf;
  mem->allocsize = newsize;

  return (int)needed;
}

static int mem_addn(struct mem *mem, const char *buf, size_t len)
{
  if(len + 1 < len || mem_need(mem, len + 1) < 0)
    return -1;
  mem->recent = mem->buf + mem->len;
  memcpy(mem->recent, buf, len);
  mem->len += len;
  mem->buf[mem->len] = '\0';
  return (int)len;
}

static int mem_add(struct mem *mem, const char *str)
{
  return mem_addn(mem, str, strlen(str));
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 2, 3)))
#endif
static int mem_addf(struct mem *mem, const char *format, ...)
{
  int i, x;
  va_list va;

  /* we need about 100 chars or less to write 95% of lines */
  x = 128;

  /* first try: there is probably enough memory to write everything.
     second try: there is definitely enough memory to write everything. */
  for(i = 0; i < 2; ++i) {
    if(x < 0 || mem_need(mem, (size_t)x + 1) < 0)
      break;

    va_start(va, format);
    x = vsnprintf(mem->buf + mem->len, mem->allocsize - mem->len, format, va);
    va_end(va);

    if(x >= 0 && (size_t)x < (mem->allocsize - mem->len)) {
      mem->recent = mem->buf + mem->len;
      mem->len += (size_t)x;
      return x;
    }

#ifdef _WIN32
    /* Not all versions of Windows CRT vsnprintf are compliant with C99. Some
       return -1 if buffer too small. Try _vscprintf to get the needed size. */
    if(!i && x < 0) {
      va_start(va, format);
      x = _vscprintf(format, va);
      va_end(va);
    }
#endif
  }

  if(mem->buf)
    mem->buf[mem->len] = '\0';
  return -1;
}

static int mydebug(CURL *curl, curl_infotype type,
                   char *data, size_t size, void *userdata)
{
  struct transfer *t = (struct transfer *)userdata;
  static const char s_infotype[CURLINFO_END][3] = {
    "* ", "< ", "> ", "{ ", "} ", "{ ", "} " };

  (void)curl;

  switch(type) {
  case CURLINFO_TEXT:
  case CURLINFO_HEADER_OUT:
  case CURLINFO_HEADER_IN:
    /* mem_addn is faster than passing large data as %s to mem_addf */
    mem_addn(&t->log, s_infotype[type], 2);
    mem_addn(&t->log, data, size);
    if(!size || data[size - 1] != '\n')
      mem_add(&t->log, "\n");
    break;
  default:
    break;
  }

  return 0;
}

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  struct transfer *t = (struct transfer *)userdata;

  return fwrite(ptr, size, nmemb, t->bodyfp);
}

int main(void)
{
  CURLcode result;
  unsigned i;
  int total_failed = 0;
  char errbuf[CURL_ERROR_SIZE] = { 0, };
  struct transfer transfer[2];

  memset(transfer, 0, sizeof(transfer));

  transfer[0].url = "https://httpbin.org/get";
  transfer[0].bodyfile = "200.txt";
  transfer[0].logfile = "200_transfer_log.txt";

  transfer[1].url = "https://httpbin.org/status/400";
  transfer[1].bodyfile = "400.txt";
  transfer[1].logfile = "400_transfer_log.txt";

  result = curl_global_init(CURL_GLOBAL_ALL);
  if(result != CURLE_OK) {
    fprintf(stderr, "curl_global_init failed\n");
    return (int)result;
  }

  /* You could enable global tracing for extra verbosity when verbosity is
     enabled for a transfer. */
#if 0
  curl_global_trace("all");
#endif

  for(i = 0; i < sizeof(transfer) / sizeof(transfer[0]); ++i) {
    int failed = 0;
    struct transfer *t = &transfer[i];

    t->curl = curl_easy_init();

    if(!t->curl) {
      fprintf(stderr, "curl_easy_init failed\n");
      curl_global_cleanup();
      return 1;
    }

    curl_easy_setopt(t->curl, CURLOPT_URL, t->url);

    /* Enable following redirects */
    curl_easy_setopt(t->curl, CURLOPT_FOLLOWLOCATION, 1L);

    /* Enable verbose logging to memory */
    curl_easy_setopt(t->curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(t->curl, CURLOPT_DEBUGFUNCTION, mydebug);
    curl_easy_setopt(t->curl, CURLOPT_DEBUGDATA, t);

    /* Enable writing the body to a file */
    curl_easy_setopt(t->curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(t->curl, CURLOPT_WRITEDATA, t);

    /* Enable immediate error on HTTP status codes >= 400 in most cases,
       instead of downloading the body to a file */
    curl_easy_setopt(t->curl, CURLOPT_FAILONERROR, 1L);

    /* Enable detailed error messages */
    curl_easy_setopt(t->curl, CURLOPT_ERRORBUFFER, errbuf);

    mem_addf(&t->log, "Downloading %s to file %s\n", t->url, t->bodyfile);
    printf("%s", t->log.recent);

    /* Create the body file */
    t->bodyfp = fopen(t->bodyfile, "wb");

    if(t->bodyfp) {
      /* Perform the transfer */
      result = curl_easy_perform(t->curl);

      /* Save the body file */
      fclose(t->bodyfp);
      t->bodyfp = NULL;

      if(result == CURLE_OK) {
        /* You could retrieve more information about the transfer here via
           curl_easy_getinfo and mark the transfer as failed if needed. */
        mem_addf(&t->log, "Transfer successful.\n");
        fprintf(stderr, "%s", t->log.recent);
        failed = 0;
      }
      else {
        mem_addf(&t->log, "Transfer failed: (%d) %s\n", result,
                 (errbuf[0] ? errbuf : curl_easy_strerror(result)));
        fprintf(stderr, "%s", t->log.recent);
        failed = 1;
      }
    }
    else {
      mem_addf(&t->log, "Failed to create body output file %s: %s\n",
               t->bodyfile, strerror(errno));
      fprintf(stderr, "%s", t->log.recent);
      failed = 1;
    }

    if(failed) {
      FILE *fp = fopen(t->logfile, "wb");

      if(fp && t->log.len == fwrite(t->log.buf, 1, t->log.len, fp))
        fprintf(stderr, "Transfer log written to %s\n", t->logfile);
      else {
        fprintf(stderr, "Failed to write transfer log to %s: %s\n",
                t->logfile, strerror(errno));
      }

      if(fp)
        fclose(fp);

      /* Depending on how the transfer failed a body file may or may not have
         been written, and you may or may not want it. */
      unlink(t->bodyfile);

      ++total_failed;
    }

    mem_reset(&t->log);

    curl_easy_cleanup(t->curl);

    t->curl = NULL;

    printf("\n");
  }

  curl_global_cleanup();

  return total_failed ? 1 : 0;
}
