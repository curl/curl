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
 * upload pausing
 * </DESC>
 */
/* This is based on the PoC client of issue #11769
 */
#include <fetch/fetch.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifndef _MSC_VER
/* somewhat Unix-specific */
#include <unistd.h> /* getopt() */
#endif

#ifndef _MSC_VER
static void log_line_start(FILE *log, const char *idsbuf, fetch_infotype type)
{
  /*
   * This is the trace look that is similar to what libfetch makes on its
   * own.
   */
  static const char *const s_infotype[] = {
      "* ", "< ", "> ", "{ ", "} ", "{ ", "} "};
  if (idsbuf && *idsbuf)
    fprintf(log, "%s%s", idsbuf, s_infotype[type]);
  else
    fputs(s_infotype[type], log);
}

#define TRC_IDS_FORMAT_IDS_1 "[%" FETCH_FORMAT_FETCH_OFF_T "-x] "
#define TRC_IDS_FORMAT_IDS_2 "[%" FETCH_FORMAT_FETCH_OFF_T "-%" FETCH_FORMAT_FETCH_OFF_T "] "
/*
** callback for FETCHOPT_DEBUGFUNCTION
*/
static int debug_cb(FETCH *handle, fetch_infotype type,
                    char *data, size_t size,
                    void *userdata)
{
  FILE *output = stderr;
  static int newl = 0;
  static int traced_data = 0;
  char idsbuf[60];
  fetch_off_t xfer_id, conn_id;

  (void)handle; /* not used */
  (void)userdata;

  if (!fetch_easy_getinfo(handle, FETCHINFO_XFER_ID, &xfer_id) && xfer_id >= 0)
  {
    if (!fetch_easy_getinfo(handle, FETCHINFO_CONN_ID, &conn_id) &&
        conn_id >= 0)
    {
      fetch_msnprintf(idsbuf, sizeof(idsbuf), TRC_IDS_FORMAT_IDS_2, xfer_id,
                      conn_id);
    }
    else
    {
      fetch_msnprintf(idsbuf, sizeof(idsbuf), TRC_IDS_FORMAT_IDS_1, xfer_id);
    }
  }
  else
    idsbuf[0] = 0;

  switch (type)
  {
  case FETCHINFO_HEADER_OUT:
    if (size > 0)
    {
      size_t st = 0;
      size_t i;
      for (i = 0; i < size - 1; i++)
      {
        if (data[i] == '\n')
        { /* LF */
          if (!newl)
          {
            log_line_start(output, idsbuf, type);
          }
          (void)fwrite(data + st, i - st + 1, 1, output);
          st = i + 1;
          newl = 0;
        }
      }
      if (!newl)
        log_line_start(output, idsbuf, type);
      (void)fwrite(data + st, i - st + 1, 1, output);
    }
    newl = (size && (data[size - 1] != '\n')) ? 1 : 0;
    traced_data = 0;
    break;
  case FETCHINFO_TEXT:
  case FETCHINFO_HEADER_IN:
    if (!newl)
      log_line_start(output, idsbuf, type);
    (void)fwrite(data, size, 1, output);
    newl = (size && (data[size - 1] != '\n')) ? 1 : 0;
    traced_data = 0;
    break;
  case FETCHINFO_DATA_OUT:
  case FETCHINFO_DATA_IN:
  case FETCHINFO_SSL_DATA_IN:
  case FETCHINFO_SSL_DATA_OUT:
    if (!traced_data)
    {
      if (!newl)
        log_line_start(output, idsbuf, type);
      fprintf(output, "[%ld bytes data]\n", (long)size);
      newl = 0;
      traced_data = 1;
    }
    break;
  default: /* nada */
    newl = 0;
    traced_data = 1;
    break;
  }

  return 0;
}

#define PAUSE_READ_AFTER 1
static size_t total_read = 0;

static size_t read_callback(char *ptr, size_t size, size_t nmemb,
                            void *userdata)
{
  (void)size;
  (void)nmemb;
  (void)userdata;
  if (total_read >= PAUSE_READ_AFTER)
  {
    fprintf(stderr, "read_callback, return PAUSE\n");
    return FETCH_READFUNC_PAUSE;
  }
  else
  {
    ptr[0] = '\n';
    ++total_read;
    fprintf(stderr, "read_callback, return 1 byte\n");
    return 1;
  }
}

static int progress_callback(void *clientp,
                             fetch_off_t dltotal,
                             fetch_off_t dlnow,
                             fetch_off_t ultotal,
                             fetch_off_t ulnow)
{
  (void)dltotal;
  (void)dlnow;
  (void)ultotal;
  (void)ulnow;
  (void)clientp;
#if 0
  /* Used to unpause on progress, but keeping for now. */
  {
    FETCH *fetch = (FETCH *)clientp;
    fetch_easy_pause(fetch, FETCHPAUSE_CONT);
    /* fetch_easy_pause(fetch, FETCHPAUSE_RECV_CONT); */
  }
#endif
  return 0;
}

#define ERR()                                                            \
  do                                                                     \
  {                                                                      \
    fprintf(stderr, "something unexpected went wrong - bailing out!\n"); \
    exit(2);                                                             \
  } while (0)

static void usage(const char *msg)
{
  if (msg)
    fprintf(stderr, "%s\n", msg);
  fprintf(stderr,
          "usage: [options] url\n"
          "  upload and pause, options:\n"
          "  -V http_version (http/1.1, h2, h3) http version to use\n");
}
#endif /* !_MSC_VER */

int main(int argc, char *argv[])
{
#ifndef _MSC_VER
  FETCH *fetch;
  FETCHcode rc = FETCHE_OK;
  FETCHU *cu;
  struct fetch_slist *resolve = NULL;
  char resolve_buf[1024];
  char *url, *host = NULL, *port = NULL;
  int http_version = FETCH_HTTP_VERSION_1_1;
  int ch;

  while ((ch = getopt(argc, argv, "V:")) != -1)
  {
    switch (ch)
    {
    case 'V':
    {
      if (!strcmp("http/1.1", optarg))
        http_version = FETCH_HTTP_VERSION_1_1;
      else if (!strcmp("h2", optarg))
        http_version = FETCH_HTTP_VERSION_2_0;
      else if (!strcmp("h3", optarg))
        http_version = FETCH_HTTP_VERSION_3ONLY;
      else
      {
        usage("invalid http version");
        return 1;
      }
      break;
    }
    default:
      usage("invalid option");
      return 1;
    }
  }
  argc -= optind;
  argv += optind;

  if (argc != 1)
  {
    usage("not enough arguments");
    return 2;
  }
  url = argv[0];

  fetch_global_init(FETCH_GLOBAL_DEFAULT);
  fetch_global_trace("ids,time");

  cu = fetch_url();
  if (!cu)
  {
    fprintf(stderr, "out of memory\n");
    exit(1);
  }
  if (fetch_url_set(cu, FETCHUPART_URL, url, 0))
  {
    fprintf(stderr, "not a URL: '%s'\n", url);
    exit(1);
  }
  if (fetch_url_get(cu, FETCHUPART_HOST, &host, 0))
  {
    fprintf(stderr, "could not get host of '%s'\n", url);
    exit(1);
  }
  if (fetch_url_get(cu, FETCHUPART_PORT, &port, 0))
  {
    fprintf(stderr, "could not get port of '%s'\n", url);
    exit(1);
  }
  memset(&resolve, 0, sizeof(resolve));
  fetch_msnprintf(resolve_buf, sizeof(resolve_buf) - 1, "%s:%s:127.0.0.1",
                  host, port);
  resolve = fetch_slist_append(resolve, resolve_buf);

  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "out of memory\n");
    exit(1);
  }
  /* We want to use our own read function. */
  fetch_easy_setopt(fetch, FETCHOPT_READFUNCTION, read_callback);

  /* It will help us to continue the read function. */
  fetch_easy_setopt(fetch, FETCHOPT_XFERINFOFUNCTION, progress_callback);
  fetch_easy_setopt(fetch, FETCHOPT_XFERINFODATA, fetch);
  fetch_easy_setopt(fetch, FETCHOPT_NOPROGRESS, 0L);

  /* It will help us to ensure that keepalive does not help. */
  fetch_easy_setopt(fetch, FETCHOPT_TCP_KEEPALIVE, 1L);
  fetch_easy_setopt(fetch, FETCHOPT_TCP_KEEPIDLE, 1L);
  fetch_easy_setopt(fetch, FETCHOPT_TCP_KEEPINTVL, 1L);
  fetch_easy_setopt(fetch, FETCHOPT_TCP_KEEPCNT, 1L);

  /* Enable uploading. */
  fetch_easy_setopt(fetch, FETCHOPT_CUSTOMREQUEST, "POST");
  fetch_easy_setopt(fetch, FETCHOPT_UPLOAD, 1L);

  fetch_easy_setopt(fetch, FETCHOPT_SSL_VERIFYPEER, 0L);
  fetch_easy_setopt(fetch, FETCHOPT_SSL_VERIFYHOST, 0L);

  if (fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L) != FETCHE_OK ||
      fetch_easy_setopt(fetch, FETCHOPT_DEBUGFUNCTION, debug_cb) != FETCHE_OK ||
      fetch_easy_setopt(fetch, FETCHOPT_RESOLVE, resolve) != FETCHE_OK)
    ERR();

  fetch_easy_setopt(fetch, FETCHOPT_URL, url);
  fetch_easy_setopt(fetch, FETCHOPT_HTTP_VERSION, http_version);

  rc = fetch_easy_perform(fetch);

  if (fetch)
  {
    fetch_easy_cleanup(fetch);
  }

  fetch_slist_free_all(resolve);
  fetch_free(host);
  fetch_free(port);
  fetch_url_cleanup(cu);
  fetch_global_cleanup();

  return (int)rc;
#else
  (void)argc;
  (void)argv;
  fprintf(stderr, "Not supported with this compiler.\n");
  return 1;
#endif /* !_MSC_VER */
}
