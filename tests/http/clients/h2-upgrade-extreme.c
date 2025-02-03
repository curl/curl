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
 * HTTP/2 Upgrade test
 * </DESC>
 */
#include <fetch/fetch.h>

#include <stdio.h>
#include <stdlib.h>
/* #include <error.h> */
#include <errno.h>

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

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *opaque)
{
  (void)ptr;
  (void)opaque;
  return size * nmemb;
}

int main(int argc, char *argv[])
{
  const char *url;
  FETCHM *multi;
  FETCH *easy;
  FETCHMcode mc;
  int running_handles = 0, start_count, numfds;
  FETCHMsg *msg;
  int msgs_in_queue;
  char range[128];

  if (argc != 2)
  {
    fprintf(stderr, "%s URL\n", argv[0]);
    exit(2);
  }

  url = argv[1];
  multi = fetch_multi_init();
  if (!multi)
  {
    fprintf(stderr, "fetch_multi_init failed\n");
    exit(1);
  }

  start_count = 200;
  do
  {
    if (start_count)
    {
      easy = fetch_easy_init();
      if (!easy)
      {
        fprintf(stderr, "fetch_easy_init failed\n");
        exit(1);
      }
      fetch_easy_setopt(easy, FETCHOPT_VERBOSE, 1L);
      fetch_easy_setopt(easy, FETCHOPT_DEBUGFUNCTION, debug_cb);
      fetch_easy_setopt(easy, FETCHOPT_URL, url);
      fetch_easy_setopt(easy, FETCHOPT_NOSIGNAL, 1L);
      fetch_easy_setopt(easy, FETCHOPT_AUTOREFERER, 1L);
      fetch_easy_setopt(easy, FETCHOPT_FAILONERROR, 1L);
      fetch_easy_setopt(easy, FETCHOPT_HTTP_VERSION, FETCH_HTTP_VERSION_2_0);
      fetch_easy_setopt(easy, FETCHOPT_WRITEFUNCTION, write_cb);
      fetch_easy_setopt(easy, FETCHOPT_WRITEDATA, NULL);
      fetch_easy_setopt(easy, FETCHOPT_HTTPGET, 1L);
      fetch_msnprintf(range, sizeof(range),
                      "%" FETCH_FORMAT_FETCH_OFF_TU "-"
                      "%" FETCH_FORMAT_FETCH_OFF_TU,
                      (fetch_off_t)0,
                      (fetch_off_t)16384);
      fetch_easy_setopt(easy, FETCHOPT_RANGE, range);

      mc = fetch_multi_add_handle(multi, easy);
      if (mc != FETCHM_OK)
      {
        fprintf(stderr, "fetch_multi_add_handle: %s\n",
                fetch_multi_strerror(mc));
        exit(1);
      }
      --start_count;
    }

    mc = fetch_multi_perform(multi, &running_handles);
    if (mc != FETCHM_OK)
    {
      fprintf(stderr, "fetch_multi_perform: %s\n",
              fetch_multi_strerror(mc));
      exit(1);
    }

    if (running_handles)
    {
      mc = fetch_multi_poll(multi, NULL, 0, 1000000, &numfds);
      if (mc != FETCHM_OK)
      {
        fprintf(stderr, "fetch_multi_poll: %s\n",
                fetch_multi_strerror(mc));
        exit(1);
      }
    }

    /* Check for finished handles and remove. */
    /* !checksrc! disable EQUALSNULL 1 */
    while ((msg = fetch_multi_info_read(multi, &msgs_in_queue)) != NULL)
    {
      if (msg->msg == FETCHMSG_DONE)
      {
        long status = 0;
        fetch_off_t xfer_id;
        fetch_easy_getinfo(msg->easy_handle, FETCHINFO_XFER_ID, &xfer_id);
        fetch_easy_getinfo(msg->easy_handle, FETCHINFO_RESPONSE_CODE, &status);
        if (msg->data.result == FETCHE_SEND_ERROR ||
            msg->data.result == FETCHE_RECV_ERROR)
        {
          /* We get these if the server had a GOAWAY in transit on
           * re-using a connection */
        }
        else if (msg->data.result)
        {
          fprintf(stderr, "transfer #%" FETCH_FORMAT_FETCH_OFF_T ": failed with %d\n", xfer_id, msg->data.result);
          exit(1);
        }
        else if (status != 206)
        {
          fprintf(stderr, "transfer #%" FETCH_FORMAT_FETCH_OFF_T ": wrong http status %ld (expected 206)\n", xfer_id, status);
          exit(1);
        }
        fetch_multi_remove_handle(multi, msg->easy_handle);
        fetch_easy_cleanup(msg->easy_handle);
        fprintf(stderr, "transfer #%" FETCH_FORMAT_FETCH_OFF_T " retiring "
                        "(%d now running)\n",
                xfer_id, running_handles);
      }
    }

    fprintf(stderr, "running_handles=%d, yet_to_start=%d\n",
            running_handles, start_count);

  } while (running_handles > 0 || start_count);

  fprintf(stderr, "exiting\n");
  exit(EXIT_SUCCESS);
}
