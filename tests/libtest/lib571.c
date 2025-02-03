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
#include "test.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include "warnless.h"
#include "memdebug.h"

#define RTP_PKT_CHANNEL(p) ((int)((unsigned char)((p)[1])))

#define RTP_PKT_LENGTH(p) ((((int)((unsigned char)((p)[2]))) << 8) | \
                           ((int)((unsigned char)((p)[3]))))

#define RTP_DATA_SIZE 12
static const char *RTP_DATA = "$_1234\n\0Rsdf";

static int rtp_packet_count = 0;

static size_t rtp_write(char *ptr, size_t size, size_t nmemb, void *stream)
{
  char *data = (char *)ptr;
  int channel = RTP_PKT_CHANNEL(data);
  int message_size;
  int coded_size = RTP_PKT_LENGTH(data);
  size_t failure = (size && nmemb) ? 0 : 1;
  int i;
  (void)stream;

  message_size = fetchx_uztosi(size * nmemb) - 4;

  printf("RTP: message size %d, channel %d\n", message_size, channel);
  if (message_size != coded_size)
  {
    printf("RTP embedded size (%d) does not match the write size (%d).\n",
           coded_size, message_size);
    return failure;
  }

  data += 4;
  for (i = 0; i < message_size; i += RTP_DATA_SIZE)
  {
    if (message_size - i > RTP_DATA_SIZE)
    {
      if (memcmp(RTP_DATA, data + i, RTP_DATA_SIZE) != 0)
      {
        printf("RTP PAYLOAD CORRUPTED [%s]\n", data + i);
        /* return failure; */
      }
    }
    else
    {
      if (memcmp(RTP_DATA, data + i, message_size - i) != 0)
      {
        printf("RTP PAYLOAD END CORRUPTED (%d), [%s]\n",
               message_size - i, data + i);
        /* return failure; */
      }
    }
  }

  rtp_packet_count++;
  fprintf(stderr, "packet count is %d\n", rtp_packet_count);

  return size * nmemb;
}

/* build request url */
static char *suburl(const char *base, int i)
{
  return fetch_maprintf("%s%.4d", base, i);
}

FETCHcode test(char *URL)
{
  FETCHcode res;
  FETCH *fetch;
  char *stream_uri = NULL;
  int request = 1;

  FILE *protofile = fopen(libtest_arg2, "wb");
  if (!protofile)
  {
    fprintf(stderr, "Couldn't open the protocol dump file\n");
    return TEST_ERR_MAJOR_BAD;
  }

  if (fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed\n");
    fclose(protofile);
    return TEST_ERR_MAJOR_BAD;
  }

  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fclose(protofile);
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
  test_setopt(fetch, FETCHOPT_URL, URL);

  stream_uri = suburl(URL, request++);
  if (!stream_uri)
  {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(fetch, FETCHOPT_RTSP_STREAM_URI, stream_uri);
  fetch_free(stream_uri);
  stream_uri = NULL;

  test_setopt(fetch, FETCHOPT_INTERLEAVEFUNCTION, rtp_write);
  test_setopt(fetch, FETCHOPT_TIMEOUT, 30L);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  test_setopt(fetch, FETCHOPT_WRITEDATA, protofile);

  test_setopt(fetch, FETCHOPT_RTSP_TRANSPORT, "RTP/AVP/TCP;interleaved=0-1");
  test_setopt(fetch, FETCHOPT_RTSP_REQUEST, FETCH_RTSPREQ_SETUP);

  res = fetch_easy_perform(fetch);
  if (res)
    goto test_cleanup;

  /* This PLAY starts the interleave */
  stream_uri = suburl(URL, request++);
  if (!stream_uri)
  {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(fetch, FETCHOPT_RTSP_STREAM_URI, stream_uri);
  fetch_free(stream_uri);
  stream_uri = NULL;
  test_setopt(fetch, FETCHOPT_RTSP_REQUEST, FETCH_RTSPREQ_PLAY);

  res = fetch_easy_perform(fetch);
  if (res)
    goto test_cleanup;

  /* The DESCRIBE request will try to consume data after the Content */
  stream_uri = suburl(URL, request++);
  if (!stream_uri)
  {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(fetch, FETCHOPT_RTSP_STREAM_URI, stream_uri);
  fetch_free(stream_uri);
  stream_uri = NULL;
  test_setopt(fetch, FETCHOPT_RTSP_REQUEST, FETCH_RTSPREQ_DESCRIBE);

  res = fetch_easy_perform(fetch);
  if (res)
    goto test_cleanup;

  stream_uri = suburl(URL, request++);
  if (!stream_uri)
  {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(fetch, FETCHOPT_RTSP_STREAM_URI, stream_uri);
  fetch_free(stream_uri);
  stream_uri = NULL;
  test_setopt(fetch, FETCHOPT_RTSP_REQUEST, FETCH_RTSPREQ_PLAY);

  res = fetch_easy_perform(fetch);
  if (res)
    goto test_cleanup;

  fprintf(stderr, "PLAY COMPLETE\n");

  /* Use Receive to get the rest of the data */
  while (!res && rtp_packet_count < 19)
  {
    fprintf(stderr, "LOOPY LOOP!\n");
    test_setopt(fetch, FETCHOPT_RTSP_REQUEST, FETCH_RTSPREQ_RECEIVE);
    res = fetch_easy_perform(fetch);
  }

test_cleanup:
  fetch_free(stream_uri);

  if (protofile)
    fclose(protofile);

  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
