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
#include "first.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "testutil.h"
#include "memdebug.h"

#define RTP_PKT_CHANNEL(p)   ((int)((unsigned char)((p)[1])))

#define RTP_PKT_LENGTH(p)  ((((int)((unsigned char)((p)[2]))) << 8) | \
                             ((int)((unsigned char)((p)[3]))))

#define RTP_DATA_SIZE 12

static int rtp_packet_count = 0;

static size_t rtp_write(char *ptr, size_t size, size_t nmemb, void *stream)
{
  static const char *RTP_DATA = "$_1234\n\0Rsdf";

  char *data = (char *)ptr;
  int channel = RTP_PKT_CHANNEL(data);
  int message_size;
  int coded_size = RTP_PKT_LENGTH(data);
  size_t failure = (size && nmemb) ? 0 : 1;
  int i;
  (void)stream;

  message_size = curlx_uztosi(size * nmemb) - 4;

  curl_mprintf("RTP: message size %d, channel %d\n", message_size, channel);
  if(message_size != coded_size) {
    curl_mprintf("RTP embedded size (%d) does not match "
                 "the write size (%d).\n",
                 coded_size, message_size);
    return failure;
  }

  data += 4;
  for(i = 0; i < message_size; i += RTP_DATA_SIZE) {
    if(message_size - i > RTP_DATA_SIZE) {
      if(memcmp(RTP_DATA, data + i, RTP_DATA_SIZE) != 0) {
        curl_mprintf("RTP PAYLOAD CORRUPTED [%s]\n", data + i);
        /* return failure; */
      }
    }
    else {
      if(memcmp(RTP_DATA, data + i, message_size - i) != 0) {
        curl_mprintf("RTP PAYLOAD END CORRUPTED (%d), [%s]\n",
                     message_size - i, data + i);
        /* return failure; */
      }
    }
  }

  rtp_packet_count++;
  curl_mfprintf(stderr, "packet count is %d\n", rtp_packet_count);

  return size * nmemb;
}

static CURLcode test_lib571(char *URL)
{
  CURLcode res;
  CURL *curl;
  char *stream_uri = NULL;
  int request = 1;

  FILE *protofile = fopen(libtest_arg2, "wb");
  if(!protofile) {
    curl_mfprintf(stderr, "Couldn't open the protocol dump file\n");
    return TEST_ERR_MAJOR_BAD;
  }

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    fclose(protofile);
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    fclose(protofile);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
  test_setopt(curl, CURLOPT_URL, URL);

  stream_uri = tutil_suburl(URL, request++);
  if(!stream_uri) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(curl, CURLOPT_RTSP_STREAM_URI, stream_uri);
  curl_free(stream_uri);
  stream_uri = NULL;

  test_setopt(curl, CURLOPT_INTERLEAVEFUNCTION, rtp_write);
  test_setopt(curl, CURLOPT_TIMEOUT, 30L);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);
  test_setopt(curl, CURLOPT_WRITEDATA, protofile);

  test_setopt(curl, CURLOPT_RTSP_TRANSPORT, "RTP/AVP/TCP;interleaved=0-1");
  test_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_SETUP);

  res = curl_easy_perform(curl);
  if(res)
    goto test_cleanup;

  /* This PLAY starts the interleave */
  stream_uri = tutil_suburl(URL, request++);
  if(!stream_uri) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(curl, CURLOPT_RTSP_STREAM_URI, stream_uri);
  curl_free(stream_uri);
  stream_uri = NULL;
  test_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_PLAY);

  res = curl_easy_perform(curl);
  if(res)
    goto test_cleanup;

  /* The DESCRIBE request will try to consume data after the Content */
  stream_uri = tutil_suburl(URL, request++);
  if(!stream_uri) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(curl, CURLOPT_RTSP_STREAM_URI, stream_uri);
  curl_free(stream_uri);
  stream_uri = NULL;
  test_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_DESCRIBE);

  res = curl_easy_perform(curl);
  if(res)
    goto test_cleanup;

  stream_uri = tutil_suburl(URL, request++);
  if(!stream_uri) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(curl, CURLOPT_RTSP_STREAM_URI, stream_uri);
  curl_free(stream_uri);
  stream_uri = NULL;
  test_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_PLAY);

  res = curl_easy_perform(curl);
  if(res)
    goto test_cleanup;

  curl_mfprintf(stderr, "PLAY COMPLETE\n");

  /* Use Receive to get the rest of the data */
  while(!res && rtp_packet_count < 19) {
    curl_mfprintf(stderr, "LOOPY LOOP!\n");
    test_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_RECEIVE);
    res = curl_easy_perform(curl);
  }

test_cleanup:
  curl_free(stream_uri);

  if(protofile)
    fclose(protofile);

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
