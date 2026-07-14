/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Linus Nielsen Feltzing <linus@haxx.se>
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

#if defined(USE_SSL) && defined(USE_SSLS_EXPORT)

#define T1678_IMPORT_COUNT 64
#define T1678_FIRST_TICKET_SIZE 4096
#define T1678_FIRST_QUICTP_SIZE 127

static unsigned char *t1678_make_packet(size_t *packet_len)
{
  const size_t t1678_total =
    1 +                                /* format version */
    1 + 2 + T1678_FIRST_TICKET_SIZE +  /* first ticket */
    1 + 2 + T1678_FIRST_QUICTP_SIZE +  /* first QUIC traffic params */
    1 + 2 + 1 +                        /* second ticket */
    1 + 2 + 1;                         /* second QUIC traffic params */

  unsigned char *packet = curlx_malloc(t1678_total);
  unsigned char *p;

  if(!packet)
    return NULL;

  p = packet;

  /* CURL_SPACK_VERSION */
  *p++ = 0x01;

  /* First CURL_SPACK_TICKET */
  *p++ = 0x04;
  *p++ = (unsigned char)(T1678_FIRST_TICKET_SIZE >> 8);
  *p++ = (unsigned char)T1678_FIRST_TICKET_SIZE;
  memset(p, 'A', T1678_FIRST_TICKET_SIZE);
  p += T1678_FIRST_TICKET_SIZE;

  /* First CURL_SPACK_QUICTP */
  *p++ = 0x07;
  *p++ = (unsigned char)(T1678_FIRST_QUICTP_SIZE >> 8);
  *p++ = (unsigned char)T1678_FIRST_QUICTP_SIZE;
  memset(p, 'Q', T1678_FIRST_QUICTP_SIZE);
  p += T1678_FIRST_QUICTP_SIZE;

  /* Second CURL_SPACK_TICKET: one byte. */
  *p++ = 0x04;
  *p++ = 0x00;
  *p++ = 0x01;
  *p++ = 'B';

  /* Second CURL_SPACK_QUICTP: one byte. */
  *p++ = 0x07;
  *p++ = 0x00;
  *p++ = 0x01;
  *p++ = 'R';

  *packet_len = t1678_total;
  return packet;
}

static CURLcode test_lib1678(const char *URL)
{
  unsigned char *packet;
  size_t packet_len;
  CURLSH *share = NULL;
  CURL *easy = NULL;
  CURLSHcode shrc;
  CURLcode result = CURLE_FAILED_INIT;
  int i;

  (void)URL;
  packet = t1678_make_packet(&packet_len);
  if(!packet)
    goto test_cleanup;

  result = curl_global_init(CURL_GLOBAL_DEFAULT);
  if(result != CURLE_OK)
    goto test_cleanup;

  share = curl_share_init();
  easy = curl_easy_init();

  if(!share || !easy)
    goto test_cleanup;

  shrc = curl_share_setopt(share,
                           CURLSHOPT_SHARE,
                           CURL_LOCK_DATA_SSL_SESSION);
  if(shrc != CURLSHE_OK)
    goto test_cleanup;

  result = curl_easy_setopt(easy, CURLOPT_SHARE, share);
  if(result)
    goto test_cleanup;

  for(i = 0; i < T1678_IMPORT_COUNT; ++i) {
    result = curl_easy_ssls_import(easy,
                                   "example.test:443",
                                   NULL,
                                   0,
                                   packet,
                                   packet_len);
    if(result) {
      curl_mfprintf(stderr,
                    "import %d failed: %d (%s)\n",
                    i, (int)result,
                    curl_easy_strerror(result));
      break;
    }
  }

test_cleanup:
  curlx_free(packet);
  curl_easy_cleanup(easy);
  curl_share_cleanup(share);
  curl_global_cleanup();

  return result;
}
#else
static CURLcode test_lib1678(const char *URL)
{
  (void)URL;
  return CURLE_OK;
}
#endif /* USE_SSL && USE_SSLS_EXPORT */
