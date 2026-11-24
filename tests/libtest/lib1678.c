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

#if defined(USE_SSL) && defined(USE_SSLS_EXPORT)

#define T1678_IMPORT_COUNT 64
#define T1678_FIRST_TICKET_SIZE 4096
#define T1678_FIRST_QUICTP_SIZE 127
#define T1678_FIRST_ALPN_SIZE 10

/* A TLS 1.3 session in the order written by the packer. */
static const uint8_t t1678_session[] = {
  0x01,                                /* format version */
  0x04, 0x00, 0x03, 'T', 0x00, 'K',    /* binary ticket */
  0x02, 0x03, 0x04,                    /* TLS 1.3 */
  0x03, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* CURL_OFF_T_MAX */
  0x05, 0x00, 0x02, 'h', '2'           /* ALPN */
};

static CURLcode t1678_export_cb(CURL *handle,
                                void *userptr,
                                const char *session_key,
                                const unsigned char *shmac,
                                size_t shmac_len,
                                const unsigned char *sdata,
                                size_t sdata_len,
                                curl_off_t valid_until,
                                int ietf_tls_id,
                                const char *alpn,
                                size_t earlydata_max)
{
  size_t *exported = (size_t *)userptr;
  (void)handle;
  (void)session_key;
  (void)shmac;
  (void)shmac_len;
  (void)earlydata_max;

  if(!sdata || sdata_len != sizeof(t1678_session) ||
     memcmp(sdata, t1678_session, sdata_len)) {
    curl_mfprintf(stderr, "session data changed on export\n");
    return TEST_ERR_FAILURE;
  }
  if(valid_until != CURL_OFF_T_MAX || ietf_tls_id != 0x0304 ||
     !alpn || strcmp(alpn, "h2")) {
    curl_mfprintf(stderr, "unexpected exported session metadata\n");
    return TEST_ERR_FAILURE;
  }
  (*exported)++;
  return CURLE_OK;
}

static uint8_t *t1678_make_packet(size_t *packet_len)
{
  const size_t t1678_total =
    1 +                                /* format version */
    1 + 2 + T1678_FIRST_TICKET_SIZE +  /* first ticket */
    1 + 2 + T1678_FIRST_QUICTP_SIZE +  /* first QUIC traffic params */
    1 + 2 + T1678_FIRST_ALPN_SIZE +  /* first ALPN params */
    1 + 2 + 1 +                        /* second ticket */
    1 + 2 + 1 +                        /* second ALPN */
    1 + 2 + 1;                         /* second QUIC traffic params */

  uint8_t *packet = curlx_malloc(t1678_total);
  uint8_t *p;

  if(!packet)
    return NULL;

  p = packet;

  /* CURL_SPACK_VERSION */
  *p++ = 0x01;

  /* First CURL_SPACK_TICKET */
  *p++ = 0x04;
  *p++ = (uint8_t)(T1678_FIRST_TICKET_SIZE >> 8);
  *p++ = (uint8_t)(T1678_FIRST_TICKET_SIZE & 0x0ff);
  memset(p, 'A', T1678_FIRST_TICKET_SIZE);
  p += T1678_FIRST_TICKET_SIZE;

  /* First CURL_SPACK_QUICTP */
  *p++ = 0x07;
  *p++ = (uint8_t)(T1678_FIRST_QUICTP_SIZE >> 8);
  *p++ = (uint8_t)(T1678_FIRST_QUICTP_SIZE & 0x0ff);
  memset(p, 'Q', T1678_FIRST_QUICTP_SIZE);
  p += T1678_FIRST_QUICTP_SIZE;

  /* First CURL_SPACK_ALPN */
  *p++ = 0x05;
  *p++ = (uint8_t)(T1678_FIRST_ALPN_SIZE >> 8);
  *p++ = (uint8_t)(T1678_FIRST_ALPN_SIZE & 0x0ff);
  memset(p, 'a', T1678_FIRST_ALPN_SIZE);
  p += T1678_FIRST_ALPN_SIZE;

  /* Second CURL_SPACK_TICKET: one byte. */
  *p++ = 0x04;
  *p++ = 0x00;
  *p++ = 0x01;
  *p++ = 'B';

  /* Second CURL_SPACK_ALPN: one byte. */
  *p++ = 0x05;
  *p++ = 0x00;
  *p++ = 0x01;
  *p++ = 'b';

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
  static const uint8_t no_ticket[] = { 0x01 };
  static const uint8_t empty_ticket[] = { 0x01, 0x04, 0x00, 0x00 };
  static const uint8_t neg_valid_until[] = {
    0x01, 0x04, 0x00, 0x01, 'A',
    0x03, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  static const uint8_t shmac[64] = { 0 };
  uint8_t *packet;
  size_t packet_len;
  size_t exported = 0;
  CURLSH *share = NULL;
  CURL *easy = NULL;
  CURLSHcode shrc;
  CURLcode result = CURLE_FAILED_INIT;
  int i;

  (void)URL;
  packet = t1678_make_packet(&packet_len);
  if(!packet)
    goto test_cleanup;

  result = curl_global_init(CURL_GLOBAL_ALL);
  if(result != CURLE_OK)
    goto test_cleanup;

  result = CURLE_FAILED_INIT;
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

  if(curl_easy_ssls_import(NULL, "example.test:443", NULL, 0, packet,
                           packet_len) != CURLE_BAD_FUNCTION_ARGUMENT) {
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto test_cleanup;
  }
  if(curl_easy_ssls_import(easy, "example.test:443", NULL, 0, NULL,
                           packet_len) != CURLE_BAD_FUNCTION_ARGUMENT) {
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto test_cleanup;
  }
  if(curl_easy_ssls_import(easy, "example.test:443", NULL, 0, packet, 0) !=
     CURLE_BAD_FUNCTION_ARGUMENT) {
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto test_cleanup;
  }
  if(curl_easy_ssls_export(NULL, NULL, NULL) !=
     CURLE_BAD_FUNCTION_ARGUMENT) {
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto test_cleanup;
  }
  if(curl_easy_ssls_export(easy, NULL, NULL) !=
     CURLE_BAD_FUNCTION_ARGUMENT) {
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto test_cleanup;
  }

  if(curl_easy_ssls_import(easy, "example.test:443", NULL, 0, no_ticket,
                           sizeof(no_ticket)) != CURLE_READ_ERROR) {
    result = CURLE_READ_ERROR;
    goto test_cleanup;
  }
  if(curl_easy_ssls_import(easy, "example.test:443", NULL, 0, empty_ticket,
                           sizeof(empty_ticket)) != CURLE_READ_ERROR) {
    result = CURLE_READ_ERROR;
    goto test_cleanup;
  }
  if(curl_easy_ssls_import(easy, "example.test:443", NULL, 0, neg_valid_until,
                           sizeof(neg_valid_until)) != CURLE_READ_ERROR) {
    result = CURLE_READ_ERROR;
    goto test_cleanup;
  }

  result = curl_easy_ssls_import(easy, NULL, shmac, sizeof(shmac),
                                 t1678_session, sizeof(t1678_session));
  if(result)
    goto test_cleanup;
  result = curl_easy_ssls_export(easy, t1678_export_cb, &exported);
  if(result)
    goto test_cleanup;
  if(exported != 1) {
    curl_mfprintf(stderr, "expected exactly one exported session\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

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
