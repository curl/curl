/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
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

#ifdef USE_NGHTTP2
#define _MPRINTF_REPLACE
#include <curl/mprintf.h>

#include <nghttp2/nghttp2.h>
#include "urldata.h"
#include "http2.h"
#include "http.h"
#include "sendf.h"
#include "curl_base64.h"
#include "curl_memory.h"

/* include memdebug.h last */
#include "memdebug.h"

/*
 * Store nghttp2 version info in this buffer, Prefix with a space.  Return
 * total length written.
 */
int Curl_http2_ver(char *p, size_t len)
{
  nghttp2_info *h2 = nghttp2_version(0);
  return snprintf(p, len, " nghttp2/%s", h2->version_str);
}

/*
 * The implementation of nghttp2_send_callback type. Here we write |data| with
 * size |length| to the network and return the number of bytes actually
 * written. See the documentation of nghttp2_send_callback for the details.
 */
static ssize_t send_callback(nghttp2_session *h2,
                             const uint8_t *data, size_t length, int flags,
                             void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  ssize_t written;
  CURLcode rc =
    Curl_write(conn, conn->sock[0], data, length, &written);
  (void)h2;
  (void)flags;

  if(rc) {
    failf(conn->data, "Failed sending HTTP2 data");
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  else if(!written)
    return NGHTTP2_ERR_WOULDBLOCK;

  return written;
}

/*
 * The implementation of nghttp2_recv_callback type. Here we read data from
 * the network and write them in |buf|. The capacity of |buf| is |length|
 * bytes. Returns the number of bytes stored in |buf|. See the documentation
 * of nghttp2_recv_callback for the details.
 */
static ssize_t recv_callback(nghttp2_session *h2,
                             uint8_t *buf, size_t length, int flags,
                             void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  ssize_t nread;
  CURLcode rc = Curl_read(conn, conn->sock[0], (char *)buf, length, &nread);
  (void)h2;
  (void)flags;

  if(rc) {
    failf(conn->data, "Failed recving HTTP2 data");
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  if(!nread)
    return NGHTTP2_ERR_WOULDBLOCK;

  return nread;
}

/*
 * This is all callbacks nghttp2 calls
 */
static const nghttp2_session_callbacks callbacks = {
  send_callback,
  recv_callback,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL
};

/*
 * The HTTP2 settings we send in the Upgrade request
 */
static nghttp2_settings_entry settings[] = {
  { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 },
  { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, NGHTTP2_INITIAL_WINDOW_SIZE },
};

/*
 * Append headers to ask for a HTTP1.1 to HTTP2 upgrade.
 */
CURLcode Curl_http2_request(Curl_send_buffer *req,
                            struct connectdata *conn)
{
  uint8_t binsettings[80];
  CURLcode result;
  ssize_t binlen;
  char *base64;
  size_t blen;

  if(!conn->proto.httpc.h2) {
    /* The nghttp2 session is not yet setup, do it */
    int rc = nghttp2_session_client_new(&conn->proto.httpc.h2,
                                        &callbacks, &conn);
    if(rc) {
      failf(conn->data, "Couldn't initialize nghttp2!");
      return CURLE_OUT_OF_MEMORY; /* most likely at least */
    }
  }

  /* As long as we have a fixed set of settings, we don't have to dynamically
   * figure out the base64 strings since it'll always be the same. However,
   * the settings will likely not be fixed every time in the future.
   */

  /* this returns number of bytes it wrote */
  binlen = nghttp2_pack_settings_payload(binsettings,
                                         sizeof(binsettings),
                                         settings,
                                         sizeof(settings)/sizeof(settings[0]));
  if(!binlen) {
    failf(conn->data, "nghttp2 unexpectedly failed on pack_settings_payload");
    return CURLE_FAILED_INIT;
  }

  result = Curl_base64_encode(conn->data, (const char *)binsettings, binlen,
                              &base64, &blen);
  if(result)
    return result;

  result = Curl_add_bufferf(req,
                            "Connection: Upgrade, HTTP2-Settings\r\n"
                            "Upgrade: %s\r\n"
                            "HTTP2-Settings: %s\r\n",
                            NGHTTP2_PROTO_VERSION_ID, base64);
  free(base64);

  return result;
}

#endif
