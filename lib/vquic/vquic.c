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

#include "curl_setup.h"

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include "urldata.h"
#include "dynbuf.h"
#include "curl_log.h"
#include "curl_msh3.h"
#include "curl_ngtcp2.h"
#include "curl_quiche.h"
#include "vquic.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


#ifdef ENABLE_QUIC

#ifdef O_BINARY
#define QLOGMODE O_WRONLY|O_CREAT|O_BINARY
#else
#define QLOGMODE O_WRONLY|O_CREAT
#endif

void Curl_quic_ver(char *p, size_t len)
{
#ifdef USE_NGTCP2
  Curl_ngtcp2_ver(p, len);
#elif defined(USE_QUICHE)
  Curl_quiche_ver(p, len);
#elif defined(USE_MSH3)
  Curl_msh3_ver(p, len);
#endif
}

/*
 * If the QLOGDIR environment variable is set, open and return a file
 * descriptor to write the log to.
 *
 * This function returns error if something failed outside of failing to
 * create the file. Open file success is deemed by seeing if the returned fd
 * is != -1.
 */
CURLcode Curl_qlogdir(struct Curl_easy *data,
                      unsigned char *scid,
                      size_t scidlen,
                      int *qlogfdp)
{
  const char *qlog_dir = getenv("QLOGDIR");
  *qlogfdp = -1;
  if(qlog_dir) {
    struct dynbuf fname;
    CURLcode result;
    unsigned int i;
    Curl_dyn_init(&fname, DYN_QLOG_NAME);
    result = Curl_dyn_add(&fname, qlog_dir);
    if(!result)
      result = Curl_dyn_add(&fname, "/");
    for(i = 0; (i < scidlen) && !result; i++) {
      char hex[3];
      msnprintf(hex, 3, "%02x", scid[i]);
      result = Curl_dyn_add(&fname, hex);
    }
    if(!result)
      result = Curl_dyn_add(&fname, ".sqlog");

    if(!result) {
      int qlogfd = open(Curl_dyn_ptr(&fname), QLOGMODE,
                        data->set.new_file_perms);
      if(qlogfd != -1)
        *qlogfdp = qlogfd;
    }
    Curl_dyn_free(&fname);
    if(result)
      return result;
  }

  return CURLE_OK;
}

CURLcode Curl_cf_quic_create(struct Curl_cfilter **pcf,
                             struct Curl_easy *data,
                             struct connectdata *conn,
                             const struct Curl_addrinfo *ai,
                             int transport)
{
  DEBUGASSERT(transport == TRNSPRT_QUIC);
#ifdef USE_NGTCP2
  return Curl_cf_ngtcp2_create(pcf, data, conn, ai);
#elif defined(USE_QUICHE)
  return Curl_cf_quiche_create(pcf, data, conn, ai);
#elif defined(USE_MSH3)
  return Curl_cf_msh3_create(pcf, data, conn, ai);
#else
  *pcf = NULL;
  (void)data;
  (void)conn;
  (void)ai;
  return CURLE_NOT_BUILT_IN;
#endif
}

bool Curl_conn_is_http3(const struct Curl_easy *data,
                        const struct connectdata *conn,
                        int sockindex)
{
#ifdef USE_NGTCP2
  return Curl_conn_is_ngtcp2(data, conn, sockindex);
#elif defined(USE_QUICHE)
  return Curl_conn_is_quiche(data, conn, sockindex);
#elif defined(USE_MSH3)
  return Curl_conn_is_msh3(data, conn, sockindex);
#else
  return ((conn->handler->protocol & PROTO_FAMILY_HTTP) &&
          (conn->httpversion == 30));
#endif
}

CURLcode Curl_conn_may_http3(struct Curl_easy *data,
                             const struct connectdata *conn)
{
  if(!(conn->handler->flags & PROTOPT_SSL)) {
    failf(data, "HTTP/3 requested for non-HTTPS URL");
    return CURLE_URL_MALFORMAT;
  }
#ifndef CURL_DISABLE_PROXY
  if(conn->bits.socksproxy) {
    failf(data, "HTTP/3 is not supported over a SOCKS proxy");
    return CURLE_URL_MALFORMAT;
  }
  if(conn->bits.httpproxy && conn->bits.tunnel_proxy) {
    failf(data, "HTTP/3 is not supported over a HTTP proxy");
    return CURLE_URL_MALFORMAT;
  }
#endif

  return CURLE_OK;
}

#else /* ENABLE_QUIC */

CURLcode Curl_conn_may_http3(struct Curl_easy *data,
                             const struct connectdata *conn)
{
  (void)conn;
  (void)data;
  DEBUGF(infof(data, "QUIC is not supported in this build"));
  return CURLE_NOT_BUILT_IN;
}

#endif /* !ENABLE_QUIC */
