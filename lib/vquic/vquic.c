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
#include "cfilters.h"
#include "curl_log.h"
#include "curl_msh3.h"
#include "curl_ngtcp2.h"
#include "curl_quiche.h"
#include "vquic.h"
#include "vquic_int.h"

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

CURLcode vquic_ctx_init(struct cf_quic_ctx *qctx, size_t pktbuflen)
{
  qctx->num_blocked_pkt = 0;
  qctx->num_blocked_pkt_sent = 0;
  memset(&qctx->blocked_pkt, 0, sizeof(qctx->blocked_pkt));

  qctx->pktbuflen = pktbuflen;
  qctx->pktbuf = malloc(qctx->pktbuflen);
  if(!qctx->pktbuf)
    return CURLE_OUT_OF_MEMORY;

#if defined(__linux__) && defined(UDP_SEGMENT) && defined(HAVE_SENDMSG)
  qctx->no_gso = FALSE;
#else
  qctx->no_gso = TRUE;
#endif

  return CURLE_OK;
}

void vquic_ctx_free(struct cf_quic_ctx *qctx)
{
  free(qctx->pktbuf);
  qctx->pktbuf = NULL;
}

static CURLcode send_packet_no_gso(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct cf_quic_ctx *qctx,
                                   const uint8_t *pkt, size_t pktlen,
                                   size_t gsolen, size_t *psent);

static CURLcode do_sendmsg(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           struct cf_quic_ctx *qctx,
                           const uint8_t *pkt, size_t pktlen, size_t gsolen,
                           size_t *psent)
{
#ifdef HAVE_SENDMSG
  struct iovec msg_iov;
  struct msghdr msg = {0};
  ssize_t sent;
#if defined(__linux__) && defined(UDP_SEGMENT)
  uint8_t msg_ctrl[32];
  struct cmsghdr *cm;
#endif

  *psent = 0;
  msg_iov.iov_base = (uint8_t *)pkt;
  msg_iov.iov_len = pktlen;
  msg.msg_iov = &msg_iov;
  msg.msg_iovlen = 1;

#if defined(__linux__) && defined(UDP_SEGMENT)
  if(pktlen > gsolen) {
    /* Only set this, when we need it. macOS, for example,
     * does not seem to like a msg_control of length 0. */
    msg.msg_control = msg_ctrl;
    assert(sizeof(msg_ctrl) >= CMSG_SPACE(sizeof(uint16_t)));
    msg.msg_controllen = CMSG_SPACE(sizeof(uint16_t));
    cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_UDP;
    cm->cmsg_type = UDP_SEGMENT;
    cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
    *(uint16_t *)(void *)CMSG_DATA(cm) = gsolen & 0xffff;
  }
#endif


  while((sent = sendmsg(qctx->sockfd, &msg, 0)) == -1 && SOCKERRNO == EINTR)
    ;

  if(sent == -1) {
    switch(SOCKERRNO) {
    case EAGAIN:
#if EAGAIN != EWOULDBLOCK
    case EWOULDBLOCK:
#endif
      return CURLE_AGAIN;
    case EMSGSIZE:
      /* UDP datagram is too large; caused by PMTUD. Just let it be lost. */
      break;
    case EIO:
      if(pktlen > gsolen) {
        /* GSO failure */
        failf(data, "sendmsg() returned %zd (errno %d); disable GSO", sent,
              SOCKERRNO);
        qctx->no_gso = TRUE;
        return send_packet_no_gso(cf, data, qctx, pkt, pktlen, gsolen, psent);
      }
      /* FALLTHROUGH */
    default:
      failf(data, "sendmsg() returned %zd (errno %d)", sent, SOCKERRNO);
      return CURLE_SEND_ERROR;
    }
  }
  else {
    assert(pktlen == (size_t)sent);
  }
#else
  ssize_t sent;
  (void)gsolen;

  *psent = 0;

  while((sent = send(qctx->sockfd, (const char *)pkt, pktlen, 0)) == -1 &&
        SOCKERRNO == EINTR)
    ;

  if(sent == -1) {
    if(SOCKERRNO == EAGAIN || SOCKERRNO == EWOULDBLOCK) {
      return CURLE_AGAIN;
    }
    else {
      failf(data, "send() returned %zd (errno %d)", sent, SOCKERRNO);
      if(SOCKERRNO != EMSGSIZE) {
        return CURLE_SEND_ERROR;
      }
      /* UDP datagram is too large; caused by PMTUD. Just let it be
         lost. */
    }
  }
#endif
  (void)cf;
  *psent = pktlen;

  return CURLE_OK;
}

static CURLcode send_packet_no_gso(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct cf_quic_ctx *qctx,
                                   const uint8_t *pkt, size_t pktlen,
                                   size_t gsolen, size_t *psent)
{
  const uint8_t *p, *end = pkt + pktlen;
  size_t sent;

  *psent = 0;

  for(p = pkt; p < end; p += gsolen) {
    size_t len = CURLMIN(gsolen, (size_t)(end - p));
    CURLcode curlcode = do_sendmsg(cf, data, qctx, p, len, len, &sent);
    if(curlcode != CURLE_OK) {
      return curlcode;
    }
    *psent += sent;
  }

  return CURLE_OK;
}

CURLcode vquic_send_packet(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           struct cf_quic_ctx *qctx,
                           const uint8_t *pkt, size_t pktlen, size_t gsolen,
                           size_t *psent)
{
  if(qctx->no_gso && pktlen > gsolen) {
    return send_packet_no_gso(cf, data, qctx, pkt, pktlen, gsolen, psent);
  }

  return do_sendmsg(cf, data, qctx, pkt, pktlen, gsolen, psent);
}



void vquic_push_blocked_pkt(struct Curl_cfilter *cf,
                            struct cf_quic_ctx *qctx,
                            const uint8_t *pkt, size_t pktlen, size_t gsolen)
{
  struct vquic_blocked_pkt *blkpkt;

  (void)cf;
  assert(qctx->num_blocked_pkt <
         sizeof(qctx->blocked_pkt) / sizeof(qctx->blocked_pkt[0]));

  blkpkt = &qctx->blocked_pkt[qctx->num_blocked_pkt++];

  blkpkt->pkt = pkt;
  blkpkt->pktlen = pktlen;
  blkpkt->gsolen = gsolen;
}

CURLcode vquic_send_blocked_pkt(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                struct cf_quic_ctx *qctx)
{
  size_t sent;
  CURLcode curlcode;
  struct vquic_blocked_pkt *blkpkt;

  (void)cf;
  for(; qctx->num_blocked_pkt_sent < qctx->num_blocked_pkt;
      ++qctx->num_blocked_pkt_sent) {
    blkpkt = &qctx->blocked_pkt[qctx->num_blocked_pkt_sent];
    curlcode = vquic_send_packet(cf, data, qctx, blkpkt->pkt,
                                 blkpkt->pktlen, blkpkt->gsolen, &sent);

    if(curlcode) {
      if(curlcode == CURLE_AGAIN) {
        blkpkt->pkt += sent;
        blkpkt->pktlen -= sent;
      }
      return curlcode;
    }
  }

  qctx->num_blocked_pkt = 0;
  qctx->num_blocked_pkt_sent = 0;

  return CURLE_OK;
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
  (void)transport;
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
