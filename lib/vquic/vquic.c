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
#include "../curl_setup.h"
#include "../urldata.h"
#include "vquic.h"

#include "../curl_trc.h"

#if !defined(CURL_DISABLE_HTTP) && defined(USE_HTTP3)

#ifdef HAVE_NETINET_UDP_H
#include <netinet/udp.h>
#endif

#ifdef USE_NGHTTP3
#include <nghttp3/nghttp3.h>
#endif

#include "../bufq.h"
#include "../curlx/dynbuf.h"
#include "../curlx/fopen.h"
#include "../cfilters.h"
#include "curl_ngtcp2.h"
#include "curl_quiche.h"
#include "../multiif.h"
#include "../progress.h"
#include "../rand.h"
#include "vquic_int.h"
#include "../curlx/strerr.h"
#include "../curlx/strparse.h"


#define NW_CHUNK_SIZE     (64 * 1024)
#define NW_SEND_CHUNKS    1

int Curl_vquic_init(void)
{
#if defined(USE_NGTCP2) && defined(OPENSSL_QUIC_API2)
  if(ngtcp2_crypto_ossl_init())
    return 0;
#endif

  return 1;
}

void Curl_quic_ver(char *p, size_t len)
{
#if defined(USE_NGTCP2) && defined(USE_NGHTTP3)
  Curl_ngtcp2_ver(p, len);
#elif defined(USE_QUICHE)
  Curl_quiche_ver(p, len);
#endif
}

CURLcode vquic_ctx_init(struct Curl_easy *data,
                        struct cf_quic_ctx *qctx)
{
  Curl_bufq_init2(&qctx->sendbuf, NW_CHUNK_SIZE, NW_SEND_CHUNKS,
                  BUFQ_OPT_SOFT_LIMIT);
#if defined(__linux__) && defined(UDP_SEGMENT) && defined(HAVE_SENDMSG)
  qctx->no_gso = FALSE;
#else
  qctx->no_gso = TRUE;
#endif
#ifdef DEBUGBUILD
  {
    const char *p = getenv("CURL_DBG_QUIC_WBLOCK");
    if(p) {
      curl_off_t l;
      if(!curlx_str_number(&p, &l, 100))
        qctx->wblock_percent = (int)l;
    }
  }
#endif
  vquic_ctx_set_time(qctx, Curl_pgrs_now(data));

  return CURLE_OK;
}

void vquic_ctx_free(struct cf_quic_ctx *qctx)
{
  Curl_bufq_free(&qctx->sendbuf);
}

void vquic_ctx_set_time(struct cf_quic_ctx *qctx,
                        const struct curltime *pnow)
{
  qctx->last_op = *pnow;
}

void vquic_ctx_update_time(struct cf_quic_ctx *qctx,
                           const struct curltime *pnow)
{
  qctx->last_op = *pnow;
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
  CURLcode result = CURLE_OK;
#ifdef HAVE_SENDMSG
  struct iovec msg_iov;
  struct msghdr msg = { 0 };
  ssize_t rv;
#if defined(__linux__) && defined(UDP_SEGMENT)
  uint8_t msg_ctrl[32];
  struct cmsghdr *cm;
#endif

  *psent = 0;
  msg_iov.iov_base = (uint8_t *)CURL_UNCONST(pkt);
  msg_iov.iov_len = pktlen;
  msg.msg_iov = &msg_iov;
  msg.msg_iovlen = 1;

#if defined(__linux__) && defined(UDP_SEGMENT)
  if(pktlen > gsolen) {
    /* Only set this, when we need it. macOS, for example,
     * does not seem to like a msg_control of length 0. */
    memset(msg_ctrl, 0, sizeof(msg_ctrl));
    msg.msg_control = msg_ctrl;
    assert(sizeof(msg_ctrl) >= CMSG_SPACE(sizeof(int)));
    msg.msg_controllen = CMSG_SPACE(sizeof(int));
    cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_UDP;
    cm->cmsg_type = UDP_SEGMENT;
    cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
    *(uint16_t *)(void *)CMSG_DATA(cm) = gsolen & 0xffff;
  }
#endif

  while((rv = sendmsg(qctx->sockfd, &msg, 0)) == -1 && SOCKERRNO == SOCKEINTR)
    ;

  if(!curlx_sztouz(rv, psent)) {
    switch(SOCKERRNO) {
    case EAGAIN:
#if EAGAIN != SOCKEWOULDBLOCK
    case SOCKEWOULDBLOCK:
#endif
      return CURLE_AGAIN;
    case SOCKEMSGSIZE:
      /* UDP datagram is too large; caused by PMTUD. Just let it be lost. */
      *psent = pktlen;
      break;
    case EIO:
      if(pktlen > gsolen) {
        /* GSO failure */
        infof(data, "sendmsg() returned %zd (errno %d); disable GSO", rv,
              SOCKERRNO);
        qctx->no_gso = TRUE;
        return send_packet_no_gso(cf, data, qctx, pkt, pktlen, gsolen, psent);
      }
      FALLTHROUGH();
    default:
      failf(data, "sendmsg() returned %zd (errno %d)", rv, SOCKERRNO);
      result = CURLE_SEND_ERROR;
      goto out;
    }
  }
  else if(pktlen != *psent) {
    failf(data, "sendmsg() sent only %zu/%zu bytes", *psent, pktlen);
    result = CURLE_SEND_ERROR;
    goto out;
  }
#else
  ssize_t rv;
  (void)gsolen;

  *psent = 0;

  while((rv = swrite(qctx->sockfd, pkt, pktlen)) == -1 &&
        SOCKERRNO == SOCKEINTR)
    ;

  if(!curlx_sztouz(rv, psent)) {
    if(SOCKERRNO == EAGAIN || SOCKERRNO == SOCKEWOULDBLOCK) {
      result = CURLE_AGAIN;
      goto out;
    }
    else {
      if(SOCKERRNO != SOCKEMSGSIZE) {
        failf(data, "send() returned %zd (errno %d)", rv, SOCKERRNO);
        result = CURLE_SEND_ERROR;
        goto out;
      }
      /* UDP datagram is too large; caused by PMTUD. Just let it be lost. */
      *psent = pktlen;
    }
  }
#endif
  (void)cf;

out:
  return result;
}

#ifdef CURLVERBOSE
#ifdef HAVE_SENDMSG
#define VQUIC_SEND_METHOD   "sendmsg"
#else
#define VQUIC_SEND_METHOD   "send"
#endif
#endif

static CURLcode send_packet_no_gso(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct cf_quic_ctx *qctx,
                                   const uint8_t *pkt, size_t pktlen,
                                   size_t gsolen, size_t *psent)
{
  const uint8_t *p, *end = pkt + pktlen;
  size_t sent, len;
  CURLcode result = CURLE_OK;
  VERBOSE(size_t calls = 0);

  *psent = 0;

  for(p = pkt; p < end; p += gsolen) {
    len = CURLMIN(gsolen, (size_t)(end - p));
    result = do_sendmsg(cf, data, qctx, p, len, len, &sent);
    if(result)
      goto out;
    *psent += sent;
    VERBOSE(++calls);
  }
out:
  CURL_TRC_CF(data, cf, "vquic_%s(len=%zu, gso=%zu, calls=%zu)"
              " -> %d, sent=%zu",
              VQUIC_SEND_METHOD, pktlen, gsolen, calls, result, *psent);
  return result;
}

static CURLcode vquic_send_packets(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct cf_quic_ctx *qctx,
                                   const uint8_t *pkt, size_t pktlen,
                                   size_t gsolen, size_t *psent)
{
  CURLcode result;
#ifdef DEBUGBUILD
  /* simulate network blocking/partial writes */
  if(qctx->wblock_percent > 0) {
    unsigned char c;
    *psent = 0;
    Curl_rand(data, &c, 1);
    if(c >= ((100 - qctx->wblock_percent) * 256 / 100)) {
      CURL_TRC_CF(data, cf, "vquic_flush() simulate EWOULDBLOCK");
      return CURLE_AGAIN;
    }
  }
#endif
  if(qctx->no_gso && pktlen > gsolen) {
    result = send_packet_no_gso(cf, data, qctx, pkt, pktlen, gsolen, psent);
  }
  else {
    result = do_sendmsg(cf, data, qctx, pkt, pktlen, gsolen, psent);
    CURL_TRC_CF(data, cf, "vquic_%s(len=%zu, gso=%zu, calls=1)"
                " -> %d, sent=%zu",
                VQUIC_SEND_METHOD, pktlen, gsolen, result, *psent);
  }
  if(!result)
    qctx->last_io = qctx->last_op;
  return result;
}

CURLcode vquic_flush(struct Curl_cfilter *cf, struct Curl_easy *data,
                     struct cf_quic_ctx *qctx)
{
  const unsigned char *buf;
  size_t blen, sent;
  CURLcode result;
  size_t gsolen;

  while(Curl_bufq_peek(&qctx->sendbuf, &buf, &blen)) {
    gsolen = qctx->gsolen;
    if(qctx->split_len) {
      gsolen = qctx->split_gsolen;
      if(blen > qctx->split_len)
        blen = qctx->split_len;
    }

    result = vquic_send_packets(cf, data, qctx, buf, blen, gsolen, &sent);
    if(result) {
      if(result == CURLE_AGAIN) {
        Curl_bufq_skip(&qctx->sendbuf, sent);
        if(qctx->split_len)
          qctx->split_len -= sent;
      }
      return result;
    }
    Curl_bufq_skip(&qctx->sendbuf, sent);
    if(qctx->split_len)
      qctx->split_len -= sent;
  }
  return CURLE_OK;
}

CURLcode vquic_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                    struct cf_quic_ctx *qctx, size_t gsolen)
{
  qctx->gsolen = gsolen;
  return vquic_flush(cf, data, qctx);
}

CURLcode vquic_send_tail_split(struct Curl_cfilter *cf, struct Curl_easy *data,
                               struct cf_quic_ctx *qctx, size_t gsolen,
                               size_t tail_len, size_t tail_gsolen)
{
  DEBUGASSERT(Curl_bufq_len(&qctx->sendbuf) > tail_len);
  qctx->split_len = Curl_bufq_len(&qctx->sendbuf) - tail_len;
  qctx->split_gsolen = gsolen;
  qctx->gsolen = tail_gsolen;
  CURL_TRC_CF(data, cf, "vquic_send_tail_split: [%zu gso=%zu][%zu gso=%zu]",
              qctx->split_len, qctx->split_gsolen, tail_len, qctx->gsolen);
  return vquic_flush(cf, data, qctx);
}

#if defined(HAVE_SENDMMSG) || defined(HAVE_SENDMSG)
static size_t vquic_msghdr_get_udp_gro(struct msghdr *msg)
{
  int gso_size = 0;
#if defined(__linux__) && defined(UDP_GRO)
  struct cmsghdr *cmsg;

  /* Workaround musl CMSG_NXTHDR issue */
#if defined(__clang__) && !defined(__GLIBC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-compare"
#pragma clang diagnostic ignored "-Wcast-align"
#endif
  for(cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
#if defined(__clang__) && !defined(__GLIBC__)
#pragma clang diagnostic pop
#endif
    if(cmsg->cmsg_level == SOL_UDP && cmsg->cmsg_type == UDP_GRO) {
      memcpy(&gso_size, CMSG_DATA(cmsg), sizeof(gso_size));

      break;
    }
  }
#endif
  (void)msg;

  return (size_t)gso_size;
}
#endif

#ifdef HAVE_SENDMMSG
static CURLcode recvmmsg_packets(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 struct cf_quic_ctx *qctx,
                                 size_t max_pkts,
                                 vquic_recv_pkts_cb *recv_cb, void *userp)
{
#if defined(__linux__) && defined(UDP_GRO)
#define MMSG_NUM  16
#define UDP_GRO_CNT_MAX  64
#else
#define MMSG_NUM  64
#define UDP_GRO_CNT_MAX  1
#endif
#define MSG_BUF_SIZE  (UDP_GRO_CNT_MAX * 1500)
  struct iovec msg_iov[MMSG_NUM];
  struct mmsghdr mmsg[MMSG_NUM];
  uint8_t msg_ctrl[MMSG_NUM * CMSG_SPACE(sizeof(int))];
  struct sockaddr_storage remote_addr[MMSG_NUM];
  size_t total_nread = 0, pkts = 0, calls = 0;
  int mcount, i, n;
  char errstr[STRERROR_LEN];
  CURLcode result = CURLE_OK;
  size_t gso_size;
  char *sockbuf = NULL;
  uint8_t (*bufs)[MSG_BUF_SIZE] = NULL;

  DEBUGASSERT(max_pkts > 0);
  result = Curl_multi_xfer_sockbuf_borrow(data, MMSG_NUM * MSG_BUF_SIZE,
                                          &sockbuf);
  if(result)
    goto out;
  bufs = (uint8_t (*)[MSG_BUF_SIZE])sockbuf;

  total_nread = 0;
  while(pkts < max_pkts) {
    n = (int)CURLMIN(CURLMIN(MMSG_NUM, IOV_MAX), max_pkts);
    memset(&mmsg, 0, sizeof(mmsg));
    for(i = 0; i < n; ++i) {
      msg_iov[i].iov_base = bufs[i];
      msg_iov[i].iov_len = (int)sizeof(bufs[i]);
      mmsg[i].msg_hdr.msg_iov = &msg_iov[i];
      mmsg[i].msg_hdr.msg_iovlen = 1;
      mmsg[i].msg_hdr.msg_name = &remote_addr[i];
      mmsg[i].msg_hdr.msg_namelen = sizeof(remote_addr[i]);
      mmsg[i].msg_hdr.msg_control = &msg_ctrl[i * CMSG_SPACE(sizeof(int))];
      mmsg[i].msg_hdr.msg_controllen = CMSG_SPACE(sizeof(int));
    }

    while((mcount = recvmmsg(qctx->sockfd, mmsg, n, 0, NULL)) == -1 &&
          (SOCKERRNO == SOCKEINTR || SOCKERRNO == SOCKEMSGSIZE))
      ;
    if(mcount == -1) {
      if(SOCKERRNO == EAGAIN || SOCKERRNO == SOCKEWOULDBLOCK) {
        CURL_TRC_CF(data, cf, "ingress, recvmmsg -> EAGAIN");
        goto out;
      }
      if(!cf->connected && SOCKERRNO == SOCKECONNREFUSED) {
        struct ip_quadruple ip;
        if(!Curl_cf_socket_peek(cf->next, data, NULL, NULL, &ip))
          failf(data, "QUIC: connection to %s port %u refused",
                ip.remote_ip, ip.remote_port);
        result = CURLE_COULDNT_CONNECT;
        goto out;
      }
      curlx_strerror(SOCKERRNO, errstr, sizeof(errstr));
      failf(data, "QUIC: recvmmsg() unexpectedly returned %d (errno=%d; %s)",
                  mcount, SOCKERRNO, errstr);
      result = CURLE_RECV_ERROR;
      goto out;
    }

    ++calls;
    for(i = 0; i < mcount; ++i) {
      /* A zero-length UDP packet is no QUIC packet. Ignore. */
      if(!mmsg[i].msg_len)
        continue;
      total_nread += mmsg[i].msg_len;

      gso_size = vquic_msghdr_get_udp_gro(&mmsg[i].msg_hdr);
      if(gso_size == 0)
        gso_size = mmsg[i].msg_len;

      result = recv_cb(bufs[i], mmsg[i].msg_len, gso_size,
                       mmsg[i].msg_hdr.msg_name,
                       mmsg[i].msg_hdr.msg_namelen, 0, userp);
      if(result)
        goto out;
      pkts += (mmsg[i].msg_len + gso_size - 1) / gso_size;
    }
  }

out:
  if(total_nread || result)
    CURL_TRC_CF(data, cf, "vquic_recvmmsg(len=%zu, packets=%zu, calls=%zu)"
                " -> %d", total_nread, pkts, calls, result);
  Curl_multi_xfer_sockbuf_release(data, sockbuf);
  return result;
}

#elif defined(HAVE_SENDMSG)
static CURLcode recvmsg_packets(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                struct cf_quic_ctx *qctx,
                                size_t max_pkts,
                                vquic_recv_pkts_cb *recv_cb, void *userp)
{
  struct iovec msg_iov;
  struct msghdr msg;
  uint8_t buf[64 * 1024];
  struct sockaddr_storage remote_addr;
  size_t total_nread, pkts, calls;
  ssize_t rc;
  size_t nread;
  char errstr[STRERROR_LEN];
  CURLcode result = CURLE_OK;
  uint8_t msg_ctrl[CMSG_SPACE(sizeof(int))];
  size_t gso_size;

  DEBUGASSERT(max_pkts > 0);
  for(pkts = 0, total_nread = 0, calls = 0; pkts < max_pkts;) {
    /* fully initialise this on each call to `recvmsg()`. There seem to
     * operating systems out there that mess with `msg_iov.iov_len`. */
    memset(&msg, 0, sizeof(msg));
    msg_iov.iov_base = buf;
    msg_iov.iov_len = (int)sizeof(buf);
    msg.msg_iov = &msg_iov;
    msg.msg_iovlen = 1;
    msg.msg_control = msg_ctrl;
    msg.msg_name = &remote_addr;
    msg.msg_namelen = sizeof(remote_addr);
    msg.msg_controllen = sizeof(msg_ctrl);

    while((rc = recvmsg(qctx->sockfd, &msg, 0)) == -1 &&
          (SOCKERRNO == SOCKEINTR || SOCKERRNO == SOCKEMSGSIZE))
      ;
    if(!curlx_sztouz(rc, &nread)) {
      if(SOCKERRNO == EAGAIN || SOCKERRNO == SOCKEWOULDBLOCK) {
        goto out;
      }
      if(!cf->connected && SOCKERRNO == SOCKECONNREFUSED) {
        struct ip_quadruple ip;
        if(!Curl_cf_socket_peek(cf->next, data, NULL, NULL, &ip))
          failf(data, "QUIC: connection to %s port %u refused",
                ip.remote_ip, ip.remote_port);
        result = CURLE_COULDNT_CONNECT;
        goto out;
      }
      curlx_strerror(SOCKERRNO, errstr, sizeof(errstr));
      failf(data, "QUIC: recvmsg() unexpectedly returned %zd (errno=%d; %s)",
            rc, SOCKERRNO, errstr);
      result = CURLE_RECV_ERROR;
      goto out;
    }

    total_nread += nread;
    ++calls;

    /* A 0-length UDP packet is no QUIC packet */
    if(!nread)
      continue;

    gso_size = vquic_msghdr_get_udp_gro(&msg);
    if(gso_size == 0)
      gso_size = nread;

    result = recv_cb(buf, nread, gso_size,
                     msg.msg_name, msg.msg_namelen, 0, userp);
    if(result)
      goto out;
    pkts += (nread + gso_size - 1) / gso_size;
  }

out:
  if(total_nread || result)
    CURL_TRC_CF(data, cf, "vquic_recvmsg(len=%zu, packets=%zu, calls=%zu)"
                " -> %d", total_nread, pkts, calls, result);
  return result;
}

#else /* HAVE_SENDMMSG || HAVE_SENDMSG */
static CURLcode recvfrom_packets(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 struct cf_quic_ctx *qctx,
                                 size_t max_pkts,
                                 vquic_recv_pkts_cb *recv_cb, void *userp)
{
  uint8_t buf[64 * 1024];
  int bufsize = (int)sizeof(buf);
  struct sockaddr_storage remote_addr;
  socklen_t remote_addrlen = sizeof(remote_addr);
  size_t total_nread, pkts, calls = 0, nread;
  ssize_t rv;
  char errstr[STRERROR_LEN];
  CURLcode result = CURLE_OK;

  DEBUGASSERT(max_pkts > 0);
  for(pkts = 0, total_nread = 0; pkts < max_pkts;) {
    while((rv = recvfrom(qctx->sockfd, (char *)buf, bufsize, 0,
                         (struct sockaddr *)&remote_addr,
                         &remote_addrlen)) == -1 &&
          (SOCKERRNO == SOCKEINTR || SOCKERRNO == SOCKEMSGSIZE))
      ;
    if(!curlx_sztouz(rv, &nread)) {
      if(SOCKERRNO == EAGAIN || SOCKERRNO == SOCKEWOULDBLOCK) {
        CURL_TRC_CF(data, cf, "ingress, recvfrom -> EAGAIN");
        goto out;
      }
      if(!cf->connected && SOCKERRNO == SOCKECONNREFUSED) {
        struct ip_quadruple ip;
        if(!Curl_cf_socket_peek(cf->next, data, NULL, NULL, &ip))
          failf(data, "QUIC: connection to %s port %u refused",
                ip.remote_ip, ip.remote_port);
        result = CURLE_COULDNT_CONNECT;
        goto out;
      }
      curlx_strerror(SOCKERRNO, errstr, sizeof(errstr));
      failf(data, "QUIC: recvfrom() unexpectedly returned %zd (errno=%d; %s)",
            rv, SOCKERRNO, errstr);
      result = CURLE_RECV_ERROR;
      goto out;
    }

    ++pkts;
    ++calls;

    /* A 0-length UDP packet is no QUIC packet */
    if(!nread)
      continue;

    total_nread += nread;
    result = recv_cb(buf, nread, nread, &remote_addr, remote_addrlen,
                     0, userp);
    if(result)
      goto out;
  }

out:
  if(total_nread || result)
    CURL_TRC_CF(data, cf, "vquic_recvfrom(len=%zu, packets=%zu, calls=%zu)"
                " -> %d", total_nread, pkts, calls, result);
  return result;
}
#endif /* !HAVE_SENDMMSG && !HAVE_SENDMSG */

CURLcode vquic_recv_packets(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            struct cf_quic_ctx *qctx,
                            size_t max_pkts,
                            vquic_recv_pkts_cb *recv_cb, void *userp)
{
  CURLcode result;
#ifdef HAVE_SENDMMSG
  result = recvmmsg_packets(cf, data, qctx, max_pkts, recv_cb, userp);
#elif defined(HAVE_SENDMSG)
  result = recvmsg_packets(cf, data, qctx, max_pkts, recv_cb, userp);
#else
  result = recvfrom_packets(cf, data, qctx, max_pkts, recv_cb, userp);
#endif
  if(!result) {
    if(!qctx->got_first_byte) {
      qctx->got_first_byte = TRUE;
      qctx->first_byte_at = qctx->last_op;
    }
    qctx->last_io = qctx->last_op;
  }
  return result;
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
  char *qlog_dir = curl_getenv("QLOGDIR");
  *qlogfdp = -1;
  if(qlog_dir) {
    struct dynbuf fname;
    CURLcode result;
    unsigned int i;
    curlx_dyn_init(&fname, DYN_QLOG_NAME);
    result = curlx_dyn_add(&fname, qlog_dir);
    if(!result)
      result = curlx_dyn_add(&fname, "/");
    for(i = 0; (i < scidlen) && !result; i++) {
      char hex[3];
      curl_msnprintf(hex, 3, "%02x", scid[i]);
      result = curlx_dyn_add(&fname, hex);
    }
    if(!result)
      result = curlx_dyn_add(&fname, ".sqlog");

    if(!result) {
      int qlogfd = curlx_open(curlx_dyn_ptr(&fname),
                              O_WRONLY | O_CREAT | CURL_O_BINARY,
                              data->set.new_file_perms
#ifdef _WIN32
                              & (_S_IREAD | _S_IWRITE)
#endif
                              );
      if(qlogfd != -1)
        *qlogfdp = qlogfd;
    }
    curlx_dyn_free(&fname);
    curlx_free(qlog_dir);
    if(result)
      return result;
  }

  return CURLE_OK;
}

CURLcode Curl_cf_quic_create(struct Curl_cfilter **pcf,
                             struct Curl_easy *data,
                             struct connectdata *conn,
                             const struct Curl_addrinfo *ai,
                             uint8_t transport)
{
  (void)transport;
  DEBUGASSERT(transport == TRNSPRT_QUIC);
#if defined(USE_NGTCP2) && defined(USE_NGHTTP3)
  return Curl_cf_ngtcp2_create(pcf, data, conn, ai);
#elif defined(USE_QUICHE)
  return Curl_cf_quiche_create(pcf, data, conn, ai);
#else
  *pcf = NULL;
  (void)data;
  (void)conn;
  (void)ai;
  return CURLE_NOT_BUILT_IN;
#endif
}

CURLcode Curl_conn_may_http3(struct Curl_easy *data,
                             const struct connectdata *conn,
                             unsigned char transport)
{
  if(transport == TRNSPRT_UNIX) {
    /* cannot do QUIC over a Unix domain socket */
    return CURLE_QUIC_CONNECT_ERROR;
  }
  if(!(conn->scheme->flags & PROTOPT_SSL)) {
    failf(data, "HTTP/3 requested for non-HTTPS URL");
    return CURLE_URL_MALFORMAT;
  }
#ifndef CURL_DISABLE_PROXY
  if(conn->bits.socksproxy) {
    failf(data, "HTTP/3 is not supported over a SOCKS proxy");
    return CURLE_URL_MALFORMAT;
  }
  if(conn->bits.httpproxy && conn->bits.tunnel_proxy) {
    failf(data, "HTTP/3 is not supported over an HTTP proxy");
    return CURLE_URL_MALFORMAT;
  }
#endif

  return CURLE_OK;
}

#ifdef CURLVERBOSE
const char *vquic_h3_err_str(uint64_t error_code)
{
  if(error_code <= UINT_MAX) {
    switch((unsigned int)error_code) {
    case CURL_H3_ERR_NO_ERROR:
      return "NO_ERROR";
    case CURL_H3_ERR_GENERAL_PROTOCOL_ERROR:
      return "GENERAL_PROTOCOL_ERROR";
    case CURL_H3_ERR_INTERNAL_ERROR:
      return "INTERNAL_ERROR";
    case CURL_H3_ERR_STREAM_CREATION_ERROR:
      return "STREAM_CREATION_ERROR";
    case CURL_H3_ERR_CLOSED_CRITICAL_STREAM:
      return "CLOSED_CRITICAL_STREAM";
    case CURL_H3_ERR_FRAME_UNEXPECTED:
      return "FRAME_UNEXPECTED";
    case CURL_H3_ERR_FRAME_ERROR:
      return "FRAME_ERROR";
    case CURL_H3_ERR_EXCESSIVE_LOAD:
      return "EXCESSIVE_LOAD";
    case CURL_H3_ERR_ID_ERROR:
      return "ID_ERROR";
    case CURL_H3_ERR_SETTINGS_ERROR:
      return "SETTINGS_ERROR";
    case CURL_H3_ERR_MISSING_SETTINGS:
      return "MISSING_SETTINGS";
    case CURL_H3_ERR_REQUEST_REJECTED:
      return "REQUEST_REJECTED";
    case CURL_H3_ERR_REQUEST_CANCELLED:
      return "REQUEST_CANCELLED";
    case CURL_H3_ERR_REQUEST_INCOMPLETE:
      return "REQUEST_INCOMPLETE";
    case CURL_H3_ERR_MESSAGE_ERROR:
      return "MESSAGE_ERROR";
    case CURL_H3_ERR_CONNECT_ERROR:
      return "CONNECT_ERROR";
    case CURL_H3_ERR_VERSION_FALLBACK:
      return "VERSION_FALLBACK";
    default:
      break;
    }
  }
  /* RFC 9114 ch. 8.1 + 9, reserved future error codes that are NO_ERROR */
  if((error_code >= 0x21) && !((error_code - 0x21) % 0x1f))
    return "NO_ERROR";
  return "unknown";
}
#endif /* CURLVERBOSE */

#if defined(USE_NGTCP2) || defined(USE_NGHTTP3)

static void *vquic_ngtcp2_malloc(size_t size, void *user_data)
{
  (void)user_data;
  return Curl_cmalloc(size);
}

static void vquic_ngtcp2_free(void *ptr, void *user_data)
{
  (void)user_data;
  Curl_cfree(ptr);
}

static void *vquic_ngtcp2_calloc(size_t nmemb, size_t size, void *user_data)
{
  (void)user_data;
  return Curl_ccalloc(nmemb, size);
}

static void *vquic_ngtcp2_realloc(void *ptr, size_t size, void *user_data)
{
  (void)user_data;
  return Curl_crealloc(ptr, size);
}

#ifdef USE_NGTCP2
static struct ngtcp2_mem vquic_ngtcp2_mem = {
  NULL,
  vquic_ngtcp2_malloc,
  vquic_ngtcp2_free,
  vquic_ngtcp2_calloc,
  vquic_ngtcp2_realloc
};
struct ngtcp2_mem *Curl_ngtcp2_mem(void)
{
  return &vquic_ngtcp2_mem;
}
#endif

#ifdef USE_NGHTTP3
static struct nghttp3_mem vquic_nghttp3_mem = {
  NULL,
  vquic_ngtcp2_malloc,
  vquic_ngtcp2_free,
  vquic_ngtcp2_calloc,
  vquic_ngtcp2_realloc
};
struct nghttp3_mem *Curl_nghttp3_mem(void)
{
  return &vquic_nghttp3_mem;
}
#endif

#endif /* USE_NGTCP2 || USE_NGHTTP3 */

#else /* CURL_DISABLE_HTTP || !USE_HTTP3 */

CURLcode Curl_conn_may_http3(struct Curl_easy *data,
                             const struct connectdata *conn,
                             unsigned char transport)
{
  (void)data;
  (void)conn;
  (void)transport;
  DEBUGF(infof(data, "QUIC is not supported in this build"));
  return CURLE_NOT_BUILT_IN;
}

#endif /* !CURL_DISABLE_HTTP && USE_HTTP3 */
