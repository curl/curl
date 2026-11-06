/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                             | (__| |_| |  _ <| |___
 *                              \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2026 curl contributors
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received a copy of the distribution. The terms
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
#include "unitcheck.h"

#ifdef __linux__
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#endif

#include "cfilters.h"
#include "urldata.h"
#include "vquic/vquic_int.h"

#if defined(__linux__) && defined(USE_HTTP3) && defined(HAVE_SENDMMSG) && \
  defined(UDP_GRO) && defined(UDP_SEGMENT) && defined(SO_TIMESTAMPNS)

#define T4783_SENDS 16
#define T4783_DATAGRAMS (2 * T4783_SENDS)
#define T4783_MAX_CALLBACKS T4783_DATAGRAMS
#define T4783_SMALL_SIZE 512
#define T4783_LARGE_SIZE 768
#define T4783_PAYLOAD_SIZE (2 * T4783_LARGE_SIZE)

struct t4783_callback_record {
  size_t buflen;
  size_t gso_size;
  size_t actual_datagrams;
  size_t modeled_datagrams;
};

struct t4783_ancillary_record {
  int msg_flags;
  size_t controllen;
  size_t udp_gro_cmsg_len;
  size_t udp_gro_size;
  bool timestamp_seen;
  bool timestamp_valid;
  bool tos_seen;
  bool tos_valid;
  bool udp_gro_seen;
  bool udp_gro_valid;
};

struct t4783_state {
  struct t4783_callback_record records[T4783_MAX_CALLBACKS];
  struct t4783_ancillary_record ancillary[T4783_MAX_CALLBACKS];
  size_t callback_count;
  size_t ancillary_count;
  size_t actual_datagrams;
  size_t modeled_datagrams;
  size_t gro_aggregates;
  size_t errors;
};

static size_t t4783_datagram_size(size_t index)
{
  return ((index / 2) % 2) ? T4783_LARGE_SIZE : T4783_SMALL_SIZE;
}

static unsigned char t4783_datagram_marker(size_t index)
{
  const unsigned char base = (unsigned char)('a' + index / 2);
  return (index % 2) ? (unsigned char)(base - 'a' + 'A') : base;
}

static bool t4783_matches_datagram(const unsigned char *buf, size_t len,
                                   size_t index)
{
  size_t i;
  unsigned char marker;

  if(index >= T4783_DATAGRAMS || len != t4783_datagram_size(index))
    return FALSE;
  marker = t4783_datagram_marker(index);
  for(i = 0; i < len; ++i) {
    if(buf[i] != marker)
      return FALSE;
  }
  return TRUE;
}

static void t4783_recvmsg_observer(void *control, size_t controllen,
                                   int msg_flags, void *userp)
{
  struct t4783_state *state = userp;
  struct t4783_ancillary_record *record;
  struct msghdr msg;
  struct cmsghdr *cmsg;

  if(state->ancillary_count >= T4783_MAX_CALLBACKS) {
    ++state->errors;
    return;
  }
  record = &state->ancillary[state->ancillary_count++];
  record->msg_flags = msg_flags;
  record->controllen = controllen;
  memset(&msg, 0, sizeof(msg));
  msg.msg_control = control;
  msg.msg_controllen = controllen;
  for(cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if(cmsg->cmsg_level == SOL_SOCKET &&
       cmsg->cmsg_type == SO_TIMESTAMPNS) {
      record->timestamp_seen = TRUE;
      if(cmsg->cmsg_len >= CMSG_LEN(sizeof(struct timespec)))
        record->timestamp_valid = TRUE;
    }
    else if(cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS) {
      record->tos_seen = TRUE;
      if(cmsg->cmsg_len >= CMSG_LEN(sizeof(uint8_t)))
        record->tos_valid = TRUE;
    }
    if(cmsg->cmsg_level == SOL_UDP && cmsg->cmsg_type == UDP_GRO) {
      int gro_size;
      if(cmsg->cmsg_len < CMSG_LEN(sizeof(gro_size)))
        continue;
      if(!record->udp_gro_seen) {
        record->udp_gro_seen = TRUE;
        record->udp_gro_cmsg_len = cmsg->cmsg_len;
        memcpy(&gro_size, CMSG_DATA(cmsg), sizeof(gro_size));
        if(gro_size > 0) {
          record->udp_gro_valid = TRUE;
          record->udp_gro_size = (size_t)gro_size;
        }
      }
    }
  }
}

static CURLcode t4783_recv_cb(const unsigned char *buf, size_t buflen,
                              size_t gso_size,
                              struct sockaddr_storage *remote_addr,
                              socklen_t remote_addrlen, uint8_t ecn,
                              void *userp)
{
  struct t4783_state *state = userp;
  struct t4783_callback_record *record;
  size_t offset, index, count;

  (void)remote_addr;
  (void)remote_addrlen;
  (void)ecn;
  if(state->callback_count >= T4783_MAX_CALLBACKS) {
    ++state->errors;
    return CURLE_OK;
  }

  record = &state->records[state->callback_count++];
  record->buflen = buflen;
  record->gso_size = gso_size;
  if(!gso_size) {
    ++state->errors;
    return CURLE_OK;
  }

  /* Validate the actual aggregate payload independently of gso_size. */
  for(offset = 0, index = state->actual_datagrams; offset < buflen;) {
    size_t datagram_len;
    if(index >= T4783_DATAGRAMS) {
      ++state->errors;
      break;
    }
    datagram_len = t4783_datagram_size(index);
    if(datagram_len > buflen - offset ||
       !t4783_matches_datagram(buf + offset, datagram_len, index)) {
      ++state->errors;
      break;
    }
    offset += datagram_len;
    ++index;
  }
  if(offset == buflen) {
    count = index - state->actual_datagrams;
    record->actual_datagrams = count;
    state->actual_datagrams = index;
    if(count > 1)
      ++state->gro_aggregates;
  }

  /* Model the individual inputs curl's backend derives from gso_size. */
  for(offset = 0, index = state->modeled_datagrams; offset < buflen;
      offset += gso_size, ++index) {
    size_t part_len = CURLMIN(gso_size, buflen - offset);
    if(index >= T4783_DATAGRAMS ||
       !t4783_matches_datagram(buf + offset, part_len, index))
      ++state->errors;
    ++record->modeled_datagrams;
    ++state->modeled_datagrams;
  }
  return CURLE_OK;
}

static bool t4783_option(int fd, int level, int option, int value)
{
  return setsockopt(fd, level, option, &value, sizeof(value)) == 0;
}

static bool t4783_unsupported_error(int error)
{
  return error == ENOPROTOOPT || error == EOPNOTSUPP || error == ENOTSUP;
}
#endif

static CURLcode test_unit4783(const char *arg)
{
#if defined(__linux__) && defined(USE_HTTP3) && defined(HAVE_SENDMMSG) && \
  defined(UDP_GRO) && defined(UDP_SEGMENT) && defined(SO_TIMESTAMPNS)
  UNITTEST_BEGIN_SIMPLE

  struct Curl_easy *data = NULL;
  struct cf_quic_ctx qctx;
  struct Curl_cfilter cf;
  struct t4783_state state;
  struct sockaddr_in addr;
  socklen_t addrlen = sizeof(addr);
  curl_socket_t rx = CURL_SOCKET_BAD;
  curl_socket_t tx = CURL_SOCKET_BAD;
  CURLcode result = CURLE_OK;
  int flags, i, value = 1;
  const char *skip_reason = NULL;
  bool qctx_initialized = FALSE;

  (void)arg;
  memset(&qctx, 0, sizeof(qctx));
  memset(&cf, 0, sizeof(cf));
  memset(&state, 0, sizeof(state));
  memset(&addr, 0, sizeof(addr));

  rx = CURL_SOCKET(AF_INET, SOCK_DGRAM, 0);
  tx = CURL_SOCKET(AF_INET, SOCK_DGRAM, 0);
  if(rx == CURL_SOCKET_BAD || tx == CURL_SOCKET_BAD) {
    fail("could not create loopback UDP sockets");
    goto cleanup;
  }
  if(!t4783_option((int)rx, IPPROTO_UDP, UDP_GRO, value)) {
    if(t4783_unsupported_error(errno)) {
      skip_reason = "kernel does not support UDP_GRO";
    }
    else
      fail("could not enable UDP_GRO");
    goto cleanup;
  }
  if(!t4783_option((int)rx, SOL_SOCKET, SO_TIMESTAMPNS, value)) {
    if(t4783_unsupported_error(errno))
      skip_reason = "kernel does not support SO_TIMESTAMPNS";
    else
      fail("could not enable SO_TIMESTAMPNS");
    goto cleanup;
  }
  if(!t4783_option((int)rx, IPPROTO_IP, IP_RECVTOS, value)) {
    if(t4783_unsupported_error(errno))
      skip_reason = "kernel does not support IP_RECVTOS";
    else
      fail("could not enable IP_RECVTOS");
    goto cleanup;
  }
  if(!t4783_option((int)tx, IPPROTO_IP, IP_TOS, 3)) {
    if(t4783_unsupported_error(errno))
      skip_reason = "kernel does not support IP_TOS";
    else
      fail("could not set IP_TOS");
    goto cleanup;
  }

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if(bind((int)rx, (struct sockaddr *)&addr, sizeof(addr)) ||
     getsockname((int)rx, (struct sockaddr *)&addr, &addrlen)) {
    fail("could not bind loopback UDP receiver");
    goto cleanup;
  }
  flags = fcntl((int)rx, F_GETFL, 0);
  if(flags == -1 || fcntl((int)rx, F_SETFL, flags | O_NONBLOCK) == -1) {
    fail("could not make loopback UDP receiver nonblocking");
    goto cleanup;
  }

  {
    int segment_size = 0;
    socklen_t segment_size_len = sizeof(segment_size);
    if(getsockopt((int)tx, IPPROTO_UDP, UDP_SEGMENT, &segment_size,
                  &segment_size_len)) {
      int sockerr = errno;
      if(t4783_unsupported_error(sockerr))
        skip_reason = "kernel does not support UDP_SEGMENT";
      else {
        char errbuf[CURL_ERROR_SIZE];
        curl_mfprintf(stderr,
                      "unit4783: getsockopt(UDP_SEGMENT) failed: "
                      "errno=%d (%s)\n", sockerr,
                      curlx_strerror(sockerr, errbuf, sizeof(errbuf)));
        fail("could not query UDP_SEGMENT support");
      }
      goto cleanup;
    }
  }

  for(i = 0; i < T4783_SENDS; ++i) {
    uint16_t segment_size = (i % 2) ? T4783_LARGE_SIZE : T4783_SMALL_SIZE;
    unsigned char payload[T4783_PAYLOAD_SIZE];
    unsigned char control[CMSG_SPACE(sizeof(segment_size))];
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    size_t payload_len = 2 * (size_t)segment_size;
    ssize_t sent;

    memset(payload, (unsigned char)('a' + i), segment_size);
    memset(payload + segment_size, (unsigned char)('A' + i), segment_size);
    memset(control, 0, sizeof(control));
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = payload;
    iov.iov_len = payload_len;
    msg.msg_name = &addr;
    msg.msg_namelen = sizeof(addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = IPPROTO_UDP;
    cmsg->cmsg_type = UDP_SEGMENT;
    cmsg->cmsg_len = CMSG_LEN(sizeof(segment_size));
    memcpy(CMSG_DATA(cmsg), &segment_size, sizeof(segment_size));

    sent = sendmsg((int)tx, &msg, 0);
    if(sent != (ssize_t)payload_len) {
      int sockerr = sent == -1 ? errno : 0;
      if(sent == -1 && t4783_unsupported_error(sockerr))
        skip_reason = "kernel does not support UDP_SEGMENT";
      else {
        if(sent == -1) {
          char errbuf[CURL_ERROR_SIZE];
          curl_mfprintf(stderr,
                        "unit4783: sendmsg(UDP_SEGMENT) failed: "
                        "errno=%d (%s)\n", sockerr,
                        curlx_strerror(sockerr, errbuf, sizeof(errbuf)));
        }
        else
          curl_mfprintf(stderr,
                        "unit4783: sendmsg(UDP_SEGMENT) returned %zd, "
                        "expected %zu\n", sent, payload_len);
        fail("UDP_SEGMENT loopback send failed");
      }
      goto cleanup;
    }
  }

  result = Curl_open(&data);
  if(result) {
    fail("Curl_open() failed");
    goto cleanup;
  }
  result = Curl_vquic_ctx_init(data, &qctx);
  if(result) {
    fail("Curl_vquic_ctx_init() failed");
    goto cleanup;
  }
  qctx_initialized = TRUE;
  qctx.sockfd = rx;
  qctx.recvmsg_observer = t4783_recvmsg_observer;
  qctx.recvmsg_observer_userp = &state;
  cf.connected = TRUE;

  result = Curl_vquic_recv_packets(&cf, data, &qctx, T4783_DATAGRAMS,
                                   t4783_recv_cb, &state);
  fail_unless(result == CURLE_OK, "Curl_vquic_recv_packets() failed");

  curl_mfprintf(stderr,
                "unit4783 callbacks=%zu actual_datagrams=%zu "
                "modeled_datagrams=%zu gro_aggregates=%zu "
                "ancillary_records=%zu errors=%zu\n",
                state.callback_count, state.actual_datagrams,
                state.modeled_datagrams, state.gro_aggregates,
                state.ancillary_count, state.errors);
  for(i = 0; (size_t)i < state.callback_count; ++i) {
    const struct t4783_callback_record *record = &state.records[i];
    const struct t4783_ancillary_record *ancillary = &state.ancillary[i];
    curl_mfprintf(stderr,
                  "unit4783 callback[%d] len=%zu gso_size=%zu "
                  "aggregate_datagrams=%zu modeled_datagrams=%zu "
                  "flags=0x%x controllen=%zu UDP_GRO_cmsg_len=%zu "
                  "UDP_GRO_size=%zu UDP_GRO_cmsg=%d timestamp=%d/%d "
                  "TOS=%d/%d\n",
                  i, record->buflen, record->gso_size,
                  record->actual_datagrams, record->modeled_datagrams,
                  (unsigned int)ancillary->msg_flags, ancillary->controllen,
                  ancillary->udp_gro_cmsg_len, ancillary->udp_gro_size,
                  ancillary->udp_gro_seen, ancillary->timestamp_seen,
                  ancillary->timestamp_valid, ancillary->tos_seen,
                  ancillary->tos_valid);
  }
  if(!state.gro_aggregates &&
     state.actual_datagrams == T4783_DATAGRAMS) {
    skip_reason = "kernel did not coalesce UDP_SEGMENT packets with UDP_GRO";
    goto cleanup;
  }
  fail_unless(state.ancillary_count == state.callback_count,
              "receive observer and callback counts differed");
  fail_unless(state.errors == 0, "callback payload boundaries were incorrect");
  fail_unless(state.actual_datagrams == T4783_DATAGRAMS,
              "did not observe all original UDP datagrams");
  fail_unless(state.modeled_datagrams == T4783_DATAGRAMS,
              "QUIC receive callback did not preserve datagram boundaries");
  for(i = 0; (size_t)i < state.callback_count; ++i) {
    const struct t4783_callback_record *record = &state.records[i];
    const struct t4783_ancillary_record *ancillary = &state.ancillary[i];
    if(record->actual_datagrams > 1) {
      fail_unless(ancillary->timestamp_seen && ancillary->timestamp_valid,
                  "aggregate receive had no valid timestamp CMSG");
      fail_unless(ancillary->tos_seen && ancillary->tos_valid,
                  "aggregate receive had no valid IPv4 TOS CMSG");
      if(record->gso_size < record->buflen) {
        fail_unless(ancillary->udp_gro_valid &&
                    ancillary->udp_gro_size == record->gso_size,
                    "callback segment size did not match UDP_GRO CMSG");
      }
      else {
        fail_unless(ancillary->msg_flags & MSG_CTRUNC,
                    "missing GRO metadata was not accompanied by MSG_CTRUNC");
        fail_unless(!ancillary->udp_gro_valid,
                    "truncated receive unexpectedly had valid GRO metadata");
      }
    }
  }

cleanup:
  if(qctx_initialized)
    Curl_vquic_ctx_free(&qctx);
  if(data)
    Curl_close(&data);
  if(rx != CURL_SOCKET_BAD)
    sclose(rx);
  if(tx != CURL_SOCKET_BAD)
    sclose(tx);
  if(skip_reason)
    unittest_skip(skip_reason);
  UNITTEST_END_SIMPLE
#else
  UNITTEST_BEGIN_SIMPLE
  unittest_skip("requires Linux, HTTP/3, recvmmsg and UDP_GRO/UDP_SEGMENT");
  UNITTEST_END_SIMPLE
#endif
}
