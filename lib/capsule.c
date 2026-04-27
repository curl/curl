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

#if !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP)

#include <curl/curl.h>
#include "urldata.h"
#include "curlx/dynbuf.h"
#include "cfilters.h"
#include "curl_trc.h"
#include "bufq.h"
#include "capsule.h"


/**
 * Convert 64-bit value from network byte order to host byte order
 */
static uint64_t capsule_ntohll(uint64_t value)
{
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
  return value;
#elif (defined(__GNUC__) || defined(__clang__)) && \
      defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
  return __builtin_bswap64(value);
#else
  union {
      uint64_t u64;
      uint32_t u32[2];
  } src, dst;

  src.u64 = value;
  dst.u32[0] = ntohl(src.u32[1]);
  dst.u32[1] = ntohl(src.u32[0]);
  return dst.u64;
#endif
}

static size_t capsule_varint_len(uint64_t value)
{
  if(value <= 0x3F)
    return 1;
  else if(value <= 0x3FFF)
    return 2;
  else if(value <= 0x3FFFFFFF)
    return 4;
  return 8;
}

/**
 * Encode a variable-length integer into a plain buffer.
 * @param buf   Output buffer (must have at least 8 bytes)
 * @param value Value to encode (must be <= 0x3FFFFFFFFFFFFFFF)
 * @return Number of bytes written
 */
static size_t capsule_encode_varint_buf(uint8_t *buf, uint64_t value)
{
  DEBUGASSERT(value <= 0x3FFFFFFFFFFFFFFF);

  if(value <= 0x3F) {
    buf[0] = (uint8_t)value;
    return 1;
  }
  else if(value <= 0x3FFF) {
    uint16_t encoded = (uint16_t)value & 0x3FFF;
    encoded = ntohs(encoded | 0x4000);
    memcpy(buf, &encoded, 2);
    return 2;
  }
  else if(value <= 0x3FFFFFFF) {
    uint32_t encoded = (uint32_t)value & 0x3FFFFFFF;
    encoded = ntohl(encoded | 0x80000000);
    memcpy(buf, &encoded, 4);
    return 4;
  }
  else {
    uint64_t encoded = (uint64_t)value & 0x3FFFFFFFFFFFFFFF;
    encoded = capsule_ntohll(encoded | 0xC000000000000000);
    memcpy(buf, &encoded, 8);
    return 8;
  }
}

static CURLcode capsule_peek_u8(struct bufq *recvbufq,
                                size_t offset,
                                uint8_t *pbyte)
{
  const unsigned char *peek = NULL;
  size_t peeklen = 0;

  if(!Curl_bufq_peek_at(recvbufq, offset, &peek, &peeklen) || !peeklen)
    return CURLE_AGAIN;
  *pbyte = peek[0];
  return CURLE_OK;
}

static CURLcode capsule_decode_varint_at(struct bufq *recvbufq,
                                         size_t offset,
                                         uint64_t *pvalue,
                                         size_t *pconsumed)
{
  uint8_t first_byte, byte;
  uint64_t value;
  size_t nbytes;
  size_t i;
  CURLcode result;

  result = capsule_peek_u8(recvbufq, offset, &first_byte);
  if(result)
    return result;

  nbytes = (size_t)1 << (first_byte >> 6); /* 1, 2, 4 or 8 bytes */
  value = first_byte & 0x3F;

  for(i = 1; i < nbytes; ++i) {
    result = capsule_peek_u8(recvbufq, offset + i, &byte);
    if(result)
      return result;
    value = (value << 8) | byte;
  }

  *pvalue = value;
  *pconsumed = nbytes;
  return CURLE_OK;
}

size_t Curl_capsule_encap_udp_hdr(uint8_t *hdr, size_t hdrlen,
                                  size_t payload_len)
{
  size_t off = 0;
  DEBUGASSERT(hdrlen >= HTTP_CAPSULE_HEADER_MAX_SIZE);
  if(hdrlen < HTTP_CAPSULE_HEADER_MAX_SIZE)
    return 0;
  hdr[off++] = 0; /* capsule type: HTTP Datagram */
  off += capsule_encode_varint_buf(hdr + off, (uint64_t)payload_len + 1);
  hdr[off++] = 0; /* context ID */
  return off;
}

CURLcode Curl_capsule_encap_udp_datagram(struct dynbuf *dyn,
                                         const void *buf, size_t blen)
{
  CURLcode result;
  uint8_t hdr[HTTP_CAPSULE_HEADER_MAX_SIZE];
  size_t hdr_len;

  curlx_dyn_init(dyn, HTTP_CAPSULE_HEADER_MAX_SIZE + blen);
  hdr_len = Curl_capsule_encap_udp_hdr(hdr, sizeof(hdr), blen);
  DEBUGASSERT(hdr_len);
  if(!hdr_len)
    return CURLE_FAILED_INIT;

  result = curlx_dyn_addn(dyn, hdr, hdr_len);
  if(result)
    return result;

  return curlx_dyn_addn(dyn, buf, blen);
}

size_t Curl_capsule_udp_payload_written(size_t payload_len,
                                        size_t capsule_bytes)
{
  uint64_t capsule_len;
  size_t hdr_len = 2; /* capsule type + context ID */

#if SIZEOF_SIZE_T > 4
  if(payload_len >= (size_t)UINT64_C(0x3FFFFFFFFFFFFFFF))
    capsule_len = UINT64_C(0x3FFFFFFFFFFFFFFF);
  else
#endif
    capsule_len = (uint64_t)payload_len + 1;
  hdr_len += capsule_varint_len(capsule_len);

  if(capsule_bytes <= hdr_len)
    return 0;
  capsule_bytes -= hdr_len;
  if(capsule_bytes > payload_len)
    capsule_bytes = payload_len;
  return capsule_bytes;
}

size_t Curl_capsule_process_udp_raw(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct bufq *recvbufq,
                                    unsigned char *buf, size_t len,
                                    CURLcode *err)
{
  const unsigned char *context_id, *capsule_type;
  size_t read_size, varint_len;
  uint64_t capsule_length;
  size_t offset, payload_len;
  size_t bytes_read = 0;
  CURLcode result = CURLE_OK;

  if(!len) {
    *err = CURLE_BAD_FUNCTION_ARGUMENT;
    return 0;
  }

  if(Curl_bufq_is_empty(recvbufq)) {
    *err = CURLE_AGAIN;
    return 0;
  }

  if(!Curl_bufq_peek(recvbufq, &capsule_type, &read_size) || !read_size) {
    *err = CURLE_AGAIN;
    return 0;
  }

  if(capsule_type[0]) {
    infof(data, "Error! Invalid capsule type: %d", capsule_type[0]);
    *err = CURLE_RECV_ERROR;
    return 0;
  }

  offset = 1;
  result = capsule_decode_varint_at(recvbufq, offset, &capsule_length,
                                    &varint_len);
  if(result == CURLE_AGAIN) {
    *err = CURLE_AGAIN;
    return 0;
  }
  else if(result) {
    *err = CURLE_RECV_ERROR;
    return 0;
  }
  offset += varint_len;

  if(!Curl_bufq_peek_at(recvbufq, offset, &context_id, &read_size) ||
     !read_size) {
    *err = CURLE_AGAIN;
    return 0;
  }

  if(*context_id) {
    infof(data, "Error! Invalid context ID: %02x", *context_id);
    *err = CURLE_RECV_ERROR;
    return 0;
  }
  offset += 1;

  if(!capsule_length) {
    infof(data, "Error! Invalid capsule length: 0");
    *err = CURLE_RECV_ERROR;
    return 0;
  }
  payload_len = (size_t)(capsule_length - 1);

  if(Curl_bufq_len(recvbufq) < offset + payload_len) {
    *err = CURLE_AGAIN;
    return 0;
  }

  if(payload_len > len) {
    infof(data, "UDP payload does not fit destination buffer: %zu > %zu",
          payload_len, len);
    Curl_bufq_skip(recvbufq, offset + payload_len);
    *err = CURLE_RECV_ERROR;
    return 0;
  }

  Curl_bufq_skip(recvbufq, offset);
  if(!payload_len) {
    *err = CURLE_OK;
    return 0;
  }
  result = Curl_bufq_read(recvbufq, buf, payload_len, &bytes_read);
  if(result || (bytes_read != payload_len)) {
    infof(data, "Error! Read less than expected %zu %zu",
          payload_len, bytes_read);
    *err = CURLE_RECV_ERROR;
    return 0;
  }

  if(cf && data) {
    CURL_TRC_CF(data, cf, "Processed UDP capsule raw: size=%zu "
                "length_left %zu", payload_len, Curl_bufq_len(recvbufq));
  }
  *err = CURLE_OK;
  return bytes_read;
}
#endif /* !CURL_DISABLE_PROXY && !CURL_DISABLE_HTTP */
