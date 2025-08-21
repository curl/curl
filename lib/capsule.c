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

#include <openssl/bio.h>
#include <curl/curl.h>
#include "urldata.h"
#include "curlx/dynbuf.h"
#include "sendf.h"
#include "http.h"
#include "http1.h"
#include "http_proxy.h"
#include "url.h"
#include "select.h"
#include "progress.h"
#include "cfilters.h"
#include "cf-h1-proxy.h"
#include "connect.h"
#include "curl_trc.h"
#include "bufq.h"
#include "strcase.h"
#include "vtls/vtls.h"
#include "transfer.h"
#include "multiif.h"
#include "curlx/strparse.h"
#include "capsule.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

uint64_t curl_capsule_ntohll(uint64_t value)
{
  union {
      uint64_t u64;
      uint32_t u32[2];
  } src, dst;

  src.u64 = value;

  dst.u32[0] = ntohl(src.u32[1]);
  dst.u32[1] = ntohl(src.u32[0]);

  return dst.u64;
}

CURLcode curl_capsule_encode_varint(struct dynbuf *dyn, uint64_t value)
{
  CURLcode result;
  DEBUGASSERT(value <= 0x3FFFFFFFFFFFFFFF);

  if(value <= 0x3F) {
    uint8_t encoded;
    encoded = (char)value;
    result = curlx_dyn_addn(dyn, &encoded, sizeof(encoded));
  }
  else if(value <= 0x3FFF) {
    /* Set bits 15-14 to "01", preserve lower 14 bits */
    uint16_t encoded;
    encoded = (uint16_t)value & 0x3FFF;
    encoded = ntohs(encoded | 0x4000);
    result = curlx_dyn_addn(dyn, &encoded, sizeof(encoded));
  }
  else if(value <= 0x3FFFFFFF) {
    /* Set bits 31-30 to "10", preserve lower 30 bits */
    uint32_t encoded;
    encoded = (uint32_t)value & 0x3FFFFFFF;
    encoded = ntohl(encoded | 0x80000000);
    result = curlx_dyn_addn(dyn, &encoded, sizeof(encoded));
  }
  else {
    /* Set bits 63-62 to "11", preserve lower 62 bits */
    uint64_t encoded;
    encoded = (uint64_t)value & 0x3FFFFFFFFFFFFFFF;
    encoded = curl_capsule_ntohll(encoded | 0xC000000000000000);
    result = curlx_dyn_addn(dyn, &encoded, sizeof(encoded));
  }
  return result;
}

uint64_t curl_capsule_decode_varint(char **start)
{
  uint8_t first_byte, bytes_left;
  uint64_t value;
  char *pos;

  pos = *start;
  first_byte = *pos;
  pos++;

  if(first_byte <= 0x3F) {
    *start = pos;
    return first_byte;
  }

  /* remove length bits, encoded in the first two bits of the first byte */
  value = first_byte & 0x3F;
  bytes_left = (uint8_t)((1 << (first_byte >> 6)) - 1);

  do {
    value = (value << 8) | (uint8_t)(*pos);
    pos++;
  } while(--bytes_left);

  *start = pos;
  return value;
}

CURLcode curl_capsule_encap_udp_datagram(struct dynbuf *dyn,
                                         const void *buf, size_t blen)
{
  CURLcode result = CURLE_OK;
  uint8_t cap_type = 0; /* HTTP Datagram */
  uint8_t ctx_id = 0; /* Context ID for UDP Proxying Payload */

  curlx_dyn_init(dyn, HTTP_CAPSULE_HEADER_MAX_SIZE + blen);

  result = curlx_dyn_addn(dyn, &cap_type, sizeof(cap_type));

  result = curl_capsule_encode_varint(dyn, blen + 1);

  result = curlx_dyn_addn(dyn, &ctx_id, sizeof(ctx_id));

  result = curlx_dyn_addn(dyn, buf, blen);

  return result;
}

size_t curl_capsule_process_udp(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 struct bufq *recvbufq,
                                 char *buf, size_t len, CURLcode *err)
{
  /* All variable declarations at the beginning */
  BIO_MSG *my_bio = (BIO_MSG *)buf;
  BIO_MSG *bio_msg = NULL;
  const unsigned char *context_id, *capsule_type;
  unsigned char *capsule_data;
  const unsigned char *temp_buf;
  char *decode_ptr;
  size_t num_msg = 32; /* MASQUE FIX: How to get this value from OpenSSL */
  size_t stride = len;
  size_t read_size;
  size_t offset, capsule_length;
  size_t remaining_capsule_length;
  size_t bytes_read, bytes_to_read;
  size_t total_available_space;
  uint8_t idx = 0;
  CURLcode result = CURLE_OK;

  /* Parse data in recvbufq, which is formatted as udp capsules,
     into BIO_MSG structures obtained from BIO_MSG_N (my_bio, stride, idx),
     so that we can use the BIO_MSG API to read them.
     The data is formatted as:
     [capsule_type][varint_length][context_id][data] where capsule_type is 0
     for HTTP Datagram, context_id is 0 for UDP Proxying Payload, and data is
     the actual payload.
  */

  /* Process available capsules from recvbuf until full or no more data */
  while(idx < num_msg && !Curl_bufq_is_empty(recvbufq)) {
    offset = 0;

    /* Read the capsule type (should be 0 for HTTP Datagram) */
    if(!Curl_bufq_peek(recvbufq, &capsule_type, &read_size))
      break;

    if(capsule_type[0]) {
      infof(data, "Error! Invalid capsule type: %d", capsule_type[0]);
      result = CURLE_RECV_ERROR;
      break;
    }

    /* Skip over the capsule type */
    offset += 1;

    /* Read enough bytes to determine varint length
     * NOTE handle spread over multiple chunks */
    read_size = 0;
    Curl_bufq_peek_at(recvbufq, offset,
                      (const unsigned char **)&temp_buf, &read_size);
    if(read_size < 1)
      break;

    /* Determine varint length */
    decode_ptr = (char *)(uintptr_t)temp_buf;
    capsule_length = curl_capsule_decode_varint(&decode_ptr);

    if(capsule_length == HTTP_INVALID_VARINT) {
      infof(data, "Error! Invalid varint length encoding");
      result = CURLE_RECV_ERROR;
      break;
    }

    /* Skip over the varint in the actual buffer */
    offset += (decode_ptr - (char *)(uintptr_t)temp_buf);

    /* Read context ID (should be 0 for UDP Proxying Payload) */
    if(!Curl_bufq_peek_at(recvbufq, offset, &context_id, &read_size))
      break;

    if(*context_id) {
      infof(data, "Error! Invalid context ID: %02x", *context_id);
      result = CURLE_RECV_ERROR;
      break;
    }

    /* Skip over the context ID */
    offset += 1;

    /* Adjust length (subtract context ID length) */
    capsule_length--;
    if(Curl_bufq_len(recvbufq) < offset + capsule_length) {
      infof(data, "Not enough data for capsule length: %zu, "
            "retry after reading more data", capsule_length);
      result = CURLE_OK;
      break;
    }

    /* Skip capsule header (type + varint + context_id) in recvbuf */
    Curl_bufq_skip(recvbufq, offset);

    /* Handle large capsules that span multiple BIO_MSG buffers */
    remaining_capsule_length = capsule_length;

    /* Check if we have enough BIO_MSG buffers to fit the entire capsule */
    bio_msg = &BIO_MSG_N(my_bio, stride, idx);
    total_available_space = (num_msg - idx) * bio_msg->data_len;

    if(total_available_space < capsule_length) {
      /* Not enough space in this call - we need to buffer for next call */
      infof(data, "Capsule too large for available buffers: capsule=%zu,"
            "available_space=%zu, retry after reading more data",
            capsule_length, total_available_space);
      result = CURLE_AGAIN;
      break;
    }

    /* Read capsule data across multiple BIO_MSG buffers as needed */
    while(remaining_capsule_length > 0 && idx < num_msg) {
      /* Get pointer to current BIO_MSG data buffer */
      bio_msg = &BIO_MSG_N(my_bio, stride, idx);
      capsule_data = (unsigned char *)bio_msg->data;

      /* Determine how much to read into this buffer */
      bytes_to_read = remaining_capsule_length < bio_msg->data_len ?
                            remaining_capsule_length : bio_msg->data_len;

      /* Read data into current buffer */
      bytes_read = 0;
      *err = Curl_bufq_read(recvbufq, capsule_data,
                            bytes_to_read, &bytes_read);

      if(bytes_read != bytes_to_read) {
        infof(data, "Error! Read less than expected %zu %zu",
              bytes_to_read, bytes_read);
        result = CURLE_RECV_ERROR;
        break;
      }

      /* Set the actual data length in the BIO_MSG structure */
      bio_msg->data_len = bytes_read;
      remaining_capsule_length -= bytes_read;

      /* Move to next BIO_MSG buffer */
      idx++;
    }

    /* Verify we read the entire capsule */
    if(remaining_capsule_length > 0) {
      infof(data, "Error! Could not fit entire capsule: remaining=%zu",
            remaining_capsule_length);
      result = CURLE_RECV_ERROR;
      break;
    }

    CURL_TRC_CF(data, cf, "Processed UDP capsule: size=%zu length_left %zu",
                           capsule_length, Curl_bufq_len(recvbufq));
  }

  *err = result != CURLE_OK ? result : CURLE_AGAIN;
  return (idx ? idx : 0);
}

#endif /* !CURL_DISABLE_PROXY */
