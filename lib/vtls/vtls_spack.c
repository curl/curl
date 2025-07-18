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

#if defined(USE_SSL) && defined(USE_SSLS_EXPORT)

#include "../urldata.h"
#include "../curl_trc.h"
#include "vtls_scache.h"
#include "vtls_spack.h"
#include "../strdup.h"

/* The last #include files should be: */
#include "../curl_memory.h"
#include "../memdebug.h"

#ifdef _MSC_VER
#if _MSC_VER >= 1600
#include <stdint.h>
#else
typedef unsigned char uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
#endif
#endif /* _MSC_VER */

#ifndef UINT16_MAX
#define UINT16_MAX    0xffff
#endif
#ifndef UINT32_MAX
#define UINT32_MAX    0xffffffff
#endif

#define CURL_SPACK_VERSION       0x01
#define CURL_SPACK_IETF_ID       0x02
#define CURL_SPACK_VALID_UNTIL   0x03
#define CURL_SPACK_TICKET        0x04
#define CURL_SPACK_ALPN          0x05
#define CURL_SPACK_EARLYDATA     0x06
#define CURL_SPACK_QUICTP        0x07

static CURLcode spack_enc8(struct dynbuf *buf, uint8_t b)
{
  return curlx_dyn_addn(buf, &b, 1);
}

static CURLcode
spack_dec8(uint8_t *val, const uint8_t **src, const uint8_t *end)
{
  if(end - *src < 1)
    return CURLE_READ_ERROR;
  *val = **src;
  *src += 1;
  return CURLE_OK;
}

static CURLcode spack_enc16(struct dynbuf *buf, uint16_t val)
{
  uint8_t nval[2];
  nval[0] = (uint8_t)(val >> 8);
  nval[1] = (uint8_t)val;
  return curlx_dyn_addn(buf, nval, sizeof(nval));
}

static CURLcode
spack_dec16(uint16_t *val, const uint8_t **src, const uint8_t *end)
{
  if(end - *src < 2)
    return CURLE_READ_ERROR;
  *val = (uint16_t)((*src)[0] << 8 | (*src)[1]);
  *src += 2;
  return CURLE_OK;
}

static CURLcode spack_enc32(struct dynbuf *buf, uint32_t val)
{
  uint8_t nval[4];
  nval[0] = (uint8_t)(val >> 24);
  nval[1] = (uint8_t)(val >> 16);
  nval[2] = (uint8_t)(val >> 8);
  nval[3] = (uint8_t)val;
  return curlx_dyn_addn(buf, nval, sizeof(nval));
}

static CURLcode
spack_dec32(uint32_t *val, const uint8_t **src, const uint8_t *end)
{
  if(end - *src < 4)
    return CURLE_READ_ERROR;
  *val = (uint32_t)(*src)[0] << 24 | (uint32_t)(*src)[1] << 16 |
         (uint32_t)(*src)[2] << 8 | (*src)[3];
  *src += 4;
  return CURLE_OK;
}

static CURLcode spack_enc64(struct dynbuf *buf, uint64_t val)
{
  uint8_t nval[8];
  nval[0] = (uint8_t)(val >> 56);
  nval[1] = (uint8_t)(val >> 48);
  nval[2] = (uint8_t)(val >> 40);
  nval[3] = (uint8_t)(val >> 32);                  \
  nval[4] = (uint8_t)(val >> 24);
  nval[5] = (uint8_t)(val >> 16);
  nval[6] = (uint8_t)(val >> 8);
  nval[7] = (uint8_t)val;
  return curlx_dyn_addn(buf, nval, sizeof(nval));
}

static CURLcode
spack_dec64(uint64_t *val, const uint8_t **src, const uint8_t *end)
{
  if(end - *src < 8)
    return CURLE_READ_ERROR;
  *val = (uint64_t)(*src)[0] << 56 | (uint64_t)(*src)[1] << 48 |
         (uint64_t)(*src)[2] << 40 | (uint64_t)(*src)[3] << 32 |
         (uint64_t)(*src)[4] << 24 | (uint64_t)(*src)[5] << 16 |
         (uint64_t)(*src)[6] << 8 | (*src)[7];
  *src += 8;
  return CURLE_OK;
}

static CURLcode spack_encstr16(struct dynbuf *buf, const char *s)
{
  size_t slen = strlen(s);
  CURLcode r;
  if(slen > UINT16_MAX)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  r = spack_enc16(buf, (uint16_t)slen);
  if(!r) {
    r = curlx_dyn_addn(buf, s, slen);
  }
  return r;
}

static CURLcode
spack_decstr16(char **val, const uint8_t **src, const uint8_t *end)
{
  uint16_t slen;
  CURLcode r;

  *val = NULL;
  r = spack_dec16(&slen, src, end);
  if(r)
    return r;
  if(end - *src < slen)
    return CURLE_READ_ERROR;
  *val = Curl_memdup0((const char *)(*src), slen);
  *src += slen;
  return *val ? CURLE_OK : CURLE_OUT_OF_MEMORY;
}

static CURLcode spack_encdata16(struct dynbuf *buf,
                                const uint8_t *data, size_t data_len)
{
  CURLcode r;
  if(data_len > UINT16_MAX)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  r = spack_enc16(buf, (uint16_t)data_len);
  if(!r) {
    r = curlx_dyn_addn(buf, data, data_len);
  }
  return r;
}

static CURLcode
spack_decdata16(uint8_t **val, size_t *val_len,
                const uint8_t **src, const uint8_t *end)
{
  uint16_t data_len;
  CURLcode r;

  *val = NULL;
  r = spack_dec16(&data_len, src, end);
  if(r)
    return r;
  if(end - *src < data_len)
    return CURLE_READ_ERROR;
  *val = Curl_memdup0((const char *)(*src), data_len);
  *val_len = data_len;
  *src += data_len;
  return *val ? CURLE_OK : CURLE_OUT_OF_MEMORY;
}

CURLcode Curl_ssl_session_pack(struct Curl_easy *data,
                               struct Curl_ssl_session *s,
                               struct dynbuf *buf)
{
  CURLcode r;
  DEBUGASSERT(s->sdata);
  DEBUGASSERT(s->sdata_len);

  if(s->valid_until < 0)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  r = spack_enc8(buf, CURL_SPACK_VERSION);
  if(!r)
    r = spack_enc8(buf, CURL_SPACK_TICKET);
  if(!r)
    r = spack_encdata16(buf, s->sdata, s->sdata_len);
  if(!r)
    r = spack_enc8(buf, CURL_SPACK_IETF_ID);
  if(!r)
    r = spack_enc16(buf, (uint16_t)s->ietf_tls_id);
  if(!r)
    r = spack_enc8(buf, CURL_SPACK_VALID_UNTIL);
  if(!r)
    r = spack_enc64(buf, (uint64_t)s->valid_until);
  if(!r && s->alpn) {
    r = spack_enc8(buf, CURL_SPACK_ALPN);
    if(!r)
      r = spack_encstr16(buf, s->alpn);
  }
  if(!r && s->earlydata_max) {
    if(s->earlydata_max > UINT32_MAX)
      r = CURLE_BAD_FUNCTION_ARGUMENT;
    if(!r)
      r = spack_enc8(buf, CURL_SPACK_EARLYDATA);
    if(!r)
      r = spack_enc32(buf, (uint32_t)s->earlydata_max);
  }
  if(!r && s->quic_tp && s->quic_tp_len) {
    r = spack_enc8(buf, CURL_SPACK_QUICTP);
    if(!r)
      r = spack_encdata16(buf, s->quic_tp, s->quic_tp_len);
  }

  if(r)
    CURL_TRC_SSLS(data, "error packing data: %d", r);
  return r;
}

CURLcode Curl_ssl_session_unpack(struct Curl_easy *data,
                                 const void *bufv, size_t buflen,
                                 struct Curl_ssl_session **ps)
{
  struct Curl_ssl_session *s = NULL;
  const unsigned char *buf = (const unsigned char *)bufv;
  const unsigned char *end = buf + buflen;
  uint8_t val8, *pval8;
  uint16_t val16;
  uint32_t val32;
  uint64_t val64;
  CURLcode r;

  DEBUGASSERT(buf);
  DEBUGASSERT(buflen);
  *ps = NULL;

  r = spack_dec8(&val8, &buf, end);
  if(r)
    goto out;
  if(val8 != CURL_SPACK_VERSION) {
    r = CURLE_READ_ERROR;
    goto out;
  }

  s = calloc(1, sizeof(*s));
  if(!s) {
    r = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  while(buf < end) {
    r = spack_dec8(&val8, &buf, end);
    if(r)
      goto out;

    switch(val8) {
    case CURL_SPACK_ALPN:
      r = spack_decstr16(&s->alpn, &buf, end);
      if(r)
        goto out;
      break;
    case CURL_SPACK_EARLYDATA:
      r = spack_dec32(&val32, &buf, end);
      if(r)
        goto out;
      s->earlydata_max = val32;
      break;
    case CURL_SPACK_IETF_ID:
      r = spack_dec16(&val16, &buf, end);
      if(r)
        goto out;
      s->ietf_tls_id = val16;
      break;
    case CURL_SPACK_QUICTP: {
      r = spack_decdata16(&pval8, &s->quic_tp_len, &buf, end);
      if(r)
        goto out;
      s->quic_tp = pval8;
      break;
    }
    case CURL_SPACK_TICKET: {
      r = spack_decdata16(&pval8, &s->sdata_len, &buf, end);
      if(r)
        goto out;
      s->sdata = pval8;
      break;
    }
    case CURL_SPACK_VALID_UNTIL:
      r = spack_dec64(&val64, &buf, end);
      if(r)
        goto out;
      s->valid_until = (curl_off_t)val64;
      break;
    default:  /* unknown tag */
      r = CURLE_READ_ERROR;
      goto out;
    }
  }

out:
  if(r) {
    CURL_TRC_SSLS(data, "error unpacking data: %d", r);
    Curl_ssl_session_destroy(s);
  }
  else
    *ps = s;
  return r;
}

#endif /* USE_SSL && USE_SSLS_EXPORT */
