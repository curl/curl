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

#ifdef USE_HTTPSRR

#include "urldata.h"
#include "curl_addrinfo.h"
#include "httpsrr.h"
#include "connect.h"
#include "sendf.h"
#include "strdup.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define MAX_ALPN_LENGTH 255

static CURLcode httpsrr_decode_alpn(const char *cp, size_t len,
                                    unsigned char *alpns)
{
  /*
   * The wire-format value for "alpn" consists of at least one alpn-id
   * prefixed by its length as a single octet, and these length-value pairs
   * are concatenated to form the SvcParamValue. These pairs MUST exactly fill
   * the SvcParamValue; otherwise, the SvcParamValue is malformed.
   */
  int idnum = 0;

  while(len > 0) {
    size_t tlen = (size_t) *cp++;
    enum alpnid id;
    len--;
    if(tlen > len)
      return CURLE_BAD_CONTENT_ENCODING;

    /* we only store ALPN ids we know about */
    id = Curl_alpn2alpnid(cp, tlen);
    if(id != ALPN_none) {
      if(idnum == MAX_HTTPSRR_ALPNS)
        break;
      if(idnum && memchr(alpns, id, idnum))
        /* this ALPN id is already stored */
        ;
      else
        alpns[idnum++] = (unsigned char)id;
    }
    cp += tlen;
    len -= tlen;
  }
  if(idnum < MAX_HTTPSRR_ALPNS)
    alpns[idnum] = ALPN_none; /* terminate the list */
  return CURLE_OK;
}

CURLcode Curl_httpsrr_set(struct Curl_easy *data,
                          struct Curl_https_rrinfo *hi,
                          uint16_t rrkey, const uint8_t *val, size_t vlen)
{
  CURLcode result = CURLE_OK;
  switch(rrkey) {
  case HTTPS_RR_CODE_MANDATORY:
    CURL_TRC_DNS(data, "HTTPS RR MANDATORY left to implement");
    break;
  case HTTPS_RR_CODE_ALPN: /* str_list */
    result = httpsrr_decode_alpn((const char *)val, vlen, hi->alpns);
    CURL_TRC_DNS(data, "HTTPS RR ALPN: %u %u %u %u",
                 hi->alpns[0], hi->alpns[1], hi->alpns[2], hi->alpns[3]);
    break;
  case HTTPS_RR_CODE_NO_DEF_ALPN:
    if(vlen) /* no data */
      return CURLE_BAD_FUNCTION_ARGUMENT;
    hi->no_def_alpn = TRUE;
    CURL_TRC_DNS(data, "HTTPS RR no-def-alpn");
    break;
  case HTTPS_RR_CODE_IPV4: /* addr4 list */
    if(!vlen || (vlen & 3)) /* the size must be 4-byte aligned */
      return CURLE_BAD_FUNCTION_ARGUMENT;
    hi->ipv4hints = Curl_memdup(val, vlen);
    if(!hi->ipv4hints)
      return CURLE_OUT_OF_MEMORY;
    hi->ipv4hints_len = vlen;
    CURL_TRC_DNS(data, "HTTPS RR IPv4");
    break;
  case HTTPS_RR_CODE_ECH:
    if(!vlen)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    hi->echconfiglist = Curl_memdup(val, vlen);
    if(!hi->echconfiglist)
      return CURLE_OUT_OF_MEMORY;
    hi->echconfiglist_len = vlen;
    CURL_TRC_DNS(data, "HTTPS RR ECH");
    break;
  case HTTPS_RR_CODE_IPV6: /* addr6 list */
    if(!vlen || (vlen & 15)) /* the size must be 16-byte aligned */
      return CURLE_BAD_FUNCTION_ARGUMENT;
    hi->ipv6hints = Curl_memdup(val, vlen);
    if(!hi->ipv6hints)
      return CURLE_OUT_OF_MEMORY;
    hi->ipv6hints_len = vlen;
    CURL_TRC_DNS(data, "HTTPS RR IPv6");
    break;
  case HTTPS_RR_CODE_PORT:
    if(vlen != 2)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    hi->port = (unsigned short)((val[0] << 8) | val[1]);
    CURL_TRC_DNS(data, "HTTPS RR port %u", hi->port);
    break;
  default:
    CURL_TRC_DNS(data, "HTTPS RR unknown code");
    break;
  }
  return result;
}

struct Curl_https_rrinfo *
Curl_httpsrr_dup_move(struct Curl_https_rrinfo *rrinfo)
{
  struct Curl_https_rrinfo *dup = Curl_memdup(rrinfo, sizeof(*rrinfo));
  if(dup)
    memset(rrinfo, 0, sizeof(*rrinfo));
  return dup;
}

void Curl_httpsrr_cleanup(struct Curl_https_rrinfo *rrinfo)
{
  Curl_safefree(rrinfo->target);
  Curl_safefree(rrinfo->echconfiglist);
  Curl_safefree(rrinfo->ipv4hints);
  Curl_safefree(rrinfo->ipv6hints);
}


#ifdef USE_ARES

static CURLcode httpsrr_opt(struct Curl_easy *data,
                            const ares_dns_rr_t *rr,
                            ares_dns_rr_key_t key, size_t idx,
                            struct Curl_https_rrinfo *hinfo)
{
  const unsigned char *val = NULL;
  unsigned short code;
  size_t len = 0;

  code  = ares_dns_rr_get_opt(rr, key, idx, &val, &len);
  return Curl_httpsrr_set(data, hinfo, code, val, len);
}

CURLcode Curl_httpsrr_from_ares(struct Curl_easy *data,
                                const ares_dns_record_t *dnsrec,
                                struct Curl_https_rrinfo *hinfo)
{
  CURLcode result = CURLE_OK;
  size_t i;

  for(i = 0; i < ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER); i++) {
    const char *target;
    size_t opt;
    const ares_dns_rr_t *rr =
      ares_dns_record_rr_get_const(dnsrec, ARES_SECTION_ANSWER, i);
    if(ares_dns_rr_get_type(rr) != ARES_REC_TYPE_HTTPS)
      continue;
    /* When SvcPriority is 0, the SVCB record is in AliasMode. Otherwise, it
       is in ServiceMode */
    target = ares_dns_rr_get_str(rr, ARES_RR_HTTPS_TARGET);
    if(target && target[0]) {
      hinfo->target = strdup(target);
      if(!hinfo->target) {
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }
      CURL_TRC_DNS(data, "HTTPS RR target: %s", hinfo->target);
    }
    CURL_TRC_DNS(data, "HTTPS RR priority: %u",
                 ares_dns_rr_get_u16(rr, ARES_RR_HTTPS_PRIORITY));
    for(opt = 0; opt < ares_dns_rr_get_opt_cnt(rr, ARES_RR_HTTPS_PARAMS);
        opt++) {
      result = httpsrr_opt(data, rr, ARES_RR_HTTPS_PARAMS, opt, hinfo);
      if(result)
        break;
    }
  }
out:
  return result;
}

#endif /* USE_ARES */

#endif /* USE_HTTPSRR */
