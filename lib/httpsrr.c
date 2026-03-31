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
#include "httpsrr.h"
#include "connect.h"
#include "curl_trc.h"
#include "curlx/strdup.h"
#include "curlx/inet_ntop.h"

static CURLcode httpsrr_decode_alpn(const uint8_t *cp, size_t len,
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
    size_t tlen = *cp++;
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

#ifdef CURLVERBOSE
static void httpsrr_report_addr(struct Curl_easy *data, int ai_family,
                                const uint8_t *addr, size_t total_len)
{
  char buf[MAX_IPADR_LEN];
  struct dynbuf tmp;
  size_t i, alen = (ai_family == AF_INET6) ? 16 : 4;
  const char *sep = "";
  bool incomplete = FALSE;
  CURLcode result;

  if(!CURL_TRC_DNS_is_verbose(data))
    return;

  curlx_dyn_init(&tmp, 1024);
  for(i = 0; i < (total_len / alen); ++i) {
    if(!curlx_inet_ntop(ai_family, addr + (i * alen), buf, sizeof(buf))) {
      CURL_TRC_DNS(data, "[HTTPS-RR] error parsing address #%zu", i);
      goto out;
    }
    result = curlx_dyn_addf(&tmp, "%s%s", sep, buf);
    if(result) {
      incomplete = TRUE;
      break;
    }
    sep = ", ";
  }

  CURL_TRC_DNS(data, "[HTTPS-RR] IPv%d: %s%s",
               (ai_family == AF_INET6) ? 6 : 4,
               curlx_dyn_len(&tmp) ? curlx_dyn_ptr(&tmp) : "(none)",
               incomplete ? " ..." : "");
out:
  curlx_dyn_free(&tmp);
}

void Curl_httpsrr_trace(struct Curl_easy *data,
                        struct Curl_https_rrinfo *hi)
{
  if(!hi || !hi->complete) {
    CURL_TRC_DNS(data, "[HTTPS-RR] not available");
    return;
  }

  if(hi->target)
    CURL_TRC_DNS(data, "[HTTPS-RR] target: %s", hi->target);
  if(hi->priority)
    CURL_TRC_DNS(data, "[HTTPS-RR] priority: %u", hi->priority);
  if(hi->mandatory)
    CURL_TRC_DNS(data, "[HTTPS-RR] MANDATORY present, but not supported");
  if(hi->alpns[0])
    CURL_TRC_DNS(data, "[HTTPS-RR] ALPN: %u %u %u %u",
                 hi->alpns[0], hi->alpns[1], hi->alpns[2], hi->alpns[3]);
  if(hi->port)
    CURL_TRC_DNS(data, "[HTTPS-RR] port %u", hi->port);
  if(hi->no_def_alpn)
    CURL_TRC_DNS(data, "[HTTPS-RR] no-def-alpn");
  if(hi->ipv6hints_len)
    httpsrr_report_addr(data, AF_INET6, hi->ipv6hints, hi->ipv6hints_len);
  if(hi->ipv4hints_len)
    httpsrr_report_addr(data, AF_INET, hi->ipv4hints, hi->ipv4hints_len);
  if(hi->echconfiglist_len)
    CURL_TRC_DNS(data, "[HTTPS-RR] ECH");
}

#else
#define httpsrr_report_addr(a,b,c,d)    Curl_nop_stmt
#endif /* CURLVERBOSE */

CURLcode Curl_httpsrr_set(struct Curl_https_rrinfo *hi,
                          uint16_t rrkey, const uint8_t *val, size_t vlen)
{
  CURLcode result = CURLE_OK;
  switch(rrkey) {
  case HTTPS_RR_CODE_MANDATORY:
    hi->mandatory = TRUE;
    break;
  case HTTPS_RR_CODE_ALPN: /* str_list */
    result = httpsrr_decode_alpn(val, vlen, hi->alpns);
    break;
  case HTTPS_RR_CODE_NO_DEF_ALPN:
    if(vlen) /* no data */
      return CURLE_BAD_FUNCTION_ARGUMENT;
    hi->no_def_alpn = TRUE;
    break;
  case HTTPS_RR_CODE_IPV4: /* addr4 list */
    if(!vlen || (vlen & 3)) /* the size must be 4-byte aligned */
      return CURLE_BAD_FUNCTION_ARGUMENT;
    curlx_free(hi->ipv4hints);
    hi->ipv4hints = curlx_memdup(val, vlen);
    if(!hi->ipv4hints)
      return CURLE_OUT_OF_MEMORY;
    hi->ipv4hints_len = vlen;
    break;
  case HTTPS_RR_CODE_ECH:
    if(!vlen)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    curlx_free(hi->echconfiglist);
    hi->echconfiglist = curlx_memdup(val, vlen);
    if(!hi->echconfiglist)
      return CURLE_OUT_OF_MEMORY;
    hi->echconfiglist_len = vlen;
    break;
  case HTTPS_RR_CODE_IPV6: /* addr6 list */
    if(!vlen || (vlen & 15)) /* the size must be 16-byte aligned */
      return CURLE_BAD_FUNCTION_ARGUMENT;
    curlx_free(hi->ipv6hints);
    hi->ipv6hints = curlx_memdup(val, vlen);
    if(!hi->ipv6hints)
      return CURLE_OUT_OF_MEMORY;
    hi->ipv6hints_len = vlen;
    break;
  case HTTPS_RR_CODE_PORT:
    if(vlen != 2)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    hi->port = (unsigned short)((val[0] << 8) | val[1]);
    break;
  default:
    /* unknown code */
    break;
  }
  return result;
}

struct Curl_https_rrinfo *
Curl_httpsrr_dup_move(struct Curl_https_rrinfo *rrinfo)
{
  struct Curl_https_rrinfo *dup = curlx_memdup(rrinfo, sizeof(*rrinfo));
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
  Curl_safefree(rrinfo->rrname);
  rrinfo->complete = FALSE;
}

#ifdef USE_ARES

static CURLcode httpsrr_opt(const ares_dns_rr_t *rr,
                            ares_dns_rr_key_t key, size_t idx,
                            struct Curl_https_rrinfo *hinfo)
{
  const unsigned char *val = NULL;
  unsigned short code;
  size_t len = 0;

  code = ares_dns_rr_get_opt(rr, key, idx, &val, &len);
  return Curl_httpsrr_set(hinfo, code, val, len);
}

CURLcode Curl_httpsrr_from_ares(const ares_dns_record_t *dnsrec,
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
      curlx_free(hinfo->target);
      hinfo->target = curlx_strdup(target);
      if(!hinfo->target) {
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }
    }
    hinfo->priority = ares_dns_rr_get_u16(rr, ARES_RR_HTTPS_PRIORITY);
    for(opt = 0; opt < ares_dns_rr_get_opt_cnt(rr, ARES_RR_HTTPS_PARAMS);
        opt++) {
      result = httpsrr_opt(rr, ARES_RR_HTTPS_PARAMS, opt, hinfo);
      if(result)
        break;
    }
  }
out:
  hinfo->complete = !result;
  Curl_safefree(hinfo->rrname);
  return result;
}

#endif /* USE_ARES */

#endif /* USE_HTTPSRR */
