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

static CURLcode httpsrr_print_addr(struct dynbuf *dyn,
                                   int ai_family,
                                   const uint8_t *addr,
                                   size_t total_len)
{
  char buf[MAX_IPADR_LEN];
  size_t i, alen = (ai_family == AF_INET6) ? 16 : 4;
  const char *sep = "";
  CURLcode result = CURLE_OK;

  for(i = 0; (i < (total_len / alen)) && !result; ++i) {
    if(!curlx_inet_ntop(ai_family, addr + (i * alen), buf, sizeof(buf)))
      result = curlx_dyn_add(dyn, "<error parsing address>");
    else
      result = curlx_dyn_addf(dyn, "%s%s", sep, buf);
    sep = ",";
  }
  return result;
}

void Curl_httpsrr_trace(struct Curl_easy *data,
                        struct Curl_https_rrinfo *rr)
{
  struct dynbuf tmp;
  CURLcode result;

  if(!rr || !rr->complete) {
    CURL_TRC_DNS(data, "[HTTPS-RR] not available");
    return;
  }
  curlx_dyn_init(&tmp, 1024);
  result = Curl_httpsrr_print(&tmp, rr);
  if(!result)
    CURL_TRC_DNS(data, "HTTPS-RR: %s", curlx_dyn_ptr(&tmp));
  else
    CURL_TRC_DNS(data, "Error printing HTTPS-RR information");
  curlx_dyn_free(&tmp);
}

CURLcode Curl_httpsrr_print(struct dynbuf *tmp,
                            struct Curl_https_rrinfo *rr)
{
  CURLcode result;
  int i;

  curlx_dyn_reset(tmp);
  result = curlx_dyn_addf(tmp, "%u %s", rr->priority,
                          rr->target ? rr->target : ".");
  if(!result && rr->mandatory)
    result = curlx_dyn_add(tmp, " mandatory-keys(ignored)");
  if(!result && rr->alpns[0]) {
    const char *sep = "", *name;
    result = curlx_dyn_add(tmp, " alpn=");
    for(i = 0; !result && (i < 4); ++i) {
      switch(rr->alpns[i]) {
      case ALPN_h1:
        name = "http/1.1";
        break;
      case ALPN_h2:
        name = "h2";
        break;
      case ALPN_h3:
        name = "h3";
        break;
      default:
        name = NULL;
      }
      if(name) {
        result = curlx_dyn_addf(tmp, "%s%s", sep, name);
        sep = ",";
      }
    }
  }
  if(!result && rr->port_set) {
    result = curlx_dyn_addf(tmp, " port=%u", rr->port);
  }
  if(!result && rr->no_def_alpn)
    result = curlx_dyn_add(tmp, " no-default-alpn");
  if(!result && rr->ipv6hints_len) {
    result = curlx_dyn_add(tmp, " ipv6hint=");
    if(!result)
      result = httpsrr_print_addr(
        tmp, AF_INET6, rr->ipv6hints, rr->ipv6hints_len);
  }
  if(!result && rr->ipv4hints_len) {
    result = curlx_dyn_add(tmp, " ipv4hint=");
    if(!result)
      result = httpsrr_print_addr(
        tmp, AF_INET, rr->ipv4hints, rr->ipv4hints_len);
  }
  if(!result && rr->echconfiglist_len)
    result = curlx_dyn_addf(tmp, " ech=<%zu bytes>", rr->echconfiglist_len);

  return result;
}

#endif /* CURLVERBOSE */

CURLcode Curl_httpsrr_set(struct Curl_https_rrinfo *rr,
                          uint16_t rrkey, const uint8_t *val, size_t vlen)
{
  CURLcode result = CURLE_OK;
  switch(rrkey) {
  case HTTPS_RR_CODE_MANDATORY:
    rr->mandatory = TRUE;
    break;
  case HTTPS_RR_CODE_ALPN: /* str_list */
    result = httpsrr_decode_alpn(val, vlen, rr->alpns);
    break;
  case HTTPS_RR_CODE_NO_DEF_ALPN:
    if(vlen) /* no data */
      return CURLE_BAD_FUNCTION_ARGUMENT;
    rr->no_def_alpn = TRUE;
    break;
  case HTTPS_RR_CODE_IPV4: /* addr4 list */
    if(!vlen || (vlen & 3)) /* the size must be 4-byte aligned */
      return CURLE_BAD_FUNCTION_ARGUMENT;
    curlx_free(rr->ipv4hints);
    rr->ipv4hints = curlx_memdup(val, vlen);
    if(!rr->ipv4hints)
      return CURLE_OUT_OF_MEMORY;
    rr->ipv4hints_len = vlen;
    break;
  case HTTPS_RR_CODE_ECH:
    if(!vlen)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    curlx_free(rr->echconfiglist);
    rr->echconfiglist = curlx_memdup(val, vlen);
    if(!rr->echconfiglist)
      return CURLE_OUT_OF_MEMORY;
    rr->echconfiglist_len = vlen;
    break;
  case HTTPS_RR_CODE_IPV6: /* addr6 list */
    if(!vlen || (vlen & 15)) /* the size must be 16-byte aligned */
      return CURLE_BAD_FUNCTION_ARGUMENT;
    curlx_free(rr->ipv6hints);
    rr->ipv6hints = curlx_memdup(val, vlen);
    if(!rr->ipv6hints)
      return CURLE_OUT_OF_MEMORY;
    rr->ipv6hints_len = vlen;
    break;
  case HTTPS_RR_CODE_PORT:
    if(vlen != 2)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    rr->port = (uint16_t)((val[0] << 8) | val[1]);
    rr->port_set = TRUE;
    break;
  default:
    /* unknown code */
    break;
  }
  return result;
}

struct Curl_https_rrinfo *Curl_httpsrr_dup_move(
  struct Curl_https_rrinfo *rrinfo)
{
  struct Curl_https_rrinfo *dup = curlx_memdup(rrinfo, sizeof(*rrinfo));
  if(dup)
    memset(rrinfo, 0, sizeof(*rrinfo));
  return dup;
}

void Curl_httpsrr_cleanup(struct Curl_https_rrinfo *rrinfo)
{
  curlx_safefree(rrinfo->target);
  curlx_safefree(rrinfo->echconfiglist);
  curlx_safefree(rrinfo->ipv4hints);
  curlx_safefree(rrinfo->ipv6hints);
  curlx_safefree(rrinfo->rrname);
  rrinfo->complete = FALSE;
}

bool Curl_httpsrr_applicable(struct Curl_easy *data,
                             const struct Curl_https_rrinfo *rr)
{
  if(!data->conn || !rr)
    return FALSE;
  return (!rr->target || !rr->target[0] ||
          (rr->target[0] == '.' && !rr->target[1])) &&
         (!rr->port_set || rr->port == data->conn->remote_port);
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
  curlx_safefree(hinfo->rrname);
  return result;
}

#endif /* USE_ARES */

#endif /* USE_HTTPSRR */
