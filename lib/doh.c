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

#ifndef CURL_DISABLE_DOH

#include "urldata.h"
#include "curl_addrinfo.h"
#include "doh.h"

#include "sendf.h"
#include "multiif.h"
#include "url.h"
#include "share.h"
#include "curlx/base64.h"
#include "connect.h"
#include "strdup.h"
#include "curlx/dynbuf.h"
#include "escape.h"
#include "urlapi-int.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define DNS_CLASS_IN 0x01

#ifndef CURL_DISABLE_VERBOSE_STRINGS
static const char * const errors[]={
  "",
  "Bad label",
  "Out of range",
  "Label loop",
  "Too small",
  "Out of memory",
  "RDATA length",
  "Malformat",
  "Bad RCODE",
  "Unexpected TYPE",
  "Unexpected CLASS",
  "No content",
  "Bad ID",
  "Name too long"
};

static const char *doh_strerror(DOHcode code)
{
  if((code >= DOH_OK) && (code <= DOH_DNS_NAME_TOO_LONG))
    return errors[code];
  return "bad error code";
}

#endif /* !CURL_DISABLE_VERBOSE_STRINGS */

/* @unittest 1655
 */
UNITTEST DOHcode doh_req_encode(const char *host,
                                DNStype dnstype,
                                unsigned char *dnsp, /* buffer */
                                size_t len,  /* buffer size */
                                size_t *olen) /* output length */
{
  const size_t hostlen = strlen(host);
  unsigned char *orig = dnsp;
  const char *hostp = host;

  /* The expected output length is 16 bytes more than the length of
   * the QNAME-encoding of the hostname.
   *
   * A valid DNS name may not contain a zero-length label, except at
   * the end. For this reason, a name beginning with a dot, or
   * containing a sequence of two or more consecutive dots, is invalid
   * and cannot be encoded as a QNAME.
   *
   * If the hostname ends with a trailing dot, the corresponding
   * QNAME-encoding is one byte longer than the hostname. If (as is
   * also valid) the hostname is shortened by the omission of the
   * trailing dot, then its QNAME-encoding will be two bytes longer
   * than the hostname.
   *
   * Each [ label, dot ] pair is encoded as [ length, label ],
   * preserving overall length. A final [ label ] without a dot is
   * also encoded as [ length, label ], increasing overall length
   * by one. The encoding is completed by appending a zero byte,
   * representing the zero-length root label, again increasing
   * the overall length by one.
   */

  size_t expected_len;
  DEBUGASSERT(hostlen);
  expected_len = 12 + 1 + hostlen + 4;
  if(host[hostlen-1]!='.')
    expected_len++;

  if(expected_len > DOH_MAX_DNSREQ_SIZE)
    return DOH_DNS_NAME_TOO_LONG;

  if(len < expected_len)
    return DOH_TOO_SMALL_BUFFER;

  *dnsp++ = 0; /* 16 bit id */
  *dnsp++ = 0;
  *dnsp++ = 0x01; /* |QR|   Opcode  |AA|TC|RD| Set the RD bit */
  *dnsp++ = '\0'; /* |RA|   Z    |   RCODE   |                */
  *dnsp++ = '\0';
  *dnsp++ = 1;    /* QDCOUNT (number of entries in the question section) */
  *dnsp++ = '\0';
  *dnsp++ = '\0'; /* ANCOUNT */
  *dnsp++ = '\0';
  *dnsp++ = '\0'; /* NSCOUNT */
  *dnsp++ = '\0';
  *dnsp++ = '\0'; /* ARCOUNT */

  /* encode each label and store it in the QNAME */
  while(*hostp) {
    size_t labellen;
    char *dot = strchr(hostp, '.');
    if(dot)
      labellen = dot - hostp;
    else
      labellen = strlen(hostp);
    if((labellen > 63) || (!labellen)) {
      /* label is too long or too short, error out */
      *olen = 0;
      return DOH_DNS_BAD_LABEL;
    }
    /* label is non-empty, process it */
    *dnsp++ = (unsigned char)labellen;
    memcpy(dnsp, hostp, labellen);
    dnsp += labellen;
    hostp += labellen;
    /* advance past dot, but only if there is one */
    if(dot)
      hostp++;
  } /* next label */

  *dnsp++ = 0; /* append zero-length label for root */

  /* There are assigned TYPE codes beyond 255: use range [1..65535]  */
  *dnsp++ = (unsigned char)(255 & (dnstype >> 8)); /* upper 8 bit TYPE */
  *dnsp++ = (unsigned char)(255 & dnstype);      /* lower 8 bit TYPE */

  *dnsp++ = '\0'; /* upper 8 bit CLASS */
  *dnsp++ = DNS_CLASS_IN; /* IN - "the Internet" */

  *olen = dnsp - orig;

  /* verify that our estimation of length is valid, since
   * this has led to buffer overflows in this function */
  DEBUGASSERT(*olen == expected_len);
  return DOH_OK;
}

static size_t
doh_probe_write_cb(char *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct Curl_easy *data = userp;
  struct doh_request *doh_req = Curl_meta_get(data, CURL_EZM_DOH_PROBE);
  if(!doh_req)
    return CURL_WRITEFUNC_ERROR;

  if(curlx_dyn_addn(&doh_req->resp_body, contents, realsize))
    return 0;

  return realsize;
}

#if defined(USE_HTTPSRR) && defined(DEBUGBUILD)

/* doh_print_buf truncates if the hex string will be more than this */
#define LOCAL_PB_HEXMAX 400

static void doh_print_buf(struct Curl_easy *data,
                          const char *prefix,
                          unsigned char *buf, size_t len)
{
  unsigned char hexstr[LOCAL_PB_HEXMAX];
  size_t hlen = LOCAL_PB_HEXMAX;
  bool truncated = FALSE;

  if(len > (LOCAL_PB_HEXMAX / 2))
    truncated = TRUE;
  Curl_hexencode(buf, len, hexstr, hlen);
  if(!truncated)
    infof(data, "%s: len=%d, val=%s", prefix, (int)len, hexstr);
  else
    infof(data, "%s: len=%d (truncated)val=%s", prefix, (int)len, hexstr);
  return;
}
#endif

/* called from multi when a sub transfer, e.g. doh probe, is done.
 * This looks up the the probe response at its meta CURL_EZM_DOH_PROBE
 * and copies the response body over to the struct at the master's
 * meta at CURL_EZM_DOH_MASTER. */
static void doh_probe_done(struct Curl_easy *data,
                           struct Curl_easy *doh, CURLcode result)
{
  struct doh_probes *dohp = data->state.async.doh;
  DEBUGASSERT(dohp);
  if(dohp) {
    struct doh_request *doh_req = Curl_meta_get(doh, CURL_EZM_DOH_PROBE);
    int i;

    for(i = 0; i < DOH_SLOT_COUNT; ++i) {
      if(dohp->probe_resp[i].probe_mid == doh->mid)
        break;
    }
    if(i >= DOH_SLOT_COUNT) {
      failf(data, "unknown sub request done");
      return;
    }

    dohp->pending--;
    infof(doh, "a DoH request is completed, %u to go", dohp->pending);
    dohp->probe_resp[i].result = result;
    /* We expect either the meta data still to exist or the sub request
     * to have already failed. */
    DEBUGASSERT(doh_req || result);
    if(doh_req) {
      if(!result) {
        dohp->probe_resp[i].dnstype = doh_req->dnstype;
        result = curlx_dyn_addn(&dohp->probe_resp[i].body,
                                curlx_dyn_ptr(&doh_req->resp_body),
                                curlx_dyn_len(&doh_req->resp_body));
        curlx_dyn_free(&doh_req->resp_body);
      }
      Curl_meta_remove(doh, CURL_EZM_DOH_PROBE);
    }

    if(result)
      infof(doh, "DoH request %s", curl_easy_strerror(result));

    if(!dohp->pending) {
      /* DoH completed, run the transfer picking up the results */
      Curl_expire(data, 0, EXPIRE_RUN_NOW);
    }
  }
}

static void doh_probe_dtor(void *key, size_t klen, void *e)
{
  (void)key;
  (void)klen;
  if(e) {
    struct doh_request *doh_req = e;
    curl_slist_free_all(doh_req->req_hds);
    curlx_dyn_free(&doh_req->resp_body);
    free(e);
  }
}

#define ERROR_CHECK_SETOPT(x,y)                         \
  do {                                                  \
    result = curl_easy_setopt((CURL *)doh, x, y);       \
    if(result &&                                        \
       result != CURLE_NOT_BUILT_IN &&                  \
       result != CURLE_UNKNOWN_OPTION)                  \
      goto error;                                       \
  } while(0)

static CURLcode doh_probe_run(struct Curl_easy *data,
                              DNStype dnstype,
                              const char *host,
                              const char *url, CURLM *multi,
                              unsigned int *pmid)
{
  struct Curl_easy *doh = NULL;
  CURLcode result = CURLE_OK;
  timediff_t timeout_ms;
  struct doh_request *doh_req;
  DOHcode d;

  *pmid = UINT_MAX;

  doh_req = calloc(1, sizeof(*doh_req));
  if(!doh_req)
    return CURLE_OUT_OF_MEMORY;
  doh_req->dnstype = dnstype;
  curlx_dyn_init(&doh_req->resp_body, DYN_DOH_RESPONSE);

  d = doh_req_encode(host, dnstype, doh_req->req_body,
                     sizeof(doh_req->req_body),
                     &doh_req->req_body_len);
  if(d) {
    failf(data, "Failed to encode DoH packet [%d]", d);
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }

  timeout_ms = Curl_timeleft(data, NULL, TRUE);
  if(timeout_ms <= 0) {
    result = CURLE_OPERATION_TIMEDOUT;
    goto error;
  }

  doh_req->req_hds =
    curl_slist_append(NULL, "Content-Type: application/dns-message");
  if(!doh_req->req_hds) {
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }

  /* Curl_open() is the internal version of curl_easy_init() */
  result = Curl_open(&doh);
  if(result)
    goto error;

  /* pass in the struct pointer via a local variable to please coverity and
     the gcc typecheck helpers */
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  doh->state.feat = &Curl_trc_feat_dns;
#endif
  ERROR_CHECK_SETOPT(CURLOPT_URL, url);
  ERROR_CHECK_SETOPT(CURLOPT_DEFAULT_PROTOCOL, "https");
  ERROR_CHECK_SETOPT(CURLOPT_WRITEFUNCTION, doh_probe_write_cb);
  ERROR_CHECK_SETOPT(CURLOPT_WRITEDATA, doh);
  ERROR_CHECK_SETOPT(CURLOPT_POSTFIELDS, doh_req->req_body);
  ERROR_CHECK_SETOPT(CURLOPT_POSTFIELDSIZE, (long)doh_req->req_body_len);
  ERROR_CHECK_SETOPT(CURLOPT_HTTPHEADER, doh_req->req_hds);
#ifdef USE_HTTP2
  ERROR_CHECK_SETOPT(CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
  ERROR_CHECK_SETOPT(CURLOPT_PIPEWAIT, 1L);
#endif
#ifndef DEBUGBUILD
  /* enforce HTTPS if not debug */
  ERROR_CHECK_SETOPT(CURLOPT_PROTOCOLS, (long)CURLPROTO_HTTPS);
#else
  /* in debug mode, also allow http */
  ERROR_CHECK_SETOPT(CURLOPT_PROTOCOLS, (long)CURLPROTO_HTTP|CURLPROTO_HTTPS);
#endif
  ERROR_CHECK_SETOPT(CURLOPT_TIMEOUT_MS, (long)timeout_ms);
  ERROR_CHECK_SETOPT(CURLOPT_SHARE, (CURLSH *)data->share);
  if(data->set.err && data->set.err != stderr)
    ERROR_CHECK_SETOPT(CURLOPT_STDERR, data->set.err);
  if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_dns))
    ERROR_CHECK_SETOPT(CURLOPT_VERBOSE, 1L);
  if(data->set.no_signal)
    ERROR_CHECK_SETOPT(CURLOPT_NOSIGNAL, 1L);

  ERROR_CHECK_SETOPT(CURLOPT_SSL_VERIFYHOST,
    data->set.doh_verifyhost ? 2L : 0L);
  ERROR_CHECK_SETOPT(CURLOPT_SSL_VERIFYPEER,
    data->set.doh_verifypeer ? 1L : 0L);
  ERROR_CHECK_SETOPT(CURLOPT_SSL_VERIFYSTATUS,
    data->set.doh_verifystatus ? 1L : 0L);

  /* Inherit *some* SSL options from the user's transfer. This is a
     best-guess as to which options are needed for compatibility. #3661

     Note DoH does not inherit the user's proxy server so proxy SSL settings
     have no effect and are not inherited. If that changes then two new
     options should be added to check doh proxy insecure separately,
     CURLOPT_DOH_PROXY_SSL_VERIFYHOST and CURLOPT_DOH_PROXY_SSL_VERIFYPEER.
     */
  if(data->set.ssl.falsestart)
    ERROR_CHECK_SETOPT(CURLOPT_SSL_FALSESTART, 1L);
  if(data->set.str[STRING_SSL_CAFILE]) {
    ERROR_CHECK_SETOPT(CURLOPT_CAINFO,
                       data->set.str[STRING_SSL_CAFILE]);
  }
  if(data->set.blobs[BLOB_CAINFO]) {
    ERROR_CHECK_SETOPT(CURLOPT_CAINFO_BLOB,
                       data->set.blobs[BLOB_CAINFO]);
  }
  if(data->set.str[STRING_SSL_CAPATH]) {
    ERROR_CHECK_SETOPT(CURLOPT_CAPATH,
                       data->set.str[STRING_SSL_CAPATH]);
  }
  if(data->set.str[STRING_SSL_CRLFILE]) {
    ERROR_CHECK_SETOPT(CURLOPT_CRLFILE,
                       data->set.str[STRING_SSL_CRLFILE]);
  }
  if(data->set.ssl.certinfo)
    ERROR_CHECK_SETOPT(CURLOPT_CERTINFO, 1L);
  if(data->set.ssl.fsslctx)
    ERROR_CHECK_SETOPT(CURLOPT_SSL_CTX_FUNCTION, data->set.ssl.fsslctx);
  if(data->set.ssl.fsslctxp)
    ERROR_CHECK_SETOPT(CURLOPT_SSL_CTX_DATA, data->set.ssl.fsslctxp);
  if(data->set.fdebug)
    ERROR_CHECK_SETOPT(CURLOPT_DEBUGFUNCTION, data->set.fdebug);
  if(data->set.debugdata)
    ERROR_CHECK_SETOPT(CURLOPT_DEBUGDATA, data->set.debugdata);
  if(data->set.str[STRING_SSL_EC_CURVES]) {
    ERROR_CHECK_SETOPT(CURLOPT_SSL_EC_CURVES,
                       data->set.str[STRING_SSL_EC_CURVES]);
  }

  (void)curl_easy_setopt(doh, CURLOPT_SSL_OPTIONS,
                         (long)data->set.ssl.primary.ssl_options);

  doh->state.internal = TRUE;
  doh->master_mid = data->mid; /* master transfer of this one */

  result = Curl_meta_set(doh, CURL_EZM_DOH_PROBE, doh_req, doh_probe_dtor);
  doh_req = NULL; /* call took ownership */
  if(result)
    goto error;

  /* DoH handles must not inherit private_data. The handles may be passed to
     the user via callbacks and the user will be able to identify them as
     internal handles because private data is not set. The user can then set
     private_data via CURLOPT_PRIVATE if they so choose. */
  DEBUGASSERT(!doh->set.private_data);

  if(curl_multi_add_handle(multi, doh))
    goto error;

  *pmid = doh->mid;
  return CURLE_OK;

error:
  Curl_close(&doh);
  if(doh_req)
    doh_probe_dtor(NULL, 0, doh_req);
  return result;
}

/*
 * Curl_doh() resolves a name using DoH. It resolves a name and returns a
 * 'Curl_addrinfo *' with the address information.
 */

struct Curl_addrinfo *Curl_doh(struct Curl_easy *data,
                               const char *hostname,
                               int port,
                               int ip_version,
                               int *waitp)
{
  CURLcode result = CURLE_OK;
  struct doh_probes *dohp = NULL;
  struct connectdata *conn = data->conn;
  size_t i;

  DEBUGASSERT(conn);
  DEBUGASSERT(!data->state.async.doh);
  if(data->state.async.doh)
    Curl_doh_cleanup(data);

  data->state.async.done = FALSE;
  data->state.async.port = port;
  data->state.async.ip_version = ip_version;
  data->state.async.hostname = strdup(hostname);
  if(!data->state.async.hostname)
    return NULL;

  /* start clean, consider allocating this struct on demand */
  data->state.async.doh = dohp = calloc(1, sizeof(struct doh_probes));
  if(!dohp)
    return NULL;

  for(i = 0; i < DOH_SLOT_COUNT; ++i) {
    dohp->probe_resp[i].probe_mid = UINT_MAX;
    curlx_dyn_init(&dohp->probe_resp[i].body, DYN_DOH_RESPONSE);
  }

  conn->bits.doh = TRUE;
  dohp->host = data->state.async.hostname;
  dohp->port = data->state.async.port;
  /* We are making sub easy handles and want to be called back when
   * one is done. */
  data->sub_xfer_done = doh_probe_done;

  /* create IPv4 DoH request */
  result = doh_probe_run(data, DNS_TYPE_A,
                         hostname, data->set.str[STRING_DOH],
                         data->multi,
                         &dohp->probe_resp[DOH_SLOT_IPV4].probe_mid);
  if(result)
    goto error;
  dohp->pending++;

#ifdef USE_IPV6
  if((ip_version != CURL_IPRESOLVE_V4) && Curl_ipv6works(data)) {
    /* create IPv6 DoH request */
    result = doh_probe_run(data, DNS_TYPE_AAAA,
                           hostname, data->set.str[STRING_DOH],
                           data->multi,
                           &dohp->probe_resp[DOH_SLOT_IPV6].probe_mid);
    if(result)
      goto error;
    dohp->pending++;
  }
#endif

#ifdef USE_HTTPSRR
  if(conn->handler->protocol & PROTO_FAMILY_HTTP) {
    /* Only use HTTPS RR for HTTP(S) transfers */
    char *qname = NULL;
    if(port != PORT_HTTPS) {
      qname = aprintf("_%d._https.%s", port, hostname);
      if(!qname)
        goto error;
    }
    result = doh_probe_run(data, DNS_TYPE_HTTPS,
                           qname ? qname : hostname, data->set.str[STRING_DOH],
                           data->multi,
                           &dohp->probe_resp[DOH_SLOT_HTTPS_RR].probe_mid);
    free(qname);
    if(result)
      goto error;
    dohp->pending++;
  }
#endif
  *waitp = TRUE; /* this never returns synchronously */
  return NULL;

error:
  Curl_doh_cleanup(data);
  return NULL;
}

static DOHcode doh_skipqname(const unsigned char *doh, size_t dohlen,
                             unsigned int *indexp)
{
  unsigned char length;
  do {
    if(dohlen < (*indexp + 1))
      return DOH_DNS_OUT_OF_RANGE;
    length = doh[*indexp];
    if((length & 0xc0) == 0xc0) {
      /* name pointer, advance over it and be done */
      if(dohlen < (*indexp + 2))
        return DOH_DNS_OUT_OF_RANGE;
      *indexp += 2;
      break;
    }
    if(length & 0xc0)
      return DOH_DNS_BAD_LABEL;
    if(dohlen < (*indexp + 1 + length))
      return DOH_DNS_OUT_OF_RANGE;
    *indexp += (unsigned int)(1 + length);
  } while(length);
  return DOH_OK;
}

static unsigned short doh_get16bit(const unsigned char *doh,
                                   unsigned int index)
{
  return (unsigned short)((doh[index] << 8) | doh[index + 1]);
}

static unsigned int doh_get32bit(const unsigned char *doh, unsigned int index)
{
  /* make clang and gcc optimize this to bswap by incrementing
     the pointer first. */
  doh += index;

  /* avoid undefined behavior by casting to unsigned before shifting
     24 bits, possibly into the sign bit. codegen is same, but
     ub sanitizer will not be upset */
  return ((unsigned)doh[0] << 24) | ((unsigned)doh[1] << 16) |
         ((unsigned)doh[2] << 8) | doh[3];
}

static void doh_store_a(const unsigned char *doh, int index,
                        struct dohentry *d)
{
  /* silently ignore addresses over the limit */
  if(d->numaddr < DOH_MAX_ADDR) {
    struct dohaddr *a = &d->addr[d->numaddr];
    a->type = DNS_TYPE_A;
    memcpy(&a->ip.v4, &doh[index], 4);
    d->numaddr++;
  }
}

static void doh_store_aaaa(const unsigned char *doh, int index,
                              struct dohentry *d)
{
  /* silently ignore addresses over the limit */
  if(d->numaddr < DOH_MAX_ADDR) {
    struct dohaddr *a = &d->addr[d->numaddr];
    a->type = DNS_TYPE_AAAA;
    memcpy(&a->ip.v6, &doh[index], 16);
    d->numaddr++;
  }
}

#ifdef USE_HTTPSRR
static DOHcode doh_store_https(const unsigned char *doh, int index,
                               struct dohentry *d, uint16_t len)
{
  /* silently ignore RRs over the limit */
  if(d->numhttps_rrs < DOH_MAX_HTTPS) {
    struct dohhttps_rr *h = &d->https_rrs[d->numhttps_rrs];
    h->val = Curl_memdup(&doh[index], len);
    if(!h->val)
      return DOH_OUT_OF_MEM;
    h->len = len;
    d->numhttps_rrs++;
  }
  return DOH_OK;
}
#endif

static DOHcode doh_store_cname(const unsigned char *doh, size_t dohlen,
                               unsigned int index, struct dohentry *d)
{
  struct dynbuf *c;
  unsigned int loop = 128; /* a valid DNS name can never loop this much */
  unsigned char length;

  if(d->numcname == DOH_MAX_CNAME)
    return DOH_OK; /* skip! */

  c = &d->cname[d->numcname++];
  do {
    if(index >= dohlen)
      return DOH_DNS_OUT_OF_RANGE;
    length = doh[index];
    if((length & 0xc0) == 0xc0) {
      int newpos;
      /* name pointer, get the new offset (14 bits) */
      if((index + 1) >= dohlen)
        return DOH_DNS_OUT_OF_RANGE;

      /* move to the new index */
      newpos = (length & 0x3f) << 8 | doh[index + 1];
      index = (unsigned int)newpos;
      continue;
    }
    else if(length & 0xc0)
      return DOH_DNS_BAD_LABEL; /* bad input */
    else
      index++;

    if(length) {
      if(curlx_dyn_len(c)) {
        if(curlx_dyn_addn(c, STRCONST(".")))
          return DOH_OUT_OF_MEM;
      }
      if((index + length) > dohlen)
        return DOH_DNS_BAD_LABEL;

      if(curlx_dyn_addn(c, &doh[index], length))
        return DOH_OUT_OF_MEM;
      index += length;
    }
  } while(length && --loop);

  if(!loop)
    return DOH_DNS_LABEL_LOOP;
  return DOH_OK;
}

static DOHcode doh_rdata(const unsigned char *doh,
                         size_t dohlen,
                         unsigned short rdlength,
                         unsigned short type,
                         int index,
                         struct dohentry *d)
{
  /* RDATA
     - A (TYPE 1):  4 bytes
     - AAAA (TYPE 28): 16 bytes
     - NS (TYPE 2): N bytes
     - HTTPS (TYPE 65): N bytes */
  DOHcode rc;

  switch(type) {
  case DNS_TYPE_A:
    if(rdlength != 4)
      return DOH_DNS_RDATA_LEN;
    doh_store_a(doh, index, d);
    break;
  case DNS_TYPE_AAAA:
    if(rdlength != 16)
      return DOH_DNS_RDATA_LEN;
    doh_store_aaaa(doh, index, d);
    break;
#ifdef USE_HTTPSRR
  case DNS_TYPE_HTTPS:
    rc = doh_store_https(doh, index, d, rdlength);
    if(rc)
      return rc;
    break;
#endif
  case DNS_TYPE_CNAME:
    rc = doh_store_cname(doh, dohlen, (unsigned int)index, d);
    if(rc)
      return rc;
    break;
  case DNS_TYPE_DNAME:
    /* explicit for clarity; just skip; rely on synthesized CNAME  */
    break;
  default:
    /* unsupported type, just skip it */
    break;
  }
  return DOH_OK;
}

UNITTEST void de_init(struct dohentry *de)
{
  int i;
  memset(de, 0, sizeof(*de));
  de->ttl = INT_MAX;
  for(i = 0; i < DOH_MAX_CNAME; i++)
    curlx_dyn_init(&de->cname[i], DYN_DOH_CNAME);
}


UNITTEST DOHcode doh_resp_decode(const unsigned char *doh,
                                 size_t dohlen,
                                 DNStype dnstype,
                                 struct dohentry *d)
{
  unsigned char rcode;
  unsigned short qdcount;
  unsigned short ancount;
  unsigned short type = 0;
  unsigned short rdlength;
  unsigned short nscount;
  unsigned short arcount;
  unsigned int index = 12;
  DOHcode rc;

  if(dohlen < 12)
    return DOH_TOO_SMALL_BUFFER; /* too small */
  if(!doh || doh[0] || doh[1])
    return DOH_DNS_BAD_ID; /* bad ID */
  rcode = doh[3] & 0x0f;
  if(rcode)
    return DOH_DNS_BAD_RCODE; /* bad rcode */

  qdcount = doh_get16bit(doh, 4);
  while(qdcount) {
    rc = doh_skipqname(doh, dohlen, &index);
    if(rc)
      return rc; /* bad qname */
    if(dohlen < (index + 4))
      return DOH_DNS_OUT_OF_RANGE;
    index += 4; /* skip question's type and class */
    qdcount--;
  }

  ancount = doh_get16bit(doh, 6);
  while(ancount) {
    unsigned short class;
    unsigned int ttl;

    rc = doh_skipqname(doh, dohlen, &index);
    if(rc)
      return rc; /* bad qname */

    if(dohlen < (index + 2))
      return DOH_DNS_OUT_OF_RANGE;

    type = doh_get16bit(doh, index);
    if((type != DNS_TYPE_CNAME)    /* may be synthesized from DNAME */
       && (type != DNS_TYPE_DNAME) /* if present, accept and ignore */
       && (type != dnstype))
      /* Not the same type as was asked for nor CNAME nor DNAME */
      return DOH_DNS_UNEXPECTED_TYPE;
    index += 2;

    if(dohlen < (index + 2))
      return DOH_DNS_OUT_OF_RANGE;
    class = doh_get16bit(doh, index);
    if(DNS_CLASS_IN != class)
      return DOH_DNS_UNEXPECTED_CLASS; /* unsupported */
    index += 2;

    if(dohlen < (index + 4))
      return DOH_DNS_OUT_OF_RANGE;

    ttl = doh_get32bit(doh, index);
    if(ttl < d->ttl)
      d->ttl = ttl;
    index += 4;

    if(dohlen < (index + 2))
      return DOH_DNS_OUT_OF_RANGE;

    rdlength = doh_get16bit(doh, index);
    index += 2;
    if(dohlen < (index + rdlength))
      return DOH_DNS_OUT_OF_RANGE;

    rc = doh_rdata(doh, dohlen, rdlength, type, (int)index, d);
    if(rc)
      return rc; /* bad doh_rdata */
    index += rdlength;
    ancount--;
  }

  nscount = doh_get16bit(doh, 8);
  while(nscount) {
    rc = doh_skipqname(doh, dohlen, &index);
    if(rc)
      return rc; /* bad qname */

    if(dohlen < (index + 8))
      return DOH_DNS_OUT_OF_RANGE;

    index += 2 + 2 + 4; /* type, class and ttl */

    if(dohlen < (index + 2))
      return DOH_DNS_OUT_OF_RANGE;

    rdlength = doh_get16bit(doh, index);
    index += 2;
    if(dohlen < (index + rdlength))
      return DOH_DNS_OUT_OF_RANGE;
    index += rdlength;
    nscount--;
  }

  arcount = doh_get16bit(doh, 10);
  while(arcount) {
    rc = doh_skipqname(doh, dohlen, &index);
    if(rc)
      return rc; /* bad qname */

    if(dohlen < (index + 8))
      return DOH_DNS_OUT_OF_RANGE;

    index += 2 + 2 + 4; /* type, class and ttl */

    if(dohlen < (index + 2))
      return DOH_DNS_OUT_OF_RANGE;

    rdlength = doh_get16bit(doh, index);
    index += 2;
    if(dohlen < (index + rdlength))
      return DOH_DNS_OUT_OF_RANGE;
    index += rdlength;
    arcount--;
  }

  if(index != dohlen)
    return DOH_DNS_MALFORMAT; /* something is wrong */

#ifdef USE_HTTTPS
  if((type != DNS_TYPE_NS) && !d->numcname && !d->numaddr && !d->numhttps_rrs)
#else
  if((type != DNS_TYPE_NS) && !d->numcname && !d->numaddr)
#endif
    /* nothing stored! */
    return DOH_NO_CONTENT;

  return DOH_OK; /* ok */
}

#ifndef CURL_DISABLE_VERBOSE_STRINGS
static void doh_show(struct Curl_easy *data,
                     const struct dohentry *d)
{
  int i;
  infof(data, "[DoH] TTL: %u seconds", d->ttl);
  for(i = 0; i < d->numaddr; i++) {
    const struct dohaddr *a = &d->addr[i];
    if(a->type == DNS_TYPE_A) {
      infof(data, "[DoH] A: %u.%u.%u.%u",
            a->ip.v4[0], a->ip.v4[1],
            a->ip.v4[2], a->ip.v4[3]);
    }
    else if(a->type == DNS_TYPE_AAAA) {
      int j;
      char buffer[128] = "[DoH] AAAA: ";
      size_t len = strlen(buffer);
      char *ptr = &buffer[len];
      len = sizeof(buffer) - len;
      for(j = 0; j < 16; j += 2) {
        size_t l;
        msnprintf(ptr, len, "%s%02x%02x", j ? ":" : "", d->addr[i].ip.v6[j],
                  d->addr[i].ip.v6[j + 1]);
        l = strlen(ptr);
        len -= l;
        ptr += l;
      }
      infof(data, "%s", buffer);
    }
  }
#ifdef USE_HTTPSRR
  for(i = 0; i < d->numhttps_rrs; i++) {
# ifdef DEBUGBUILD
    doh_print_buf(data, "DoH HTTPS",
                  d->https_rrs[i].val, d->https_rrs[i].len);
# else
    infof(data, "DoH HTTPS RR: length %d", d->https_rrs[i].len);
# endif
  }
#endif
  for(i = 0; i < d->numcname; i++) {
    infof(data, "CNAME: %s", curlx_dyn_ptr(&d->cname[i]));
  }
}
#else
#define doh_show(x,y)
#endif

/*
 * doh2ai()
 *
 * This function returns a pointer to the first element of a newly allocated
 * Curl_addrinfo struct linked list filled with the data from a set of DoH
 * lookups. Curl_addrinfo is meant to work like the addrinfo struct does for
 * an IPv6 stack, but usable also for IPv4, all hosts and environments.
 *
 * The memory allocated by this function *MUST* be free'd later on calling
 * Curl_freeaddrinfo(). For each successful call to this function there
 * must be an associated call later to Curl_freeaddrinfo().
 */

static CURLcode doh2ai(const struct dohentry *de, const char *hostname,
                       int port, struct Curl_addrinfo **aip)
{
  struct Curl_addrinfo *ai;
  struct Curl_addrinfo *prevai = NULL;
  struct Curl_addrinfo *firstai = NULL;
  struct sockaddr_in *addr;
#ifdef USE_IPV6
  struct sockaddr_in6 *addr6;
#endif
  CURLcode result = CURLE_OK;
  int i;
  size_t hostlen = strlen(hostname) + 1; /* include null-terminator */

  DEBUGASSERT(de);

  if(!de->numaddr)
    return CURLE_COULDNT_RESOLVE_HOST;

  for(i = 0; i < de->numaddr; i++) {
    size_t ss_size;
    CURL_SA_FAMILY_T addrtype;
    if(de->addr[i].type == DNS_TYPE_AAAA) {
#ifndef USE_IPV6
      /* we cannot handle IPv6 addresses */
      continue;
#else
      ss_size = sizeof(struct sockaddr_in6);
      addrtype = AF_INET6;
#endif
    }
    else {
      ss_size = sizeof(struct sockaddr_in);
      addrtype = AF_INET;
    }

    ai = calloc(1, sizeof(struct Curl_addrinfo) + ss_size + hostlen);
    if(!ai) {
      result = CURLE_OUT_OF_MEMORY;
      break;
    }
    ai->ai_addr = (void *)((char *)ai + sizeof(struct Curl_addrinfo));
    ai->ai_canonname = (void *)((char *)ai->ai_addr + ss_size);
    memcpy(ai->ai_canonname, hostname, hostlen);

    if(!firstai)
      /* store the pointer we want to return from this function */
      firstai = ai;

    if(prevai)
      /* make the previous entry point to this */
      prevai->ai_next = ai;

    ai->ai_family = addrtype;

    /* we return all names as STREAM, so when using this address for TFTP
       the type must be ignored and conn->socktype be used instead! */
    ai->ai_socktype = SOCK_STREAM;

    ai->ai_addrlen = (curl_socklen_t)ss_size;

    /* leave the rest of the struct filled with zero */

    switch(ai->ai_family) {
    case AF_INET:
      addr = (void *)ai->ai_addr; /* storage area for this info */
      DEBUGASSERT(sizeof(struct in_addr) == sizeof(de->addr[i].ip.v4));
      memcpy(&addr->sin_addr, &de->addr[i].ip.v4, sizeof(struct in_addr));
      addr->sin_family = (CURL_SA_FAMILY_T)addrtype;
      addr->sin_port = htons((unsigned short)port);
      break;

#ifdef USE_IPV6
    case AF_INET6:
      addr6 = (void *)ai->ai_addr; /* storage area for this info */
      DEBUGASSERT(sizeof(struct in6_addr) == sizeof(de->addr[i].ip.v6));
      memcpy(&addr6->sin6_addr, &de->addr[i].ip.v6, sizeof(struct in6_addr));
      addr6->sin6_family = (CURL_SA_FAMILY_T)addrtype;
      addr6->sin6_port = htons((unsigned short)port);
      break;
#endif
    }

    prevai = ai;
  }

  if(result) {
    Curl_freeaddrinfo(firstai);
    firstai = NULL;
  }
  *aip = firstai;

  return result;
}

#ifndef CURL_DISABLE_VERBOSE_STRINGS
static const char *doh_type2name(DNStype dnstype)
{
  switch(dnstype) {
    case DNS_TYPE_A:
      return "A";
    case DNS_TYPE_AAAA:
      return "AAAA";
#ifdef USE_HTTPSRR
    case DNS_TYPE_HTTPS:
      return "HTTPS";
#endif
    default:
       return "unknown";
  }
}
#endif

UNITTEST void de_cleanup(struct dohentry *d)
{
  int i = 0;
  for(i = 0; i < d->numcname; i++) {
    curlx_dyn_free(&d->cname[i]);
  }
#ifdef USE_HTTPSRR
  for(i = 0; i < d->numhttps_rrs; i++)
    Curl_safefree(d->https_rrs[i].val);
#endif
}

#ifdef USE_HTTPSRR

/*
 * @brief decode the DNS name in a binary RRData
 * @param buf points to the buffer (in/out)
 * @param remaining points to the remaining buffer length (in/out)
 * @param dnsname returns the string form name on success
 * @return is 1 for success, error otherwise
 *
 * The encoding here is defined in
 * https://tools.ietf.org/html/rfc1035#section-3.1
 *
 * The input buffer pointer will be modified so it points to
 * just after the end of the DNS name encoding on output. (And
 * that is why it is an "unsigned char **" :-)
 */
static CURLcode doh_decode_rdata_name(const unsigned char **buf,
                                      size_t *remaining, char **dnsname)
{
  const unsigned char *cp = NULL;
  size_t rem = 0;
  unsigned char clen = 0; /* chunk len */
  struct dynbuf thename;

  DEBUGASSERT(buf && remaining && dnsname);
  if(!buf || !remaining || !dnsname || !*remaining)
    return CURLE_OUT_OF_MEMORY;
  curlx_dyn_init(&thename, CURL_MAXLEN_host_name);
  rem = *remaining;
  cp = *buf;
  clen = *cp++;
  if(clen == 0) {
    /* special case - return "." as name */
    if(curlx_dyn_addn(&thename, ".", 1))
      return CURLE_OUT_OF_MEMORY;
  }
  while(clen) {
    if(clen >= rem) {
      curlx_dyn_free(&thename);
      return CURLE_OUT_OF_MEMORY;
    }
    if(curlx_dyn_addn(&thename, cp, clen) ||
       curlx_dyn_addn(&thename, ".", 1))
      return CURLE_TOO_LARGE;

    cp += clen;
    rem -= (clen + 1);
    if(rem <= 0) {
      curlx_dyn_free(&thename);
      return CURLE_OUT_OF_MEMORY;
    }
    clen = *cp++;
  }
  *buf = cp;
  *remaining = rem - 1;
  *dnsname = curlx_dyn_ptr(&thename);
  return CURLE_OK;
}

UNITTEST CURLcode doh_resp_decode_httpsrr(struct Curl_easy *data,
                                          const unsigned char *cp, size_t len,
                                          struct Curl_https_rrinfo **hrr);

/* @unittest 1658 */
UNITTEST CURLcode doh_resp_decode_httpsrr(struct Curl_easy *data,
                                          const unsigned char *cp, size_t len,
                                          struct Curl_https_rrinfo **hrr)
{
  uint16_t pcode = 0, plen = 0;
  uint32_t expected_min_pcode = 0;
  struct Curl_https_rrinfo *lhrr = NULL;
  char *dnsname = NULL;
  CURLcode result = CURLE_OUT_OF_MEMORY;
  size_t olen;

  *hrr = NULL;
  if(len <= 2)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  lhrr = calloc(1, sizeof(struct Curl_https_rrinfo));
  if(!lhrr)
    return CURLE_OUT_OF_MEMORY;
  lhrr->priority = doh_get16bit(cp, 0);
  cp += 2;
  len -= 2;
  if(doh_decode_rdata_name(&cp, &len, &dnsname) != CURLE_OK)
    goto err;
  lhrr->target = dnsname;
  if(Curl_junkscan(dnsname, &olen, FALSE)) {
    /* unacceptable hostname content */
    result = CURLE_WEIRD_SERVER_REPLY;
    goto err;
  }
  lhrr->port = -1; /* until set */
  while(len >= 4) {
    pcode = doh_get16bit(cp, 0);
    plen = doh_get16bit(cp, 2);
    cp += 4;
    len -= 4;
    if(pcode < expected_min_pcode || plen > len) {
      result = CURLE_WEIRD_SERVER_REPLY;
      goto err;
    }
    result = Curl_httpsrr_set(data, lhrr, pcode, cp, plen);
    if(result)
      goto err;
    cp += plen;
    len -= plen;
    expected_min_pcode = pcode + 1;
  }
  DEBUGASSERT(!len);
  *hrr = lhrr;
  return CURLE_OK;
err:
  Curl_httpsrr_cleanup(lhrr);
  Curl_safefree(lhrr);
  return result;
}

#ifdef DEBUGBUILD
UNITTEST void doh_print_httpsrr(struct Curl_easy *data,
                                struct Curl_https_rrinfo *hrr);

UNITTEST void doh_print_httpsrr(struct Curl_easy *data,
                                struct Curl_https_rrinfo *hrr)
{
  DEBUGASSERT(hrr);
  infof(data, "HTTPS RR: priority %d, target: %s",
        hrr->priority, hrr->target);
  if(hrr->alpns[0] != ALPN_none)
    infof(data, "HTTPS RR: alpns %u %u %u %u",
          hrr->alpns[0], hrr->alpns[1], hrr->alpns[2], hrr->alpns[3]);
  else
    infof(data, "HTTPS RR: no alpns");
  if(hrr->no_def_alpn)
    infof(data, "HTTPS RR: no_def_alpn set");
  else
    infof(data, "HTTPS RR: no_def_alpn not set");
  if(hrr->ipv4hints) {
    doh_print_buf(data, "HTTPS RR: ipv4hints",
                  hrr->ipv4hints, hrr->ipv4hints_len);
  }
  else
    infof(data, "HTTPS RR: no ipv4hints");
  if(hrr->echconfiglist) {
    doh_print_buf(data, "HTTPS RR: ECHConfigList",
                  hrr->echconfiglist, hrr->echconfiglist_len);
  }
  else
    infof(data, "HTTPS RR: no ECHConfigList");
  if(hrr->ipv6hints) {
    doh_print_buf(data, "HTTPS RR: ipv6hint",
                  hrr->ipv6hints, hrr->ipv6hints_len);
  }
  else
    infof(data, "HTTPS RR: no ipv6hints");
  return;
}
# endif
#endif

CURLcode Curl_doh_is_resolved(struct Curl_easy *data,
                              struct Curl_dns_entry **dnsp)
{
  CURLcode result;
  struct doh_probes *dohp = data->state.async.doh;
  *dnsp = NULL; /* defaults to no response */
  if(!dohp)
    return CURLE_OUT_OF_MEMORY;

  if(dohp->probe_resp[DOH_SLOT_IPV4].probe_mid == UINT_MAX &&
     dohp->probe_resp[DOH_SLOT_IPV6].probe_mid == UINT_MAX) {
    failf(data, "Could not DoH-resolve: %s", dohp->host);
    return CONN_IS_PROXIED(data->conn) ? CURLE_COULDNT_RESOLVE_PROXY :
      CURLE_COULDNT_RESOLVE_HOST;
  }
  else if(!dohp->pending) {
    DOHcode rc[DOH_SLOT_COUNT];
    struct dohentry de;
    int slot;

    /* Clear any result the might still be there */
    Curl_resolv_unlink(data, &data->state.async.dns);

    memset(rc, 0, sizeof(rc));
    /* remove DoH handles from multi handle and close them */
    Curl_doh_close(data);
    /* parse the responses, create the struct and return it! */
    de_init(&de);
    for(slot = 0; slot < DOH_SLOT_COUNT; slot++) {
      struct doh_response *p = &dohp->probe_resp[slot];
      if(!p->dnstype)
        continue;
      rc[slot] = doh_resp_decode(curlx_dyn_uptr(&p->body),
                                 curlx_dyn_len(&p->body),
                                 p->dnstype, &de);
#ifndef CURL_DISABLE_VERBOSE_STRINGS
      if(rc[slot]) {
        infof(data, "DoH: %s type %s for %s", doh_strerror(rc[slot]),
              doh_type2name(p->dnstype), dohp->host);
      }
#endif
    } /* next slot */

    result = CURLE_COULDNT_RESOLVE_HOST; /* until we know better */
    if(!rc[DOH_SLOT_IPV4] || !rc[DOH_SLOT_IPV6]) {
      /* we have an address, of one kind or other */
      struct Curl_dns_entry *dns;
      struct Curl_addrinfo *ai;


      if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_dns)) {
        CURL_TRC_DNS(data, "hostname: %s", dohp->host);
        doh_show(data, &de);
      }

      result = doh2ai(&de, dohp->host, dohp->port, &ai);
      if(result) {
        de_cleanup(&de);
        return result;
      }

      /* we got a response, create a dns entry. */
      dns = Curl_dnscache_mk_entry(data, ai, dohp->host, 0, dohp->port, FALSE);
      if(dns) {
        /* Now add and HTTPSRR information if we have */
#ifdef USE_HTTPSRR
        if(de.numhttps_rrs > 0 && result == CURLE_OK) {
          struct Curl_https_rrinfo *hrr = NULL;
          result = doh_resp_decode_httpsrr(data, de.https_rrs->val,
                                           de.https_rrs->len, &hrr);
          if(result) {
            infof(data, "Failed to decode HTTPS RR");
            return result;
          }
          infof(data, "Some HTTPS RR to process");
# ifdef DEBUGBUILD
          doh_print_httpsrr(data, hrr);
# endif
          dns->hinfo = hrr;
       }
#endif
        /* and add the entry to the cache */
        data->state.async.dns = dns;
        result = Curl_dnscache_add(data, dns);
        *dnsp = data->state.async.dns;
      }
    } /* address processing done */

    /* All done */
    data->state.async.done = TRUE;
    de_cleanup(&de);
    Curl_doh_cleanup(data);
    return result;

  } /* !dohp->pending */

  /* else wait for pending DoH transactions to complete */
  return CURLE_OK;
}

void Curl_doh_close(struct Curl_easy *data)
{
  struct doh_probes *doh = data->state.async.doh;
  if(doh && data->multi) {
    struct Curl_easy *probe_data;
    unsigned int mid;
    size_t slot;
    for(slot = 0; slot < DOH_SLOT_COUNT; slot++) {
      mid = doh->probe_resp[slot].probe_mid;
      if(mid == UINT_MAX)
        continue;
      doh->probe_resp[slot].probe_mid = UINT_MAX;
      /* should have been called before data is removed from multi handle */
      DEBUGASSERT(data->multi);
      probe_data = data->multi ? Curl_multi_get_easy(data->multi, mid) :
        NULL;
      if(!probe_data) {
        DEBUGF(infof(data, "Curl_doh_close: xfer for mid=%u not found!",
                     doh->probe_resp[slot].probe_mid));
        continue;
      }
      /* data->multi might already be reset at this time */
      curl_multi_remove_handle(data->multi, probe_data);
      Curl_close(&probe_data);
    }
    data->sub_xfer_done = NULL;
  }
}

void Curl_doh_cleanup(struct Curl_easy *data)
{
  struct doh_probes *dohp = data->state.async.doh;
  if(dohp) {
    int i;
    Curl_doh_close(data);
    for(i = 0; i < DOH_SLOT_COUNT; ++i) {
      curlx_dyn_free(&dohp->probe_resp[i].body);
    }
    Curl_safefree(data->state.async.doh);
  }
}

#endif /* CURL_DISABLE_DOH */
