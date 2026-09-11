#ifndef HEADER_CURL_VTLS_CONFIG_H
#define HEADER_CURL_VTLS_CONFIG_H
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

struct Curl_easy;
struct connectdata;
struct Curl_peer;

struct ssl_filter_config {
  char *CApath;          /* certificate directory (does not work on Windows) */
  char *CAfile;          /* certificate to verify peer against */
  char *issuercert;      /* optional issuer certificate filename */
  char *clientcert;
  char *cipher_list;     /* list of ciphers to use */
  char *cipher_list13;   /* list of TLS 1.3 cipher suites to use */
  char *signature_algorithms; /* list of signature algorithms to use */
  char *pinned_key;
  char *CRLfile;         /* CRL to check certificate revocation */
  char *cert_type;       /* format for certificate (default: PEM) */
  char *key;             /* private key filename */
  char *key_type;        /* format for private key (default: PEM) */
  char *key_passwd;      /* plain text private key password */
  struct curl_blob *cert_blob;
  struct curl_blob *ca_info_blob;
  struct curl_blob *issuercert_blob;
  struct curl_blob *key_blob;
  char *curves;          /* list of curves to use */
  uint32_t version_max; /* max supported version the client wants to use */
  uint8_t ssl_options;  /* the CURLOPT_SSL_OPTIONS bitmask */
  uint8_t version;    /* what version the client wants to use */
  BIT(verifypeer);       /* set TRUE if this is desired */
  BIT(verifyhost);       /* set TRUE if CN/SAN must match hostname */
  BIT(verifystatus);     /* set TRUE if certificate status must be checked */
  BIT(native_ca_store);  /* use the native CA store of operating system */
  BIT(cache_session);    /* cache session or not */
  BIT(deep_copy);        /* members are deep copies, eg. owned here */
  BIT(earlydata);        /* use TLS 1.3 early data */
  BIT(auto_client_cert);   /* automatically locate and use a client
                              certificate for authentication (Schannel) */
  BIT(enable_beast); /* allow this flaw for interoperability's sake */
  BIT(no_partialchain); /* do not accept partial certificate chains */
  BIT(no_revoke);    /* disable SSL certificate revocation checks */
  BIT(revoke_best_effort); /* ignore SSL revocation offline/missing revocation
                              list errors */
};

struct ssl_easy_config {
  long certverifyresult; /* result from the certificate verification */
  uint32_t version_max; /* max supported version the client wants to use */
  uint8_t version;    /* what version the client wants to use */
  uint8_t ssl_options;  /* the CURLOPT_SSL_OPTIONS bitmask */
  BIT(verifypeer);       /* set TRUE if this is desired */
  BIT(verifyhost);       /* set TRUE if CN/SAN must match hostname */
  BIT(verifystatus);     /* set TRUE if certificate status must be checked */
  BIT(cache_session);    /* cache session or not */
  BIT(certinfo);     /* gather lots of certificate info */
  BIT(custom_cafile); /* application has set custom CA file */
  BIT(custom_capath); /* application has set custom CA path */
  BIT(custom_cablob); /* application has set custom CA blob */
};

void Curl_ssl_config_init(struct ssl_easy_config *sslc);
void Curl_ssl_config_cleanup(struct ssl_filter_config *sslc);

/**
 * Init the SSL configs for origin and proxy from data's settings.
 */
CURLcode Curl_ssl_easy_config_complete(struct Curl_easy *data,
                                       struct Curl_peer *origin,
                                       struct ssl_filter_config *ssl_origin,
                                       struct ssl_filter_config *ssl_proxy);

/**
 * Init SSL configs (main + proxy) for a new connection from the easy handle.
 */
CURLcode Curl_ssl_conn_config_init(struct ssl_filter_config *ssl_config,
                                   struct ssl_filter_config *proxy_ssl_config,
                                   struct connectdata *conn);

/**
 * Free allocated resources in SSL configs (main + proxy) for
 * the given connection.
 */
void Curl_ssl_conn_config_cleanup(struct connectdata *conn);

/**
 * Return TRUE if `conn_config` is functionally the
 * same as the one on `candidate`.
 * @param proxy   match the proxy SSL config or the main one
 */
bool Curl_ssl_conn_config_match(struct Curl_easy *data,
                                struct ssl_filter_config *conn_config,
                                struct connectdata *candidate,
                                bool proxy);

/* Update certain connection SSL config flags after they have
 * been changed on the easy handle. Works for `verifypeer`,
 * `verifyhost` and `verifystatus`. */
void Curl_ssl_conn_config_update(struct Curl_easy *data, bool for_proxy);

#endif /* HEADER_CURL_VTLS_CONFIG_H */
