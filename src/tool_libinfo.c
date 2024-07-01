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
#include "tool_setup.h"

#include "strcase.h"

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_libinfo.h"

#include "memdebug.h" /* keep this as LAST include */

/* global variable definitions, for libcurl runtime info */

static const char *no_protos = NULL;

curl_version_info_data *curlinfo = NULL;
const char * const *built_in_protos = &no_protos;

size_t proto_count = 0;

const char *proto_file = NULL;
const char *proto_ftp = NULL;
const char *proto_ftps = NULL;
const char *proto_http = NULL;
const char *proto_https = NULL;
const char *proto_rtsp = NULL;
const char *proto_scp = NULL;
const char *proto_sftp = NULL;
const char *proto_tftp = NULL;
const char *proto_ipfs = "ipfs";
const char *proto_ipns = "ipns";

static struct proto_name_tokenp {
  const char   *proto_name;
  const char  **proto_tokenp;
} const possibly_built_in[] = {
  { "file",     &proto_file  },
  { "ftp",      &proto_ftp   },
  { "ftps",     &proto_ftps  },
  { "http",     &proto_http  },
  { "https",    &proto_https },
  { "rtsp",     &proto_rtsp  },
  { "scp",      &proto_scp   },
  { "sftp",     &proto_sftp  },
  { "tftp",     &proto_tftp  },
  {  NULL,      NULL         }
};

bool feature_altsvc = FALSE;
bool feature_brotli = FALSE;
bool feature_hsts = FALSE;
bool feature_http2 = FALSE;
bool feature_http3 = FALSE;
bool feature_httpsproxy = FALSE;
bool feature_libz = FALSE;
bool feature_ntlm = FALSE;
bool feature_ntlm_wb = FALSE;
bool feature_spnego = FALSE;
bool feature_ssl = FALSE;
bool feature_tls_srp = FALSE;
bool feature_zstd = FALSE;

static struct feature_name_presentp {
  const char   *feature_name;
  bool         *feature_presentp;
  int           feature_bitmask;
} const maybe_feature[] = {
  /* Keep alphabetically sorted. */
  {"alt-svc",        &feature_altsvc,     CURL_VERSION_ALTSVC},
  {"AsynchDNS",      NULL,                CURL_VERSION_ASYNCHDNS},
  {"brotli",         &feature_brotli,     CURL_VERSION_BROTLI},
  {"CharConv",       NULL,                CURL_VERSION_CONV},
  {"Debug",          NULL,                CURL_VERSION_DEBUG},
  {"gsasl",          NULL,                CURL_VERSION_GSASL},
  {"GSS-API",        NULL,                CURL_VERSION_GSSAPI},
  {"HSTS",           &feature_hsts,       CURL_VERSION_HSTS},
  {"HTTP2",          &feature_http2,      CURL_VERSION_HTTP2},
  {"HTTP3",          &feature_http3,      CURL_VERSION_HTTP3},
  {"HTTPS-proxy",    &feature_httpsproxy, CURL_VERSION_HTTPS_PROXY},
  {"IDN",            NULL,                CURL_VERSION_IDN},
  {"IPv6",           NULL,                CURL_VERSION_IPV6},
  {"Kerberos",       NULL,                CURL_VERSION_KERBEROS5},
  {"Largefile",      NULL,                CURL_VERSION_LARGEFILE},
  {"libz",           &feature_libz,       CURL_VERSION_LIBZ},
  {"MultiSSL",       NULL,                CURL_VERSION_MULTI_SSL},
  {"NTLM",           &feature_ntlm,       CURL_VERSION_NTLM},
  {"NTLM_WB",        &feature_ntlm_wb,    CURL_VERSION_NTLM_WB},
  {"PSL",            NULL,                CURL_VERSION_PSL},
  {"SPNEGO",         &feature_spnego,     CURL_VERSION_SPNEGO},
  {"SSL",            &feature_ssl,        CURL_VERSION_SSL},
  {"SSPI",           NULL,                CURL_VERSION_SSPI},
  {"threadsafe",     NULL,                CURL_VERSION_THREADSAFE},
  {"TLS-SRP",        &feature_tls_srp,    CURL_VERSION_TLSAUTH_SRP},
  {"TrackMemory",    NULL,                CURL_VERSION_CURLDEBUG},
  {"Unicode",        NULL,                CURL_VERSION_UNICODE},
  {"UnixSockets",    NULL,                CURL_VERSION_UNIX_SOCKETS},
  {"zstd",           &feature_zstd,       CURL_VERSION_ZSTD},
  {NULL,             NULL,                0}
};

static const char *fnames[sizeof(maybe_feature) / sizeof(maybe_feature[0])];
const char * const *feature_names = fnames;

/*
 * libcurl_info_init: retrieves runtime information about libcurl,
 * setting a global pointer 'curlinfo' to libcurl's runtime info
 * struct, count protocols and flag those we are interested in.
 * Global pointer feature_names is set to the feature names array. If
 * the latter is not returned by curl_version_info(), it is built from
 * the returned features bit mask.
 */

CURLcode get_libcurl_info(void)
{
  CURLcode result = CURLE_OK;
  const char *const *builtin;

  /* Pointer to libcurl's runtime version information */
  curlinfo = curl_version_info(CURLVERSION_NOW);
  if(!curlinfo)
    return CURLE_FAILED_INIT;

  if(curlinfo->protocols) {
    const struct proto_name_tokenp *p;

    built_in_protos = curlinfo->protocols;

    for(builtin = built_in_protos; !result && *builtin; builtin++) {
      /* Identify protocols we are interested in. */
      for(p = possibly_built_in; p->proto_name; p++)
        if(curl_strequal(p->proto_name, *builtin)) {
          *p->proto_tokenp = *builtin;
          break;
        }
    }
    proto_count = builtin - built_in_protos;
  }

  if(curlinfo->age >= CURLVERSION_ELEVENTH && curlinfo->feature_names)
    feature_names = curlinfo->feature_names;
  else {
    const struct feature_name_presentp *p;
    const char **cpp = fnames;

    for(p = maybe_feature; p->feature_name; p++)
      if(curlinfo->features & p->feature_bitmask)
        *cpp++ = p->feature_name;
    *cpp = NULL;
  }

  /* Identify features we are interested in. */
  for(builtin = feature_names; *builtin; builtin++) {
    const struct feature_name_presentp *p;

    for(p = maybe_feature; p->feature_name; p++)
      if(curl_strequal(p->feature_name, *builtin)) {
        if(p->feature_presentp)
          *p->feature_presentp = TRUE;
        break;
      }
  }

  return CURLE_OK;
}

/* Tokenize a protocol name.
 * Return the address of the protocol name listed by the library, or NULL if
 * not found.
 * Although this may seem useless, this always returns the same address for
 * a given protocol and thus allows comparing pointers rather than strings.
 * In addition, the returned pointer is not deallocated until the program ends.
 */

const char *proto_token(const char *proto)
{
  const char * const *builtin;

  if(!proto)
    return NULL;
  for(builtin = built_in_protos; *builtin; builtin++)
    if(curl_strequal(*builtin, proto))
      break;
  return *builtin;
}
