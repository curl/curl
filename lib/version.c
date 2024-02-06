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

#ifdef USE_NGHTTP2
#include <nghttp2/nghttp2.h>
#endif

#include <curl/curl.h>
#include "urldata.h"
#include "vtls/vtls.h"
#include "http2.h"
#include "vssh/ssh.h"
#include "vquic/vquic.h"
#include "curl_printf.h"
#include "easy_lock.h"

#ifdef USE_ARES
#  if defined(CURL_STATICLIB) && !defined(CARES_STATICLIB) &&   \
  defined(_WIN32)
#    define CARES_STATICLIB
#  endif
#  include <ares.h>
#endif

#ifdef USE_LIBIDN2
#include <idn2.h>
#endif

#ifdef USE_LIBPSL
#include <libpsl.h>
#endif

#ifdef USE_LIBRTMP
#include <librtmp/rtmp.h>
#endif

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif

#ifdef HAVE_BROTLI
#if defined(__GNUC__)
/* Ignore -Wvla warnings in brotli headers */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvla"
#endif
#include <brotli/decode.h>
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#endif

#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

#ifdef USE_GSASL
#include <gsasl.h>
#endif

#ifdef USE_OPENLDAP
#include <ldap.h>
#endif

#ifdef HAVE_BROTLI
static void brotli_version(char *buf, size_t bufsz)
{
  uint32_t brotli_version = BrotliDecoderVersion();
  unsigned int major = brotli_version >> 24;
  unsigned int minor = (brotli_version & 0x00FFFFFF) >> 12;
  unsigned int patch = brotli_version & 0x00000FFF;
  (void)msnprintf(buf, bufsz, "%u.%u.%u", major, minor, patch);
}
#endif

#ifdef HAVE_ZSTD
static void zstd_version(char *buf, size_t bufsz)
{
  unsigned long zstd_version = (unsigned long)ZSTD_versionNumber();
  unsigned int major = (unsigned int)(zstd_version / (100 * 100));
  unsigned int minor = (unsigned int)((zstd_version -
                                       (major * 100 * 100)) / 100);
  unsigned int patch = (unsigned int)(zstd_version -
                                      (major * 100 * 100) - (minor * 100));
  (void)msnprintf(buf, bufsz, "%u.%u.%u", major, minor, patch);
}
#endif

/*
 * curl_version() returns a pointer to a static buffer.
 *
 * It is implemented to work multi-threaded by making sure repeated invokes
 * generate the exact same string and never write any temporary data like
 * zeros in the data.
 */

#define VERSION_PARTS 16 /* number of substrings we can concatenate */

char *curl_version(void)
{
  static char out[300];
  char *outp;
  size_t outlen;
  const char *src[VERSION_PARTS];
#ifdef USE_SSL
  char ssl_version[200];
#endif
#ifdef HAVE_LIBZ
  char z_version[40];
#endif
#ifdef HAVE_BROTLI
  char br_version[40] = "brotli/";
#endif
#ifdef HAVE_ZSTD
  char zst_version[40] = "zstd/";
#endif
#ifdef USE_ARES
  char cares_version[40];
#endif
#if defined(USE_LIBIDN2)
  char idn_version[40];
#endif
#ifdef USE_LIBPSL
  char psl_version[40];
#endif
#ifdef USE_SSH
  char ssh_version[40];
#endif
#ifdef USE_NGHTTP2
  char h2_version[40];
#endif
#ifdef ENABLE_QUIC
  char h3_version[40];
#endif
#ifdef USE_LIBRTMP
  char rtmp_version[40];
#endif
#ifdef USE_HYPER
  char hyper_buf[30];
#endif
#ifdef USE_GSASL
  char gsasl_buf[30];
#endif
#ifdef USE_OPENLDAP
  char ldap_buf[30];
#endif
  int i = 0;
  int j;

#ifdef DEBUGBUILD
  /* Override version string when environment variable CURL_VERSION is set */
  const char *debugversion = getenv("CURL_VERSION");
  if(debugversion) {
    strncpy(out, debugversion, sizeof(out)-1);
    out[sizeof(out)-1] = '\0';
    return out;
  }
#endif

  src[i++] = LIBCURL_NAME "/" LIBCURL_VERSION;
#ifdef USE_SSL
  Curl_ssl_version(ssl_version, sizeof(ssl_version));
  src[i++] = ssl_version;
#endif
#ifdef HAVE_LIBZ
  msnprintf(z_version, sizeof(z_version), "zlib/%s", zlibVersion());
  src[i++] = z_version;
#endif
#ifdef HAVE_BROTLI
  brotli_version(&br_version[7], sizeof(br_version) - 7);
  src[i++] = br_version;
#endif
#ifdef HAVE_ZSTD
  zstd_version(&zst_version[5], sizeof(zst_version) - 5);
  src[i++] = zst_version;
#endif
#ifdef USE_ARES
  msnprintf(cares_version, sizeof(cares_version),
            "c-ares/%s", ares_version(NULL));
  src[i++] = cares_version;
#endif
#ifdef USE_LIBIDN2
  msnprintf(idn_version, sizeof(idn_version),
            "libidn2/%s", idn2_check_version(NULL));
  src[i++] = idn_version;
#elif defined(USE_WIN32_IDN)
  src[i++] = (char *)"WinIDN";
#endif

#ifdef USE_LIBPSL
  {
    int num = psl_check_version_number(0);
    msnprintf(psl_version, sizeof(psl_version), "libpsl/%d.%d.%d",
              num >> 16, (num >> 8) & 0xff, num & 0xff);
    src[i++] = psl_version;
  }
#endif

#ifdef USE_SSH
  Curl_ssh_version(ssh_version, sizeof(ssh_version));
  src[i++] = ssh_version;
#endif
#ifdef USE_NGHTTP2
  Curl_http2_ver(h2_version, sizeof(h2_version));
  src[i++] = h2_version;
#endif
#ifdef ENABLE_QUIC
  Curl_quic_ver(h3_version, sizeof(h3_version));
  src[i++] = h3_version;
#endif
#ifdef USE_LIBRTMP
  {
    char suff[2];
    if(RTMP_LIB_VERSION & 0xff) {
      suff[0] = (RTMP_LIB_VERSION & 0xff) + 'a' - 1;
      suff[1] = '\0';
    }
    else
      suff[0] = '\0';

    msnprintf(rtmp_version, sizeof(rtmp_version), "librtmp/%d.%d%s",
              RTMP_LIB_VERSION >> 16, (RTMP_LIB_VERSION >> 8) & 0xff,
              suff);
    src[i++] = rtmp_version;
  }
#endif
#ifdef USE_HYPER
  msnprintf(hyper_buf, sizeof(hyper_buf), "Hyper/%s", hyper_version());
  src[i++] = hyper_buf;
#endif
#ifdef USE_GSASL
  msnprintf(gsasl_buf, sizeof(gsasl_buf), "libgsasl/%s",
            gsasl_check_version(NULL));
  src[i++] = gsasl_buf;
#endif
#ifdef USE_OPENLDAP
  {
    LDAPAPIInfo api;
    api.ldapai_info_version = LDAP_API_INFO_VERSION;

    if(ldap_get_option(NULL, LDAP_OPT_API_INFO, &api) == LDAP_OPT_SUCCESS) {
      unsigned int patch = api.ldapai_vendor_version % 100;
      unsigned int major = api.ldapai_vendor_version / 10000;
      unsigned int minor =
        ((api.ldapai_vendor_version - major * 10000) - patch) / 100;
      msnprintf(ldap_buf, sizeof(ldap_buf), "%s/%u.%u.%u",
                api.ldapai_vendor_name, major, minor, patch);
      src[i++] = ldap_buf;
      ldap_memfree(api.ldapai_vendor_name);
      ber_memvfree((void **)api.ldapai_extensions);
    }
  }
#endif

  DEBUGASSERT(i <= VERSION_PARTS);

  outp = &out[0];
  outlen = sizeof(out);
  for(j = 0; j < i; j++) {
    size_t n = strlen(src[j]);
    /* we need room for a space, the string and the final zero */
    if(outlen <= (n + 2))
      break;
    if(j) {
      /* prepend a space if not the first */
      *outp++ = ' ';
      outlen--;
    }
    memcpy(outp, src[j], n);
    outp += n;
    outlen -= n;
  }
  *outp = 0;

  return out;
}

/* data for curl_version_info

   Keep the list sorted alphabetically. It is also written so that each
   protocol line has its own #if line to make things easier on the eye.
 */

static const char * const supported_protocols[] = {
#ifndef CURL_DISABLE_DICT
  "dict",
#endif
#ifndef CURL_DISABLE_FILE
  "file",
#endif
#ifndef CURL_DISABLE_FTP
  "ftp",
#endif
#if defined(USE_SSL) && !defined(CURL_DISABLE_FTP)
  "ftps",
#endif
#ifndef CURL_DISABLE_GOPHER
  "gopher",
#endif
#if defined(USE_SSL) && !defined(CURL_DISABLE_GOPHER)
  "gophers",
#endif
#ifndef CURL_DISABLE_HTTP
  "http",
#endif
#if defined(USE_SSL) && !defined(CURL_DISABLE_HTTP)
  "https",
#endif
#ifndef CURL_DISABLE_IMAP
  "imap",
#endif
#if defined(USE_SSL) && !defined(CURL_DISABLE_IMAP)
  "imaps",
#endif
#ifndef CURL_DISABLE_LDAP
  "ldap",
#if !defined(CURL_DISABLE_LDAPS) && \
    ((defined(USE_OPENLDAP) && defined(USE_SSL)) || \
     (!defined(USE_OPENLDAP) && defined(HAVE_LDAP_SSL)))
  "ldaps",
#endif
#endif
#ifndef CURL_DISABLE_MQTT
  "mqtt",
#endif
#ifndef CURL_DISABLE_POP3
  "pop3",
#endif
#if defined(USE_SSL) && !defined(CURL_DISABLE_POP3)
  "pop3s",
#endif
#ifdef USE_LIBRTMP
  "rtmp",
  "rtmpe",
  "rtmps",
  "rtmpt",
  "rtmpte",
  "rtmpts",
#endif
#ifndef CURL_DISABLE_RTSP
  "rtsp",
#endif
#if defined(USE_SSH) && !defined(USE_WOLFSSH)
  "scp",
#endif
#ifdef USE_SSH
  "sftp",
#endif
#if !defined(CURL_DISABLE_SMB) && defined(USE_CURL_NTLM_CORE)
  "smb",
#  ifdef USE_SSL
  "smbs",
#  endif
#endif
#ifndef CURL_DISABLE_SMTP
  "smtp",
#endif
#if defined(USE_SSL) && !defined(CURL_DISABLE_SMTP)
  "smtps",
#endif
#ifndef CURL_DISABLE_TELNET
  "telnet",
#endif
#ifndef CURL_DISABLE_TFTP
  "tftp",
#endif
#ifdef USE_WEBSOCKETS
  "ws",
#endif
#if defined(USE_SSL) && defined(USE_WEBSOCKETS)
  "wss",
#endif

  NULL
};

/*
 * Feature presence run-time check functions.
 *
 * Warning: the value returned by these should not change between
 * curl_global_init() and curl_global_cleanup() calls.
 */

#if defined(USE_LIBIDN2)
static int idn_present(curl_version_info_data *info)
{
  return info->libidn != NULL;
}
#else
#define idn_present     NULL
#endif

#if defined(USE_SSL) && !defined(CURL_DISABLE_PROXY) && \
  !defined(CURL_DISABLE_HTTP)
static int https_proxy_present(curl_version_info_data *info)
{
  (void) info;
  return Curl_ssl_supports(NULL, SSLSUPP_HTTPS_PROXY);
}
#endif

/*
 * Features table.
 *
 * Keep the features alphabetically sorted.
 * Use FEATURE() macro to define an entry: this allows documentation check.
 */

#define FEATURE(name, present, bitmask) {(name), (present), (bitmask)}

struct feat {
  const char *name;
  int        (*present)(curl_version_info_data *info);
  int        bitmask;
};

static const struct feat features_table[] = {
#ifndef CURL_DISABLE_ALTSVC
  FEATURE("alt-svc",     NULL,                CURL_VERSION_ALTSVC),
#endif
#ifdef CURLRES_ASYNCH
  FEATURE("AsynchDNS",   NULL,                CURL_VERSION_ASYNCHDNS),
#endif
#ifdef HAVE_BROTLI
  FEATURE("brotli",      NULL,                CURL_VERSION_BROTLI),
#endif
#ifdef DEBUGBUILD
  FEATURE("Debug",       NULL,                CURL_VERSION_DEBUG),
#endif
#ifdef USE_GSASL
  FEATURE("gsasl",       NULL,                CURL_VERSION_GSASL),
#endif
#ifdef HAVE_GSSAPI
  FEATURE("GSS-API",     NULL,                CURL_VERSION_GSSAPI),
#endif
#ifndef CURL_DISABLE_HSTS
  FEATURE("HSTS",        NULL,                CURL_VERSION_HSTS),
#endif
#if defined(USE_NGHTTP2)
  FEATURE("HTTP2",       NULL,                CURL_VERSION_HTTP2),
#endif
#if defined(ENABLE_QUIC)
  FEATURE("HTTP3",       NULL,                CURL_VERSION_HTTP3),
#endif
#if defined(USE_SSL) && !defined(CURL_DISABLE_PROXY) && \
  !defined(CURL_DISABLE_HTTP)
  FEATURE("HTTPS-proxy", https_proxy_present, CURL_VERSION_HTTPS_PROXY),
#endif
#if defined(USE_LIBIDN2) || defined(USE_WIN32_IDN)
  FEATURE("IDN",         idn_present,         CURL_VERSION_IDN),
#endif
#ifdef ENABLE_IPV6
  FEATURE("IPv6",        NULL,                CURL_VERSION_IPV6),
#endif
#ifdef USE_KERBEROS5
  FEATURE("Kerberos",    NULL,                CURL_VERSION_KERBEROS5),
#endif
#if (SIZEOF_CURL_OFF_T > 4) && \
    ( (SIZEOF_OFF_T > 4) || defined(USE_WIN32_LARGE_FILES) )
  FEATURE("Largefile",   NULL,                CURL_VERSION_LARGEFILE),
#endif
#ifdef HAVE_LIBZ
  FEATURE("libz",        NULL,                CURL_VERSION_LIBZ),
#endif
#ifdef CURL_WITH_MULTI_SSL
  FEATURE("MultiSSL",    NULL,                CURL_VERSION_MULTI_SSL),
#endif
#ifdef USE_NTLM
  FEATURE("NTLM",        NULL,                CURL_VERSION_NTLM),
#endif
#if !defined(CURL_DISABLE_HTTP) && defined(USE_NTLM) && \
  defined(NTLM_WB_ENABLED)
  FEATURE("NTLM_WB",     NULL,                CURL_VERSION_NTLM_WB),
#endif
#if defined(USE_LIBPSL)
  FEATURE("PSL",         NULL,                CURL_VERSION_PSL),
#endif
#ifdef USE_SPNEGO
  FEATURE("SPNEGO",      NULL,                CURL_VERSION_SPNEGO),
#endif
#ifdef USE_SSL
  FEATURE("SSL",         NULL,                CURL_VERSION_SSL),
#endif
#ifdef USE_WINDOWS_SSPI
  FEATURE("SSPI",        NULL,                CURL_VERSION_SSPI),
#endif
#ifdef GLOBAL_INIT_IS_THREADSAFE
  FEATURE("threadsafe",  NULL,                CURL_VERSION_THREADSAFE),
#endif
#ifdef USE_TLS_SRP
  FEATURE("TLS-SRP",     NULL,                CURL_VERSION_TLSAUTH_SRP),
#endif
#ifdef CURLDEBUG
  FEATURE("TrackMemory", NULL,                CURL_VERSION_CURLDEBUG),
#endif
#if defined(_WIN32) && defined(UNICODE) && defined(_UNICODE)
  FEATURE("Unicode",     NULL,                CURL_VERSION_UNICODE),
#endif
#ifdef USE_UNIX_SOCKETS
  FEATURE("UnixSockets", NULL,                CURL_VERSION_UNIX_SOCKETS),
#endif
#ifdef HAVE_ZSTD
  FEATURE("zstd",        NULL,                CURL_VERSION_ZSTD),
#endif
  {NULL,             NULL,                0}
};

static const char *feature_names[sizeof(features_table) /
                                 sizeof(features_table[0])] = {NULL};


static curl_version_info_data version_info = {
  CURLVERSION_NOW,
  LIBCURL_VERSION,
  LIBCURL_VERSION_NUM,
  OS,   /* as found by configure or set by hand at build-time */
  0,    /* features bitmask is built at run-time */
  NULL, /* ssl_version */
  0,    /* ssl_version_num, this is kept at zero */
  NULL, /* zlib_version */
  supported_protocols,
  NULL, /* c-ares version */
  0,    /* c-ares version numerical */
  NULL, /* libidn version */
  0,    /* iconv version */
  NULL, /* ssh lib version */
  0,    /* brotli_ver_num */
  NULL, /* brotli version */
  0,    /* nghttp2 version number */
  NULL, /* nghttp2 version string */
  NULL, /* quic library string */
#ifdef CURL_CA_BUNDLE
  CURL_CA_BUNDLE, /* cainfo */
#else
  NULL,
#endif
#ifdef CURL_CA_PATH
  CURL_CA_PATH,  /* capath */
#else
  NULL,
#endif
  0,    /* zstd_ver_num */
  NULL, /* zstd version */
  NULL, /* Hyper version */
  NULL, /* gsasl version */
  feature_names
};

curl_version_info_data *curl_version_info(CURLversion stamp)
{
  size_t n;
  const struct feat *p;
  int features = 0;

#if defined(USE_SSH)
  static char ssh_buffer[80];
#endif
#ifdef USE_SSL
#ifdef CURL_WITH_MULTI_SSL
  static char ssl_buffer[200];
#else
  static char ssl_buffer[80];
#endif
#endif
#ifdef HAVE_BROTLI
  static char brotli_buffer[80];
#endif
#ifdef HAVE_ZSTD
  static char zstd_buffer[80];
#endif

  (void)stamp; /* avoid compiler warnings, we don't use this */

#ifdef USE_SSL
  Curl_ssl_version(ssl_buffer, sizeof(ssl_buffer));
  version_info.ssl_version = ssl_buffer;
#endif

#ifdef HAVE_LIBZ
  version_info.libz_version = zlibVersion();
  /* libz left NULL if non-existing */
#endif
#ifdef USE_ARES
  {
    int aresnum;
    version_info.ares = ares_version(&aresnum);
    version_info.ares_num = aresnum;
  }
#endif
#ifdef USE_LIBIDN2
  /* This returns a version string if we use the given version or later,
     otherwise it returns NULL */
  version_info.libidn = idn2_check_version(IDN2_VERSION);
#endif

#if defined(USE_SSH)
  Curl_ssh_version(ssh_buffer, sizeof(ssh_buffer));
  version_info.libssh_version = ssh_buffer;
#endif

#ifdef HAVE_BROTLI
  version_info.brotli_ver_num = BrotliDecoderVersion();
  brotli_version(brotli_buffer, sizeof(brotli_buffer));
  version_info.brotli_version = brotli_buffer;
#endif

#ifdef HAVE_ZSTD
  version_info.zstd_ver_num = (unsigned int)ZSTD_versionNumber();
  zstd_version(zstd_buffer, sizeof(zstd_buffer));
  version_info.zstd_version = zstd_buffer;
#endif

#ifdef USE_NGHTTP2
  {
    nghttp2_info *h2 = nghttp2_version(0);
    version_info.nghttp2_ver_num = h2->version_num;
    version_info.nghttp2_version = h2->version_str;
  }
#endif

#ifdef ENABLE_QUIC
  {
    static char quicbuffer[80];
    Curl_quic_ver(quicbuffer, sizeof(quicbuffer));
    version_info.quic_version = quicbuffer;
  }
#endif

#ifdef USE_HYPER
  {
    static char hyper_buffer[30];
    msnprintf(hyper_buffer, sizeof(hyper_buffer), "Hyper/%s", hyper_version());
    version_info.hyper_version = hyper_buffer;
  }
#endif

#ifdef USE_GSASL
  {
    version_info.gsasl_version = gsasl_check_version(NULL);
  }
#endif

  /* Get available features, build bitmask and names array. */
  n = 0;
  for(p = features_table; p->name; p++)
    if(!p->present || p->present(&version_info)) {
      features |= p->bitmask;
      feature_names[n++] = p->name;
    }

  feature_names[n] = NULL;  /* Terminate array. */
  version_info.features = features;

  return &version_info;
}
