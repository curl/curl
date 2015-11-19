/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#include <curl/curl.h>
#include "urldata.h"
#include "vtls/vtls.h"
#include "http2.h"
#include "curl_printf.h"

#ifdef USE_ARES
#  if defined(CURL_STATICLIB) && !defined(CARES_STATICLIB) && \
     (defined(WIN32) || defined(_WIN32) || defined(__SYMBIAN32__))
#    define CARES_STATICLIB
#  endif
#  include <ares.h>
#endif

#ifdef USE_LIBIDN
#include <stringprep.h>
#endif

#ifdef USE_LIBPSL
#include <libpsl.h>
#endif

#if defined(HAVE_ICONV) && defined(CURL_DOES_CONVERSIONS)
#include <iconv.h>
#endif

#ifdef USE_LIBRTMP
#include <librtmp/rtmp.h>
#endif

#ifdef USE_LIBSSH2
#include <libssh2.h>
#endif

#ifdef HAVE_LIBSSH2_VERSION
/* get it run-time if possible */
#define CURL_LIBSSH2_VERSION libssh2_version(0)
#else
/* use build-time if run-time not possible */
#define CURL_LIBSSH2_VERSION LIBSSH2_VERSION
#endif

char *curl_version(void)
{
  static char version[200];
  char *ptr = version;
  size_t len;
  size_t left = sizeof(version);

  strcpy(ptr, LIBCURL_NAME "/" LIBCURL_VERSION);
  len = strlen(ptr);
  left -= len;
  ptr += len;

  if(left > 1) {
    len = Curl_ssl_version(ptr + 1, left - 1);

    if(len > 0) {
      *ptr = ' ';
      left -= ++len;
      ptr += len;
    }
  }

#ifdef HAVE_LIBZ
  len = snprintf(ptr, left, " zlib/%s", zlibVersion());
  left -= len;
  ptr += len;
#endif
#ifdef USE_ARES
  /* this function is only present in c-ares, not in the original ares */
  len = snprintf(ptr, left, " c-ares/%s", ares_version(NULL));
  left -= len;
  ptr += len;
#endif
#ifdef USE_LIBIDN
  if(stringprep_check_version(LIBIDN_REQUIRED_VERSION)) {
    len = snprintf(ptr, left, " libidn/%s", stringprep_check_version(NULL));
    left -= len;
    ptr += len;
  }
#endif
#ifdef USE_LIBPSL
  len = snprintf(ptr, left, " libpsl/%s", psl_get_version());
  left -= len;
  ptr += len;
#endif
#ifdef USE_WIN32_IDN
  len = snprintf(ptr, left, " WinIDN");
  left -= len;
  ptr += len;
#endif
#if defined(HAVE_ICONV) && defined(CURL_DOES_CONVERSIONS)
#ifdef _LIBICONV_VERSION
  len = snprintf(ptr, left, " iconv/%d.%d",
                 _LIBICONV_VERSION >> 8, _LIBICONV_VERSION & 255);
#else
  /* version unknown */
  len = snprintf(ptr, left, " iconv");
#endif /* _LIBICONV_VERSION */
  left -= len;
  ptr += len;
#endif
#ifdef USE_LIBSSH2
  len = snprintf(ptr, left, " libssh2/%s", CURL_LIBSSH2_VERSION);
  left -= len;
  ptr += len;
#endif
#ifdef USE_NGHTTP2
  len = Curl_http2_ver(ptr, left);
  left -= len;
  ptr += len;
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

    snprintf(ptr, left, " librtmp/%d.%d%s",
             RTMP_LIB_VERSION >> 16, (RTMP_LIB_VERSION >> 8) & 0xff,
             suff);
/*
  If another lib version is added below this one, this code would
  also have to do:

    len = what snprintf() returned

    left -= len;
    ptr += len;
*/
  }
#endif

  return version;
}

/* data for curl_version_info

   Keep the list sorted alphabetically. It is also written so that each
   protocol line has its own #if line to make things easier on the eye.
 */

static const char * const protocols[] = {
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
#ifndef CURL_DISABLE_POP3
  "pop3",
#endif
#if defined(USE_SSL) && !defined(CURL_DISABLE_POP3)
  "pop3s",
#endif
#ifdef USE_LIBRTMP
  "rtmp",
#endif
#ifndef CURL_DISABLE_RTSP
  "rtsp",
#endif
#ifdef USE_LIBSSH2
  "scp",
#endif
#ifdef USE_LIBSSH2
  "sftp",
#endif
#if !defined(CURL_DISABLE_SMB) && defined(USE_NTLM) && \
   (CURL_SIZEOF_CURL_OFF_T > 4) && \
   (!defined(USE_WINDOWS_SSPI) || defined(USE_WIN32_CRYPTO))
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

  NULL
};

static curl_version_info_data version_info = {
  CURLVERSION_NOW,
  LIBCURL_VERSION,
  LIBCURL_VERSION_NUM,
  OS, /* as found by configure or set by hand at build-time */
  0 /* features is 0 by default */
#ifdef ENABLE_IPV6
  | CURL_VERSION_IPV6
#endif
#ifdef USE_SSL
  | CURL_VERSION_SSL
#endif
#ifdef USE_NTLM
  | CURL_VERSION_NTLM
#endif
#if !defined(CURL_DISABLE_HTTP) && defined(USE_NTLM) && \
  defined(NTLM_WB_ENABLED)
  | CURL_VERSION_NTLM_WB
#endif
#ifdef USE_SPNEGO
  | CURL_VERSION_SPNEGO
#endif
#ifdef USE_KERBEROS5
  | CURL_VERSION_KERBEROS5
#endif
#ifdef HAVE_GSSAPI
  | CURL_VERSION_GSSAPI
#endif
#ifdef USE_WINDOWS_SSPI
  | CURL_VERSION_SSPI
#endif
#ifdef HAVE_LIBZ
  | CURL_VERSION_LIBZ
#endif
#ifdef DEBUGBUILD
  | CURL_VERSION_DEBUG
#endif
#ifdef CURLDEBUG
  | CURL_VERSION_CURLDEBUG
#endif
#ifdef CURLRES_ASYNCH
  | CURL_VERSION_ASYNCHDNS
#endif
#if (CURL_SIZEOF_CURL_OFF_T > 4) && \
    ( (SIZEOF_OFF_T > 4) || defined(USE_WIN32_LARGE_FILES) )
  | CURL_VERSION_LARGEFILE
#endif
#if defined(CURL_DOES_CONVERSIONS)
  | CURL_VERSION_CONV
#endif
#if defined(USE_TLS_SRP)
  | CURL_VERSION_TLSAUTH_SRP
#endif
#if defined(USE_NGHTTP2)
  | CURL_VERSION_HTTP2
#endif
#if defined(USE_UNIX_SOCKETS)
  | CURL_VERSION_UNIX_SOCKETS
#endif
  ,
  NULL, /* ssl_version */
  0,    /* ssl_version_num, this is kept at zero */
  NULL, /* zlib_version */
  protocols,
  NULL, /* c-ares version */
  0,    /* c-ares version numerical */
  NULL, /* libidn version */
  0,    /* iconv version */
  NULL, /* ssh lib version */
};

curl_version_info_data *curl_version_info(CURLversion stamp)
{
#ifdef USE_LIBSSH2
  static char ssh_buffer[80];
#endif

#ifdef USE_SSL
  static char ssl_buffer[80];
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
#ifdef USE_LIBIDN
  /* This returns a version string if we use the given version or later,
     otherwise it returns NULL */
  version_info.libidn = stringprep_check_version(LIBIDN_REQUIRED_VERSION);
  if(version_info.libidn)
    version_info.features |= CURL_VERSION_IDN;
#elif defined(USE_WIN32_IDN)
  version_info.features |= CURL_VERSION_IDN;
#endif

#if defined(HAVE_ICONV) && defined(CURL_DOES_CONVERSIONS)
#ifdef _LIBICONV_VERSION
  version_info.iconv_ver_num = _LIBICONV_VERSION;
#else
  /* version unknown */
  version_info.iconv_ver_num = -1;
#endif /* _LIBICONV_VERSION */
#endif

#ifdef USE_LIBSSH2
  snprintf(ssh_buffer, sizeof(ssh_buffer), "libssh2/%s", LIBSSH2_VERSION);
  version_info.libssh_version = ssh_buffer;
#endif

  (void)stamp; /* avoid compiler warnings, we don't use this */

  return &version_info;
}
