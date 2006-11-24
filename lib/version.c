/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

#include "setup.h"

#include <string.h>
#include <stdio.h>

#include <curl/curl.h>
#include "urldata.h"
#include "sslgen.h"

#define _MPRINTF_REPLACE /* use the internal *printf() functions */
#include <curl/mprintf.h>

#ifdef USE_ARES
#include <ares_version.h>
#endif

#ifdef USE_LIBIDN
#include <stringprep.h>
#endif

#if defined(HAVE_ICONV) && defined(CURL_DOES_CONVERSIONS)
#include <iconv.h>
#endif

#ifdef USE_LIBSSH2
#include <libssh2.h>
#endif


char *curl_version(void)
{
  static char version[200];
  char *ptr=version;
  size_t len;
  size_t left = sizeof(version);
  strcpy(ptr, LIBCURL_NAME "/" LIBCURL_VERSION );
  ptr=strchr(ptr, '\0');
  left -= strlen(ptr);

  len = Curl_ssl_version(ptr, left);
  left -= len;
  ptr += len;

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
  len = snprintf(ptr, left, " libssh2/%s", LIBSSH2_VERSION);
  left -= len;
  ptr += len;
#endif

  return version;
}

/* data for curl_version_info */

static const char * const protocols[] = {
#ifndef CURL_DISABLE_TFTP
  "tftp",
#endif
#ifndef CURL_DISABLE_FTP
  "ftp",
#endif
#ifndef CURL_DISABLE_TELNET
  "telnet",
#endif
#ifndef CURL_DISABLE_DICT
  "dict",
#endif
#ifndef CURL_DISABLE_LDAP
  "ldap",
#endif
#ifndef CURL_DISABLE_HTTP
  "http",
#endif
#ifndef CURL_DISABLE_FILE
  "file",
#endif

#ifdef USE_SSL
#ifndef CURL_DISABLE_HTTP
  "https",
#endif
#ifndef CURL_DISABLE_FTP
  "ftps",
#endif
#endif

#ifdef USE_LIBSSH2
  "scp",
  "sftp",
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
#ifdef HAVE_KRB4
  | CURL_VERSION_KERBEROS4
#endif
#ifdef USE_SSL
  | CURL_VERSION_SSL
#endif
#ifdef USE_NTLM
  | CURL_VERSION_NTLM
#endif
#ifdef USE_WINDOWS_SSPI
  | CURL_VERSION_SSPI
#endif
#ifdef HAVE_LIBZ
  | CURL_VERSION_LIBZ
#endif
#ifdef HAVE_GSSAPI
  | CURL_VERSION_GSSNEGOTIATE
#endif
#ifdef CURLDEBUG
  | CURL_VERSION_DEBUG
#endif
#ifdef USE_ARES
  | CURL_VERSION_ASYNCHDNS
#endif
#ifdef HAVE_SPNEGO
  | CURL_VERSION_SPNEGO
#endif
#if defined(ENABLE_64BIT) && (SIZEOF_CURL_OFF_T > 4)
  | CURL_VERSION_LARGEFILE
#endif
#if defined(CURL_DOES_CONVERSIONS)
  | CURL_VERSION_CONV
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
