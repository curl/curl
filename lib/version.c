/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#define _MPRINTF_REPLACE /* use the internal *printf() functions */
#include <curl/mprintf.h>

#ifdef USE_ARES
#include <ares_version.h>
#endif

#ifdef USE_LIBIDN
#include <stringprep.h>
#endif

#ifdef USE_SSLEAY
static int getssl_version(char *ptr, size_t left, long *num)
{

#if (SSLEAY_VERSION_NUMBER >= 0x905000)
  {
    char sub[2];
    unsigned long ssleay_value;
    sub[1]='\0';
    ssleay_value=SSLeay();
    *num = (long)ssleay_value;
    if(ssleay_value < 0x906000) {
      ssleay_value=SSLEAY_VERSION_NUMBER;
      sub[0]='\0';
    }
    else {
      if(ssleay_value&0xff0) {
        sub[0]=(char)((ssleay_value>>4)&0xff) + 'a' -1;
      }
      else
        sub[0]='\0';
    }

    return snprintf(ptr, left, " OpenSSL/%lx.%lx.%lx%s",
                    (ssleay_value>>28)&0xf,
                    (ssleay_value>>20)&0xff,
                    (ssleay_value>>12)&0xff,
                    sub);
  }

#else
  *num = SSLEAY_VERSION_NUMBER;
#if (SSLEAY_VERSION_NUMBER >= 0x900000)
  return snprintf(ptr, left, " OpenSSL/%lx.%lx.%lx",
                  (SSLEAY_VERSION_NUMBER>>28)&0xff,
                  (SSLEAY_VERSION_NUMBER>>20)&0xff,
                  (SSLEAY_VERSION_NUMBER>>12)&0xf);
#else
  {
    char sub[2];
    sub[1]='\0';
    if(SSLEAY_VERSION_NUMBER&0x0f) {
      sub[0]=(SSLEAY_VERSION_NUMBER&0x0f) + 'a' -1;
    }
    else
      sub[0]='\0';

    return snprintf(ptr, left, " SSL/%x.%x.%x%s",
                    (SSLEAY_VERSION_NUMBER>>12)&0xff,
                    (SSLEAY_VERSION_NUMBER>>8)&0xf,
                    (SSLEAY_VERSION_NUMBER>>4)&0xf, sub);
  }
#endif
#endif
}

#endif

char *curl_version(void)
{
  static char version[200];
  char *ptr=version;
  /* to prevent compier warnings, we only declare len if we have code
     that uses it */
#if defined(USE_SSLEAY) || defined(HAVE_LIBZ) || defined(USE_ARES) || \
  defined(USE_LIBIDN)
  int len;
#endif
  size_t left = sizeof(version);
  strcpy(ptr, LIBCURL_NAME "/" LIBCURL_VERSION );
  ptr=strchr(ptr, '\0');
  left -= strlen(ptr);

#ifdef USE_SSLEAY
  {
    long num;
    len = getssl_version(ptr, left, &num);
    left -= len;
    ptr += len;
  }
#endif

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

  return version;
}

/* data for curl_version_info */

static const char * const protocols[] = {
#ifndef CURL_DISABLE_FTP
  "ftp",
#endif
#ifndef CURL_DISABLE_GOPHER
  "gopher",
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

#ifdef USE_SSLEAY
#ifndef CURL_DISABLE_HTTP
  "https",
#endif
#ifndef CURL_DISABLE_FTP
  "ftps",
#endif
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
#ifdef USE_SSLEAY
  | CURL_VERSION_SSL
  | CURL_VERSION_NTLM /* since this requires OpenSSL */
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
  ,
  NULL, /* ssl_version */
  0,    /* ssl_version_num */
  NULL, /* zlib_version */
  protocols,
  NULL, /* c-ares version */
  0,    /* c-ares version numerical */
  NULL, /* libidn version */
};

curl_version_info_data *curl_version_info(CURLversion stamp)
{
#ifdef USE_SSLEAY
  static char ssl_buffer[80];
  long num;
  getssl_version(ssl_buffer, sizeof(ssl_buffer), &num);

  version_info.ssl_version = ssl_buffer;
  version_info.ssl_version_num = num;
  /* SSL stuff is left zero if undefined */
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
  (void)stamp; /* avoid compiler warnings, we don't use this */

  return &version_info;
}
