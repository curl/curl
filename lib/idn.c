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

 /*
  * IDN conversions
  */

#include "curl_setup.h"
#include "urldata.h"
#include "idn.h"
#include "sendf.h"
#include "curl_multibyte.h"
#include "warnless.h"

#ifdef USE_LIBIDN2
#include <idn2.h>

#if defined(_WIN32) && defined(UNICODE)
#define IDN2_LOOKUP(name, host, flags)                                  \
  idn2_lookup_u8((const uint8_t *)name, (uint8_t **)host, flags)
#else
#define IDN2_LOOKUP(name, host, flags)                          \
  idn2_lookup_ul((const char *)name, (char **)host, flags)
#endif
#endif  /* USE_LIBIDN2 */

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* for macOS and iOS targets */
#if defined(USE_APPLE_IDN)
#include <unicode/uidna.h>
#include <iconv.h>
#include <langinfo.h>

#define MAX_HOST_LENGTH 512

static CURLcode iconv_to_utf8(const char *in, size_t inlen,
                              char **out, size_t *outlen)
{
  iconv_t cd = iconv_open("UTF-8", nl_langinfo(CODESET));
  if(cd != (iconv_t)-1) {
    size_t iconv_outlen = *outlen;
    char *iconv_in = (char *)in;
    size_t iconv_inlen = inlen;
    size_t iconv_result = iconv(cd, &iconv_in, &iconv_inlen,
                                out, &iconv_outlen);
    *outlen -= iconv_outlen;
    iconv_close(cd);
    if(iconv_result == (size_t)-1) {
      if(errno == ENOMEM)
        return CURLE_OUT_OF_MEMORY;
      else
        return CURLE_URL_MALFORMAT;
    }

    return CURLE_OK;
  }
  else {
    if(errno == ENOMEM)
      return CURLE_OUT_OF_MEMORY;
    else
      return CURLE_FAILED_INIT;
  }
}

static CURLcode mac_idn_to_ascii(const char *in, char **out)
{
  size_t inlen = strlen(in);
  if(inlen < MAX_HOST_LENGTH) {
    char iconv_buffer[MAX_HOST_LENGTH] = {0};
    char *iconv_outptr = iconv_buffer;
    size_t iconv_outlen = sizeof(iconv_buffer);
    CURLcode iconv_result = iconv_to_utf8(in, inlen,
                                          &iconv_outptr, &iconv_outlen);
    if(!iconv_result) {
      UErrorCode err = U_ZERO_ERROR;
      UIDNA* idna = uidna_openUTS46(
        UIDNA_CHECK_BIDI|UIDNA_NONTRANSITIONAL_TO_ASCII, &err);
      if(!U_FAILURE(err)) {
        UIDNAInfo info = UIDNA_INFO_INITIALIZER;
        char buffer[MAX_HOST_LENGTH] = {0};
        (void)uidna_nameToASCII_UTF8(idna, iconv_buffer, (int)iconv_outlen,
                                     buffer, sizeof(buffer) - 1, &info, &err);
        uidna_close(idna);
        if(!U_FAILURE(err) && !info.errors) {
          *out = strdup(buffer);
          if(*out)
            return CURLE_OK;
          else
            return CURLE_OUT_OF_MEMORY;
        }
      }
    }
    else
      return iconv_result;
  }
  return CURLE_URL_MALFORMAT;
}

static CURLcode mac_ascii_to_idn(const char *in, char **out)
{
  size_t inlen = strlen(in);
  if(inlen < MAX_HOST_LENGTH) {
    UErrorCode err = U_ZERO_ERROR;
    UIDNA* idna = uidna_openUTS46(
      UIDNA_CHECK_BIDI|UIDNA_NONTRANSITIONAL_TO_UNICODE, &err);
    if(!U_FAILURE(err)) {
      UIDNAInfo info = UIDNA_INFO_INITIALIZER;
      char buffer[MAX_HOST_LENGTH] = {0};
      (void)uidna_nameToUnicodeUTF8(idna, in, -1, buffer,
                                    sizeof(buffer) - 1, &info, &err);
      uidna_close(idna);
      if(!U_FAILURE(err)) {
        *out = strdup(buffer);
        if(*out)
          return CURLE_OK;
        else
          return CURLE_OUT_OF_MEMORY;
      }
    }
  }
  return CURLE_URL_MALFORMAT;
}
#endif

#ifdef USE_WIN32_IDN
/* using Windows kernel32 and normaliz libraries. */

#if (!defined(_WIN32_WINNT) || _WIN32_WINNT < 0x600) && \
  (!defined(WINVER) || WINVER < 0x600)
WINBASEAPI int WINAPI IdnToAscii(DWORD dwFlags,
                                 const WCHAR *lpUnicodeCharStr,
                                 int cchUnicodeChar,
                                 WCHAR *lpASCIICharStr,
                                 int cchASCIIChar);
WINBASEAPI int WINAPI IdnToUnicode(DWORD dwFlags,
                                   const WCHAR *lpASCIICharStr,
                                   int cchASCIIChar,
                                   WCHAR *lpUnicodeCharStr,
                                   int cchUnicodeChar);
#endif

#define IDN_MAX_LENGTH 255

static CURLcode win32_idn_to_ascii(const char *in, char **out)
{
  wchar_t *in_w = curlx_convert_UTF8_to_wchar(in);
  *out = NULL;
  if(in_w) {
    wchar_t punycode[IDN_MAX_LENGTH];
    int chars = IdnToAscii(0, in_w, (int)(wcslen(in_w) + 1), punycode,
                           IDN_MAX_LENGTH);
    curlx_unicodefree(in_w);
    if(chars) {
      char *mstr = curlx_convert_wchar_to_UTF8(punycode);
      if(mstr) {
        *out = strdup(mstr);
        curlx_unicodefree(mstr);
        if(!*out)
          return CURLE_OUT_OF_MEMORY;
      }
      else
        return CURLE_OUT_OF_MEMORY;
    }
    else
      return CURLE_URL_MALFORMAT;
  }
  else
    return CURLE_URL_MALFORMAT;

  return CURLE_OK;
}

static CURLcode win32_ascii_to_idn(const char *in, char **output)
{
  char *out = NULL;

  wchar_t *in_w = curlx_convert_UTF8_to_wchar(in);
  if(in_w) {
    WCHAR idn[IDN_MAX_LENGTH]; /* stores a UTF-16 string */
    int chars = IdnToUnicode(0, in_w, (int)(wcslen(in_w) + 1), idn,
                             IDN_MAX_LENGTH);
    if(chars) {
      /* 'chars' is "the number of characters retrieved" */
      char *mstr = curlx_convert_wchar_to_UTF8(idn);
      if(mstr) {
        out = strdup(mstr);
        curlx_unicodefree(mstr);
        if(!out)
          return CURLE_OUT_OF_MEMORY;
      }
    }
    else
      return CURLE_URL_MALFORMAT;
  }
  else
    return CURLE_URL_MALFORMAT;
  *output = out;
  return CURLE_OK;
}

#endif /* USE_WIN32_IDN */

/*
 * Helpers for IDNA conversions.
 */
bool Curl_is_ASCII_name(const char *hostname)
{
  /* get an UNSIGNED local version of the pointer */
  const unsigned char *ch = (const unsigned char *)hostname;

  if(!hostname) /* bad input, consider it ASCII! */
    return TRUE;

  while(*ch) {
    if(*ch++ & 0x80)
      return FALSE;
  }
  return TRUE;
}

#ifdef USE_IDN
/*
 * Curl_idn_decode() returns an allocated IDN decoded string if it was
 * possible. NULL on error.
 *
 * CURLE_URL_MALFORMAT - the hostname could not be converted
 * CURLE_OUT_OF_MEMORY - memory problem
 *
 */
static CURLcode idn_decode(const char *input, char **output)
{
  char *decoded = NULL;
  CURLcode result = CURLE_OK;
#ifdef USE_LIBIDN2
  if(idn2_check_version(IDN2_VERSION)) {
    int flags = IDN2_NFC_INPUT
#if IDN2_VERSION_NUMBER >= 0x00140000
      /* IDN2_NFC_INPUT: Normalize input string using normalization form C.
         IDN2_NONTRANSITIONAL: Perform Unicode TR46 non-transitional
         processing. */
      | IDN2_NONTRANSITIONAL
#endif
      ;
    int rc = IDN2_LOOKUP(input, &decoded, flags);
    if(rc != IDN2_OK)
      /* fallback to TR46 Transitional mode for better IDNA2003
         compatibility */
      rc = IDN2_LOOKUP(input, &decoded, IDN2_TRANSITIONAL);
    if(rc != IDN2_OK)
      result = CURLE_URL_MALFORMAT;
  }
  else
    /* a too old libidn2 version */
    result = CURLE_NOT_BUILT_IN;
#elif defined(USE_WIN32_IDN)
  result = win32_idn_to_ascii(input, &decoded);
#elif defined(USE_APPLE_IDN)
  result = mac_idn_to_ascii(input, &decoded);
#endif
  if(!result)
    *output = decoded;
  return result;
}

static CURLcode idn_encode(const char *puny, char **output)
{
  char *enc = NULL;
#ifdef USE_LIBIDN2
  int rc = idn2_to_unicode_8z8z(puny, &enc, 0);
  if(rc != IDNA_SUCCESS)
    return rc == IDNA_MALLOC_ERROR ? CURLE_OUT_OF_MEMORY : CURLE_URL_MALFORMAT;
#elif defined(USE_WIN32_IDN)
  CURLcode result = win32_ascii_to_idn(puny, &enc);
  if(result)
    return result;
#elif defined(USE_APPLE_IDN)
  CURLcode result = mac_ascii_to_idn(puny, &enc);
  if(result)
    return result;
#endif
  *output = enc;
  return CURLE_OK;
}

CURLcode Curl_idn_decode(const char *input, char **output)
{
  char *d = NULL;
  CURLcode result = idn_decode(input, &d);
#ifdef USE_LIBIDN2
  if(!result) {
    char *c = strdup(d);
    idn2_free(d);
    if(c)
      d = c;
    else
      result = CURLE_OUT_OF_MEMORY;
  }
#endif
  if(!result)
    *output = d;
  return result;
}

CURLcode Curl_idn_encode(const char *puny, char **output)
{
  char *d = NULL;
  CURLcode result = idn_encode(puny, &d);
#ifdef USE_LIBIDN2
  if(!result) {
    char *c = strdup(d);
    idn2_free(d);
    if(c)
      d = c;
    else
      result = CURLE_OUT_OF_MEMORY;
  }
#endif
  if(!result)
    *output = d;
  return result;
}

/*
 * Frees data allocated by idnconvert_hostname()
 */
void Curl_free_idnconverted_hostname(struct hostname *host)
{
  Curl_safefree(host->encalloc);
}

#endif /* USE_IDN */

/*
 * Perform any necessary IDN conversion of hostname
 */
CURLcode Curl_idnconvert_hostname(struct hostname *host)
{
  /* set the name we use to display the hostname */
  host->dispname = host->name;

#ifdef USE_IDN
  /* Check name for non-ASCII and convert hostname if we can */
  if(!Curl_is_ASCII_name(host->name)) {
    char *decoded;
    CURLcode result = Curl_idn_decode(host->name, &decoded);
    if(result)
      return result;
    /* successful */
    host->name = host->encalloc = decoded;
  }
#endif
  return CURLE_OK;
}
