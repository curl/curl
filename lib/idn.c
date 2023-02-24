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

#if defined(WIN32) && defined(UNICODE)
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

#ifdef USE_WIN32_IDN
/* using Windows kernel32 and normaliz libraries. */

#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x600
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

bool Curl_win32_idn_to_ascii(const char *in, char **out)
{
  bool success = FALSE;

  wchar_t *in_w = curlx_convert_UTF8_to_wchar(in);
  if(in_w) {
    wchar_t punycode[IDN_MAX_LENGTH];
    int chars = IdnToAscii(0, in_w, -1, punycode, IDN_MAX_LENGTH);
    curlx_unicodefree(in_w);
    if(chars) {
      char *mstr = curlx_convert_wchar_to_UTF8(punycode);
      if(mstr) {
        *out = strdup(mstr);
        curlx_unicodefree(mstr);
        if(*out)
          success = TRUE;
      }
    }
  }

  return success;
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
 */
static char *idn_decode(const char *input)
{
  char *decoded = NULL;
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
      decoded = NULL;
  }
#elif defined(USE_WIN32_IDN)
  if(!Curl_win32_idn_to_ascii(input, &decoded))
    decoded = NULL;
#endif
  return decoded;
}

char *Curl_idn_decode(const char *input)
{
  char *d = idn_decode(input);
#ifdef USE_LIBIDN2
  if(d) {
    char *c = strdup(d);
    idn2_free(d);
    d = c;
  }
#endif
  return d;
}

/*
 * Frees data allocated by idnconvert_hostname()
 */
void Curl_free_idnconverted_hostname(struct hostname *host)
{
  if(host->encalloc) {
    /* must be freed with idn2_free() if allocated by libidn */
    Curl_idn_free(host->encalloc);
    host->encalloc = NULL;
  }
}

#endif /* USE_IDN */

/*
 * Perform any necessary IDN conversion of hostname
 */
CURLcode Curl_idnconvert_hostname(struct hostname *host)
{
  /* set the name we use to display the host name */
  host->dispname = host->name;

#ifdef USE_IDN
  /* Check name for non-ASCII and convert hostname if we can */
  if(!Curl_is_ASCII_name(host->name)) {
    char *decoded = idn_decode(host->name);
    if(decoded) {
      if(!*decoded) {
        /* zero length is a bad host name */
        Curl_idn_free(decoded);
        return CURLE_URL_MALFORMAT;
      }
      /* successful */
      host->encalloc = decoded;
      /* change the name pointer to point to the encoded hostname */
      host->name = host->encalloc;
    }
    else
      return CURLE_URL_MALFORMAT;
  }
#endif
  return CURLE_OK;
}
