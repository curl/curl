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
#include "curl_addrinfo.h"
#include "httpsrr.h"
#include "connect.h"

CURLcode Curl_httpsrr_decode_alpn(const unsigned char *cp, size_t len,
                                  unsigned char *alpns)
{
  /*
   * spec here is as per RFC 9460, section-7.1.1
   * encoding is a concatenated list of strings each preceded by a one
   * octet length
   * output is comma-sep list of the strings
   * implementations may or may not handle quoting of comma within
   * string values, so we might see a comma within the wire format
   * version of a string, in which case we will precede that by a
   * backslash - same goes for a backslash character, and of course
   * we need to use two backslashes in strings when we mean one;-)
   */
  struct dynbuf dval;
  int idnum = 0;

  Curl_dyn_init(&dval, DYN_DOH_RESPONSE);
  while(len > 0) {
    size_t tlen = (size_t) *cp++;
    size_t i;
    enum alpnid id;
    len--;
    if(tlen > len)
      goto err;
    /* add escape char if needed, clunky but easier to read */
    for(i = 0; i != tlen; i++) {
      if('\\' == *cp || ',' == *cp) {
        if(Curl_dyn_addn(&dval, "\\", 1))
          goto err;
      }
      if(Curl_dyn_addn(&dval, cp++, 1))
        goto err;
    }
    len -= tlen;

    /* we only store ALPN ids we know about */
    id = Curl_alpn2alpnid(Curl_dyn_ptr(&dval), Curl_dyn_len(&dval));
    if(id != ALPN_none) {
      if(idnum == MAX_HTTPSRR_ALPNS)
        break;
      alpns[idnum++] = (unsigned char)id;
    }
    Curl_dyn_reset(&dval);
  }
  Curl_dyn_free(&dval);
  if(idnum < MAX_HTTPSRR_ALPNS)
    alpns[idnum] = ALPN_none; /* terminate the list */
  return CURLE_OK;
err:
  Curl_dyn_free(&dval);
  return CURLE_BAD_CONTENT_ENCODING;
}

#endif
