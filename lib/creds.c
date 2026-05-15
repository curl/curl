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

#include <stddef.h>  /* for offsetof() */

#include "creds.h"
#include "curl_trc.h"
#include "strcase.h"
#include "urldata.h"


CURLcode Curl_creds_create(const char *user,
                           const char *passwd,
                           const char *oauth_bearer,
                           const char *sasl_authzid,
                           const char *sasl_service,
                           uint8_t source,
                           struct Curl_creds **pcreds)
{
  struct Curl_creds *creds = NULL;
  size_t ulen = user ? strlen(user) : 0;
  size_t plen = passwd ? strlen(passwd) : 0;
  size_t olen = oauth_bearer ? strlen(oauth_bearer) : 0;
  size_t salen = sasl_authzid ? strlen(sasl_authzid) : 0;
  size_t sslen = sasl_service ? strlen(sasl_service) : 0;
  char *s, *buf;
  CURLcode result = CURLE_OK;

  Curl_creds_unlink(pcreds);

  /* Everything empty/NULL, this is the NULL credential */
  if(!ulen && !plen && !olen && !salen && !sslen)
    goto out;

  if((ulen > CURL_MAX_INPUT_LENGTH) ||
     (plen > CURL_MAX_INPUT_LENGTH) ||
     (olen > CURL_MAX_INPUT_LENGTH) ||
     (salen > CURL_MAX_INPUT_LENGTH) ||
     (sslen > CURL_MAX_INPUT_LENGTH)) {
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto out;
  }

  /* null-terminator for user already part of struct */
  creds = curlx_calloc(1, sizeof(*creds) +
                       ulen + plen + 1 + olen + 1 + salen + 1 + sslen + 1);
  if(!creds) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  creds->refcount = 1;
  creds->source = source;
  /* Some compilers try to be too smart about our dynamic struct size */
  buf = ((char *)creds) + offsetof(struct Curl_creds, buf);
  creds->user = s = buf;
  if(ulen)
    memcpy(s, user, ulen + 1);
  creds->passwd = s = buf + ulen + 1;
  if(plen)
    memcpy(s, passwd, plen + 1);
  creds->oauth_bearer = s = buf + ulen + 1 + plen + 1;
  if(olen)
    memcpy(s, oauth_bearer, olen + 1);
  creds->sasl_authzid = s = buf + ulen + 1 + plen + 1 + olen + 1;
  if(salen)
    memcpy(s, sasl_authzid, salen + 1);
  creds->sasl_service = s = buf + ulen + 1 + plen + 1 + olen + 1 + salen + 1;
  if(sslen)
    memcpy(s, sasl_service, sslen + 1);

out:
  if(!result)
    *pcreds = creds;
  else
    Curl_creds_unlink(&creds);
  return result;
}

CURLcode Curl_creds_merge(const char *user,
                          const char *passwd,
                          struct Curl_creds *creds_in,
                          uint8_t source,
                          struct Curl_creds **pcreds_out)
{
  struct Curl_creds *creds_out = NULL;
  CURLcode result;

  if(!user || !user[0])
    user = Curl_creds_user(creds_in);
  if(!passwd || !passwd[0])
    passwd = Curl_creds_passwd(creds_in);
  result = Curl_creds_create(user, passwd,
                             Curl_creds_oauth_bearer(creds_in),
                             Curl_creds_sasl_authzid(creds_in),
                             Curl_creds_sasl_service(creds_in),
                             source, &creds_out);
  Curl_creds_link(pcreds_out, creds_out);
  Curl_creds_unlink(&creds_out);
  return result;
}

void Curl_creds_link(struct Curl_creds **pdest, struct Curl_creds *src)
{
  if(*pdest != src) {
    Curl_creds_unlink(pdest);
    *pdest = src;
    if(src) {
      DEBUGASSERT(src->refcount < UINT32_MAX);
      src->refcount++;
    }
  }
}

void Curl_creds_unlink(struct Curl_creds **pcreds)
{
  if(*pcreds) {
    struct Curl_creds *creds = *pcreds;

    DEBUGASSERT(creds->refcount);
    *pcreds = NULL;
    if(creds->refcount)
      creds->refcount--;
    if(!creds->refcount) {
      curlx_free(creds);
    }
  }
}

bool Curl_creds_same_user(struct Curl_creds *creds, const char *user)
{
  return creds && !Curl_timestrcmp(creds->user, user);
}

bool Curl_creds_same_passwd(struct Curl_creds *creds, const char *passwd)
{
  return creds && !Curl_timestrcmp(creds->passwd, passwd);
}

bool Curl_creds_same(struct Curl_creds *c1, struct Curl_creds *c2)
{
  return (c1 == c2) ||
         (c1 && c2 &&
          !Curl_timestrcmp(c1->user, c2->user) &&
          !Curl_timestrcmp(c1->passwd, c2->passwd) &&
          !Curl_timestrcmp(c1->oauth_bearer, c2->oauth_bearer) &&
          !Curl_timestrcmp(c1->sasl_authzid, c2->sasl_authzid) &&
          !Curl_timestrcmp(c1->sasl_service, c2->sasl_service));
}

#ifdef CURLVERBOSE
void Curl_creds_trace(struct Curl_easy *data, struct Curl_creds *creds,
                      const char *msg)
{
  if(creds) {
    CURL_TRC_M(data, "%s: user=%s, passwd=%s, "
               "sasl_authzid=%s, oauth_bearer=%s, source=%d",
               msg,
               Curl_creds_user(creds),
               Curl_creds_has_passwd(creds) ? "***" : "",
               Curl_creds_sasl_authzid(creds),
               Curl_creds_oauth_bearer(creds),
               creds->source);
  }
  else
    CURL_TRC_M(data, "%s: -", msg);
}
#endif
