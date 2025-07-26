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

#if !defined(CURL_DISABLE_HTTP) && defined(USE_NTLM)

/*
 * NTLM details:
 *
 * https://davenport.sourceforge.net/ntlm.html
 * https://www.innovation.ch/java/ntlm.html
 */

#include "urldata.h"
#include "sendf.h"
#include "strcase.h"
#include "http_ntlm.h"
#include "curl_ntlm_core.h"
#include "curlx/base64.h"
#include "vauth/vauth.h"
#include "url.h"
#include "curlx/strparse.h"

/* SSL backend-specific #if branches in this file must be kept in the order
   documented in curl_ntlm_core. */
#ifdef USE_WINDOWS_SSPI
#include "curl_sspi.h"
#endif

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

CURLcode Curl_input_ntlm(struct Curl_easy *data,
                         bool proxy,         /* if proxy or not */
                         const char *header) /* rest of the www-authenticate:
                                                header */
{
  /* point to the correct struct with this */
  curlntlm *state;
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;

  state = proxy ? &conn->proxy_ntlm_state : &conn->http_ntlm_state;

  if(checkprefix("NTLM", header)) {
    struct ntlmdata *ntlm = Curl_auth_ntlm_get(conn, proxy);
    if(!ntlm)
      return CURLE_FAILED_INIT;

    header += strlen("NTLM");
    curlx_str_passblanks(&header);
    if(*header) {
      unsigned char *hdr;
      size_t hdrlen;

      result = curlx_base64_decode(header, &hdr, &hdrlen);
      if(!result) {
        struct bufref hdrbuf;

        Curl_bufref_init(&hdrbuf);
        Curl_bufref_set(&hdrbuf, hdr, hdrlen, curl_free);
        result = Curl_auth_decode_ntlm_type2_message(data, &hdrbuf, ntlm);
        Curl_bufref_free(&hdrbuf);
      }
      if(result)
        return result;

      *state = NTLMSTATE_TYPE2; /* We got a type-2 message */
    }
    else {
      if(*state == NTLMSTATE_LAST) {
        infof(data, "NTLM auth restarted");
        Curl_auth_ntlm_remove(conn, proxy);
      }
      else if(*state == NTLMSTATE_TYPE3) {
        infof(data, "NTLM handshake rejected");
        Curl_auth_ntlm_remove(conn, proxy);
        *state = NTLMSTATE_NONE;
        return CURLE_REMOTE_ACCESS_DENIED;
      }
      else if(*state >= NTLMSTATE_TYPE1) {
        infof(data, "NTLM handshake failure (internal error)");
        return CURLE_REMOTE_ACCESS_DENIED;
      }

      *state = NTLMSTATE_TYPE1; /* We should send away a type-1 */
    }
  }

  return result;
}

/*
 * This is for creating NTLM header output
 */
CURLcode Curl_output_ntlm(struct Curl_easy *data, bool proxy)
{
  char *base64 = NULL;
  size_t len = 0;
  CURLcode result = CURLE_OK;
  struct bufref ntlmmsg;

  /* point to the address of the pointer that holds the string to send to the
     server, which is for a plain host or for an HTTP proxy */
  char **allocuserpwd;

  /* point to the username, password, service and host */
  const char *userp;
  const char *passwdp;
  const char *service = NULL;
  const char *hostname = NULL;

  /* point to the correct struct with this */
  struct ntlmdata *ntlm;
  curlntlm *state;
  struct auth *authp;
  struct connectdata *conn = data->conn;

  DEBUGASSERT(conn);
  DEBUGASSERT(data);

  if(proxy) {
#ifndef CURL_DISABLE_PROXY
    allocuserpwd = &data->state.aptr.proxyuserpwd;
    userp = data->state.aptr.proxyuser;
    passwdp = data->state.aptr.proxypasswd;
    service = data->set.str[STRING_PROXY_SERVICE_NAME] ?
      data->set.str[STRING_PROXY_SERVICE_NAME] : "HTTP";
    hostname = conn->http_proxy.host.name;
    state = &conn->proxy_ntlm_state;
    authp = &data->state.authproxy;
#else
    return CURLE_NOT_BUILT_IN;
#endif
  }
  else {
    allocuserpwd = &data->state.aptr.userpwd;
    userp = data->state.aptr.user;
    passwdp = data->state.aptr.passwd;
    service = data->set.str[STRING_SERVICE_NAME] ?
      data->set.str[STRING_SERVICE_NAME] : "HTTP";
    hostname = conn->host.name;
    state = &conn->http_ntlm_state;
    authp = &data->state.authhost;
  }
  ntlm = Curl_auth_ntlm_get(conn, proxy);
  if(!ntlm)
    return CURLE_OUT_OF_MEMORY;
  authp->done = FALSE;

  /* not set means empty */
  if(!userp)
    userp = "";

  if(!passwdp)
    passwdp = "";

#ifdef USE_WINDOWS_SSPI
  if(!Curl_pSecFn) {
    /* not thread safe and leaks - use curl_global_init() to avoid */
    CURLcode err = Curl_sspi_global_init();
    if(!Curl_pSecFn)
      return err;
  }
#ifdef SECPKG_ATTR_ENDPOINT_BINDINGS
  ntlm->sslContext = conn->sslContext;
#endif
#endif

  Curl_bufref_init(&ntlmmsg);

  /* connection is already authenticated, do not send a header in future
   * requests so go directly to NTLMSTATE_LAST */
  if(*state == NTLMSTATE_TYPE3)
    *state = NTLMSTATE_LAST;

  switch(*state) {
  case NTLMSTATE_TYPE1:
  default: /* for the weird cases we (re)start here */
    /* Create a type-1 message */
    result = Curl_auth_create_ntlm_type1_message(data, userp, passwdp, service,
                                                 hostname, ntlm, &ntlmmsg);
    if(!result) {
      DEBUGASSERT(Curl_bufref_len(&ntlmmsg) != 0);
      result = curlx_base64_encode((const char *) Curl_bufref_ptr(&ntlmmsg),
                                  Curl_bufref_len(&ntlmmsg), &base64, &len);
      if(!result) {
        free(*allocuserpwd);
        *allocuserpwd = aprintf("%sAuthorization: NTLM %s\r\n",
                                proxy ? "Proxy-" : "",
                                base64);
        free(base64);
        if(!*allocuserpwd)
          result = CURLE_OUT_OF_MEMORY;
      }
    }
    break;

  case NTLMSTATE_TYPE2:
    /* We already received the type-2 message, create a type-3 message */
    result = Curl_auth_create_ntlm_type3_message(data, userp, passwdp,
                                                 ntlm, &ntlmmsg);
    if(!result && Curl_bufref_len(&ntlmmsg)) {
      result = curlx_base64_encode((const char *) Curl_bufref_ptr(&ntlmmsg),
                                   Curl_bufref_len(&ntlmmsg), &base64, &len);
      if(!result) {
        free(*allocuserpwd);
        *allocuserpwd = aprintf("%sAuthorization: NTLM %s\r\n",
                                proxy ? "Proxy-" : "",
                                base64);
        free(base64);
        if(!*allocuserpwd)
          result = CURLE_OUT_OF_MEMORY;
        else {
          *state = NTLMSTATE_TYPE3; /* we send a type-3 */
          authp->done = TRUE;
        }
      }
    }
    break;

  case NTLMSTATE_LAST:
    /* since this is a little artificial in that this is used without any
       outgoing auth headers being set, we need to set the bit by force */
    if(proxy)
      data->info.proxyauthpicked = CURLAUTH_NTLM;
    else
      data->info.httpauthpicked = CURLAUTH_NTLM;
    Curl_safefree(*allocuserpwd);
    authp->done = TRUE;
    break;
  }
  Curl_bufref_free(&ntlmmsg);

  return result;
}

#endif /* !CURL_DISABLE_HTTP && USE_NTLM */
