/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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

#if !defined(CURL_DISABLE_HTTP) && defined(USE_NTLM)

/*
 * NTLM details:
 *
 * https://davenport.sourceforge.io/ntlm.html
 * https://www.innovation.ch/java/ntlm.html
 */

#define DEBUG_ME 0

#include "urldata.h"
#include "sendf.h"
#include "strcase.h"
#include "http_ntlm.h"
#include "curl_ntlm_core.h"
#include "curl_ntlm_wb.h"
#include "vauth/vauth.h"
#include "url.h"

/* SSL backend-specific #if branches in this file must be kept in the order
   documented in curl_ntlm_core. */
#if defined(USE_WINDOWS_SSPI)
#include "curl_sspi.h"
#endif

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#if DEBUG_ME
# define DEBUG_OUT(x) x
#else
# define DEBUG_OUT(x) Curl_nop_stmt
#endif

CURLcode Curl_input_ntlm(struct connectdata *conn,
                         bool proxy,         /* if proxy or not */
                         const char *header) /* rest of the www-authenticate:
                                                header */
{
  /* point to the correct struct with this */
  struct ntlmdata *ntlm;
  curlntlm *state;
  CURLcode result = CURLE_OK;

  ntlm = proxy ? &conn->proxyntlm : &conn->ntlm;
  state = proxy ? &conn->proxy_ntlm_state : &conn->http_ntlm_state;

  if(checkprefix("NTLM", header)) {
    header += strlen("NTLM");

    while(*header && ISSPACE(*header))
      header++;

    if(*header) {
      result = Curl_auth_decode_ntlm_type2_message(conn->data, header, ntlm);
      if(result)
        return result;

      *state = NTLMSTATE_TYPE2; /* We got a type-2 message */
    }
    else {
      if(*state == NTLMSTATE_LAST) {
        infof(conn->data, "NTLM auth restarted\n");
        Curl_http_auth_cleanup_ntlm(conn);
      }
      else if(*state == NTLMSTATE_TYPE3) {
        infof(conn->data, "NTLM handshake rejected\n");
        Curl_http_auth_cleanup_ntlm(conn);
        *state = NTLMSTATE_NONE;
        return CURLE_REMOTE_ACCESS_DENIED;
      }
      else if(*state >= NTLMSTATE_TYPE1) {
        infof(conn->data, "NTLM handshake failure (internal error)\n");
        return CURLE_REMOTE_ACCESS_DENIED;
      }

      *state = NTLMSTATE_TYPE1; /* We should send away a type-1 */
    }
  }

  return result;
}

/*
 * This is for creating ntlm header output
 */
CURLcode Curl_output_ntlm(struct connectdata *conn, bool proxy)
{
  char *base64 = NULL;
  size_t len = 0;
  CURLcode result;

  /* point to the address of the pointer that holds the string to send to the
     server, which is for a plain host or for a HTTP proxy */
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

  DEBUGASSERT(conn);
  DEBUGASSERT(conn->data);

  if(proxy) {
    allocuserpwd = &conn->allocptr.proxyuserpwd;
    userp = conn->http_proxy.user;
    passwdp = conn->http_proxy.passwd;
    service = conn->data->set.str[STRING_PROXY_SERVICE_NAME] ?
              conn->data->set.str[STRING_PROXY_SERVICE_NAME] : "HTTP";
    hostname = conn->http_proxy.host.name;
    ntlm = &conn->proxyntlm;
    state = &conn->proxy_ntlm_state;
    authp = &conn->data->state.authproxy;
  }
  else {
    allocuserpwd = &conn->allocptr.userpwd;
    userp = conn->user;
    passwdp = conn->passwd;
    service = conn->data->set.str[STRING_SERVICE_NAME] ?
              conn->data->set.str[STRING_SERVICE_NAME] : "HTTP";
    hostname = conn->host.name;
    ntlm = &conn->ntlm;
    state = &conn->http_ntlm_state;
    authp = &conn->data->state.authhost;
  }
  authp->done = FALSE;

  /* not set means empty */
  if(!userp)
    userp = "";

  if(!passwdp)
    passwdp = "";

#ifdef USE_WINDOWS_SSPI
  if(s_hSecDll == NULL) {
    /* not thread safe and leaks - use curl_global_init() to avoid */
    CURLcode err = Curl_sspi_global_init();
    if(s_hSecDll == NULL)
      return err;
  }
#ifdef SECPKG_ATTR_ENDPOINT_BINDINGS
  ntlm->sslContext = conn->sslContext;
#endif
#endif

  switch(*state) {
  case NTLMSTATE_TYPE1:
  default: /* for the weird cases we (re)start here */
    /* Create a type-1 message */
    result = Curl_auth_create_ntlm_type1_message(conn->data, userp, passwdp,
                                                 service, hostname,
                                                 ntlm, &base64,
                                                 &len);
    if(result)
      return result;

    if(base64) {
      free(*allocuserpwd);
      *allocuserpwd = aprintf("%sAuthorization: NTLM %s\r\n",
                              proxy ? "Proxy-" : "",
                              base64);
      free(base64);
      if(!*allocuserpwd)
        return CURLE_OUT_OF_MEMORY;

      DEBUG_OUT(fprintf(stderr, "**** Header %s\n ", *allocuserpwd));
    }
    break;

  case NTLMSTATE_TYPE2:
    /* We already received the type-2 message, create a type-3 message */
    result = Curl_auth_create_ntlm_type3_message(conn->data, userp, passwdp,
                                                 ntlm, &base64, &len);
    if(result)
      return result;

    if(base64) {
      free(*allocuserpwd);
      *allocuserpwd = aprintf("%sAuthorization: NTLM %s\r\n",
                              proxy ? "Proxy-" : "",
                              base64);
      free(base64);
      if(!*allocuserpwd)
        return CURLE_OUT_OF_MEMORY;

      DEBUG_OUT(fprintf(stderr, "**** %s\n ", *allocuserpwd));

      *state = NTLMSTATE_TYPE3; /* we send a type-3 */
      authp->done = TRUE;
    }
    break;

  case NTLMSTATE_TYPE3:
    /* connection is already authenticated,
     * don't send a header in future requests */
    *state = NTLMSTATE_LAST;
    /* FALLTHROUGH */
  case NTLMSTATE_LAST:
    Curl_safefree(*allocuserpwd);
    authp->done = TRUE;
    break;
  }

  return CURLE_OK;
}

void Curl_http_auth_cleanup_ntlm(struct connectdata *conn)
{
  Curl_auth_cleanup_ntlm(&conn->ntlm);
  Curl_auth_cleanup_ntlm(&conn->proxyntlm);

#if defined(NTLM_WB_ENABLED)
  Curl_http_auth_cleanup_ntlm_wb(conn);
#endif
}

#endif /* !CURL_DISABLE_HTTP && USE_NTLM */
