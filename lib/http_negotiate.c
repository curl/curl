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

#if !defined(CURL_DISABLE_HTTP) && defined(USE_SPNEGO)

#include "urldata.h"
#include "cfilters.h"
#include "sendf.h"
#include "http_negotiate.h"
#include "vauth/vauth.h"
#include "vtls/vtls.h"
#include "curlx/strparse.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


static void http_auth_nego_reset(struct connectdata *conn,
                                 struct negotiatedata *neg_ctx,
                                 bool proxy)
{
  if(proxy)
    conn->proxy_negotiate_state = GSS_AUTHNONE;
  else
    conn->http_negotiate_state = GSS_AUTHNONE;
  if(neg_ctx)
    Curl_auth_cleanup_spnego(neg_ctx);
}


CURLcode Curl_input_negotiate(struct Curl_easy *data, struct connectdata *conn,
                              bool proxy, const char *header)
{
  CURLcode result;
  size_t len;

  /* Point to the username, password, service and host */
  const char *userp;
  const char *passwdp;
  const char *service;
  const char *host;

  /* Point to the correct struct with this */
  struct negotiatedata *neg_ctx;
  curlnegotiate state;

  if(proxy) {
#ifndef CURL_DISABLE_PROXY
    userp = conn->http_proxy.user;
    passwdp = conn->http_proxy.passwd;
    service = data->set.str[STRING_PROXY_SERVICE_NAME] ?
              data->set.str[STRING_PROXY_SERVICE_NAME] : "HTTP";
    host = conn->http_proxy.host.name;
    state = conn->proxy_negotiate_state;
#else
    return CURLE_NOT_BUILT_IN;
#endif
  }
  else {
    userp = conn->user;
    passwdp = conn->passwd;
    service = data->set.str[STRING_SERVICE_NAME] ?
              data->set.str[STRING_SERVICE_NAME] : "HTTP";
    host = conn->host.name;
    state = conn->http_negotiate_state;
  }

  neg_ctx = Curl_auth_nego_get(conn, proxy);
  if(!neg_ctx)
    return CURLE_OUT_OF_MEMORY;

  /* Not set means empty */
  if(!userp)
    userp = "";

  if(!passwdp)
    passwdp = "";

  /* Obtain the input token, if any */
  header += strlen("Negotiate");
  curlx_str_passblanks(&header);

  len = strlen(header);
  neg_ctx->havenegdata = len != 0;
  if(!len) {
    if(state == GSS_AUTHSUCC) {
      infof(data, "Negotiate auth restarted");
      http_auth_nego_reset(conn, neg_ctx, proxy);
    }
    else if(state != GSS_AUTHNONE) {
      /* The server rejected our authentication and has not supplied any more
      negotiation mechanisms */
      http_auth_nego_reset(conn, neg_ctx, proxy);
      return CURLE_LOGIN_DENIED;
    }
  }

  /* Supports SSL channel binding for Windows ISS extended protection */
#if defined(USE_WINDOWS_SSPI) && defined(SECPKG_ATTR_ENDPOINT_BINDINGS)
  neg_ctx->sslContext = conn->sslContext;
#endif
  /* Check if the connection is using SSL and get the channel binding data */
#ifdef HAVE_GSSAPI
#ifdef USE_SSL
  curlx_dyn_init(&neg_ctx->channel_binding_data, SSL_CB_MAX_SIZE + 1);
  if(Curl_conn_is_ssl(conn, FIRSTSOCKET)) {
    result = Curl_ssl_get_channel_binding(
      data, FIRSTSOCKET, &neg_ctx->channel_binding_data);
    if(result) {
      http_auth_nego_reset(conn, neg_ctx, proxy);
      return result;
    }
  }
#else
  curlx_dyn_init(&neg_ctx->channel_binding_data, 1);
#endif /* USE_SSL */
#endif /* HAVE_GSSAPI */

  /* Initialize the security context and decode our challenge */
  result = Curl_auth_decode_spnego_message(data, userp, passwdp, service,
                                           host, header, neg_ctx);

#ifdef HAVE_GSSAPI
  curlx_dyn_free(&neg_ctx->channel_binding_data);
#endif

  if(result)
    http_auth_nego_reset(conn, neg_ctx, proxy);

  return result;
}

CURLcode Curl_output_negotiate(struct Curl_easy *data,
                               struct connectdata *conn, bool proxy)
{
  struct negotiatedata *neg_ctx;
  struct auth *authp;
  curlnegotiate *state;
  char *base64 = NULL;
  size_t len = 0;
  char *userp;
  CURLcode result;

  if(proxy) {
#ifndef CURL_DISABLE_PROXY
    authp = &data->state.authproxy;
    state = &conn->proxy_negotiate_state;
#else
    return CURLE_NOT_BUILT_IN;
#endif
  }
  else {
    authp = &data->state.authhost;
    state = &conn->http_negotiate_state;
  }
  neg_ctx = Curl_auth_nego_get(conn, proxy);
  if(!neg_ctx)
    return CURLE_OUT_OF_MEMORY;

  authp->done = FALSE;

  if(*state == GSS_AUTHRECV) {
    if(neg_ctx->havenegdata) {
      neg_ctx->havemultiplerequests = TRUE;
    }
  }
  else if(*state == GSS_AUTHSUCC) {
    if(!neg_ctx->havenoauthpersist) {
      neg_ctx->noauthpersist = !neg_ctx->havemultiplerequests;
    }
  }

  if(neg_ctx->noauthpersist ||
     (*state != GSS_AUTHDONE && *state != GSS_AUTHSUCC)) {

    if(neg_ctx->noauthpersist && *state == GSS_AUTHSUCC) {
      infof(data, "Curl_output_negotiate, "
            "no persistent authentication: cleanup existing context");
      http_auth_nego_reset(conn, neg_ctx, proxy);
    }
    if(!neg_ctx->context) {
      result = Curl_input_negotiate(data, conn, proxy, "Negotiate");
      if(result == CURLE_AUTH_ERROR) {
        /* negotiate auth failed, let's continue unauthenticated to stay
         * compatible with the behavior before curl-7_64_0-158-g6c6035532 */
        authp->done = TRUE;
        return CURLE_OK;
      }
      else if(result)
        return result;
    }

    result = Curl_auth_create_spnego_message(neg_ctx, &base64, &len);
    if(result)
      return result;

    userp = aprintf("%sAuthorization: Negotiate %s\r\n", proxy ? "Proxy-" : "",
                    base64);

    if(proxy) {
#ifndef CURL_DISABLE_PROXY
      free(data->state.aptr.proxyuserpwd);
      data->state.aptr.proxyuserpwd = userp;
#endif
    }
    else {
      free(data->state.aptr.userpwd);
      data->state.aptr.userpwd = userp;
    }

    free(base64);

    if(!userp) {
      return CURLE_OUT_OF_MEMORY;
    }

    *state = GSS_AUTHSENT;
  #ifdef HAVE_GSSAPI
    if(neg_ctx->status == GSS_S_COMPLETE ||
       neg_ctx->status == GSS_S_CONTINUE_NEEDED) {
      *state = GSS_AUTHDONE;
    }
  #else
  #ifdef USE_WINDOWS_SSPI
    if(neg_ctx->status == SEC_E_OK ||
       neg_ctx->status == SEC_I_CONTINUE_NEEDED) {
      *state = GSS_AUTHDONE;
    }
  #endif
  #endif
  }

  if(*state == GSS_AUTHDONE || *state == GSS_AUTHSUCC) {
    /* connection is already authenticated,
     * do not send a header in future requests */
    authp->done = TRUE;
  }

  neg_ctx->havenegdata = FALSE;

  return CURLE_OK;
}

#endif /* !CURL_DISABLE_HTTP && USE_SPNEGO */
