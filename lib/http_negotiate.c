/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#if defined(HAVE_GSSAPI) && !defined(CURL_DISABLE_HTTP) && defined(USE_SPNEGO)

#include "urldata.h"
#include "sendf.h"
#include "rawstr.h"
#include "http_negotiate.h"
#include "vauth/vauth.h"
#include "curl_printf.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

CURLcode Curl_input_negotiate(struct connectdata *conn, bool proxy,
                              const char *header)
{
  struct SessionHandle *data = conn->data;

  /* Point to the service and host */
  const char *service;
  const char *host;

  /* Point to the correct struct with this */
  struct negotiatedata *neg_ctx;

  if(proxy) {
    service = data->set.str[STRING_PROXY_SERVICE_NAME];
    host = conn->host.name;
    neg_ctx = &data->state.proxyneg;
  }
  else {
    service = data->set.str[STRING_SERVICE_NAME];
    host = conn->proxy.name;
    neg_ctx = &data->state.negotiate;
  }

  /* Obtain the input token, if any */
  header += strlen("Negotiate");
  while(*header && ISSPACE(*header))
    header++;

  /* Initilise the security context and decode our challenge */
  return Curl_auth_decode_spnego_message(data, NULL, NULL, service, host,
                                         header, neg_ctx);
}

CURLcode Curl_output_negotiate(struct connectdata *conn, bool proxy)
{
  struct negotiatedata *neg_ctx = proxy?&conn->data->state.proxyneg:
    &conn->data->state.negotiate;
  char *base64 = NULL;
  size_t len = 0;
  char *userp;
  CURLcode result;

  result = Curl_auth_create_spnego_message(conn->data, neg_ctx, &base64, &len);
  if(result)
    return result;

  userp = aprintf("%sAuthorization: Negotiate %s\r\n", proxy ? "Proxy-" : "",
                  base64);

  if(proxy) {
    Curl_safefree(conn->allocptr.proxyuserpwd);
    conn->allocptr.proxyuserpwd = userp;
  }
  else {
    Curl_safefree(conn->allocptr.userpwd);
    conn->allocptr.userpwd = userp;
  }

  free(base64);

  return (userp == NULL) ? CURLE_OUT_OF_MEMORY : CURLE_OK;
}

void Curl_cleanup_negotiate(struct SessionHandle *data)
{
  Curl_auth_spnego_cleanup(&data->state.negotiate);
  Curl_auth_spnego_cleanup(&data->state.proxyneg);
}

#endif /* HAVE_GSSAPI && !CURL_DISABLE_HTTP && USE_SPNEGO */
