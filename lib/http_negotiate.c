/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

#include "curl_setup.h"

#if defined(HAVE_GSSAPI) && !defined(CURL_DISABLE_HTTP) && defined(USE_SPNEGO)

#include "urldata.h"
#include "sendf.h"
#include "curl_gssapi.h"
#include "rawstr.h"
#include "curl_base64.h"
#include "http_negotiate.h"
#include "curl_sasl.h"
#include "url.h"
#include "curl_printf.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

CURLcode Curl_input_negotiate(struct connectdata *conn, bool proxy,
                              const char *header)
{
  struct SessionHandle *data = conn->data;
  struct negotiatedata *neg_ctx = proxy?&data->state.proxyneg:
    &data->state.negotiate;
  OM_uint32 major_status, minor_status, discard_st;
  gss_buffer_desc spn_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
  size_t len;
  size_t rawlen = 0;
  CURLcode result;

  if(neg_ctx->context && neg_ctx->status == GSS_S_COMPLETE) {
    /* We finished successfully our part of authentication, but server
     * rejected it (since we're again here). Exit with an error since we
     * can't invent anything better */
    Curl_cleanup_negotiate(data);
    return CURLE_LOGIN_DENIED;
  }

  if(!neg_ctx->server_name) {
    /* Generate our SPN */
    char *spn = Curl_sasl_build_gssapi_spn(
      proxy ? data->set.str[STRING_PROXY_SERVICE_NAME] :
      data->set.str[STRING_SERVICE_NAME],
      proxy ? conn->proxy.name : conn->host.name);
    if(!spn)
      return CURLE_OUT_OF_MEMORY;

    /* Populate the SPN structure */
    spn_token.value = spn;
    spn_token.length = strlen(spn);

    /* Import the SPN */
    major_status = gss_import_name(&minor_status, &spn_token,
                                   GSS_C_NT_HOSTBASED_SERVICE,
                                   &neg_ctx->server_name);
    if(GSS_ERROR(major_status)) {
      Curl_gss_log_error(data, minor_status, "gss_import_name() failed: ");

      free(spn);

      return CURLE_OUT_OF_MEMORY;
    }

    free(spn);
  }

  header += strlen("Negotiate");
  while(*header && ISSPACE(*header))
    header++;

  len = strlen(header);
  if(len > 0) {
    result = Curl_base64_decode(header, (unsigned char **)&input_token.value,
                                &rawlen);
    if(result)
      return result;

    if(!rawlen) {
      infof(data, "Negotiate handshake failure (empty challenge message)\n");

      return CURLE_BAD_CONTENT_ENCODING;
    }

    input_token.length = rawlen;

    DEBUGASSERT(input_token.value != NULL);
  }

  major_status = Curl_gss_init_sec_context(data,
                                           &minor_status,
                                           &neg_ctx->context,
                                           neg_ctx->server_name,
                                           &Curl_spnego_mech_oid,
                                           GSS_C_NO_CHANNEL_BINDINGS,
                                           &input_token,
                                           &output_token,
                                           TRUE,
                                           NULL);
  Curl_safefree(input_token.value);

  neg_ctx->status = major_status;
  if(GSS_ERROR(major_status)) {
    if(output_token.value)
      gss_release_buffer(&discard_st, &output_token);
    Curl_gss_log_error(conn->data, minor_status,
                       "gss_init_sec_context() failed: ");
    return CURLE_OUT_OF_MEMORY;
  }

  if(!output_token.value || !output_token.length) {
    if(output_token.value)
      gss_release_buffer(&discard_st, &output_token);
    return CURLE_OUT_OF_MEMORY;
  }

  neg_ctx->output_token = output_token;

  return CURLE_OK;
}

CURLcode Curl_output_negotiate(struct connectdata *conn, bool proxy)
{
  struct negotiatedata *neg_ctx = proxy?&conn->data->state.proxyneg:
    &conn->data->state.negotiate;
  char *encoded = NULL;
  size_t len = 0;
  char *userp;
  CURLcode result;
  OM_uint32 discard_st;

  result = Curl_base64_encode(conn->data,
                              neg_ctx->output_token.value,
                              neg_ctx->output_token.length,
                              &encoded, &len);
  if(result) {
    gss_release_buffer(&discard_st, &neg_ctx->output_token);
    neg_ctx->output_token.value = NULL;
    neg_ctx->output_token.length = 0;
    return result;
  }

  if(!encoded || !len) {
    gss_release_buffer(&discard_st, &neg_ctx->output_token);
    neg_ctx->output_token.value = NULL;
    neg_ctx->output_token.length = 0;
    return CURLE_REMOTE_ACCESS_DENIED;
  }

  userp = aprintf("%sAuthorization: Negotiate %s\r\n", proxy ? "Proxy-" : "",
                  encoded);
  if(proxy) {
    Curl_safefree(conn->allocptr.proxyuserpwd);
    conn->allocptr.proxyuserpwd = userp;
  }
  else {
    Curl_safefree(conn->allocptr.userpwd);
    conn->allocptr.userpwd = userp;
  }

  free(encoded);

  return (userp == NULL) ? CURLE_OUT_OF_MEMORY : CURLE_OK;
}

static void cleanup(struct negotiatedata *neg_ctx)
{
  OM_uint32 minor_status;
  if(neg_ctx->context != GSS_C_NO_CONTEXT)
    gss_delete_sec_context(&minor_status, &neg_ctx->context, GSS_C_NO_BUFFER);

  if(neg_ctx->output_token.value)
    gss_release_buffer(&minor_status, &neg_ctx->output_token);

  if(neg_ctx->server_name != GSS_C_NO_NAME)
    gss_release_name(&minor_status, &neg_ctx->server_name);

  memset(neg_ctx, 0, sizeof(*neg_ctx));
}

void Curl_cleanup_negotiate(struct SessionHandle *data)
{
  cleanup(&data->state.negotiate);
  cleanup(&data->state.proxyneg);
}

#endif /* HAVE_GSSAPI && !CURL_DISABLE_HTTP && USE_SPNEGO */
