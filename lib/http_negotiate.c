/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef HAVE_GSSAPI
#ifdef HAVE_OLD_GSSMIT
#define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#define NCOMPAT 1
#endif

#ifndef CURL_DISABLE_HTTP

#include "urldata.h"
#include "sendf.h"
#include "curl_gssapi.h"
#include "rawstr.h"
#include "curl_base64.h"
#include "http_negotiate.h"
#include "curl_memory.h"
#include "url.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

static int
get_gss_name(struct connectdata *conn, bool proxy, gss_name_t *server)
{
  OM_uint32 major_status, minor_status;
  gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
  char name[2048];
  const char* service = "HTTP";

  token.length = strlen(service) + 1 + strlen(proxy ? conn->proxy.name :
                                              conn->host.name) + 1;
  if(token.length + 1 > sizeof(name))
    return EMSGSIZE;

  snprintf(name, sizeof(name), "%s@%s", service, proxy ? conn->proxy.name :
           conn->host.name);

  token.value = (void *) name;
  major_status = gss_import_name(&minor_status,
                                 &token,
                                 GSS_C_NT_HOSTBASED_SERVICE,
                                 server);

  return GSS_ERROR(major_status) ? -1 : 0;
}

static void
log_gss_error(struct connectdata *conn, OM_uint32 error_status,
              const char *prefix)
{
  OM_uint32 maj_stat, min_stat;
  OM_uint32 msg_ctx = 0;
  gss_buffer_desc status_string;
  char buf[1024];
  size_t len;

  snprintf(buf, sizeof(buf), "%s", prefix);
  len = strlen(buf);
  do {
    maj_stat = gss_display_status(&min_stat,
                                  error_status,
                                  GSS_C_MECH_CODE,
                                  GSS_C_NO_OID,
                                  &msg_ctx,
                                  &status_string);
      if(sizeof(buf) > len + status_string.length + 1) {
        snprintf(buf + len, sizeof(buf) - len,
                 ": %s", (char*) status_string.value);
      len += status_string.length;
    }
    gss_release_buffer(&min_stat, &status_string);
  } while(!GSS_ERROR(maj_stat) && msg_ctx != 0);

  infof(conn->data, "%s\n", buf);
}

/* returning zero (0) means success, everything else is treated as "failure"
   with no care exactly what the failure was */
int Curl_input_negotiate(struct connectdata *conn, bool proxy,
                         const char *header)
{
  struct SessionHandle *data = conn->data;
  struct negotiatedata *neg_ctx = proxy?&data->state.proxyneg:
    &data->state.negotiate;
  OM_uint32 major_status, minor_status, discard_st;
  gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
  int ret;
  size_t len;
  size_t rawlen = 0;
  CURLcode error;

  if(neg_ctx->context && neg_ctx->status == GSS_S_COMPLETE) {
    /* We finished successfully our part of authentication, but server
     * rejected it (since we're again here). Exit with an error since we
     * can't invent anything better */
    Curl_cleanup_negotiate(data);
    return -1;
  }

  if(neg_ctx->server_name == NULL &&
      (ret = get_gss_name(conn, proxy, &neg_ctx->server_name)))
    return ret;

  header += strlen("Negotiate");
  while(*header && ISSPACE(*header))
    header++;

  len = strlen(header);
  if(len > 0) {
    error = Curl_base64_decode(header,
                               (unsigned char **)&input_token.value, &rawlen);
    if(error || rawlen == 0)
      return -1;
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
                                           NULL);
  Curl_safefree(input_token.value);

  neg_ctx->status = major_status;
  if(GSS_ERROR(major_status)) {
    if(output_token.value)
      gss_release_buffer(&discard_st, &output_token);
    log_gss_error(conn, minor_status, "gss_init_sec_context() failed: ");
    return -1;
  }

  if(!output_token.value || !output_token.length) {
    if(output_token.value)
      gss_release_buffer(&discard_st, &output_token);
    return -1;
  }

  neg_ctx->output_token = output_token;
  return 0;
}


CURLcode Curl_output_negotiate(struct connectdata *conn, bool proxy)
{
  struct negotiatedata *neg_ctx = proxy?&conn->data->state.proxyneg:
    &conn->data->state.negotiate;
  char *encoded = NULL;
  size_t len = 0;
  char *userp;
  CURLcode error;
  OM_uint32 discard_st;

  error = Curl_base64_encode(conn->data,
                             neg_ctx->output_token.value,
                             neg_ctx->output_token.length,
                             &encoded, &len);
  if(error) {
    gss_release_buffer(&discard_st, &neg_ctx->output_token);
    neg_ctx->output_token.value = NULL;
    neg_ctx->output_token.length = 0;
    return error;
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

  Curl_safefree(encoded);

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


#endif
#endif
