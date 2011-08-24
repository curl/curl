/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "setup.h"

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

#ifdef HAVE_SPNEGO
#  include <spnegohelp.h>
#  ifdef USE_SSLEAY
#    ifdef USE_OPENSSL
#      include <openssl/objects.h>
#    else
#      include <objects.h>
#    endif
#  else
#    error "Can't compile SPNEGO support without OpenSSL."
#  endif
#endif

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

static int
get_gss_name(struct connectdata *conn, bool proxy, gss_name_t *server)
{
  struct negotiatedata *neg_ctx = proxy?&conn->data->state.proxyneg:
    &conn->data->state.negotiate;
  OM_uint32 major_status, minor_status;
  gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
  char name[2048];
  const char* service;

  /* GSSAPI implementation by Globus (known as GSI) requires the name to be
     of form "<service>/<fqdn>" instead of <service>@<fqdn> (ie. slash instead
     of at-sign). Also GSI servers are often identified as 'host' not 'khttp'.
     Change following lines if you want to use GSI */

  /* IIS uses the <service>@<fqdn> form but uses 'http' as the service name */

  if(neg_ctx->gss)
    service = "KHTTP";
  else
    service = "HTTP";

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

  infof(conn->data, "%s", buf);
}

/* returning zero (0) means success, everything else is treated as "failure"
   with no care exactly what the failure was */
int Curl_input_negotiate(struct connectdata *conn, bool proxy,
                         const char *header)
{
  struct SessionHandle *data = conn->data;
  struct negotiatedata *neg_ctx = proxy?&data->state.proxyneg:
    &data->state.negotiate;
  OM_uint32 major_status, minor_status, minor_status2;
  gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
  int ret;
  size_t len;
  size_t rawlen = 0;
  bool gss;
  const char* protocol;
  CURLcode error;

  while(*header && ISSPACE(*header))
    header++;
  if(checkprefix("GSS-Negotiate", header)) {
    protocol = "GSS-Negotiate";
    gss = TRUE;
  }
  else if(checkprefix("Negotiate", header)) {
    protocol = "Negotiate";
    gss = FALSE;
  }
  else
    return -1;

  if(neg_ctx->context) {
    if(neg_ctx->gss != gss) {
      return -1;
    }
  }
  else {
    neg_ctx->protocol = protocol;
    neg_ctx->gss = gss;
  }

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

  header += strlen(neg_ctx->protocol);
  while(*header && ISSPACE(*header))
    header++;

  len = strlen(header);
  if(len > 0) {
    error = Curl_base64_decode(header,
                               (unsigned char **)&input_token.value, &rawlen);
    if(error || rawlen == 0)
      return -1;
    input_token.length = rawlen;

#ifdef HAVE_SPNEGO /* Handle SPNEGO */
    if(checkprefix("Negotiate", header)) {
      ASN1_OBJECT *   object            = NULL;
      int             rc                = 1;
      unsigned char * spnegoToken       = NULL;
      size_t          spnegoTokenLength = 0;
      unsigned char * mechToken         = NULL;
      size_t          mechTokenLength   = 0;

      if(input_token.value == NULL)
        return CURLE_OUT_OF_MEMORY;

      spnegoToken = malloc(input_token.length);
      if(spnegoToken == NULL)
        return CURLE_OUT_OF_MEMORY;

      spnegoTokenLength = input_token.length;

      object = OBJ_txt2obj ("1.2.840.113554.1.2.2", 1);
      if(!parseSpnegoTargetToken(spnegoToken,
                                 spnegoTokenLength,
                                 NULL,
                                 NULL,
                                 &mechToken,
                                 &mechTokenLength,
                                 NULL,
                                 NULL)) {
        free(spnegoToken);
        spnegoToken = NULL;
        infof(data, "Parse SPNEGO Target Token failed\n");
      }
      else {
        free(input_token.value);
        input_token.value = malloc(mechTokenLength);
        if(input_token.value == NULL)
          return CURLE_OUT_OF_MEMORY;

        memcpy(input_token.value, mechToken,mechTokenLength);
        input_token.length = mechTokenLength;
        free(mechToken);
        mechToken = NULL;
        infof(data, "Parse SPNEGO Target Token succeeded\n");
      }
    }
#endif
  }

  major_status = Curl_gss_init_sec_context(data,
                                           &minor_status,
                                           &neg_ctx->context,
                                           neg_ctx->server_name,
                                           GSS_C_NO_CHANNEL_BINDINGS,
                                           &input_token,
                                           &output_token,
                                           NULL);
  if(input_token.length > 0)
    gss_release_buffer(&minor_status2, &input_token);
  neg_ctx->status = major_status;
  if(GSS_ERROR(major_status)) {
    /* Curl_cleanup_negotiate(data) ??? */
    log_gss_error(conn, minor_status,
                  "gss_init_sec_context() failed: ");
    return -1;
  }

  if(output_token.length == 0) {
    return -1;
  }

  neg_ctx->output_token = output_token;
  /* conn->bits.close = FALSE; */

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

#ifdef HAVE_SPNEGO /* Handle SPNEGO */
  if(checkprefix("Negotiate", neg_ctx->protocol)) {
    ASN1_OBJECT *   object            = NULL;
    int             rc                = 1;
    unsigned char * spnegoToken       = NULL;
    size_t          spnegoTokenLength = 0;
    unsigned char * responseToken       = NULL;
    size_t          responseTokenLength = 0;

    responseToken = malloc(neg_ctx->output_token.length);
    if(responseToken == NULL)
      return CURLE_OUT_OF_MEMORY;
    memcpy(responseToken, neg_ctx->output_token.value,
           neg_ctx->output_token.length);
    responseTokenLength = neg_ctx->output_token.length;

    object=OBJ_txt2obj ("1.2.840.113554.1.2.2", 1);
    if(!makeSpnegoInitialToken (object,
                                 responseToken,
                                 responseTokenLength,
                                 &spnegoToken,
                                 &spnegoTokenLength)) {
      free(responseToken);
      responseToken = NULL;
      infof(conn->data, "Make SPNEGO Initial Token failed\n");
    }
    else {
      free(responseToken);
      responseToken = NULL;
      free(neg_ctx->output_token.value);
      neg_ctx->output_token.value = malloc(spnegoTokenLength);
      if(neg_ctx->output_token.value == NULL) {
        free(spnegoToken);
        spnegoToken = NULL;
        return CURLE_OUT_OF_MEMORY;
      }
      memcpy(neg_ctx->output_token.value, spnegoToken,spnegoTokenLength);
      neg_ctx->output_token.length = spnegoTokenLength;
      free(spnegoToken);
      spnegoToken = NULL;
      infof(conn->data, "Make SPNEGO Initial Token succeeded\n");
    }
  }
#endif
  error = Curl_base64_encode(conn->data,
                             neg_ctx->output_token.value,
                             neg_ctx->output_token.length,
                             &encoded, &len);
  if(error) {
    Curl_safefree(neg_ctx->output_token.value);
    neg_ctx->output_token.value = NULL;
    return error;
  }

  if(len == 0) {
    Curl_safefree(neg_ctx->output_token.value);
    neg_ctx->output_token.value = NULL;
    return CURLE_REMOTE_ACCESS_DENIED;
  }

  userp = aprintf("%sAuthorization: %s %s\r\n", proxy ? "Proxy-" : "",
                  neg_ctx->protocol, encoded);

  if(proxy)
    conn->allocptr.proxyuserpwd = userp;
  else
    conn->allocptr.userpwd = userp;
  free(encoded);
  Curl_cleanup_negotiate (conn->data);
  return (userp == NULL) ? CURLE_OUT_OF_MEMORY : CURLE_OK;
}

static void cleanup(struct negotiatedata *neg_ctx)
{
  OM_uint32 minor_status;
  if(neg_ctx->context != GSS_C_NO_CONTEXT)
    gss_delete_sec_context(&minor_status, &neg_ctx->context, GSS_C_NO_BUFFER);

  if(neg_ctx->output_token.length != 0)
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
