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

#ifdef USE_WINDOWS_SSPI

#ifndef CURL_DISABLE_HTTP

#include "urldata.h"
#include "sendf.h"
#include "rawstr.h"
#include "curl_base64.h"
#include "http_negotiate.h"
#include "curl_memory.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

static int
get_gss_name(struct connectdata *conn, bool proxy,
             struct negotiatedata *neg_ctx)
{
  const char* service;
  size_t length;

  if(proxy && !conn->proxy.name)
    /* proxy auth requested but no given proxy name, error out! */
    return -1;

  /* GSSAPI implementation by Globus (known as GSI) requires the name to be
     of form "<service>/<fqdn>" instead of <service>@<fqdn> (ie. slash instead
     of at-sign). Also GSI servers are often identified as 'host' not 'khttp'.
     Change following lines if you want to use GSI */

  /* IIS uses the <service>@<fqdn> form but uses 'http' as the service name,
     and SSPI then generates an NTLM token. When using <service>/<fqdn> a
     Kerberos token is generated. */

  if(neg_ctx->gss)
    service = "KHTTP";
  else
    service = "HTTP";

  length = strlen(service) + 1 + strlen(proxy ? conn->proxy.name :
                                        conn->host.name) + 1;
  if(length + 1 > sizeof(neg_ctx->server_name))
    return EMSGSIZE;

  snprintf(neg_ctx->server_name, sizeof(neg_ctx->server_name), "%s/%s",
           service, proxy ? conn->proxy.name : conn->host.name);

  return 0;
}

/* returning zero (0) means success, everything else is treated as "failure"
   with no care exactly what the failure was */
int Curl_input_negotiate(struct connectdata *conn, bool proxy,
                         const char *header)
{
  struct negotiatedata *neg_ctx = proxy?&conn->data->state.proxyneg:
    &conn->data->state.negotiate;
  BYTE              *input_token = 0;
  SecBufferDesc     out_buff_desc;
  SecBuffer         out_sec_buff;
  SecBufferDesc     in_buff_desc;
  SecBuffer         in_sec_buff;
  ULONG             context_attributes;
  TimeStamp         lifetime;

  int ret;
  size_t len = 0, input_token_len = 0;
  bool gss = FALSE;
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

  if(neg_ctx->context && neg_ctx->status == SEC_E_OK) {
    /* We finished successfully our part of authentication, but server
     * rejected it (since we're again here). Exit with an error since we
     * can't invent anything better */
    Curl_cleanup_negotiate(conn->data);
    return -1;
  }

  if(0 == strlen(neg_ctx->server_name)) {
    ret = get_gss_name(conn, proxy, neg_ctx);
    if(ret)
      return ret;
  }

  if(!neg_ctx->output_token) {
    PSecPkgInfo SecurityPackage;
    ret = s_pSecFn->QuerySecurityPackageInfo((SEC_CHAR *)"Negotiate",
                                             &SecurityPackage);
    if(ret != SEC_E_OK)
      return -1;

    /* Allocate input and output buffers according to the max token size
       as indicated by the security package */
    neg_ctx->max_token_length = SecurityPackage->cbMaxToken;
    neg_ctx->output_token = malloc(neg_ctx->max_token_length);
    s_pSecFn->FreeContextBuffer(SecurityPackage);
  }

  /* Obtain the input token, if any */
  header += strlen(neg_ctx->protocol);
  while(*header && ISSPACE(*header))
    header++;

  len = strlen(header);
  if(!len) {
    /* first call in a new negotation, we have to acquire credentials,
       and allocate memory for the context */

    neg_ctx->credentials = malloc(sizeof(CredHandle));
    neg_ctx->context = malloc(sizeof(CtxtHandle));

    if(!neg_ctx->credentials || !neg_ctx->context)
      return -1;

    neg_ctx->status =
      s_pSecFn->AcquireCredentialsHandle(NULL, (SEC_CHAR *)"Negotiate",
                                         SECPKG_CRED_OUTBOUND, NULL, NULL,
                                         NULL, NULL, neg_ctx->credentials,
                                         &lifetime);
    if(neg_ctx->status != SEC_E_OK)
      return -1;
  }
  else {
    input_token = malloc(neg_ctx->max_token_length);
    if(!input_token)
      return -1;

    error = Curl_base64_decode(header,
                               (unsigned char **)&input_token,
                               &input_token_len);
    if(error || input_token_len == 0)
      return -1;
  }

  /* prepare the output buffers, and input buffers if present */
  out_buff_desc.ulVersion = 0;
  out_buff_desc.cBuffers  = 1;
  out_buff_desc.pBuffers  = &out_sec_buff;

  out_sec_buff.cbBuffer   = neg_ctx->max_token_length;
  out_sec_buff.BufferType = SECBUFFER_TOKEN;
  out_sec_buff.pvBuffer   = neg_ctx->output_token;


  if(input_token) {
    in_buff_desc.ulVersion = 0;
    in_buff_desc.cBuffers  = 1;
    in_buff_desc.pBuffers  = &out_sec_buff;

    in_sec_buff.cbBuffer   = input_token_len;
    in_sec_buff.BufferType = SECBUFFER_TOKEN;
    in_sec_buff.pvBuffer   = input_token;
  }

  neg_ctx->status = s_pSecFn->InitializeSecurityContext(
    neg_ctx->credentials,
    input_token ? neg_ctx->context : 0,
    neg_ctx->server_name,
    ISC_REQ_CONFIDENTIALITY,
    0,
    SECURITY_NATIVE_DREP,
    input_token ? &in_buff_desc : 0,
    0,
    neg_ctx->context,
    &out_buff_desc,
    &context_attributes,
    &lifetime);

  if(GSS_ERROR(neg_ctx->status))
    return -1;

  if(neg_ctx->status == SEC_I_COMPLETE_NEEDED ||
     neg_ctx->status == SEC_I_COMPLETE_AND_CONTINUE) {
    neg_ctx->status = s_pSecFn->CompleteAuthToken(neg_ctx->context,
                                                  &out_buff_desc);
    if(GSS_ERROR(neg_ctx->status))
      return -1;
  }

  neg_ctx->output_token_length = out_sec_buff.cbBuffer;

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

  error = Curl_base64_encode(conn->data,
                             (const char*)neg_ctx->output_token,
                             neg_ctx->output_token_length,
                             &encoded, &len);
  if(error)
    return error;

  if(len == 0)
    return CURLE_REMOTE_ACCESS_DENIED;

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
  if(neg_ctx->context) {
    s_pSecFn->DeleteSecurityContext(neg_ctx->context);
    free(neg_ctx->context);
    neg_ctx->context = 0;
  }

  if(neg_ctx->credentials) {
    s_pSecFn->FreeCredentialsHandle(neg_ctx->credentials);
    free(neg_ctx->credentials);
    neg_ctx->credentials = 0;
  }

  if(neg_ctx->output_token) {
    free(neg_ctx->output_token);
    neg_ctx->output_token = 0;
  }

  neg_ctx->max_token_length = 0;
}

void Curl_cleanup_negotiate(struct SessionHandle *data)
{
  cleanup(&data->state.negotiate);
  cleanup(&data->state.proxyneg);
}


#endif
#endif
