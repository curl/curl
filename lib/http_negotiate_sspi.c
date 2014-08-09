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

#ifdef USE_WINDOWS_SSPI

#if !defined(CURL_DISABLE_HTTP) && defined(USE_SPNEGO)

#include "urldata.h"
#include "sendf.h"
#include "rawstr.h"
#include "warnless.h"
#include "curl_base64.h"
#include "curl_sasl.h"
#include "http_negotiate.h"
#include "curl_memory.h"
#include "curl_multibyte.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

/* returning zero (0) means success, everything else is treated as "failure"
   with no care exactly what the failure was */
int Curl_input_negotiate(struct connectdata *conn, bool proxy,
                         const char *header)
{
  BYTE              *input_token = NULL;
  SecBufferDesc     out_buff_desc;
  SecBuffer         out_sec_buff;
  SecBufferDesc     in_buff_desc;
  SecBuffer         in_sec_buff;
  unsigned long     context_attributes;
  TimeStamp         lifetime;
  int ret;
  size_t len = 0, input_token_len = 0;
  CURLcode error;

  /* Point to the username and password */
  const char *userp;
  const char *passwdp;

  /* Point to the correct struct with this */
  struct negotiatedata *neg_ctx;

  if(proxy) {
    userp = conn->proxyuser;
    passwdp = conn->proxypasswd;
    neg_ctx = &conn->data->state.proxyneg;
  }
  else {
    userp = conn->user;
    passwdp = conn->passwd;
    neg_ctx = &conn->data->state.negotiate;
  }

  /* Not set means empty */
  if(!userp)
    userp = "";

  if(!passwdp)
    passwdp = "";

  if(neg_ctx->context && neg_ctx->status == SEC_E_OK) {
    /* We finished successfully our part of authentication, but server
     * rejected it (since we're again here). Exit with an error since we
     * can't invent anything better */
    Curl_cleanup_negotiate(conn->data);
    return -1;
  }

  if(!neg_ctx->server_name) {
    /* Check proxy auth requested but no given proxy name */
    if(proxy && !conn->proxy.name)
      return -1;

    /* Generate our SPN */
    neg_ctx->server_name = Curl_sasl_build_spn("HTTP",
                                                proxy ? conn->proxy.name :
                                                        conn->host.name);
    if(!neg_ctx->server_name)
      return -1;
  }

  if(!neg_ctx->output_token) {
    PSecPkgInfo SecurityPackage;
    ret = s_pSecFn->QuerySecurityPackageInfo((TCHAR *) TEXT("Negotiate"),
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
  header += strlen("Negotiate");
  while(*header && ISSPACE(*header))
    header++;

  len = strlen(header);
  if(!len) {
    /* Is this the first call in a new negotiation? */
    if(neg_ctx->context) {
      /* The server rejected our authentication and hasn't suppled any more
         negotiation mechanisms */
      return -1;
    }

    /* We have to acquire credentials and allocate memory for the context */
    neg_ctx->credentials = malloc(sizeof(CredHandle));
    neg_ctx->context = malloc(sizeof(CtxtHandle));

    if(!neg_ctx->credentials || !neg_ctx->context)
      return -1;

    if(userp && *userp) {
      /* Populate our identity structure */
      error = Curl_create_sspi_identity(userp, passwdp, &neg_ctx->identity);
      if(error)
        return -1;

      /* Allow proper cleanup of the identity structure */
      neg_ctx->p_identity = &neg_ctx->identity;
    }
    else
      /* Use the current Windows user */
      neg_ctx->p_identity = NULL;

    /* Acquire our credientials handle */
    neg_ctx->status =
      s_pSecFn->AcquireCredentialsHandle(NULL,
                                         (TCHAR *) TEXT("Negotiate"),
                                         SECPKG_CRED_OUTBOUND, NULL,
                                         neg_ctx->p_identity, NULL, NULL,
                                         neg_ctx->credentials, &lifetime);
    if(neg_ctx->status != SEC_E_OK)
      return -1;
  }
  else {
    error = Curl_base64_decode(header,
                               (unsigned char **)&input_token,
                               &input_token_len);
    if(error || !input_token_len)
      return -1;
  }

  /* Setup the "output" security buffer */
  out_buff_desc.ulVersion = SECBUFFER_VERSION;
  out_buff_desc.cBuffers  = 1;
  out_buff_desc.pBuffers  = &out_sec_buff;
  out_sec_buff.BufferType = SECBUFFER_TOKEN;
  out_sec_buff.pvBuffer   = neg_ctx->output_token;
  out_sec_buff.cbBuffer   = curlx_uztoul(neg_ctx->max_token_length);

  /* Setup the "input" security buffer if present */
  if(input_token) {
    in_buff_desc.ulVersion = SECBUFFER_VERSION;
    in_buff_desc.cBuffers  = 1;
    in_buff_desc.pBuffers  = &in_sec_buff;
    in_sec_buff.BufferType = SECBUFFER_TOKEN;
    in_sec_buff.pvBuffer   = input_token;
    in_sec_buff.cbBuffer   = curlx_uztoul(input_token_len);
  }

  /* Generate our message */
  neg_ctx->status = s_pSecFn->InitializeSecurityContext(
    neg_ctx->credentials,
    input_token ? neg_ctx->context : NULL,
    neg_ctx->server_name,
    ISC_REQ_CONFIDENTIALITY,
    0,
    SECURITY_NATIVE_DREP,
    input_token ? &in_buff_desc : NULL,
    0,
    neg_ctx->context,
    &out_buff_desc,
    &context_attributes,
    &lifetime);

  Curl_safefree(input_token);

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

  if(!len)
    return CURLE_REMOTE_ACCESS_DENIED;

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
  if(neg_ctx->context) {
    s_pSecFn->DeleteSecurityContext(neg_ctx->context);
    free(neg_ctx->context);
    neg_ctx->context = NULL;
  }

  if(neg_ctx->credentials) {
    s_pSecFn->FreeCredentialsHandle(neg_ctx->credentials);
    free(neg_ctx->credentials);
    neg_ctx->credentials = NULL;
  }

  neg_ctx->max_token_length = 0;
  Curl_safefree(neg_ctx->output_token);

  Curl_safefree(neg_ctx->server_name);

  Curl_sspi_free_identity(neg_ctx->p_identity);
  neg_ctx->p_identity = NULL;
}

void Curl_cleanup_negotiate(struct SessionHandle *data)
{
  cleanup(&data->state.negotiate);
  cleanup(&data->state.proxyneg);
}

#endif /* !CURL_DISABLE_HTTP && USE_SPNEGO */

#endif /* USE_WINDOWS_SSPI */
