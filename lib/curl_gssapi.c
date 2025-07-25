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

#ifdef HAVE_GSSAPI

#include "curl_gssapi.h"
#include "sendf.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#ifdef __GNUC__
#define CURL_ALIGN8  __attribute__((aligned(8)))
#else
#define CURL_ALIGN8
#endif

#if defined(__GNUC__) && defined(__APPLE__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

gss_OID_desc Curl_spnego_mech_oid CURL_ALIGN8 = {
  6, CURL_UNCONST("\x2b\x06\x01\x05\x05\x02")
};
gss_OID_desc Curl_krb5_mech_oid CURL_ALIGN8 = {
  9, CURL_UNCONST("\x2a\x86\x48\x86\xf7\x12\x01\x02\x02")
};

#ifdef DEBUGBUILD
enum min_err_code {
  STUB_GSS_OK = 0,
  STUB_GSS_NO_MEMORY,
  STUB_GSS_INVALID_ARGS,
  STUB_GSS_INVALID_CREDS,
  STUB_GSS_INVALID_CTX,
  STUB_GSS_SERVER_ERR,
  STUB_GSS_NO_MECH,
  STUB_GSS_LAST
};

/* libcurl is also passing this struct to these functions, which are not yet
 * stubbed:
 *   gss_inquire_context()
 *   gss_unwrap()
 *   gss_wrap()
 */
struct stub_gss_ctx_id_t_desc {
  enum { STUB_GSS_NONE, STUB_GSS_KRB5, STUB_GSS_NTLM1, STUB_GSS_NTLM3 } sent;
  int have_krb5;
  int have_ntlm;
  OM_uint32 flags;
  char creds[250];
};

static OM_uint32
stub_gss_init_sec_context(OM_uint32 *min,
                          gss_cred_id_t initiator_cred_handle,
                          struct stub_gss_ctx_id_t_desc **context,
                          gss_name_t target_name,
                          const gss_OID mech_type,
                          OM_uint32 req_flags,
                          OM_uint32 time_req,
                          const gss_channel_bindings_t input_chan_bindings,
                          gss_buffer_desc *input_token,
                          gss_OID *actual_mech_type,
                          gss_buffer_desc *output_token,
                          OM_uint32 *ret_flags,
                          OM_uint32 *time_rec)
{
  struct stub_gss_ctx_id_t_desc *ctx = NULL;

  /* The token will be encoded in base64 */
  size_t length = sizeof(ctx->creds) * 3 / 4;
  size_t used = 0;
  char *token = NULL;
  const char *creds = NULL;

  (void)initiator_cred_handle;
  (void)mech_type;
  (void)time_req;
  (void)input_chan_bindings;
  (void)actual_mech_type;

  if(!min)
    return GSS_S_FAILURE;

  *min = 0;

  if(!context || !target_name || !output_token) {
    *min = STUB_GSS_INVALID_ARGS;
    return GSS_S_FAILURE;
  }

  creds = getenv("CURL_STUB_GSS_CREDS");
  if(!creds || strlen(creds) >= sizeof(ctx->creds)) {
    *min = STUB_GSS_INVALID_CREDS;
    return GSS_S_FAILURE;
  }

  ctx = *context;
  if(ctx && strcmp(ctx->creds, creds)) {
    *min = STUB_GSS_INVALID_CREDS;
    return GSS_S_FAILURE;
  }

  output_token->length = 0;
  output_token->value = NULL;

  if(input_token && input_token->length) {
    if(!ctx) {
      *min = STUB_GSS_INVALID_CTX;
      return GSS_S_FAILURE;
    }

    /* Server response, either D (RA==) or C (Qw==) */
    if(((char *) input_token->value)[0] == 'D') {
      /* Done */
      switch(ctx->sent) {
      case STUB_GSS_KRB5:
      case STUB_GSS_NTLM3:
        if(ret_flags)
          *ret_flags = ctx->flags;
        if(time_rec)
          *time_rec = GSS_C_INDEFINITE;
        return GSS_S_COMPLETE;
      default:
        *min = STUB_GSS_SERVER_ERR;
        return GSS_S_FAILURE;
      }
    }

    if(((char *) input_token->value)[0] != 'C') {
      /* We only support Done or Continue */
      *min = STUB_GSS_SERVER_ERR;
      return GSS_S_FAILURE;
    }

    /* Continue */
    switch(ctx->sent) {
    case STUB_GSS_KRB5:
      /* We sent KRB5 and it failed, let's try NTLM */
      if(ctx->have_ntlm) {
        ctx->sent = STUB_GSS_NTLM1;
        break;
      }
      else {
        *min = STUB_GSS_SERVER_ERR;
        return GSS_S_FAILURE;
      }
    case STUB_GSS_NTLM1:
      ctx->sent = STUB_GSS_NTLM3;
      break;
    default:
      *min = STUB_GSS_SERVER_ERR;
      return GSS_S_FAILURE;
    }
  }
  else {
    if(ctx) {
      *min = STUB_GSS_INVALID_CTX;
      return GSS_S_FAILURE;
    }

    ctx = calloc(1, sizeof(*ctx));
    if(!ctx) {
      *min = STUB_GSS_NO_MEMORY;
      return GSS_S_FAILURE;
    }

    if(strstr(creds, "KRB5"))
      ctx->have_krb5 = 1;

    if(strstr(creds, "NTLM"))
      ctx->have_ntlm = 1;

    if(ctx->have_krb5)
      ctx->sent = STUB_GSS_KRB5;
    else if(ctx->have_ntlm)
      ctx->sent = STUB_GSS_NTLM1;
    else {
      free(ctx);
      *min = STUB_GSS_NO_MECH;
      return GSS_S_FAILURE;
    }

    strcpy(ctx->creds, creds);
    ctx->flags = req_flags;
  }

  /* To avoid memdebug macro replacement, wrap the name in parentheses to call
     the original version. It is freed via the GSS API gss_release_buffer(). */
  token = (malloc)(length);
  if(!token) {
    free(ctx);
    *min = STUB_GSS_NO_MEMORY;
    return GSS_S_FAILURE;
  }

  {
    gss_buffer_desc target_desc;
    gss_OID name_type = GSS_C_NO_OID;
    OM_uint32 minor_status;
    OM_uint32 major_status;
    major_status = gss_display_name(&minor_status, target_name,
                                    &target_desc, &name_type);
    if(GSS_ERROR(major_status)) {
      (free)(token);
      free(ctx);
      *min = STUB_GSS_NO_MEMORY;
      return GSS_S_FAILURE;
    }

    if(strlen(creds) + target_desc.length + 5 >= sizeof(ctx->creds)) {
      (free)(token);
      free(ctx);
      *min = STUB_GSS_NO_MEMORY;
      return GSS_S_FAILURE;
    }

    /* Token format: creds:target:type:padding */
    used = msnprintf(token, length, "%s:%.*s:%d:", creds,
                     (int)target_desc.length, (const char *)target_desc.value,
                     ctx->sent);

    gss_release_buffer(&minor_status, &target_desc);
  }

  if(used >= length) {
    (free)(token);
    free(ctx);
    *min = STUB_GSS_NO_MEMORY;
    return GSS_S_FAILURE;
  }

  /* Overwrite null-terminator */
  memset(token + used, 'A', length - used);

  *context = ctx;

  output_token->value = token;
  output_token->length = length;

  return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
stub_gss_delete_sec_context(OM_uint32 *min,
                            struct stub_gss_ctx_id_t_desc **context,
                            gss_buffer_t output_token)
{
  (void)output_token;

  if(!min)
    return GSS_S_FAILURE;

  if(!context) {
    *min = STUB_GSS_INVALID_CTX;
    return GSS_S_FAILURE;
  }
  if(!*context) {
    *min = STUB_GSS_INVALID_CTX;
    return GSS_S_FAILURE;
  }

  free(*context);
  *context = NULL;
  *min = 0;

  return GSS_S_COMPLETE;
}
#endif /* DEBUGBUILD */

OM_uint32 Curl_gss_init_sec_context(struct Curl_easy *data,
                                    OM_uint32 *minor_status,
                                    gss_ctx_id_t *context,
                                    gss_name_t target_name,
                                    gss_OID mech_type,
                                    gss_channel_bindings_t input_chan_bindings,
                                    gss_buffer_t input_token,
                                    gss_buffer_t output_token,
                                    const bool mutual_auth,
                                    OM_uint32 *ret_flags)
{
  OM_uint32 req_flags = GSS_C_REPLAY_FLAG;

  if(mutual_auth)
    req_flags |= GSS_C_MUTUAL_FLAG;

  if(data->set.gssapi_delegation & CURLGSSAPI_DELEGATION_POLICY_FLAG) {
#ifdef GSS_C_DELEG_POLICY_FLAG
    req_flags |= GSS_C_DELEG_POLICY_FLAG;
#else
    infof(data, "WARNING: support for CURLGSSAPI_DELEGATION_POLICY_FLAG not "
          "compiled in");
#endif
  }

  if(data->set.gssapi_delegation & CURLGSSAPI_DELEGATION_FLAG)
    req_flags |= GSS_C_DELEG_FLAG;

#ifdef DEBUGBUILD
  if(getenv("CURL_STUB_GSS_CREDS"))
    return stub_gss_init_sec_context(minor_status,
                                     GSS_C_NO_CREDENTIAL, /* cred_handle */
                                     (struct stub_gss_ctx_id_t_desc **)context,
                                     target_name,
                                     mech_type,
                                     req_flags,
                                     0, /* time_req */
                                     input_chan_bindings,
                                     input_token,
                                     NULL, /* actual_mech_type */
                                     output_token,
                                     ret_flags,
                                     NULL /* time_rec */);
#endif /* DEBUGBUILD */

  return gss_init_sec_context(minor_status,
                              GSS_C_NO_CREDENTIAL, /* cred_handle */
                              context,
                              target_name,
                              mech_type,
                              req_flags,
                              0, /* time_req */
                              input_chan_bindings,
                              input_token,
                              NULL, /* actual_mech_type */
                              output_token,
                              ret_flags,
                              NULL /* time_rec */);
}

OM_uint32 Curl_gss_delete_sec_context(OM_uint32 *min,
                                      gss_ctx_id_t *context,
                                      gss_buffer_t output_token)
{
#ifdef DEBUGBUILD
  if(getenv("CURL_STUB_GSS_CREDS"))
    return stub_gss_delete_sec_context(min,
                                     (struct stub_gss_ctx_id_t_desc **)context,
                                     output_token);
#endif /* DEBUGBUILD */

  return gss_delete_sec_context(min, context, output_token);
}

#define GSS_LOG_BUFFER_LEN 1024
static size_t display_gss_error(OM_uint32 status, int type,
                                char *buf, size_t len) {
  OM_uint32 maj_stat;
  OM_uint32 min_stat;
  OM_uint32 msg_ctx = 0;
  gss_buffer_desc status_string = GSS_C_EMPTY_BUFFER;

  do {
    maj_stat = gss_display_status(&min_stat,
                                  status,
                                  type,
                                  GSS_C_NO_OID,
                                  &msg_ctx,
                                  &status_string);
    if(maj_stat == GSS_S_COMPLETE && status_string.length > 0) {
      if(GSS_LOG_BUFFER_LEN > len + status_string.length + 3) {
        len += msnprintf(buf + len, GSS_LOG_BUFFER_LEN - len,
                         "%.*s. ", (int)status_string.length,
                         (char *)status_string.value);
      }
    }
    gss_release_buffer(&min_stat, &status_string);
  } while(!GSS_ERROR(maj_stat) && msg_ctx);

  return len;
}

/*
 * Curl_gss_log_error()
 *
 * This is used to log a GSS-API error status.
 *
 * Parameters:
 *
 * data    [in] - The session handle.
 * prefix  [in] - The prefix of the log message.
 * major   [in] - The major status code.
 * minor   [in] - The minor status code.
 */
void Curl_gss_log_error(struct Curl_easy *data, const char *prefix,
                        OM_uint32 major, OM_uint32 minor)
{
  char buf[GSS_LOG_BUFFER_LEN];
  size_t len = 0;

  if(major != GSS_S_FAILURE)
    len = display_gss_error(major, GSS_C_GSS_CODE, buf, len);

  display_gss_error(minor, GSS_C_MECH_CODE, buf, len);

  infof(data, "%s%s", prefix, buf);
#ifdef CURL_DISABLE_VERBOSE_STRINGS
  (void)data;
  (void)prefix;
#endif
}

#if defined(__GNUC__) && defined(__APPLE__)
#pragma GCC diagnostic pop
#endif

#endif /* HAVE_GSSAPI */
