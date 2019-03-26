/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2017-2019, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/* Only provides the bare minimum to link with libcurl */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stub_gssapi.h"

/* !checksrc! disable SNPRINTF all */

#define MAX_CREDS_LENGTH 250
#define APPROX_TOKEN_LEN 250

enum min_err_code {
    GSS_OK = 0,
    GSS_NO_MEMORY,
    GSS_INVALID_ARGS,
    GSS_INVALID_CREDS,
    GSS_INVALID_CTX,
    GSS_SERVER_ERR,
    GSS_NO_MECH,
    GSS_LAST
};

static const char *min_err_table[] = {
  "stub-gss: no error",
  "stub-gss: no memory",
  "stub-gss: invalid arguments",
  "stub-gss: invalid credentials",
  "stub-gss: invalid context",
  "stub-gss: server returned error",
  "stub-gss: cannot find a mechanism",
  NULL
};

struct gss_ctx_id_t_desc_struct {
  enum { NONE, KRB5, NTLM1, NTLM3 } sent;
  int have_krb5;
  int have_ntlm;
  OM_uint32 flags;
  char creds[MAX_CREDS_LENGTH];
};

OM_uint32 gss_init_sec_context(OM_uint32 *min,
            gss_const_cred_id_t initiator_cred_handle,
            gss_ctx_id_t *context_handle,
            gss_const_name_t target_name,
            const gss_OID mech_type,
            OM_uint32 req_flags,
            OM_uint32 time_req,
            const gss_channel_bindings_t input_chan_bindings,
            const gss_buffer_t input_token,
            gss_OID *actual_mech_type,
            gss_buffer_t output_token,
            OM_uint32 *ret_flags,
            OM_uint32 *time_rec)
{
  /* The token will be encoded in base64 */
  int length = APPROX_TOKEN_LEN * 3 / 4;
  int used = 0;
  char *token = NULL;
  const char *creds = NULL;
  gss_ctx_id_t ctx = NULL;

  (void)initiator_cred_handle;
  (void)mech_type;
  (void)time_req;
  (void)input_chan_bindings;
  (void)actual_mech_type;

  if(!min)
    return GSS_S_FAILURE;

  *min = 0;

  if(!context_handle || !target_name || !output_token) {
    *min = GSS_INVALID_ARGS;
    return GSS_S_FAILURE;
  }

  creds = getenv("CURL_STUB_GSS_CREDS");
  if(!creds || strlen(creds) >= MAX_CREDS_LENGTH) {
    *min = GSS_INVALID_CREDS;
    return GSS_S_FAILURE;
  }

  ctx = *context_handle;
  if(ctx && strcmp(ctx->creds, creds)) {
    *min = GSS_INVALID_CREDS;
    return GSS_S_FAILURE;
  }

  output_token->length = 0;
  output_token->value = NULL;

  if(input_token && input_token->length) {
    if(!ctx) {
      *min = GSS_INVALID_CTX;
      return GSS_S_FAILURE;
    }

    /* Server response, either D (RA==) or C (Qw==) */
    if(((char *) input_token->value)[0] == 'D') {
      /* Done */
      switch(ctx->sent) {
      case KRB5:
      case NTLM3:
        if(ret_flags)
          *ret_flags = ctx->flags;
        if(time_rec)
          *time_rec = GSS_C_INDEFINITE;
        return GSS_S_COMPLETE;
      default:
        *min = GSS_SERVER_ERR;
        return GSS_S_FAILURE;
      }
    }

    if(((char *) input_token->value)[0] != 'C') {
      /* We only support Done or Continue */
      *min = GSS_SERVER_ERR;
      return GSS_S_FAILURE;
    }

    /* Continue */
    switch(ctx->sent) {
    case KRB5:
      /* We sent KRB5 and it failed, let's try NTLM */
      if(ctx->have_ntlm) {
        ctx->sent = NTLM1;
        break;
      }
      else {
        *min = GSS_SERVER_ERR;
        return GSS_S_FAILURE;
      }
    case NTLM1:
      ctx->sent = NTLM3;
      break;
    default:
      *min = GSS_SERVER_ERR;
      return GSS_S_FAILURE;
    }
  }
  else {
    if(ctx) {
      *min = GSS_INVALID_CTX;
      return GSS_S_FAILURE;
    }

    ctx = (gss_ctx_id_t) calloc(sizeof(*ctx), 1);
    if(!ctx) {
      *min = GSS_NO_MEMORY;
      return GSS_S_FAILURE;
    }

    if(strstr(creds, "KRB5"))
      ctx->have_krb5 = 1;

    if(strstr(creds, "NTLM"))
      ctx->have_ntlm = 1;

    if(ctx->have_krb5)
      ctx->sent = KRB5;
    else if(ctx->have_ntlm)
      ctx->sent = NTLM1;
    else {
      free(ctx);
      *min = GSS_NO_MECH;
      return GSS_S_FAILURE;
    }

    strcpy(ctx->creds, creds);
    ctx->flags = req_flags;
  }

  token = malloc(length);
  if(!token) {
    free(ctx);
    *min = GSS_NO_MEMORY;
    return GSS_S_FAILURE;
  }

  /* Token format: creds:target:type:padding */
  /* Note: this is using the *real* snprintf() and not the curl provided
     one */
  used = snprintf(token, length, "%s:%s:%d:", creds,
                  (char *) target_name, ctx->sent);

  if(used >= length) {
    free(token);
    free(ctx);
    *min = GSS_NO_MEMORY;
    return GSS_S_FAILURE;
  }

  /* Overwrite null terminator */
  memset(token + used, 'A', length - used);

  *context_handle = ctx;

  output_token->value = token;
  output_token->length = length;

  return GSS_S_CONTINUE_NEEDED;
}

OM_uint32 gss_delete_sec_context(OM_uint32 *min,
                                 gss_ctx_id_t *context_handle,
                                 gss_buffer_t output_token)
{
  (void)output_token;

  if(!min)
    return GSS_S_FAILURE;

  if(!context_handle) {
    *min = GSS_INVALID_CTX;
    return GSS_S_FAILURE;
  }

  free(*context_handle);
  *context_handle = NULL;
  *min = 0;

  return GSS_S_COMPLETE;
}

OM_uint32 gss_release_buffer(OM_uint32 *min,
                             gss_buffer_t buffer)
{
  if(min)
    *min = 0;

  if(buffer && buffer->length) {
    free(buffer->value);
    buffer->length = 0;
  }

  return GSS_S_COMPLETE;
}

OM_uint32 gss_import_name(OM_uint32 *min,
                          const gss_buffer_t input_name_buffer,
                          const gss_OID input_name_type,
                          gss_name_t *output_name)
{
  char *name = NULL;
  (void)input_name_type;

  if(!min)
    return GSS_S_FAILURE;

  if(!input_name_buffer || !output_name) {
    *min = GSS_INVALID_ARGS;
    return GSS_S_FAILURE;
  }

  name = strndup(input_name_buffer->value, input_name_buffer->length);
  if(!name) {
    *min = GSS_NO_MEMORY;
    return GSS_S_FAILURE;
  }

  *output_name = (gss_name_t) name;
  *min = 0;

  return GSS_S_COMPLETE;
}

OM_uint32 gss_release_name(OM_uint32 *min,
                           gss_name_t *input_name)
{
  if(min)
    *min = 0;

  if(input_name)
    free(*input_name);

  return GSS_S_COMPLETE;
}

OM_uint32 gss_display_status(OM_uint32 *min,
                             OM_uint32 status_value,
                             int status_type,
                             const gss_OID mech_type,
                             OM_uint32 *message_context,
                             gss_buffer_t status_string)
{
  const char maj_str[] = "Stub GSS error";
  (void)mech_type;
  if(min)
    *min = 0;

  if(message_context)
    *message_context = 0;

  if(status_string) {
    status_string->value = NULL;
    status_string->length = 0;

    if(status_value >= GSS_LAST)
      return GSS_S_FAILURE;

    switch(status_type) {
      case GSS_C_GSS_CODE:
        status_string->value = strdup(maj_str);
        break;
      case GSS_C_MECH_CODE:
        status_string->value = strdup(min_err_table[status_value]);
        break;
      default:
        return GSS_S_FAILURE;
    }

    if(status_string->value)
      status_string->length = strlen(status_string->value);
    else
      return GSS_S_FAILURE;
  }

  return GSS_S_COMPLETE;
}

/* Stubs returning error */

OM_uint32 gss_display_name(OM_uint32 *min,
                           gss_const_name_t input_name,
                           gss_buffer_t output_name_buffer,
                           gss_OID *output_name_type)
{
  (void)min;
  (void)input_name;
  (void)output_name_buffer;
  (void)output_name_type;
  return GSS_S_FAILURE;
}

OM_uint32 gss_inquire_context(OM_uint32 *min,
                              gss_const_ctx_id_t context_handle,
                              gss_name_t *src_name,
                              gss_name_t *targ_name,
                              OM_uint32 *lifetime_rec,
                              gss_OID *mech_type,
                              OM_uint32 *ctx_flags,
                              int *locally_initiated,
                              int *open_context)
{
  (void)min;
  (void)context_handle;
  (void)src_name;
  (void)targ_name;
  (void)lifetime_rec;
  (void)mech_type;
  (void)ctx_flags;
  (void)locally_initiated;
  (void)open_context;
  return GSS_S_FAILURE;
}

OM_uint32 gss_wrap(OM_uint32 *min,
                   gss_const_ctx_id_t context_handle,
                   int conf_req_flag,
                   gss_qop_t qop_req,
                   const gss_buffer_t input_message_buffer,
                   int *conf_state,
                   gss_buffer_t output_message_buffer)
{
  (void)min;
  (void)context_handle;
  (void)conf_req_flag;
  (void)qop_req;
  (void)input_message_buffer;
  (void)conf_state;
  (void)output_message_buffer;
  return GSS_S_FAILURE;
}

OM_uint32 gss_unwrap(OM_uint32 *min,
                     gss_const_ctx_id_t context_handle,
                     const gss_buffer_t input_message_buffer,
                     gss_buffer_t output_message_buffer,
                     int *conf_state,
                     gss_qop_t *qop_state)
{
  (void)min;
  (void)context_handle;
  (void)input_message_buffer;
  (void)output_message_buffer;
  (void)conf_state;
  (void)qop_state;
  return GSS_S_FAILURE;
}

OM_uint32 gss_seal(OM_uint32 *min,
                   gss_ctx_id_t context_handle,
                   int conf_req_flag,
                   int qop_req,
                   gss_buffer_t input_message_buffer,
                   int *conf_state,
                   gss_buffer_t output_message_buffer)
{
  (void)min;
  (void)context_handle;
  (void)conf_req_flag;
  (void)qop_req;
  (void)input_message_buffer;
  (void)conf_state;
  (void)output_message_buffer;
  return GSS_S_FAILURE;
}

OM_uint32 gss_unseal(OM_uint32 *min,
                     gss_ctx_id_t context_handle,
                     gss_buffer_t input_message_buffer,
                     gss_buffer_t output_message_buffer,
                     int *conf_state,
                     int *qop_state)
{
  (void)min;
  (void)context_handle;
  (void)input_message_buffer;
  (void)output_message_buffer;
  (void)conf_state;
  (void)qop_state;
  return GSS_S_FAILURE;
}
