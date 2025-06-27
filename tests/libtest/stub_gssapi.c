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

/* Only provides the bare minimum to link with libcurl */
/* Roughly based on Heimdal's gssapi.h */

/* !checksrc! disable TYPEDEFSTRUCT all */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#define GSS_ERROR(status) (status & 0x80000000)

#define GSS_S_COMPLETE 0
#define GSS_S_FAILURE (0x80000000)
#define GSS_S_CONTINUE_NEEDED (1ul)

#define GSS_C_QOP_DEFAULT 0
#define GSS_C_NO_OID ((gss_OID) 0)
#define GSS_C_NO_NAME ((gss_name_t) 0)
#define GSS_C_NO_BUFFER ((gss_buffer_t) 0)
#define GSS_C_NO_CONTEXT ((gss_ctx_id_t) 0)
#define GSS_C_NO_CREDENTIAL ((gss_cred_id_t) 0)
#define GSS_C_NO_CHANNEL_BINDINGS ((gss_channel_bindings_t) 0)

#define GSS_C_NULL_OID GSS_C_NO_OID

#define GSS_C_EMPTY_BUFFER {0, NULL}

#define GSS_C_AF_INET 2

#define GSS_C_GSS_CODE 1
#define GSS_C_MECH_CODE 2

#define GSS_C_DELEG_FLAG 1
#define GSS_C_MUTUAL_FLAG 2
#define GSS_C_REPLAY_FLAG 4
#define GSS_C_CONF_FLAG 16
#define GSS_C_INTEG_FLAG 32

/*
 * Expiration time of 2^32-1 seconds means infinite lifetime for a
 * credential or security context
 */
#define GSS_C_INDEFINITE 0xfffffffful

#define GSS_C_NT_HOSTBASED_SERVICE NULL

typedef uint32_t OM_uint32;

typedef OM_uint32 gss_qop_t;

typedef struct gss_buffer_desc_struct {
  size_t length;
  void *value;
} gss_buffer_desc, *gss_buffer_t;

struct gss_cred_id_t_desc_struct;
typedef struct gss_cred_id_t_desc_struct *gss_cred_id_t;
typedef const struct gss_cred_id_t_desc_struct *gss_const_cred_id_t;

struct gss_ctx_id_t_desc_struct;
typedef struct gss_ctx_id_t_desc_struct *gss_ctx_id_t;
typedef const struct gss_ctx_id_t_desc_struct *gss_const_ctx_id_t;

struct gss_name_t_desc_struct;
typedef struct gss_name_t_desc_struct *gss_name_t;
typedef const struct gss_name_t_desc_struct *gss_const_name_t;

typedef struct gss_OID_desc_struct {
  OM_uint32 length;
  void      *elements;
} gss_OID_desc, *gss_OID;

typedef struct gss_channel_bindings_struct {
  OM_uint32 initiator_addrtype;
  gss_buffer_desc initiator_address;
  OM_uint32 acceptor_addrtype;
  gss_buffer_desc acceptor_address;
  gss_buffer_desc application_data;
} *gss_channel_bindings_t;

OM_uint32 gss_init_sec_context(OM_uint32 *minor_status,
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
            OM_uint32 *time_rec);

OM_uint32 gss_delete_sec_context(OM_uint32 *minor_status,
                                 gss_ctx_id_t *context_handle,
                                 gss_buffer_t output_token);

OM_uint32 gss_display_status(OM_uint32 *minor_status,
                             OM_uint32 status_value,
                             int status_type,
                             const gss_OID mech_type,
                             OM_uint32 *message_context,
                             gss_buffer_t status_string);

/* upstream prototypes */
OM_uint32 gss_release_buffer(OM_uint32 * /* minor_status */,
                             gss_buffer_t /* buffer */);

OM_uint32 gss_display_name(OM_uint32 * /* minor_status */,
                           gss_const_name_t /* input_name */,
                           gss_buffer_t /* output_name_buffer */,
                           gss_OID * /* output_name_type */);

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

/* simple implementation of strndup(), which isn't portable */
static char *my_strndup(const char *ptr, size_t len)
{
  char *copy = malloc(len + 1);
  if(!copy)
    return NULL;
  memcpy(copy, ptr, len);
  copy[len] = '\0';
  return copy;
}

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
  size_t length = APPROX_TOKEN_LEN * 3 / 4;
  size_t used = 0;
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

    ctx = (gss_ctx_id_t) calloc(1, sizeof(*ctx));
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

  {
    gss_buffer_desc target_desc;
    gss_OID name_type = GSS_C_NO_OID;
    OM_uint32 minor_status;
    OM_uint32 major_status;
    major_status = gss_display_name(&minor_status, target_name,
                                    &target_desc, &name_type);
    if(GSS_ERROR(major_status)) {
      free(token);
      free(ctx);
      *min = GSS_NO_MEMORY;
      return GSS_S_FAILURE;
    }

    /* Token format: creds:target:type:padding */
    /* Note: this is using the *real* snprintf() and not the curl provided
       one */
    used = (size_t) snprintf(token, length, "%s:%s:%d:", creds,
                             (const char *)target_desc.value, ctx->sent);

    gss_release_buffer(&minor_status, &target_desc);
  }

  if(used >= length) {
    free(token);
    free(ctx);
    *min = GSS_NO_MEMORY;
    return GSS_S_FAILURE;
  }

  /* Overwrite null-terminator */
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

OM_uint32 gss_display_status(OM_uint32 *min,
                             OM_uint32 status_value,
                             int status_type,
                             const gss_OID mech_type,
                             OM_uint32 *message_context,
                             gss_buffer_t status_string)
{
  static const char maj_str[] = "Stub GSS error";
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
