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
#include "curl_trc.h"
#include "curlx/strcopy.h"

#ifdef DEBUGBUILD
#if defined(HAVE_GSSGNU) || !defined(_WIN32)
#define Curl_gss_alloc malloc  /* freed via the GSS API gss_release_buffer() */
#define Curl_gss_free  free    /* pair of the above */
#define CURL_GSS_STUB
/* For correctness this would be required for all platforms, not only Windows,
   but, as of v1.22.1, MIT Kerberos uses a special allocator only for Windows,
   and the availability of 'gssapi/gssapi_alloc.h' is difficult to detect,
   because GSS headers are not versioned, and there is also no other macro to
   indicate 1.18+ vs. previous versions. On Windows we can use 'GSS_S_BAD_MIC'.
 */
#elif defined(_WIN32) && defined(GSS_S_BAD_MIC) /* MIT Kerberos 1.15+ */
/* MIT Kerberos 1.10+ (Windows), 1.18+ (all platforms), missing from GNU GSS */
#include <gssapi/gssapi_alloc.h>
#define Curl_gss_alloc gssalloc_malloc
#define Curl_gss_free  gssalloc_free
#define CURL_GSS_STUB
#endif
#endif /* DEBUGBUILD */

#ifdef __GNUC__
#define CURL_ALIGN8  __attribute__((aligned(8)))
#else
#define CURL_ALIGN8
#endif

#if defined(CURL_HAVE_DIAG) && defined(__APPLE__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

gss_OID_desc Curl_spnego_mech_oid CURL_ALIGN8 = {
  6, CURL_UNCONST("\x2b\x06\x01\x05\x05\x02")
};
gss_OID_desc Curl_krb5_mech_oid CURL_ALIGN8 = {
  9, CURL_UNCONST("\x2a\x86\x48\x86\xf7\x12\x01\x02\x02")
};

#ifdef CURL_GSS_STUB
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

/* Stub credential: tracks which mechanisms are allowed */
struct stub_gss_cred_id_t_desc {
  int allow_krb5;
  int allow_ntlm;
};

static OM_uint32 stub_gss_init_sec_context(
  OM_uint32 *min,
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
    if(((char *)input_token->value)[0] == 'D') {
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

    if(((char *)input_token->value)[0] != 'C') {
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

    ctx = curlx_calloc(1, sizeof(*ctx));
    if(!ctx) {
      *min = STUB_GSS_NO_MEMORY;
      return GSS_S_FAILURE;
    }

    if(strstr(creds, "KRB5"))
      ctx->have_krb5 = 1;

    if(strstr(creds, "NTLM"))
      ctx->have_ntlm = 1;

    /* If a credential restricts allowed mechs, honour it */
    if(initiator_cred_handle != GSS_C_NO_CREDENTIAL) {
      struct stub_gss_cred_id_t_desc *cred =
        (struct stub_gss_cred_id_t_desc *)initiator_cred_handle;
      if(!cred->allow_krb5)
        ctx->have_krb5 = 0;
      if(!cred->allow_ntlm)
        ctx->have_ntlm = 0;
    }

    if(ctx->have_krb5)
      ctx->sent = STUB_GSS_KRB5;
    else if(ctx->have_ntlm)
      ctx->sent = STUB_GSS_NTLM1;
    else {
      curlx_free(ctx);
      *min = STUB_GSS_NO_MECH;
      return GSS_S_FAILURE;
    }

    curlx_strcopy(ctx->creds, sizeof(ctx->creds), creds, strlen(creds));
    ctx->flags = req_flags;
  }

  token = Curl_gss_alloc(length);
  if(!token) {
    curlx_free(ctx);
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
      Curl_gss_free(token);
      curlx_free(ctx);
      *min = STUB_GSS_NO_MEMORY;
      return GSS_S_FAILURE;
    }

    if(strlen(creds) + target_desc.length + 5 >= sizeof(ctx->creds)) {
      Curl_gss_free(token);
      curlx_free(ctx);
      *min = STUB_GSS_NO_MEMORY;
      return GSS_S_FAILURE;
    }

    /* Token format: creds:target:type:padding */
    used = curl_msnprintf(token, length, "%s:%.*s:%d:", creds,
                          (int)target_desc.length,
                          (const char *)target_desc.value,
                          ctx->sent);

    gss_release_buffer(&minor_status, &target_desc);
  }

  if(used >= length) {
    Curl_gss_free(token);
    curlx_free(ctx);
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

static OM_uint32 stub_gss_delete_sec_context(
  OM_uint32 *min,
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

  curlx_free(*context);
  *context = NULL;
  *min = 0;

  return GSS_S_COMPLETE;
}

/* NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10 */
static gss_OID_desc stub_ntlmssp_oid = {
  10, CURL_UNCONST("\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a")
};

static OM_uint32 stub_gss_inquire_context(
  OM_uint32 *min,
  struct stub_gss_ctx_id_t_desc *context,
  gss_name_t *src_name,
  gss_name_t *targ_name,
  OM_uint32 *lifetime_rec,
  gss_OID *mech_type,
  OM_uint32 *ctx_flags,
  int *locally_initiated,
  int *open_context)
{
  (void)src_name;
  (void)targ_name;
  (void)lifetime_rec;
  (void)ctx_flags;
  (void)locally_initiated;
  (void)open_context;

  if(!min)
    return GSS_S_FAILURE;

  if(!context) {
    *min = STUB_GSS_INVALID_CTX;
    return GSS_S_FAILURE;
  }

  *min = 0;
  if(mech_type) {
    switch(context->sent) {
    case STUB_GSS_NTLM1:
    case STUB_GSS_NTLM3:
      *mech_type = &stub_ntlmssp_oid;
      break;
    default:
      *mech_type = (gss_OID)&Curl_krb5_mech_oid;
      break;
    }
  }

  return GSS_S_COMPLETE;
}
static OM_uint32 stub_gss_acquire_cred(
  OM_uint32 *min,
  gss_name_t desired_name,
  OM_uint32 time_req,
  gss_OID_set desired_mechs,
  gss_cred_usage_t cred_usage,
  gss_cred_id_t *output_cred_handle,
  gss_OID_set *actual_mechs,
  OM_uint32 *time_rec)
{
  (void)desired_name;
  (void)time_req;
  (void)desired_mechs;
  (void)cred_usage;
  (void)actual_mechs;
  (void)time_rec;

  if(!min)
    return GSS_S_FAILURE;

  *min = 0;
  /* Allocate a stub credential that initially allows all mechanisms */
  if(output_cred_handle) {
    struct stub_gss_cred_id_t_desc *cred =
      curlx_calloc(1, sizeof(*cred));
    if(!cred) {
      *min = STUB_GSS_NO_MEMORY;
      return GSS_S_FAILURE;
    }
    cred->allow_krb5 = 1;
    cred->allow_ntlm = 1;
    *output_cred_handle = (gss_cred_id_t)cred;
  }
  return GSS_S_COMPLETE;
}

static OM_uint32 stub_gss_indicate_mechs(
  OM_uint32 *min,
  gss_OID_set *mech_set)
{
  const char *creds;
  OM_uint32 major;

  if(!min)
    return GSS_S_FAILURE;

  *min = 0;
  creds = getenv("CURL_STUB_GSS_CREDS");
  if(!creds) {
    *min = STUB_GSS_INVALID_CREDS;
    return GSS_S_FAILURE;
  }

  major = gss_create_empty_oid_set(min, mech_set);
  if(GSS_ERROR(major))
    return major;

  /* Always include Kerberos */
  gss_add_oid_set_member(min, (gss_OID)&Curl_krb5_mech_oid, mech_set);

  /* Include NTLM if the stub creds contain NTLM */
  if(strstr(creds, "NTLM"))
    gss_add_oid_set_member(min, &stub_ntlmssp_oid, mech_set);

  return GSS_S_COMPLETE;
}

#ifdef HAVE_GSS_SET_NEG_MECHS
static OM_uint32 stub_gss_set_neg_mechs(
  OM_uint32 *min,
  gss_cred_id_t cred_handle,
  const gss_OID_set mech_set)
{
  struct stub_gss_cred_id_t_desc *cred;
  size_t i;
  int found_krb5 = 0;
  int found_ntlm = 0;

  if(!min)
    return GSS_S_FAILURE;

  *min = 0;
  if(cred_handle == GSS_C_NO_CREDENTIAL)
    return GSS_S_FAILURE;

  cred = (struct stub_gss_cred_id_t_desc *)cred_handle;

  /* Determine which mechs are in the allowed set */
  if(mech_set) {
    for(i = 0; i < mech_set->count; i++) {
      gss_OID oid = &mech_set->elements[i];
      if(oid->length == Curl_krb5_mech_oid.length &&
         !memcmp(oid->elements, Curl_krb5_mech_oid.elements, oid->length))
        found_krb5 = 1;
      if(oid->length == stub_ntlmssp_oid.length &&
         !memcmp(oid->elements, stub_ntlmssp_oid.elements, oid->length))
        found_ntlm = 1;
    }
  }

  cred->allow_krb5 = found_krb5;
  cred->allow_ntlm = found_ntlm;
  return GSS_S_COMPLETE;
}
#endif /* HAVE_GSS_SET_NEG_MECHS */

static OM_uint32 stub_gss_release_cred(
  OM_uint32 *min,
  gss_cred_id_t *cred_handle)
{
  if(!min)
    return GSS_S_FAILURE;

  *min = 0;
  if(cred_handle && *cred_handle != GSS_C_NO_CREDENTIAL) {
    curlx_free(*cred_handle);
    *cred_handle = GSS_C_NO_CREDENTIAL;
  }
  return GSS_S_COMPLETE;
}

#endif /* CURL_GSS_STUB */

OM_uint32 Curl_gss_init_sec_context(struct Curl_easy *data,
                                    OM_uint32 *minor_status,
                                    gss_ctx_id_t *context,
                                    gss_name_t target_name,
                                    gss_OID mech_type,
                                    gss_channel_bindings_t input_chan_bindings,
                                    gss_buffer_t input_token,
                                    gss_buffer_t output_token,
                                    const bool mutual_auth,
                                    OM_uint32 *ret_flags,
                                    gss_cred_id_t cred_handle)
{
  OM_uint32 req_flags = GSS_C_REPLAY_FLAG;

  if(mutual_auth)
    req_flags |= GSS_C_MUTUAL_FLAG;

  if(data->set.gssapi_delegation & CURLGSSAPI_DELEGATION_POLICY_FLAG) {
#ifdef GSS_C_DELEG_POLICY_FLAG  /* MIT Kerberos 1.8+, missing from GNU GSS */
    req_flags |= GSS_C_DELEG_POLICY_FLAG;
#else
    infof(data, "WARNING: support for CURLGSSAPI_DELEGATION_POLICY_FLAG not "
          "compiled in");
#endif
  }

  if(data->set.gssapi_delegation & CURLGSSAPI_DELEGATION_FLAG)
    req_flags |= GSS_C_DELEG_FLAG;

#ifdef CURL_GSS_STUB
  if(getenv("CURL_STUB_GSS_CREDS"))
    return stub_gss_init_sec_context(minor_status,
                                     cred_handle,
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
#endif /* CURL_GSS_STUB */

  return gss_init_sec_context(minor_status,
                              cred_handle,
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
#ifdef CURL_GSS_STUB
  if(getenv("CURL_STUB_GSS_CREDS"))
    return stub_gss_delete_sec_context(min,
                                     (struct stub_gss_ctx_id_t_desc **)context,
                                     output_token);
#endif /* CURL_GSS_STUB */

  return gss_delete_sec_context(min, context, output_token);
}

OM_uint32 Curl_gss_inquire_context(OM_uint32 *minor_status,
                                   gss_ctx_id_t context,
                                   gss_OID *mech_type)
{
#ifdef CURL_GSS_STUB
  if(getenv("CURL_STUB_GSS_CREDS"))
    return stub_gss_inquire_context(minor_status,
                             (struct stub_gss_ctx_id_t_desc *)context,
                             NULL, NULL, NULL, mech_type,
                             NULL, NULL, NULL);
#endif /* CURL_GSS_STUB */

  return gss_inquire_context(minor_status, context,
                             NULL, NULL, NULL, mech_type,
                             NULL, NULL, NULL);
}

OM_uint32 Curl_gss_acquire_cred(OM_uint32 *minor_status,
                                gss_name_t desired_name,
                                OM_uint32 time_req,
                                gss_OID_set desired_mechs,
                                gss_cred_usage_t cred_usage,
                                gss_cred_id_t *output_cred_handle,
                                gss_OID_set *actual_mechs,
                                OM_uint32 *time_rec)
{
#ifdef CURL_GSS_STUB
  if(getenv("CURL_STUB_GSS_CREDS"))
    return stub_gss_acquire_cred(minor_status, desired_name, time_req,
                                 desired_mechs, cred_usage,
                                 output_cred_handle, actual_mechs, time_rec);
#endif /* CURL_GSS_STUB */

  return gss_acquire_cred(minor_status, desired_name, time_req,
                          desired_mechs, cred_usage,
                          output_cred_handle, actual_mechs, time_rec);
}

OM_uint32 Curl_gss_indicate_mechs(OM_uint32 *minor_status,
                                  gss_OID_set *mech_set)
{
#ifdef CURL_GSS_STUB
  if(getenv("CURL_STUB_GSS_CREDS"))
    return stub_gss_indicate_mechs(minor_status, mech_set);
#endif /* CURL_GSS_STUB */

  return gss_indicate_mechs(minor_status, mech_set);
}

#ifdef HAVE_GSS_SET_NEG_MECHS
OM_uint32 Curl_gss_set_neg_mechs(OM_uint32 *minor_status,
                                 gss_cred_id_t cred_handle,
                                 const gss_OID_set mech_set)
{
#ifdef CURL_GSS_STUB
  if(getenv("CURL_STUB_GSS_CREDS"))
    return stub_gss_set_neg_mechs(minor_status, cred_handle, mech_set);
#endif /* CURL_GSS_STUB */

  return gss_set_neg_mechs(minor_status, cred_handle, mech_set);
}
#endif /* HAVE_GSS_SET_NEG_MECHS */

OM_uint32 Curl_gss_release_cred(OM_uint32 *minor_status,
                                gss_cred_id_t *cred_handle)
{
#ifdef CURL_GSS_STUB
  if(getenv("CURL_STUB_GSS_CREDS"))
    return stub_gss_release_cred(minor_status, cred_handle);
#endif /* CURL_GSS_STUB */

  return gss_release_cred(minor_status, cred_handle);
}

#ifdef CURLVERBOSE
#define GSS_LOG_BUFFER_LEN 1024
static size_t display_gss_error(OM_uint32 status, int type,
                                char *buf, size_t len)
{
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
        len += curl_msnprintf(buf + len, GSS_LOG_BUFFER_LEN - len,
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
  char buf[GSS_LOG_BUFFER_LEN] = "";
  size_t len = 0;

  if(major != GSS_S_FAILURE)
    len = display_gss_error(major, GSS_C_GSS_CODE, buf, len);

  display_gss_error(minor, GSS_C_MECH_CODE, buf, len);

  infof(data, "%s%s", prefix, buf);
}
#endif /* CURLVERBOSE */

#if defined(CURL_HAVE_DIAG) && defined(__APPLE__)
#pragma GCC diagnostic pop
#endif

#endif /* HAVE_GSSAPI */
