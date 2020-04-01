/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2020, Simo Sorce, <simo@redhat.com>, et al.
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

#if defined(USE_GSSNTLMSSP) && defined(USE_NTLM)

#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_ntlmssp.h>

#include <curl/curl.h>

#include "vauth/vauth.h"
#include "vtls/vtls.h"
#include "urldata.h"
#include "curl_base64.h"
#include "curl_ntlm_core.h"
#include "warnless.h"
#include "curl_multibyte.h"
#include "sendf.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))

const gss_OID_desc gssntlmssp_mech_desc = {
  GSS_NTLMSSP_OID_LENGTH, discard_const(GSS_NTLMSSP_OID_STRING)
};
gss_const_OID gssntlmssp_mech = &gssntlmssp_mech_desc;

const gss_OID_set_desc gssntlmssp_mech_set_desc = {
  1, discard_const(&gssntlmssp_mech_desc)
};
gss_const_OID_set gssntlmssp_mech_set = &gssntlmssp_mech_set_desc;

/*
 * Curl_auth_is_ntlm_supported()
 *
 * This is used to evaluate if NTLM is supported.
 *
 * Parameters: None
 *
 * Returns TRUE if NTLM is supported by GSSAPI.
 */
bool Curl_auth_is_ntlm_supported(void)
{
  OM_uint32 maj, min;
  gss_OID_set mechs;
  bool ret = false;

  maj = gss_indicate_mechs(&min, &mechs);
  if(maj != GSS_S_COMPLETE) {
    return false;
  }

  for(size_t i = 0; i < mechs->count; i++) {
    if(gss_oid_equal(&mechs->elements[i], gssntlmssp_mech)) {
      ret = true;
    }
  }

  gss_release_oid_set(&min, &mechs);
  return ret;
}

/*
 * Curl_auth_create_ntlm_type1_message()
 *
 * This is used to generate an already encoded NTLM type-1 message ready for
 * sending to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * userp   [in]     - The user name in the format User or Domain\User.
 * passwdp [in]     - The user's password.
 * service [in]     - The service type such as http, smtp, pop or imap.
 * host    [in]     - The host name.
 * ntlm    [in/out] - The NTLM data struct being used and modified.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_auth_create_ntlm_type1_message(struct Curl_easy *data,
                                             const char *userp,
                                             const char *passwdp,
                                             const char *service,
                                             const char *host,
                                             struct ntlmdata *ntlm,
                                             char **outptr, size_t *outlen)
{
  CURLcode result = CURLE_OK;
  OM_uint32 maj, min;
  char *spn = NULL;
  gss_buffer_desc spnb;
  gss_buffer_desc userb;
  gss_name_t username = GSS_C_NO_NAME;
  gss_buffer_desc token = {0};
  gss_channel_bindings_t cb = GSS_C_NO_CHANNEL_BINDINGS;
  unsigned int cb_len = 0;
  void *cb_data = NULL;

  /* throw away any old cred */
  Curl_auth_cleanup_ntlm(ntlm);

  /* cb only filled if CBs are available */
  (void)Curl_ssl_get_tls_channel_binding(data->conn,
                                         CURL_SSL_CB_TLS_SERVER_END_POINT,
                                         &cb_data, &cb_len);
  if(cb_data) {
    ntlm->cb.application_data.value = cb_data;
    ntlm->cb.application_data.length = cb_len;
    cb = &ntlm->cb;
  }

  /* target name, GSSAPI wants a SPN formatted as svc@host */
  spn = Curl_auth_build_spn(service, NULL, host);
  if(!spn)
    return CURLE_CONV_FAILED;

  spnb.value = spn;
  spnb.length = strlen(spn);
  maj = gss_import_name(&min, &spnb, GSS_C_NT_HOSTBASED_SERVICE, &ntlm->spn);
  if(maj != GSS_S_COMPLETE) {
    result = CURLE_CONV_FAILED;
    goto done;
  }

  /* Turn user name into a GSS NAME */
  if(userp && *userp) {
    userb.value = discard_const(userp);
    userb.length = strlen(userp);
    maj = gss_import_name(&min, &userb, GSS_C_NT_USER_NAME, &username);
    if(maj != GSS_S_COMPLETE) {
      result = CURLE_CONV_FAILED;
      goto done;
    }
  }

  /* acquire creds */
  if(passwdp && *passwdp) {
    gss_buffer_desc passwdb;

    passwdb.value = discard_const(passwdp);
    passwdb.length = strlen(passwdp);
    maj = gss_acquire_cred_with_password(&min, username, &passwdb,
                                         GSS_C_INDEFINITE,
                                         discard_const(gssntlmssp_mech_set),
                                         GSS_C_INITIATE,
                                         &ntlm->cred, NULL, NULL);
  }
  else {
    maj = gss_acquire_cred(&min, username, GSS_C_INDEFINITE,
                           discard_const(gssntlmssp_mech_set), GSS_C_INITIATE,
                           &ntlm->cred, NULL, NULL);
  }
  if(maj != GSS_S_COMPLETE) {
    result = CURLE_AUTH_ERROR;
    goto done;
  }

  maj = gss_init_sec_context(&min, ntlm->cred, &ntlm->context, ntlm->spn,
                             discard_const(gssntlmssp_mech), 0, 0,
                             cb, GSS_C_NO_BUFFER,
                             NULL, &token, NULL, NULL);
  if(maj != GSS_S_COMPLETE && maj != GSS_S_CONTINUE_NEEDED) {
    result = CURLE_AUTH_ERROR;
    goto done;
  }

  result = Curl_base64_encode(data, token.value, token.length, outptr, outlen);

done:
  gss_release_name(&min, &username);
  gss_release_buffer(&min, &token);
  free(spn);
  return result;
}

/*
 * Curl_auth_decode_ntlm_type2_message()
 *
 * This is used to decode an already encoded NTLM type-2 message.
 *
 * Parameters:
 *
 * data     [in]     - The session handle.
 * type2msg [in]     - The base64 encoded type-2 message.
 * ntlm     [in/out] - The NTLM data struct being used and modified.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_auth_decode_ntlm_type2_message(struct Curl_easy *data,
                                             const char *type2msg,
                                             struct ntlmdata *ntlm)
{
  CURLcode result = CURLE_OK;
  unsigned char *type2 = NULL;
  size_t type2_len = 0;

  /* Decode the base-64 encoded type-2 message */
  if(strlen(type2msg) && *type2msg != '=') {
    result = Curl_base64_decode(type2msg, &type2, &type2_len);
    if(result)
      return result;
  }

  /* Ensure we have a valid type-2 message */
  if(!type2) {
    infof(data, "NTLM handshake failure (empty type-2 message)\n");
    return CURLE_BAD_CONTENT_ENCODING;
  }

  /* Simply store the challenge for use later */
  ntlm->input_token.value = type2;
  ntlm->input_token.length = type2_len;

  return result;
}

/*
 * Curl_auth_create_ntlm_type3_message()
 *
 * This is used to generate an already encoded NTLM type-3 message ready for
 * sending to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * userp   [in]     - The user name in the format User or Domain\User.
 * passwdp [in]     - The user's password.
 * ntlm    [in/out] - The NTLM data struct being used and modified.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_auth_create_ntlm_type3_message(struct Curl_easy *data,
                                             const char *userp UNUSED_PARAM,
                                             const char *passwdp UNUSED_PARAM,
                                             struct ntlmdata *ntlm,
                                             char **outptr, size_t *outlen)
{
  CURLcode result = CURLE_OK;
  OM_uint32 maj, min;
  gss_buffer_desc token = {0};
  gss_channel_bindings_t cb = GSS_C_NO_CHANNEL_BINDINGS;

  if(ntlm->cb.application_data.value)
    cb = &ntlm->cb;

  maj = gss_init_sec_context(&min, ntlm->cred, &ntlm->context, ntlm->spn,
                             discard_const(gssntlmssp_mech), 0, 0,
                             cb, &ntlm->input_token,
                             NULL, &token, NULL, NULL);
  if(maj != GSS_S_COMPLETE) {
    result = CURLE_AUTH_ERROR;
    goto done;
  }

  result = Curl_base64_encode(data, token.value, token.length, outptr, outlen);

  /* it's done by now, free data */
  Curl_auth_cleanup_ntlm(ntlm);

done:
  gss_release_buffer(&min, &token);
  return result;
}

/*
 * Curl_auth_cleanup_ntlm()
 *
 * This is used to clean up the NTLM specific data.
 *
 * Parameters:
 *
 * ntlm    [in/out] - The NTLM data struct being cleaned up.
 *
 */
void Curl_auth_cleanup_ntlm(struct ntlmdata *ntlm)
{
  OM_uint32 min;

  /* Free Security Context */
  gss_delete_sec_context(&min, &ntlm->context, NULL);

  /* Free Credetnials */
  gss_release_cred(&min, &ntlm->cred);

  /* Free Target Name */
  gss_release_name(&min, &ntlm->spn);

  /* Reset bindings */
  gss_release_buffer(&min, &ntlm->cb.application_data);
}

#endif /* USE_GSSNTLSSP && USE_NTLM */
