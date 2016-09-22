/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2011 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef HAVE_GSSAPI

#include "curl_gssapi.h"
#include "sendf.h"

static char spnego_oid_bytes[] = "\x2b\x06\x01\x05\x05\x02";
gss_OID_desc Curl_spnego_mech_oid = { 6, &spnego_oid_bytes };
static char krb5_oid_bytes[] = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";
gss_OID_desc Curl_krb5_mech_oid = { 9, &krb5_oid_bytes };

OM_uint32 Curl_gss_init_sec_context(
    struct Curl_easy *data,
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
  gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;
  OM_uint32 major, discard, req_flags = GSS_C_REPLAY_FLAG;

#ifdef HAVE_GSS_CRED_STORE
#define MAX_CRED_STORE_ELEMENTS 2
  gss_key_value_element_desc store_elms[MAX_CRED_STORE_ELEMENTS];
  gss_key_value_set_desc cred_store;

  const char *ccache = data->set.str[STRING_KRB5_CCNAME];
  const char *client_kt = data->set.str[STRING_KRB5_CLIENT_KTNAME];

  if(ccache || client_kt) {
    cred_store.count = 0;
    cred_store.elements = store_elms;

    if(ccache) {
      cred_store.elements[cred_store.count].key = "ccache";
      cred_store.elements[cred_store.count].value = ccache;
      cred_store.count++;
    }

    if(client_kt) {
      cred_store.elements[cred_store.count].key = "client_keytab";
      cred_store.elements[cred_store.count].value = client_kt;
      cred_store.count++;
    }

    major = gss_acquire_cred_from(minor_status, GSS_C_NO_NAME,
                                  GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                                  GSS_C_INITIATE, &cred_store,
                                  &creds, NULL, NULL);
    if(GSS_ERROR(major)) {
      infof(data, "Warning: gss_acquire_cred_from() failed\n");
      return major;
    }
  }
#endif

  if(mutual_auth)
    req_flags |= GSS_C_MUTUAL_FLAG;

  if(data->set.gssapi_delegation & CURLGSSAPI_DELEGATION_POLICY_FLAG) {
#ifdef GSS_C_DELEG_POLICY_FLAG
    req_flags |= GSS_C_DELEG_POLICY_FLAG;
#else
    infof(data, "warning: support for CURLGSSAPI_DELEGATION_POLICY_FLAG not "
        "compiled in\n");
#endif
  }

  if(data->set.gssapi_delegation & CURLGSSAPI_DELEGATION_FLAG)
    req_flags |= GSS_C_DELEG_FLAG;

  major = gss_init_sec_context(minor_status,
                              creds, /* cred_handle */
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
  /* It is valid to pass GSS_C_NO_CREDENTIAL */
  gss_release_cred(&discard, &creds);

  return major;
}

#define GSS_LOG_BUFFER_LEN 1024
static size_t display_gss_error(OM_uint32 status, int type,
                                char *buf, size_t len) {
  OM_uint32 maj_stat;
  OM_uint32 min_stat;
  OM_uint32 msg_ctx = 0;
  gss_buffer_desc status_string;

  do {
    maj_stat = gss_display_status(&min_stat,
                                  status,
                                  type,
                                  GSS_C_NO_OID,
                                  &msg_ctx,
                                  &status_string);
    if(GSS_LOG_BUFFER_LEN > len + status_string.length + 3) {
      len += snprintf(buf + len, GSS_LOG_BUFFER_LEN - len,
                      "%.*s. ", (int)status_string.length,
                      (char*)status_string.value);
    }
    gss_release_buffer(&min_stat, &status_string);
  } while(!GSS_ERROR(maj_stat) && msg_ctx != 0);

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

  infof(data, "%s%s\n", prefix, buf);
}

#endif /* HAVE_GSSAPI */
