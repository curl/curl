/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) Markus Moeller, <markus_moeller@compuserve.com>
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

#if defined(HAVE_GSSAPI) && !defined(CURL_DISABLE_PROXY)

#include "curl_gssapi.h"
#include "urldata.h"
#include "sendf.h"
#include "cfilters.h"
#include "connect.h"
#include "timeval.h"
#include "socks.h"
#include "warnless.h"
#include "strdup.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#if defined(__GNUC__) && defined(__APPLE__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#define MAX_GSS_LEN 1024

static gss_ctx_id_t gss_context = GSS_C_NO_CONTEXT;

/*
 * Helper GSS-API error functions.
 */
static int check_gss_err(struct Curl_easy *data,
                         OM_uint32 major_status,
                         OM_uint32 minor_status,
                         const char *function)
{
  if(GSS_ERROR(major_status)) {
    OM_uint32 maj_stat, min_stat;
    OM_uint32 msg_ctx = 0;
    gss_buffer_desc status_string = GSS_C_EMPTY_BUFFER;
    struct dynbuf dbuf;

    Curl_dyn_init(&dbuf, MAX_GSS_LEN);
    msg_ctx = 0;
    while(!msg_ctx) {
      /* convert major status code (GSS-API error) to text */
      maj_stat = gss_display_status(&min_stat, major_status,
                                    GSS_C_GSS_CODE,
                                    GSS_C_NULL_OID,
                                    &msg_ctx, &status_string);
      if(maj_stat == GSS_S_COMPLETE) {
        if(Curl_dyn_addn(&dbuf, status_string.value,
                         status_string.length))
          return 1; /* error */
        gss_release_buffer(&min_stat, &status_string);
        break;
      }
      gss_release_buffer(&min_stat, &status_string);
    }
    if(Curl_dyn_addn(&dbuf, ".\n", 2))
      return 1; /* error */
    msg_ctx = 0;
    while(!msg_ctx) {
      /* convert minor status code (underlying routine error) to text */
      maj_stat = gss_display_status(&min_stat, minor_status,
                                    GSS_C_MECH_CODE,
                                    GSS_C_NULL_OID,
                                    &msg_ctx, &status_string);
      if(maj_stat == GSS_S_COMPLETE) {
        if(Curl_dyn_addn(&dbuf, status_string.value,
                         status_string.length))
          return 1; /* error */
        gss_release_buffer(&min_stat, &status_string);
        break;
      }
      gss_release_buffer(&min_stat, &status_string);
    }
    failf(data, "GSS-API error: %s failed: %s", function, Curl_dyn_ptr(&dbuf));
    Curl_dyn_free(&dbuf);
    return 1;
  }

  return 0;
}

CURLcode Curl_SOCKS5_gssapi_negotiate(struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  struct connectdata *conn = cf->conn;
  curl_socket_t sock = conn->sock[cf->sockindex];
  CURLcode code;
  ssize_t actualread;
  ssize_t nwritten;
  int result;
  OM_uint32 gss_major_status, gss_minor_status, gss_status;
  OM_uint32 gss_ret_flags;
  int gss_conf_state, gss_enc;
  gss_buffer_desc  service = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc  gss_send_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc  gss_recv_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc  gss_w_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc *gss_token = GSS_C_NO_BUFFER;
  gss_name_t       server = GSS_C_NO_NAME;
  gss_name_t       gss_client_name = GSS_C_NO_NAME;
  unsigned short   us_length;
  char             *user = NULL;
  unsigned char socksreq[4]; /* room for GSS-API exchange header only */
  const char *serviceptr = data->set.str[STRING_PROXY_SERVICE_NAME] ?
                           data->set.str[STRING_PROXY_SERVICE_NAME] : "rcmd";
  const size_t serviceptr_length = strlen(serviceptr);

  /*   GSS-API request looks like
   * +----+------+-----+----------------+
   * |VER | MTYP | LEN |     TOKEN      |
   * +----+------+----------------------+
   * | 1  |  1   |  2  | up to 2^16 - 1 |
   * +----+------+-----+----------------+
   */

  /* prepare service name */
  if(strchr(serviceptr, '/')) {
    service.length = serviceptr_length;
    service.value = Curl_memdup(serviceptr, service.length);
    if(!service.value)
      return CURLE_OUT_OF_MEMORY;

    gss_major_status = gss_import_name(&gss_minor_status, &service,
                                       (gss_OID) GSS_C_NULL_OID, &server);
  }
  else {
    service.value = MALLOC(serviceptr_length +
                           strlen(conn->socks_proxy.host.name) + 2);
    if(!service.value)
      return CURLE_OUT_OF_MEMORY;
    service.length = serviceptr_length +
      strlen(conn->socks_proxy.host.name) + 1;
    msnprintf(service.value, service.length + 1, "%s@%s",
              serviceptr, conn->socks_proxy.host.name);

    gss_major_status = gss_import_name(&gss_minor_status, &service,
                                       GSS_C_NT_HOSTBASED_SERVICE, &server);
  }

  gss_release_buffer(&gss_status, &service); /* clear allocated memory */

  if(check_gss_err(data, gss_major_status,
                   gss_minor_status, "gss_import_name()")) {
    failf(data, "Failed to create service name.");
    gss_release_name(&gss_status, &server);
    return CURLE_COULDNT_CONNECT;
  }

  (void)curlx_nonblock(sock, FALSE);

  /* As long as we need to keep sending some context info, and there is no  */
  /* errors, keep sending it...                                            */
  for(;;) {
    gss_major_status = Curl_gss_init_sec_context(data,
                                                 &gss_minor_status,
                                                 &gss_context,
                                                 server,
                                                 &Curl_krb5_mech_oid,
                                                 NULL,
                                                 gss_token,
                                                 &gss_send_token,
                                                 TRUE,
                                                 &gss_ret_flags);

    if(gss_token != GSS_C_NO_BUFFER)
      gss_release_buffer(&gss_status, &gss_recv_token);
    if(check_gss_err(data, gss_major_status,
                     gss_minor_status, "gss_init_sec_context")) {
      gss_release_name(&gss_status, &server);
      gss_release_buffer(&gss_status, &gss_recv_token);
      gss_release_buffer(&gss_status, &gss_send_token);
      gss_delete_sec_context(&gss_status, &gss_context, NULL);
      failf(data, "Failed to initial GSS-API token.");
      return CURLE_COULDNT_CONNECT;
    }

    if(gss_send_token.length) {
      socksreq[0] = 1;    /* GSS-API subnegotiation version */
      socksreq[1] = 1;    /* authentication message type */
      us_length = htons((unsigned short)gss_send_token.length);
      memcpy(socksreq + 2, &us_length, sizeof(short));

      nwritten = Curl_conn_cf_send(cf->next, data, (char *)socksreq, 4,
                                   FALSE, &code);
      if(code || (4 != nwritten)) {
        failf(data, "Failed to send GSS-API authentication request.");
        gss_release_name(&gss_status, &server);
        gss_release_buffer(&gss_status, &gss_recv_token);
        gss_release_buffer(&gss_status, &gss_send_token);
        gss_delete_sec_context(&gss_status, &gss_context, NULL);
        return CURLE_COULDNT_CONNECT;
      }

      nwritten = Curl_conn_cf_send(cf->next, data,
                                   (char *)gss_send_token.value,
                                   gss_send_token.length, FALSE, &code);
      if(code || ((ssize_t)gss_send_token.length != nwritten)) {
        failf(data, "Failed to send GSS-API authentication token.");
        gss_release_name(&gss_status, &server);
        gss_release_buffer(&gss_status, &gss_recv_token);
        gss_release_buffer(&gss_status, &gss_send_token);
        gss_delete_sec_context(&gss_status, &gss_context, NULL);
        return CURLE_COULDNT_CONNECT;
      }

    }

    gss_release_buffer(&gss_status, &gss_send_token);
    gss_release_buffer(&gss_status, &gss_recv_token);
    if(gss_major_status != GSS_S_CONTINUE_NEEDED)
      break;

    /* analyse response */

    /*   GSS-API response looks like
     * +----+------+-----+----------------+
     * |VER | MTYP | LEN |     TOKEN      |
     * +----+------+----------------------+
     * | 1  |  1   |  2  | up to 2^16 - 1 |
     * +----+------+-----+----------------+
     */

    result = Curl_blockread_all(cf, data, (char *)socksreq, 4, &actualread);
    if(result || (actualread != 4)) {
      failf(data, "Failed to receive GSS-API authentication response.");
      gss_release_name(&gss_status, &server);
      gss_delete_sec_context(&gss_status, &gss_context, NULL);
      return CURLE_COULDNT_CONNECT;
    }

    /* ignore the first (VER) byte */
    if(socksreq[1] == 255) { /* status / message type */
      failf(data, "User was rejected by the SOCKS5 server (%d %d).",
            socksreq[0], socksreq[1]);
      gss_release_name(&gss_status, &server);
      gss_delete_sec_context(&gss_status, &gss_context, NULL);
      return CURLE_COULDNT_CONNECT;
    }

    if(socksreq[1] != 1) { /* status / message type */
      failf(data, "Invalid GSS-API authentication response type (%d %d).",
            socksreq[0], socksreq[1]);
      gss_release_name(&gss_status, &server);
      gss_delete_sec_context(&gss_status, &gss_context, NULL);
      return CURLE_COULDNT_CONNECT;
    }

    memcpy(&us_length, socksreq + 2, sizeof(short));
    us_length = ntohs(us_length);

    gss_recv_token.length = us_length;
    gss_recv_token.value = MALLOC(us_length);
    if(!gss_recv_token.value) {
      failf(data,
            "Could not allocate memory for GSS-API authentication "
            "response token.");
      gss_release_name(&gss_status, &server);
      gss_delete_sec_context(&gss_status, &gss_context, NULL);
      return CURLE_OUT_OF_MEMORY;
    }

    result = Curl_blockread_all(cf, data, (char *)gss_recv_token.value,
                                gss_recv_token.length, &actualread);

    if(result || (actualread != us_length)) {
      failf(data, "Failed to receive GSS-API authentication token.");
      gss_release_name(&gss_status, &server);
      gss_release_buffer(&gss_status, &gss_recv_token);
      gss_delete_sec_context(&gss_status, &gss_context, NULL);
      return CURLE_COULDNT_CONNECT;
    }

    gss_token = &gss_recv_token;
  }

  gss_release_name(&gss_status, &server);

  /* Everything is good so far, user was authenticated! */
  gss_major_status = gss_inquire_context(&gss_minor_status, gss_context,
                                         &gss_client_name, NULL, NULL, NULL,
                                         NULL, NULL, NULL);
  if(check_gss_err(data, gss_major_status,
                   gss_minor_status, "gss_inquire_context")) {
    gss_delete_sec_context(&gss_status, &gss_context, NULL);
    gss_release_name(&gss_status, &gss_client_name);
    failf(data, "Failed to determine username.");
    return CURLE_COULDNT_CONNECT;
  }
  gss_major_status = gss_display_name(&gss_minor_status, gss_client_name,
                                      &gss_send_token, NULL);
  if(check_gss_err(data, gss_major_status,
                   gss_minor_status, "gss_display_name")) {
    gss_delete_sec_context(&gss_status, &gss_context, NULL);
    gss_release_name(&gss_status, &gss_client_name);
    gss_release_buffer(&gss_status, &gss_send_token);
    failf(data, "Failed to determine username.");
    return CURLE_COULDNT_CONNECT;
  }
  user = MALLOC(gss_send_token.length + 1);
  if(!user) {
    gss_delete_sec_context(&gss_status, &gss_context, NULL);
    gss_release_name(&gss_status, &gss_client_name);
    gss_release_buffer(&gss_status, &gss_send_token);
    return CURLE_OUT_OF_MEMORY;
  }

  memcpy(user, gss_send_token.value, gss_send_token.length);
  user[gss_send_token.length] = '\0';
  gss_release_name(&gss_status, &gss_client_name);
  gss_release_buffer(&gss_status, &gss_send_token);
  infof(data, "SOCKS5 server authenticated user %s with GSS-API.",user);
  FREE(user);
  user = NULL;

  /* Do encryption */
  socksreq[0] = 1;    /* GSS-API subnegotiation version */
  socksreq[1] = 2;    /* encryption message type */

  gss_enc = 0; /* no data protection */
  /* do confidentiality protection if supported */
  if(gss_ret_flags & GSS_C_CONF_FLAG)
    gss_enc = 2;
  /* else do integrity protection */
  else if(gss_ret_flags & GSS_C_INTEG_FLAG)
    gss_enc = 1;

  infof(data, "SOCKS5 server supports GSS-API %s data protection.",
        (gss_enc == 0) ? "no" :
        ((gss_enc == 1) ? "integrity" : "confidentiality"));
  /* force for the moment to no data protection */
  gss_enc = 0;
  /*
   * Sending the encryption type in clear seems wrong. It should be
   * protected with gss_seal()/gss_wrap(). See RFC1961 extract below
   * The NEC reference implementations on which this is based is
   * therefore at fault
   *
   *  +------+------+------+.......................+
   *  + ver  | mtyp | len  |   token               |
   *  +------+------+------+.......................+
   *  + 0x01 | 0x02 | 0x02 | up to 2^16 - 1 octets |
   *  +------+------+------+.......................+
   *
   *   Where:
   *
   *  - "ver" is the protocol version number, here 1 to represent the
   *    first version of the SOCKS/GSS-API protocol
   *
   *  - "mtyp" is the message type, here 2 to represent a protection
   *    -level negotiation message
   *
   *  - "len" is the length of the "token" field in octets
   *
   *  - "token" is the GSS-API encapsulated protection level
   *
   * The token is produced by encapsulating an octet containing the
   * required protection level using gss_seal()/gss_wrap() with conf_req
   * set to FALSE. The token is verified using gss_unseal()/
   * gss_unwrap().
   *
   */
  if(data->set.socks5_gssapi_nec) {
    us_length = htons((short)1);
    memcpy(socksreq + 2, &us_length, sizeof(short));
  }
  else {
    gss_send_token.length = 1;
    gss_send_token.value = Curl_memdup(&gss_enc, 1);
    if(!gss_send_token.value) {
      gss_delete_sec_context(&gss_status, &gss_context, NULL);
      return CURLE_OUT_OF_MEMORY;
    }

    gss_major_status = gss_wrap(&gss_minor_status, gss_context, 0,
                                GSS_C_QOP_DEFAULT, &gss_send_token,
                                &gss_conf_state, &gss_w_token);

    if(check_gss_err(data, gss_major_status, gss_minor_status, "gss_wrap")) {
      gss_release_buffer(&gss_status, &gss_send_token);
      gss_release_buffer(&gss_status, &gss_w_token);
      gss_delete_sec_context(&gss_status, &gss_context, NULL);
      failf(data, "Failed to wrap GSS-API encryption value into token.");
      return CURLE_COULDNT_CONNECT;
    }
    gss_release_buffer(&gss_status, &gss_send_token);

    us_length = htons((unsigned short)gss_w_token.length);
    memcpy(socksreq + 2, &us_length, sizeof(short));
  }

  nwritten = Curl_conn_cf_send(cf->next, data, (char *)socksreq, 4, FALSE,
                               &code);
  if(code  || (4 != nwritten)) {
    failf(data, "Failed to send GSS-API encryption request.");
    gss_release_buffer(&gss_status, &gss_w_token);
    gss_delete_sec_context(&gss_status, &gss_context, NULL);
    return CURLE_COULDNT_CONNECT;
  }

  if(data->set.socks5_gssapi_nec) {
    memcpy(socksreq, &gss_enc, 1);
    nwritten = Curl_conn_cf_send(cf->next, data, (char *)socksreq, 1, FALSE,
                                 &code);
    if(code || ( 1 != nwritten)) {
      failf(data, "Failed to send GSS-API encryption type.");
      gss_delete_sec_context(&gss_status, &gss_context, NULL);
      return CURLE_COULDNT_CONNECT;
    }
  }
  else {
    nwritten = Curl_conn_cf_send(cf->next, data,
                                 (char *)gss_w_token.value,
                                 gss_w_token.length, FALSE, &code);
    if(code || ((ssize_t)gss_w_token.length != nwritten)) {
      failf(data, "Failed to send GSS-API encryption type.");
      gss_release_buffer(&gss_status, &gss_w_token);
      gss_delete_sec_context(&gss_status, &gss_context, NULL);
      return CURLE_COULDNT_CONNECT;
    }
    gss_release_buffer(&gss_status, &gss_w_token);
  }

  result = Curl_blockread_all(cf, data, (char *)socksreq, 4, &actualread);
  if(result || (actualread != 4)) {
    failf(data, "Failed to receive GSS-API encryption response.");
    gss_delete_sec_context(&gss_status, &gss_context, NULL);
    return CURLE_COULDNT_CONNECT;
  }

  /* ignore the first (VER) byte */
  if(socksreq[1] == 255) { /* status / message type */
    failf(data, "User was rejected by the SOCKS5 server (%d %d).",
          socksreq[0], socksreq[1]);
    gss_delete_sec_context(&gss_status, &gss_context, NULL);
    return CURLE_COULDNT_CONNECT;
  }

  if(socksreq[1] != 2) { /* status / message type */
    failf(data, "Invalid GSS-API encryption response type (%d %d).",
          socksreq[0], socksreq[1]);
    gss_delete_sec_context(&gss_status, &gss_context, NULL);
    return CURLE_COULDNT_CONNECT;
  }

  memcpy(&us_length, socksreq + 2, sizeof(short));
  us_length = ntohs(us_length);

  gss_recv_token.length = us_length;
  gss_recv_token.value = MALLOC(gss_recv_token.length);
  if(!gss_recv_token.value) {
    gss_delete_sec_context(&gss_status, &gss_context, NULL);
    return CURLE_OUT_OF_MEMORY;
  }
  result = Curl_blockread_all(cf, data, (char *)gss_recv_token.value,
                              gss_recv_token.length, &actualread);

  if(result || (actualread != us_length)) {
    failf(data, "Failed to receive GSS-API encryption type.");
    gss_release_buffer(&gss_status, &gss_recv_token);
    gss_delete_sec_context(&gss_status, &gss_context, NULL);
    return CURLE_COULDNT_CONNECT;
  }

  if(!data->set.socks5_gssapi_nec) {
    gss_major_status = gss_unwrap(&gss_minor_status, gss_context,
                                  &gss_recv_token, &gss_w_token,
                                  0, GSS_C_QOP_DEFAULT);

    if(check_gss_err(data, gss_major_status, gss_minor_status, "gss_unwrap")) {
      gss_release_buffer(&gss_status, &gss_recv_token);
      gss_release_buffer(&gss_status, &gss_w_token);
      gss_delete_sec_context(&gss_status, &gss_context, NULL);
      failf(data, "Failed to unwrap GSS-API encryption value into token.");
      return CURLE_COULDNT_CONNECT;
    }
    gss_release_buffer(&gss_status, &gss_recv_token);

    if(gss_w_token.length != 1) {
      failf(data, "Invalid GSS-API encryption response length (%zu).",
            gss_w_token.length);
      gss_release_buffer(&gss_status, &gss_w_token);
      gss_delete_sec_context(&gss_status, &gss_context, NULL);
      return CURLE_COULDNT_CONNECT;
    }

    memcpy(socksreq, gss_w_token.value, gss_w_token.length);
    gss_release_buffer(&gss_status, &gss_w_token);
  }
  else {
    if(gss_recv_token.length != 1) {
      failf(data, "Invalid GSS-API encryption response length (%zu).",
            gss_recv_token.length);
      gss_release_buffer(&gss_status, &gss_recv_token);
      gss_delete_sec_context(&gss_status, &gss_context, NULL);
      return CURLE_COULDNT_CONNECT;
    }

    memcpy(socksreq, gss_recv_token.value, gss_recv_token.length);
    gss_release_buffer(&gss_status, &gss_recv_token);
  }

  (void)curlx_nonblock(sock, TRUE);

  infof(data, "SOCKS5 access with%s protection granted.",
        (socksreq[0] == 0) ? "out GSS-API data":
        ((socksreq[0] == 1) ? " GSS-API integrity" :
         " GSS-API confidentiality"));

  conn->socks5_gssapi_enctype = socksreq[0];
  if(socksreq[0] == 0)
    gss_delete_sec_context(&gss_status, &gss_context, NULL);

  return CURLE_OK;
}

#if defined(__GNUC__) && defined(__APPLE__)
#pragma GCC diagnostic pop
#endif

#endif /* HAVE_GSSAPI && !CURL_DISABLE_PROXY */
