/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) David Bures
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
#include "unitcheck.h"

#ifdef USE_SCHANNEL
#include "urldata.h"
#include "cfilters.h"
#include "curl_sspi.h"
#include "vtls/schannel.h"
#include "vtls/schannel_int.h"
#include "vtls/vtls_int.h"

static const unsigned char t4782_token[] = { 1, 2, 3, 4, 5, 6, 7, 8 };

static struct {
  unsigned int generated;
  unsigned int freed;
  unsigned int sends;
  unsigned int blocks;
  size_t accepted;
  size_t first_write;
  CURLcode send_error;
  SECURITY_STATUS generate_error;
} t4782;

static SECURITY_STATUS SEC_ENTRY t4782_apply(PCtxtHandle context,
                                            PSecBufferDesc input_desc)
{
  (void)context;
  fail_unless(input_desc->cBuffers == 1, "one shutdown input buffer");
  fail_unless(*(DWORD *)input_desc->pBuffers[0].pvBuffer == SCHANNEL_SHUTDOWN,
              "shutdown token");
  return SEC_E_OK;
}

static SECURITY_STATUS SEC_ENTRY t4782_generate(
  PCredHandle credential, PCtxtHandle context, TCHAR *target,
  unsigned long flags, unsigned long reserved, unsigned long representation,
  PSecBufferDesc input_desc, unsigned long reserved2, PCtxtHandle new_context,
  PSecBufferDesc output_desc, unsigned long *attributes, PTimeStamp expiry)
{
  SecBuffer *token = &output_desc->pBuffers[0];
  (void)credential;
  (void)context;
  (void)target;
  (void)flags;
  (void)reserved;
  (void)representation;
  (void)input_desc;
  (void)reserved2;
  (void)new_context;
  (void)attributes;
  (void)expiry;
  t4782.generated++;
  token->pvBuffer = curlx_malloc(sizeof(t4782_token));
  if(!token->pvBuffer)
    return SEC_E_INSUFFICIENT_MEMORY;
  memcpy(token->pvBuffer, t4782_token, sizeof(t4782_token));
  token->cbBuffer = sizeof(t4782_token);
  token->BufferType = SECBUFFER_TOKEN;
  return t4782.generate_error;
}

static SECURITY_STATUS SEC_ENTRY t4782_free(void *buffer)
{
  t4782.freed++;
  curlx_free(buffer);
  return SEC_E_OK;
}

static SECURITY_STATUS SEC_ENTRY t4782_delete(PCtxtHandle context)
{
  (void)context;
  return SEC_E_OK;
}

static SECURITY_STATUS SEC_ENTRY t4782_free_cred(PCredHandle credential)
{
  (void)credential;
  return SEC_E_OK;
}

static CURLcode t4782_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                           const uint8_t *buffer, size_t length, bool eos,
                           size_t *written)
{
  (void)cf;
  (void)data;
  (void)eos;
  t4782.sends++;
  *written = 0;
  fail_unless(length == sizeof(t4782_token) - t4782.accepted,
              "retry begins at the unsent offset");
  verify_memory(buffer, t4782_token + t4782.accepted, (int)length);
  if(t4782.blocks) {
    t4782.blocks--;
    return CURLE_AGAIN;
  }
  if(t4782.send_error)
    return t4782.send_error;
  *written = t4782.first_write ? t4782.first_write : length;
  t4782.first_write = 0;
  t4782.accepted += *written;
  return CURLE_OK;
}

static CURLcode t4782_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                           char *buffer, size_t length, size_t *received)
{
  (void)cf;
  (void)data;
  (void)buffer;
  (void)length;
  *received = 0;
  return CURLE_AGAIN;
}

static void t4782_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  (void)cf;
  (void)data;
}

static const struct Curl_cftype t4782_filter = {
  "TEST",
  0,
  CURL_LOG_LVL_NONE,
  t4782_destroy,
  Curl_cf_def_connect,
  Curl_cf_def_shutdown,
  Curl_cf_def_adjust_pollset,
  Curl_cf_def_data_pending,
  t4782_send,
  t4782_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
};

static CURLcode t4782_setup(CURL **easy)
{
  CURLcode result = CURLE_OK;
  global_init(CURL_GLOBAL_ALL);
  *easy = curl_easy_init();
  if(!*easy) {
    curl_global_cleanup();
    return CURLE_OUT_OF_MEMORY;
  }
  return result;
}

static void t4782_stop(CURL *easy)
{
  curl_easy_cleanup(easy);
  curl_global_cleanup();
}
#endif

static CURLcode test_unit4782(const char *arg)
{
#ifdef USE_SCHANNEL
  CURL *easy = NULL;
  PSecurityFunctionTable original;
  SecurityFunctionTable functions;
  static char hostname[] = "example.invalid";
  unsigned int scenario;
  UNITTEST_BEGIN(t4782_setup(&easy))

  original = Curl_pSecFn;
  functions = *original;
  functions.ApplyControlToken = t4782_apply;
  functions.InitializeSecurityContext = t4782_generate;
  functions.FreeContextBuffer = t4782_free;
  functions.DeleteSecurityContext = t4782_delete;
  functions.FreeCredentialsHandle = t4782_free_cred;
  Curl_pSecFn = &functions;

  for(scenario = 0; scenario < 6; scenario++) {
    struct schannel_ssl_backend_data backend;
    struct ssl_connect_data ssl;
    struct connectdata connection;
    struct Curl_peer origin;
    struct Curl_cfilter cf;
    struct Curl_cfilter lower;
    CURLcode result;
    bool done;
    unsigned int attempts;

    memset(&t4782, 0, sizeof(t4782));
    memset(&backend, 0, sizeof(backend));
    memset(&ssl, 0, sizeof(ssl));
    memset(&connection, 0, sizeof(connection));
    memset(&origin, 0, sizeof(origin));
    memset(&cf, 0, sizeof(cf));
    memset(&lower, 0, sizeof(lower));
    backend.cred = curlx_calloc(1, sizeof(*backend.cred));
    backend.ctxt = curlx_calloc(1, sizeof(*backend.ctxt));
    if(!backend.cred || !backend.ctxt) {
      curlx_free(backend.cred);
      curlx_free(backend.ctxt);
      fail("allocation failed");
      break;
    }
    backend.cred->refcount = 1;
    backend.recv_sspi_close_notify = TRUE;
    ssl.backend = &backend;
    ssl.peer.origin = &origin;
    origin.hostname = hostname;
    origin.port = 443;
    cf.ctx = &ssl;
    cf.conn = &connection;
    cf.next = &lower;
    lower.cft = &t4782_filter;

    if(scenario == 0 || scenario == 2)
      t4782.blocks = 2;
    if(scenario == 1)
      t4782.first_write = 1;
    if(scenario == 3 || scenario == 4)
      t4782.send_error = CURLE_SEND_ERROR;
    if(scenario == 4)
      backend.recv_connection_closed = TRUE;
    if(scenario == 5)
      t4782.generate_error = SEC_E_INTERNAL_ERROR;

    result = Curl_ssl_schannel.shut_down(&cf, easy, TRUE, &done);
    if(scenario < 3) {
      fail_unless(result == CURLE_OK && !done && !cf.shutdown,
                  "incomplete send keeps shutdown pending");
      fail_unless(t4782.generated == 1 && t4782.freed == 0,
                  "pending token remains owned");
      fail_unless(ssl.io_need == CURL_SSL_IO_NEED_SEND,
                  "pending shutdown waits for writability");
      if(scenario != 2) {
        for(attempts = 0; !done && attempts < 3; attempts++)
          result = Curl_ssl_schannel.shut_down(&cf, easy, TRUE, &done);
        fail_unless(result == CURLE_OK && done && cf.shutdown,
                    "shutdown completed");
        fail_unless(t4782.generated == 1 && t4782.freed == 1,
                    "retry reuses and then frees one token");
        fail_unless(t4782.accepted == sizeof(t4782_token),
                    "complete record delivered once");
      }
    }
    else {
      fail_unless(result == (scenario == 4 ? CURLE_OK : CURLE_SEND_ERROR),
                  "send/generation failure retains existing error semantics");
      fail_unless(cf.shutdown, "failed shutdown does not retry");
    }
    Curl_ssl_schannel.close(&cf, easy);
    fail_unless(t4782.generated == 1 && t4782.freed == 1,
                "close releases the token exactly once");
  }

  Curl_pSecFn = original;
  UNITTEST_END(t4782_stop(easy))
#else
  (void)arg;
  return CURLE_OK;
#endif
}
