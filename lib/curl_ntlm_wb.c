/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#if !defined(CURL_DISABLE_HTTP) && defined(USE_NTLM) && \
    defined(NTLM_WB_ENABLED)

#define DEBUG_ME 0

#include "urldata.h"
#include "sendf.h"
#include "curl_ntlm_wb.h"
#include "strcase.h"
#include "vauth/vauth.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#if DEBUG_ME
# define DEBUG_OUT(x) x
#else
# define DEBUG_OUT(x) Curl_nop_stmt
#endif

CURLcode Curl_input_ntlm_wb(struct connectdata *conn,
                            bool proxy,
                            const char *header)
{
  struct ntlmdata *ntlm = proxy ? &conn->proxyntlm : &conn->ntlm;
  curlntlm *state = proxy ? &conn->proxy_ntlm_state : &conn->http_ntlm_state;

  if(!checkprefix("NTLM", header))
    return CURLE_BAD_CONTENT_ENCODING;

  header += strlen("NTLM");
  while(*header && ISSPACE(*header))
    header++;

  if(*header) {
    ntlm->challenge = strdup(header);
    if(!ntlm->challenge)
      return CURLE_OUT_OF_MEMORY;

    *state = NTLMSTATE_TYPE2; /* We got a type-2 message */
  }
  else {
    if(*state == NTLMSTATE_LAST) {
      infof(conn->data, "NTLM auth restarted\n");
      Curl_http_auth_cleanup_ntlm_wb(conn);
    }
    else if(*state == NTLMSTATE_TYPE3) {
      infof(conn->data, "NTLM handshake rejected\n");
      Curl_http_auth_cleanup_ntlm_wb(conn);
      *state = NTLMSTATE_NONE;
      return CURLE_REMOTE_ACCESS_DENIED;
    }
    else if(*state >= NTLMSTATE_TYPE1) {
      infof(conn->data, "NTLM handshake failure (internal error)\n");
      return CURLE_REMOTE_ACCESS_DENIED;
    }

    *state = NTLMSTATE_TYPE1; /* We should send away a type-1 */
  }

  return CURLE_OK;
}

/*
 * This is for creating ntlm header output by delegating challenge/response
 * to Samba's winbind daemon helper ntlm_auth.
 */
CURLcode Curl_output_ntlm_wb(struct connectdata *conn,
                              bool proxy)
{
  /* point to the address of the pointer that holds the string to send to the
     server, which is for a plain host or for a HTTP proxy */
  char **allocuserpwd;
  /* point to the name and password */
  const char *userp;
  struct ntlmdata *ntlm;
  curlntlm *state;
  struct auth *authp;

  CURLcode res = CURLE_OK;

  DEBUGASSERT(conn);
  DEBUGASSERT(conn->data);

  if(proxy) {
    allocuserpwd = &conn->allocptr.proxyuserpwd;
    userp = conn->http_proxy.user;
    ntlm = &conn->proxyntlm;
    state = &conn->proxy_ntlm_state;
    authp = &conn->data->state.authproxy;
  }
  else {
    allocuserpwd = &conn->allocptr.userpwd;
    userp = conn->user;
    ntlm = &conn->ntlm;
    state = &conn->http_ntlm_state;
    authp = &conn->data->state.authhost;
  }
  authp->done = FALSE;

  /* not set means empty */
  if(!userp)
    userp = "";

  switch(*state) {
  case NTLMSTATE_TYPE1:
  default:
    /* Use Samba's 'winbind' daemon to support NTLM authentication,
     * by delegating the NTLM challenge/response protocol to a helper
     * in ntlm_auth.
     * http://devel.squid-cache.org/ntlm/squid_helper_protocol.html
     * https://www.samba.org/samba/docs/man/manpages-3/winbindd.8.html
     * https://www.samba.org/samba/docs/man/manpages-3/ntlm_auth.1.html
     * Preprocessor symbol 'NTLM_WB_ENABLED' is defined when this
     * feature is enabled and 'NTLM_WB_FILE' symbol holds absolute
     * filename of ntlm_auth helper.
     * If NTLM authentication using winbind fails, go back to original
     * request handling process.
     */
    /* Create communication with ntlm_auth */
    res = ntlm_wb_init(conn->data, ntlm, userp);
    if(res)
      return res;
    res = ntlm_wb_response(conn->data, ntlm, "YR\n", *state);
    if(res)
      return res;

    free(*allocuserpwd);
    *allocuserpwd = aprintf("%sAuthorization: NTLM %s\r\n",
                            proxy ? "Proxy-" : "",
                            ntlm->response);
    DEBUG_OUT(fprintf(stderr, "**** Header %s\n ", *allocuserpwd));
    Curl_safefree(ntlm->response);
    if(!*allocuserpwd)
      return CURLE_OUT_OF_MEMORY;
    break;

  case NTLMSTATE_TYPE2: {
    char *input = aprintf("TT %s\n", ntlm->challenge);
    if(!input)
      return CURLE_OUT_OF_MEMORY;
    res = ntlm_wb_response(conn->data, ntlm, input, *state);
    free(input);
    if(res)
      return res;

    free(*allocuserpwd);
    *allocuserpwd = aprintf("%sAuthorization: NTLM %s\r\n",
                            proxy ? "Proxy-" : "",
                            ntlm->response);
    DEBUG_OUT(fprintf(stderr, "**** %s\n ", *allocuserpwd));
    *state = NTLMSTATE_TYPE3; /* we sent a type-3 */
    authp->done = TRUE;
    Curl_http_auth_cleanup_ntlm_wb(conn);
    if(!*allocuserpwd)
      return CURLE_OUT_OF_MEMORY;
    break;
  }
  case NTLMSTATE_TYPE3:
    /* connection is already authenticated,
     * don't send a header in future requests */
    *state = NTLMSTATE_LAST;
    /* FALLTHROUGH */
  case NTLMSTATE_LAST:
    Curl_safefree(*allocuserpwd);
    authp->done = TRUE;
    break;
  }

  return CURLE_OK;
}

void Curl_http_auth_cleanup_ntlm_wb(struct connectdata *conn)
{
  Curl_auth_cleanup_ntlm_wb(&conn->ntlm);
  Curl_auth_cleanup_ntlm_wb(&conn->proxyntlm);
}

#endif /* !CURL_DISABLE_HTTP && USE_NTLM && NTLM_WB_ENABLED */
