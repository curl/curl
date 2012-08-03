/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "setup.h"

#ifdef USE_NTLM

/*
 * NTLM details:
 *
 * http://davenport.sourceforge.net/ntlm.html
 * http://www.innovation.ch/java/ntlm.html
 */

#define DEBUG_ME 0

#include "urldata.h"
#include "sendf.h"
#include "rawstr.h"
#include "curl_ntlm.h"
#include "curl_ntlm_msgs.h"
#include "curl_ntlm_wb.h"
#include "url.h"
#include "curl_memory.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#if defined(USE_NSS)
#include "nssg.h"
#elif defined(USE_WINDOWS_SSPI)
#include "curl_sspi.h"
#endif

/* The last #include file should be: */
#include "memdebug.h"

#if DEBUG_ME
# define DEBUG_OUT(x) x
#else
# define DEBUG_OUT(x) Curl_nop_stmt
#endif

CURLcode Curl_input_ntlm(struct connectdata *conn,
                         bool proxy,         /* if proxy or not */
                         const char *header) /* rest of the www-authenticate:
                                                header */
{
  /* point to the correct struct with this */
  struct ntlmdata *ntlm;
  CURLcode result = CURLE_OK;

#ifdef USE_NSS
  result = Curl_nss_force_init(conn->data);
  if(result)
    return result;
#endif

  ntlm = proxy ? &conn->proxyntlm : &conn->ntlm;

  /* skip initial whitespaces */
  while(*header && ISSPACE(*header))
    header++;

  if(checkprefix("NTLM", header)) {
    header += strlen("NTLM");

    while(*header && ISSPACE(*header))
      header++;

    if(*header) {
      result = Curl_ntlm_decode_type2_message(conn->data, header, ntlm);
      if(CURLE_OK != result)
        return result;

      ntlm->state = NTLMSTATE_TYPE2; /* We got a type-2 message */
    }
    else {
      if(ntlm->state == NTLMSTATE_TYPE3) {
        infof(conn->data, "NTLM handshake rejected\n");
        Curl_http_ntlm_cleanup(conn);
        ntlm->state = NTLMSTATE_NONE;
        return CURLE_REMOTE_ACCESS_DENIED;
      }
      else if(ntlm->state >= NTLMSTATE_TYPE1) {
        infof(conn->data, "NTLM handshake failure (internal error)\n");
        return CURLE_REMOTE_ACCESS_DENIED;
      }

      ntlm->state = NTLMSTATE_TYPE1; /* We should send away a type-1 */
    }
  }

  return result;
}

/*
 * This is for creating ntlm header output
 */
CURLcode Curl_output_ntlm(struct connectdata *conn,
                          bool proxy)
{
  char *base64 = NULL;
  size_t len = 0;
  CURLcode error;

  /* point to the address of the pointer that holds the string to send to the
     server, which is for a plain host or for a HTTP proxy */
  char **allocuserpwd;

  /* point to the name and password for this */
  const char *userp;
  const char *passwdp;

  /* point to the correct struct with this */
  struct ntlmdata *ntlm;
  struct auth *authp;

  DEBUGASSERT(conn);
  DEBUGASSERT(conn->data);

#ifdef USE_NSS
  if(CURLE_OK != Curl_nss_force_init(conn->data))
    return CURLE_OUT_OF_MEMORY;
#endif

  if(proxy) {
    allocuserpwd = &conn->allocptr.proxyuserpwd;
    userp = conn->proxyuser;
    passwdp = conn->proxypasswd;
    ntlm = &conn->proxyntlm;
    authp = &conn->data->state.authproxy;
  }
  else {
    allocuserpwd = &conn->allocptr.userpwd;
    userp = conn->user;
    passwdp = conn->passwd;
    ntlm = &conn->ntlm;
    authp = &conn->data->state.authhost;
  }
  authp->done = FALSE;

  /* not set means empty */
  if(!userp)
    userp = "";

  if(!passwdp)
    passwdp = "";

#ifdef USE_WINDOWS_SSPI
  if(s_hSecDll == NULL) {
    /* not thread safe and leaks - use curl_global_init() to avoid */
    CURLcode err = Curl_sspi_global_init();
    if(s_hSecDll == NULL)
      return err;
  }
#endif

  switch(ntlm->state) {
  case NTLMSTATE_TYPE1:
  default: /* for the weird cases we (re)start here */
    /* Create a type-1 message */
    error = Curl_ntlm_create_type1_message(userp, passwdp, ntlm, &base64,
                                           &len);

    if(error)
      return error;

    if(base64) {
      Curl_safefree(*allocuserpwd);
      *allocuserpwd = aprintf("%sAuthorization: NTLM %s\r\n",
                              proxy ? "Proxy-" : "",
                              base64);
      DEBUG_OUT(fprintf(stderr, "**** Header %s\n ", *allocuserpwd));
      free(base64);
    }
    break;

  case NTLMSTATE_TYPE2:
    /* We already received the type-2 message, create a type-3 message */
    error = Curl_ntlm_create_type3_message(conn->data, userp, passwdp,
                                           ntlm, &base64, &len);
    if(error)
      return error;

    if(base64) {
      Curl_safefree(*allocuserpwd);
      *allocuserpwd = aprintf("%sAuthorization: NTLM %s\r\n",
                              proxy ? "Proxy-" : "",
                              base64);
      DEBUG_OUT(fprintf(stderr, "**** %s\n ", *allocuserpwd));
      free(base64);

      ntlm->state = NTLMSTATE_TYPE3; /* we send a type-3 */
      authp->done = TRUE;
    }
    break;

  case NTLMSTATE_TYPE3:
    /* connection is already authenticated,
     * don't send a header in future requests */
    if(*allocuserpwd) {
      free(*allocuserpwd);
      *allocuserpwd = NULL;
    }
    authp->done = TRUE;
    break;
  }

  return CURLE_OK;
}

void Curl_http_ntlm_cleanup(struct connectdata *conn)
{
#ifdef USE_WINDOWS_SSPI
  Curl_ntlm_sspi_cleanup(&conn->ntlm);
  Curl_ntlm_sspi_cleanup(&conn->proxyntlm);
#elif defined(NTLM_WB_ENABLED)
  Curl_ntlm_wb_cleanup(conn);
#else
  (void)conn;
#endif
}

#endif /* USE_NTLM */
