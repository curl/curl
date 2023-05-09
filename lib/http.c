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

#ifndef CURL_DISABLE_HTTP

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef USE_HYPER
#include <hyper.h>
#endif

#include "urldata.h"
#include <curl/curl.h>
#include "transfer.h"
#include "sendf.h"
#include "formdata.h"
#include "mime.h"
#include "progress.h"
#include "curl_base64.h"
#include "cookie.h"
#include "vauth/vauth.h"
#include "vtls/vtls.h"
#include "vquic/vquic.h"
#include "http_digest.h"
#include "http_ntlm.h"
#include "curl_ntlm_wb.h"
#include "http_negotiate.h"
#include "http_aws_sigv4.h"
#include "url.h"
#include "share.h"
#include "hostip.h"
#include "dynhds.h"
#include "http.h"
#include "select.h"
#include "parsedate.h" /* for the week day and month names */
#include "strtoofft.h"
#include "multiif.h"
#include "strcase.h"
#include "content_encoding.h"
#include "http_proxy.h"
#include "warnless.h"
#include "http2.h"
#include "cfilters.h"
#include "connect.h"
#include "strdup.h"
#include "altsvc.h"
#include "hsts.h"
#include "ws.h"
#include "c-hyper.h"
#include "curl_ctype.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/*
 * Forward declarations.
 */

static int http_getsock_do(struct Curl_easy *data,
                           struct connectdata *conn,
                           curl_socket_t *socks);
static bool http_should_fail(struct Curl_easy *data);

static CURLcode http_setup_conn(struct Curl_easy *data,
                                struct connectdata *conn);
#ifdef USE_WEBSOCKETS
static CURLcode ws_setup_conn(struct Curl_easy *data,
                              struct connectdata *conn);
#endif

/*
 * HTTP handler interface.
 */
const struct Curl_handler Curl_handler_http = {
  "HTTP",                               /* scheme */
  http_setup_conn,                      /* setup_connection */
  Curl_http,                            /* do_it */
  Curl_http_done,                       /* done */
  ZERO_NULL,                            /* do_more */
  Curl_http_connect,                    /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  http_getsock_do,                      /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* readwrite */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_HTTP,                            /* defport */
  CURLPROTO_HTTP,                       /* protocol */
  CURLPROTO_HTTP,                       /* family */
  PROTOPT_CREDSPERREQUEST |             /* flags */
  PROTOPT_USERPWDCTRL
};

#ifdef USE_WEBSOCKETS
const struct Curl_handler Curl_handler_ws = {
  "WS",                                 /* scheme */
  ws_setup_conn,                        /* setup_connection */
  Curl_http,                            /* do_it */
  Curl_http_done,                       /* done */
  ZERO_NULL,                            /* do_more */
  Curl_http_connect,                    /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  http_getsock_do,                      /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  Curl_ws_disconnect,                   /* disconnect */
  ZERO_NULL,                            /* readwrite */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_HTTP,                            /* defport */
  CURLPROTO_WS,                         /* protocol */
  CURLPROTO_HTTP,                       /* family */
  PROTOPT_CREDSPERREQUEST |             /* flags */
  PROTOPT_USERPWDCTRL
};
#endif

#ifdef USE_SSL
/*
 * HTTPS handler interface.
 */
const struct Curl_handler Curl_handler_https = {
  "HTTPS",                              /* scheme */
  http_setup_conn,                      /* setup_connection */
  Curl_http,                            /* do_it */
  Curl_http_done,                       /* done */
  ZERO_NULL,                            /* do_more */
  Curl_http_connect,                    /* connect_it */
  NULL,                                 /* connecting */
  ZERO_NULL,                            /* doing */
  NULL,                                 /* proto_getsock */
  http_getsock_do,                      /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* readwrite */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_HTTPS,                           /* defport */
  CURLPROTO_HTTPS,                      /* protocol */
  CURLPROTO_HTTP,                       /* family */
  PROTOPT_SSL | PROTOPT_CREDSPERREQUEST | PROTOPT_ALPN | /* flags */
  PROTOPT_USERPWDCTRL
};

#ifdef USE_WEBSOCKETS
const struct Curl_handler Curl_handler_wss = {
  "WSS",                                /* scheme */
  ws_setup_conn,                        /* setup_connection */
  Curl_http,                            /* do_it */
  Curl_http_done,                       /* done */
  ZERO_NULL,                            /* do_more */
  Curl_http_connect,                    /* connect_it */
  NULL,                                 /* connecting */
  ZERO_NULL,                            /* doing */
  NULL,                                 /* proto_getsock */
  http_getsock_do,                      /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  Curl_ws_disconnect,                   /* disconnect */
  ZERO_NULL,                            /* readwrite */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_HTTPS,                           /* defport */
  CURLPROTO_WSS,                        /* protocol */
  CURLPROTO_HTTP,                       /* family */
  PROTOPT_SSL | PROTOPT_CREDSPERREQUEST | /* flags */
  PROTOPT_USERPWDCTRL
};
#endif

#endif

static CURLcode http_setup_conn(struct Curl_easy *data,
                                struct connectdata *conn)
{
  /* allocate the HTTP-specific struct for the Curl_easy, only to survive
     during this request */
  struct HTTP *http;
  DEBUGASSERT(data->req.p.http == NULL);

  http = calloc(1, sizeof(struct HTTP));
  if(!http)
    return CURLE_OUT_OF_MEMORY;

  Curl_mime_initpart(&http->form);
  data->req.p.http = http;
  connkeep(conn, "HTTP default");

  if(data->state.httpwant == CURL_HTTP_VERSION_3ONLY) {
    CURLcode result = Curl_conn_may_http3(data, conn);
    if(result)
      return result;
  }

  return CURLE_OK;
}

#ifdef USE_WEBSOCKETS
static CURLcode ws_setup_conn(struct Curl_easy *data,
                              struct connectdata *conn)
{
  /* websockets is 1.1 only (for now) */
  data->state.httpwant = CURL_HTTP_VERSION_1_1;
  return http_setup_conn(data, conn);
}
#endif

#ifndef CURL_DISABLE_PROXY
/*
 * checkProxyHeaders() checks the linked list of custom proxy headers
 * if proxy headers are not available, then it will lookup into http header
 * link list
 *
 * It takes a connectdata struct as input to see if this is a proxy request or
 * not, as it then might check a different header list. Provide the header
 * prefix without colon!
 */
char *Curl_checkProxyheaders(struct Curl_easy *data,
                             const struct connectdata *conn,
                             const char *thisheader,
                             const size_t thislen)
{
  struct curl_slist *head;

  for(head = (conn->bits.proxy && data->set.sep_headers) ?
        data->set.proxyheaders : data->set.headers;
      head; head = head->next) {
    if(strncasecompare(head->data, thisheader, thislen) &&
       Curl_headersep(head->data[thislen]))
      return head->data;
  }

  return NULL;
}
#else
/* disabled */
#define Curl_checkProxyheaders(x,y,z,a) NULL
#endif

/*
 * Strip off leading and trailing whitespace from the value in the
 * given HTTP header line and return a strdupped copy. Returns NULL in
 * case of allocation failure. Returns an empty string if the header value
 * consists entirely of whitespace.
 */
char *Curl_copy_header_value(const char *header)
{
  const char *start;
  const char *end;
  char *value;
  size_t len;

  /* Find the end of the header name */
  while(*header && (*header != ':'))
    ++header;

  if(*header)
    /* Skip over colon */
    ++header;

  /* Find the first non-space letter */
  start = header;
  while(*start && ISSPACE(*start))
    start++;

  /* data is in the host encoding so
     use '\r' and '\n' instead of 0x0d and 0x0a */
  end = strchr(start, '\r');
  if(!end)
    end = strchr(start, '\n');
  if(!end)
    end = strchr(start, '\0');
  if(!end)
    return NULL;

  /* skip all trailing space letters */
  while((end > start) && ISSPACE(*end))
    end--;

  /* get length of the type */
  len = end - start + 1;

  value = malloc(len + 1);
  if(!value)
    return NULL;

  memcpy(value, start, len);
  value[len] = 0; /* null-terminate */

  return value;
}

#ifndef CURL_DISABLE_HTTP_AUTH
/*
 * http_output_basic() sets up an Authorization: header (or the proxy version)
 * for HTTP Basic authentication.
 *
 * Returns CURLcode.
 */
static CURLcode http_output_basic(struct Curl_easy *data, bool proxy)
{
  size_t size = 0;
  char *authorization = NULL;
  char **userp;
  const char *user;
  const char *pwd;
  CURLcode result;
  char *out;

  /* credentials are unique per transfer for HTTP, do not use the ones for the
     connection */
  if(proxy) {
#ifndef CURL_DISABLE_PROXY
    userp = &data->state.aptr.proxyuserpwd;
    user = data->state.aptr.proxyuser;
    pwd = data->state.aptr.proxypasswd;
#else
    return CURLE_NOT_BUILT_IN;
#endif
  }
  else {
    userp = &data->state.aptr.userpwd;
    user = data->state.aptr.user;
    pwd = data->state.aptr.passwd;
  }

  out = aprintf("%s:%s", user ? user : "", pwd ? pwd : "");
  if(!out)
    return CURLE_OUT_OF_MEMORY;

  result = Curl_base64_encode(out, strlen(out), &authorization, &size);
  if(result)
    goto fail;

  if(!authorization) {
    result = CURLE_REMOTE_ACCESS_DENIED;
    goto fail;
  }

  free(*userp);
  *userp = aprintf("%sAuthorization: Basic %s\r\n",
                   proxy ? "Proxy-" : "",
                   authorization);
  free(authorization);
  if(!*userp) {
    result = CURLE_OUT_OF_MEMORY;
    goto fail;
  }

  fail:
  free(out);
  return result;
}

/*
 * http_output_bearer() sets up an Authorization: header
 * for HTTP Bearer authentication.
 *
 * Returns CURLcode.
 */
static CURLcode http_output_bearer(struct Curl_easy *data)
{
  char **userp;
  CURLcode result = CURLE_OK;

  userp = &data->state.aptr.userpwd;
  free(*userp);
  *userp = aprintf("Authorization: Bearer %s\r\n",
                   data->set.str[STRING_BEARER]);

  if(!*userp) {
    result = CURLE_OUT_OF_MEMORY;
    goto fail;
  }

  fail:
  return result;
}

#endif

/* pickoneauth() selects the most favourable authentication method from the
 * ones available and the ones we want.
 *
 * return TRUE if one was picked
 */
static bool pickoneauth(struct auth *pick, unsigned long mask)
{
  bool picked;
  /* only deal with authentication we want */
  unsigned long avail = pick->avail & pick->want & mask;
  picked = TRUE;

  /* The order of these checks is highly relevant, as this will be the order
     of preference in case of the existence of multiple accepted types. */
  if(avail & CURLAUTH_NEGOTIATE)
    pick->picked = CURLAUTH_NEGOTIATE;
  else if(avail & CURLAUTH_BEARER)
    pick->picked = CURLAUTH_BEARER;
  else if(avail & CURLAUTH_DIGEST)
    pick->picked = CURLAUTH_DIGEST;
  else if(avail & CURLAUTH_NTLM)
    pick->picked = CURLAUTH_NTLM;
  else if(avail & CURLAUTH_NTLM_WB)
    pick->picked = CURLAUTH_NTLM_WB;
  else if(avail & CURLAUTH_BASIC)
    pick->picked = CURLAUTH_BASIC;
  else if(avail & CURLAUTH_AWS_SIGV4)
    pick->picked = CURLAUTH_AWS_SIGV4;
  else {
    pick->picked = CURLAUTH_PICKNONE; /* we select to use nothing */
    picked = FALSE;
  }
  pick->avail = CURLAUTH_NONE; /* clear it here */

  return picked;
}

/*
 * http_perhapsrewind()
 *
 * If we are doing POST or PUT {
 *   If we have more data to send {
 *     If we are doing NTLM {
 *       Keep sending since we must not disconnect
 *     }
 *     else {
 *       If there is more than just a little data left to send, close
 *       the current connection by force.
 *     }
 *   }
 *   If we have sent any data {
 *     If we don't have track of all the data {
 *       call app to tell it to rewind
 *     }
 *     else {
 *       rewind internally so that the operation can restart fine
 *     }
 *   }
 * }
 */
static CURLcode http_perhapsrewind(struct Curl_easy *data,
                                   struct connectdata *conn)
{
  struct HTTP *http = data->req.p.http;
  curl_off_t bytessent;
  curl_off_t expectsend = -1; /* default is unknown */

  if(!http)
    /* If this is still NULL, we have not reach very far and we can safely
       skip this rewinding stuff */
    return CURLE_OK;

  switch(data->state.httpreq) {
  case HTTPREQ_GET:
  case HTTPREQ_HEAD:
    return CURLE_OK;
  default:
    break;
  }

  bytessent = data->req.writebytecount;

  if(conn->bits.authneg) {
    /* This is a state where we are known to be negotiating and we don't send
       any data then. */
    expectsend = 0;
  }
  else if(!conn->bits.protoconnstart) {
    /* HTTP CONNECT in progress: there is no body */
    expectsend = 0;
  }
  else {
    /* figure out how much data we are expected to send */
    switch(data->state.httpreq) {
    case HTTPREQ_POST:
    case HTTPREQ_PUT:
      if(data->state.infilesize != -1)
        expectsend = data->state.infilesize;
      break;
    case HTTPREQ_POST_FORM:
    case HTTPREQ_POST_MIME:
      expectsend = http->postsize;
      break;
    default:
      break;
    }
  }

  data->state.rewindbeforesend = FALSE; /* default */

  if((expectsend == -1) || (expectsend > bytessent)) {
#if defined(USE_NTLM)
    /* There is still data left to send */
    if((data->state.authproxy.picked == CURLAUTH_NTLM) ||
       (data->state.authhost.picked == CURLAUTH_NTLM) ||
       (data->state.authproxy.picked == CURLAUTH_NTLM_WB) ||
       (data->state.authhost.picked == CURLAUTH_NTLM_WB)) {
      if(((expectsend - bytessent) < 2000) ||
         (conn->http_ntlm_state != NTLMSTATE_NONE) ||
         (conn->proxy_ntlm_state != NTLMSTATE_NONE)) {
        /* The NTLM-negotiation has started *OR* there is just a little (<2K)
           data left to send, keep on sending. */

        /* rewind data when completely done sending! */
        if(!conn->bits.authneg && (conn->writesockfd != CURL_SOCKET_BAD)) {
          data->state.rewindbeforesend = TRUE;
          infof(data, "Rewind stream before next send");
        }

        return CURLE_OK;
      }

      if(conn->bits.close)
        /* this is already marked to get closed */
        return CURLE_OK;

      infof(data, "NTLM send, close instead of sending %"
            CURL_FORMAT_CURL_OFF_T " bytes",
            (curl_off_t)(expectsend - bytessent));
    }
#endif
#if defined(USE_SPNEGO)
    /* There is still data left to send */
    if((data->state.authproxy.picked == CURLAUTH_NEGOTIATE) ||
       (data->state.authhost.picked == CURLAUTH_NEGOTIATE)) {
      if(((expectsend - bytessent) < 2000) ||
         (conn->http_negotiate_state != GSS_AUTHNONE) ||
         (conn->proxy_negotiate_state != GSS_AUTHNONE)) {
        /* The NEGOTIATE-negotiation has started *OR*
        there is just a little (<2K) data left to send, keep on sending. */

        /* rewind data when completely done sending! */
        if(!conn->bits.authneg && (conn->writesockfd != CURL_SOCKET_BAD)) {
          data->state.rewindbeforesend = TRUE;
          infof(data, "Rewind stream before next send");
        }

        return CURLE_OK;
      }

      if(conn->bits.close)
        /* this is already marked to get closed */
        return CURLE_OK;

      infof(data, "NEGOTIATE send, close instead of sending %"
        CURL_FORMAT_CURL_OFF_T " bytes",
        (curl_off_t)(expectsend - bytessent));
    }
#endif

    /* This is not NEGOTIATE/NTLM or many bytes left to send: close */
    streamclose(conn, "Mid-auth HTTP and much data left to send");
    data->req.size = 0; /* don't download any more than 0 bytes */

    /* There still is data left to send, but this connection is marked for
       closure so we can safely do the rewind right now */
  }

  if(bytessent) {
    /* mark for rewind since if we already sent something */
    data->state.rewindbeforesend = TRUE;
    infof(data, "Please rewind output before next send");
  }

  return CURLE_OK;
}

/*
 * Curl_http_auth_act() gets called when all HTTP headers have been received
 * and it checks what authentication methods that are available and decides
 * which one (if any) to use. It will set 'newurl' if an auth method was
 * picked.
 */

CURLcode Curl_http_auth_act(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;
  bool pickhost = FALSE;
  bool pickproxy = FALSE;
  CURLcode result = CURLE_OK;
  unsigned long authmask = ~0ul;

  if(!data->set.str[STRING_BEARER])
    authmask &= (unsigned long)~CURLAUTH_BEARER;

  if(100 <= data->req.httpcode && data->req.httpcode <= 199)
    /* this is a transient response code, ignore */
    return CURLE_OK;

  if(data->state.authproblem)
    return data->set.http_fail_on_error?CURLE_HTTP_RETURNED_ERROR:CURLE_OK;

  if((data->state.aptr.user || data->set.str[STRING_BEARER]) &&
     ((data->req.httpcode == 401) ||
      (conn->bits.authneg && data->req.httpcode < 300))) {
    pickhost = pickoneauth(&data->state.authhost, authmask);
    if(!pickhost)
      data->state.authproblem = TRUE;
    if(data->state.authhost.picked == CURLAUTH_NTLM &&
       conn->httpversion > 11) {
      infof(data, "Forcing HTTP/1.1 for NTLM");
      connclose(conn, "Force HTTP/1.1 connection");
      data->state.httpwant = CURL_HTTP_VERSION_1_1;
    }
  }
#ifndef CURL_DISABLE_PROXY
  if(conn->bits.proxy_user_passwd &&
     ((data->req.httpcode == 407) ||
      (conn->bits.authneg && data->req.httpcode < 300))) {
    pickproxy = pickoneauth(&data->state.authproxy,
                            authmask & ~CURLAUTH_BEARER);
    if(!pickproxy)
      data->state.authproblem = TRUE;
  }
#endif

  if(pickhost || pickproxy) {
    if((data->state.httpreq != HTTPREQ_GET) &&
       (data->state.httpreq != HTTPREQ_HEAD) &&
       !data->state.rewindbeforesend) {
      result = http_perhapsrewind(data, conn);
      if(result)
        return result;
    }
    /* In case this is GSS auth, the newurl field is already allocated so
       we must make sure to free it before allocating a new one. As figured
       out in bug #2284386 */
    Curl_safefree(data->req.newurl);
    data->req.newurl = strdup(data->state.url); /* clone URL */
    if(!data->req.newurl)
      return CURLE_OUT_OF_MEMORY;
  }
  else if((data->req.httpcode < 300) &&
          (!data->state.authhost.done) &&
          conn->bits.authneg) {
    /* no (known) authentication available,
       authentication is not "done" yet and
       no authentication seems to be required and
       we didn't try HEAD or GET */
    if((data->state.httpreq != HTTPREQ_GET) &&
       (data->state.httpreq != HTTPREQ_HEAD)) {
      data->req.newurl = strdup(data->state.url); /* clone URL */
      if(!data->req.newurl)
        return CURLE_OUT_OF_MEMORY;
      data->state.authhost.done = TRUE;
    }
  }
  if(http_should_fail(data)) {
    failf(data, "The requested URL returned error: %d",
          data->req.httpcode);
    result = CURLE_HTTP_RETURNED_ERROR;
  }

  return result;
}

#ifndef CURL_DISABLE_HTTP_AUTH
/*
 * Output the correct authentication header depending on the auth type
 * and whether or not it is to a proxy.
 */
static CURLcode
output_auth_headers(struct Curl_easy *data,
                    struct connectdata *conn,
                    struct auth *authstatus,
                    const char *request,
                    const char *path,
                    bool proxy)
{
  const char *auth = NULL;
  CURLcode result = CURLE_OK;
  (void)conn;

#ifdef CURL_DISABLE_CRYPTO_AUTH
  (void)request;
  (void)path;
#endif
#ifndef CURL_DISABLE_CRYPTO_AUTH
  if(authstatus->picked == CURLAUTH_AWS_SIGV4) {
    auth = "AWS_SIGV4";
    result = Curl_output_aws_sigv4(data, proxy);
    if(result)
      return result;
  }
  else
#endif
#ifdef USE_SPNEGO
  if(authstatus->picked == CURLAUTH_NEGOTIATE) {
    auth = "Negotiate";
    result = Curl_output_negotiate(data, conn, proxy);
    if(result)
      return result;
  }
  else
#endif
#ifdef USE_NTLM
  if(authstatus->picked == CURLAUTH_NTLM) {
    auth = "NTLM";
    result = Curl_output_ntlm(data, proxy);
    if(result)
      return result;
  }
  else
#endif
#if defined(USE_NTLM) && defined(NTLM_WB_ENABLED)
  if(authstatus->picked == CURLAUTH_NTLM_WB) {
    auth = "NTLM_WB";
    result = Curl_output_ntlm_wb(data, conn, proxy);
    if(result)
      return result;
  }
  else
#endif
#ifndef CURL_DISABLE_CRYPTO_AUTH
  if(authstatus->picked == CURLAUTH_DIGEST) {
    auth = "Digest";
    result = Curl_output_digest(data,
                                proxy,
                                (const unsigned char *)request,
                                (const unsigned char *)path);
    if(result)
      return result;
  }
  else
#endif
  if(authstatus->picked == CURLAUTH_BASIC) {
    /* Basic */
    if(
#ifndef CURL_DISABLE_PROXY
      (proxy && conn->bits.proxy_user_passwd &&
       !Curl_checkProxyheaders(data, conn, STRCONST("Proxy-authorization"))) ||
#endif
      (!proxy && data->state.aptr.user &&
       !Curl_checkheaders(data, STRCONST("Authorization")))) {
      auth = "Basic";
      result = http_output_basic(data, proxy);
      if(result)
        return result;
    }

    /* NOTE: this function should set 'done' TRUE, as the other auth
       functions work that way */
    authstatus->done = TRUE;
  }
  if(authstatus->picked == CURLAUTH_BEARER) {
    /* Bearer */
    if((!proxy && data->set.str[STRING_BEARER] &&
        !Curl_checkheaders(data, STRCONST("Authorization")))) {
      auth = "Bearer";
      result = http_output_bearer(data);
      if(result)
        return result;
    }

    /* NOTE: this function should set 'done' TRUE, as the other auth
       functions work that way */
    authstatus->done = TRUE;
  }

  if(auth) {
#ifndef CURL_DISABLE_PROXY
    infof(data, "%s auth using %s with user '%s'",
          proxy ? "Proxy" : "Server", auth,
          proxy ? (data->state.aptr.proxyuser ?
                   data->state.aptr.proxyuser : "") :
          (data->state.aptr.user ?
           data->state.aptr.user : ""));
#else
    infof(data, "Server auth using %s with user '%s'",
          auth, data->state.aptr.user ?
          data->state.aptr.user : "");
#endif
    authstatus->multipass = (!authstatus->done) ? TRUE : FALSE;
  }
  else
    authstatus->multipass = FALSE;

  return CURLE_OK;
}

/**
 * Curl_http_output_auth() setups the authentication headers for the
 * host/proxy and the correct authentication
 * method. data->state.authdone is set to TRUE when authentication is
 * done.
 *
 * @param conn all information about the current connection
 * @param request pointer to the request keyword
 * @param path pointer to the requested path; should include query part
 * @param proxytunnel boolean if this is the request setting up a "proxy
 * tunnel"
 *
 * @returns CURLcode
 */
CURLcode
Curl_http_output_auth(struct Curl_easy *data,
                      struct connectdata *conn,
                      const char *request,
                      Curl_HttpReq httpreq,
                      const char *path,
                      bool proxytunnel) /* TRUE if this is the request setting
                                           up the proxy tunnel */
{
  CURLcode result = CURLE_OK;
  struct auth *authhost;
  struct auth *authproxy;

  DEBUGASSERT(data);

  authhost = &data->state.authhost;
  authproxy = &data->state.authproxy;

  if(
#ifndef CURL_DISABLE_PROXY
    (conn->bits.httpproxy && conn->bits.proxy_user_passwd) ||
#endif
     data->state.aptr.user || data->set.str[STRING_BEARER])
    /* continue please */;
  else {
    authhost->done = TRUE;
    authproxy->done = TRUE;
    return CURLE_OK; /* no authentication with no user or password */
  }

  if(authhost->want && !authhost->picked)
    /* The app has selected one or more methods, but none has been picked
       so far by a server round-trip. Then we set the picked one to the
       want one, and if this is one single bit it'll be used instantly. */
    authhost->picked = authhost->want;

  if(authproxy->want && !authproxy->picked)
    /* The app has selected one or more methods, but none has been picked so
       far by a proxy round-trip. Then we set the picked one to the want one,
       and if this is one single bit it'll be used instantly. */
    authproxy->picked = authproxy->want;

#ifndef CURL_DISABLE_PROXY
  /* Send proxy authentication header if needed */
  if(conn->bits.httpproxy &&
     (conn->bits.tunnel_proxy == (bit)proxytunnel)) {
    result = output_auth_headers(data, conn, authproxy, request, path, TRUE);
    if(result)
      return result;
  }
  else
#else
  (void)proxytunnel;
#endif /* CURL_DISABLE_PROXY */
    /* we have no proxy so let's pretend we're done authenticating
       with it */
    authproxy->done = TRUE;

  /* To prevent the user+password to get sent to other than the original host
     due to a location-follow */
  if(Curl_auth_allowed_to_host(data)
#ifndef CURL_DISABLE_NETRC
     || conn->bits.netrc
#endif
    )
    result = output_auth_headers(data, conn, authhost, request, path, FALSE);
  else
    authhost->done = TRUE;

  if(((authhost->multipass && !authhost->done) ||
      (authproxy->multipass && !authproxy->done)) &&
     (httpreq != HTTPREQ_GET) &&
     (httpreq != HTTPREQ_HEAD)) {
    /* Auth is required and we are not authenticated yet. Make a PUT or POST
       with content-length zero as a "probe". */
    conn->bits.authneg = TRUE;
  }
  else
    conn->bits.authneg = FALSE;

  return result;
}

#else
/* when disabled */
CURLcode
Curl_http_output_auth(struct Curl_easy *data,
                      struct connectdata *conn,
                      const char *request,
                      Curl_HttpReq httpreq,
                      const char *path,
                      bool proxytunnel)
{
  (void)data;
  (void)conn;
  (void)request;
  (void)httpreq;
  (void)path;
  (void)proxytunnel;
  return CURLE_OK;
}
#endif

/*
 * Curl_http_input_auth() deals with Proxy-Authenticate: and WWW-Authenticate:
 * headers. They are dealt with both in the transfer.c main loop and in the
 * proxy CONNECT loop.
 */

static int is_valid_auth_separator(char ch)
{
  return ch == '\0' || ch == ',' || ISSPACE(ch);
}

CURLcode Curl_http_input_auth(struct Curl_easy *data, bool proxy,
                              const char *auth) /* the first non-space */
{
  /*
   * This resource requires authentication
   */
  struct connectdata *conn = data->conn;
#ifdef USE_SPNEGO
  curlnegotiate *negstate = proxy ? &conn->proxy_negotiate_state :
                                    &conn->http_negotiate_state;
#endif
  unsigned long *availp;
  struct auth *authp;

  (void) conn; /* In case conditionals make it unused. */

  if(proxy) {
    availp = &data->info.proxyauthavail;
    authp = &data->state.authproxy;
  }
  else {
    availp = &data->info.httpauthavail;
    authp = &data->state.authhost;
  }

  /*
   * Here we check if we want the specific single authentication (using ==) and
   * if we do, we initiate usage of it.
   *
   * If the provided authentication is wanted as one out of several accepted
   * types (using &), we OR this authentication type to the authavail
   * variable.
   *
   * Note:
   *
   * ->picked is first set to the 'want' value (one or more bits) before the
   * request is sent, and then it is again set _after_ all response 401/407
   * headers have been received but then only to a single preferred method
   * (bit).
   */

  while(*auth) {
#ifdef USE_SPNEGO
    if(checkprefix("Negotiate", auth) && is_valid_auth_separator(auth[9])) {
      if((authp->avail & CURLAUTH_NEGOTIATE) ||
         Curl_auth_is_spnego_supported()) {
        *availp |= CURLAUTH_NEGOTIATE;
        authp->avail |= CURLAUTH_NEGOTIATE;

        if(authp->picked == CURLAUTH_NEGOTIATE) {
          CURLcode result = Curl_input_negotiate(data, conn, proxy, auth);
          if(!result) {
            free(data->req.newurl);
            data->req.newurl = strdup(data->state.url);
            if(!data->req.newurl)
              return CURLE_OUT_OF_MEMORY;
            data->state.authproblem = FALSE;
            /* we received a GSS auth token and we dealt with it fine */
            *negstate = GSS_AUTHRECV;
          }
          else
            data->state.authproblem = TRUE;
        }
      }
    }
    else
#endif
#ifdef USE_NTLM
      /* NTLM support requires the SSL crypto libs */
      if(checkprefix("NTLM", auth) && is_valid_auth_separator(auth[4])) {
        if((authp->avail & CURLAUTH_NTLM) ||
           (authp->avail & CURLAUTH_NTLM_WB) ||
           Curl_auth_is_ntlm_supported()) {
          *availp |= CURLAUTH_NTLM;
          authp->avail |= CURLAUTH_NTLM;

          if(authp->picked == CURLAUTH_NTLM ||
             authp->picked == CURLAUTH_NTLM_WB) {
            /* NTLM authentication is picked and activated */
            CURLcode result = Curl_input_ntlm(data, proxy, auth);
            if(!result) {
              data->state.authproblem = FALSE;
#ifdef NTLM_WB_ENABLED
              if(authp->picked == CURLAUTH_NTLM_WB) {
                *availp &= ~CURLAUTH_NTLM;
                authp->avail &= ~CURLAUTH_NTLM;
                *availp |= CURLAUTH_NTLM_WB;
                authp->avail |= CURLAUTH_NTLM_WB;

                result = Curl_input_ntlm_wb(data, conn, proxy, auth);
                if(result) {
                  infof(data, "Authentication problem. Ignoring this.");
                  data->state.authproblem = TRUE;
                }
              }
#endif
            }
            else {
              infof(data, "Authentication problem. Ignoring this.");
              data->state.authproblem = TRUE;
            }
          }
        }
      }
      else
#endif
#ifndef CURL_DISABLE_CRYPTO_AUTH
        if(checkprefix("Digest", auth) && is_valid_auth_separator(auth[6])) {
          if((authp->avail & CURLAUTH_DIGEST) != 0)
            infof(data, "Ignoring duplicate digest auth header.");
          else if(Curl_auth_is_digest_supported()) {
            CURLcode result;

            *availp |= CURLAUTH_DIGEST;
            authp->avail |= CURLAUTH_DIGEST;

            /* We call this function on input Digest headers even if Digest
             * authentication isn't activated yet, as we need to store the
             * incoming data from this header in case we are going to use
             * Digest */
            result = Curl_input_digest(data, proxy, auth);
            if(result) {
              infof(data, "Authentication problem. Ignoring this.");
              data->state.authproblem = TRUE;
            }
          }
        }
        else
#endif
          if(checkprefix("Basic", auth) &&
             is_valid_auth_separator(auth[5])) {
            *availp |= CURLAUTH_BASIC;
            authp->avail |= CURLAUTH_BASIC;
            if(authp->picked == CURLAUTH_BASIC) {
              /* We asked for Basic authentication but got a 40X back
                 anyway, which basically means our name+password isn't
                 valid. */
              authp->avail = CURLAUTH_NONE;
              infof(data, "Authentication problem. Ignoring this.");
              data->state.authproblem = TRUE;
            }
          }
          else
            if(checkprefix("Bearer", auth) &&
               is_valid_auth_separator(auth[6])) {
              *availp |= CURLAUTH_BEARER;
              authp->avail |= CURLAUTH_BEARER;
              if(authp->picked == CURLAUTH_BEARER) {
                /* We asked for Bearer authentication but got a 40X back
                  anyway, which basically means our token isn't valid. */
                authp->avail = CURLAUTH_NONE;
                infof(data, "Authentication problem. Ignoring this.");
                data->state.authproblem = TRUE;
              }
            }

    /* there may be multiple methods on one line, so keep reading */
    while(*auth && *auth != ',') /* read up to the next comma */
      auth++;
    if(*auth == ',') /* if we're on a comma, skip it */
      auth++;
    while(*auth && ISSPACE(*auth))
      auth++;
  }

  return CURLE_OK;
}

/**
 * http_should_fail() determines whether an HTTP response has gotten us
 * into an error state or not.
 *
 * @param conn all information about the current connection
 *
 * @retval FALSE communications should continue
 *
 * @retval TRUE communications should not continue
 */
static bool http_should_fail(struct Curl_easy *data)
{
  int httpcode;
  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);

  httpcode = data->req.httpcode;

  /*
  ** If we haven't been asked to fail on error,
  ** don't fail.
  */
  if(!data->set.http_fail_on_error)
    return FALSE;

  /*
  ** Any code < 400 is never terminal.
  */
  if(httpcode < 400)
    return FALSE;

  /*
  ** A 416 response to a resume request is presumably because the file is
  ** already completely downloaded and thus not actually a fail.
  */
  if(data->state.resume_from && data->state.httpreq == HTTPREQ_GET &&
     httpcode == 416)
    return FALSE;

  /*
  ** Any code >= 400 that's not 401 or 407 is always
  ** a terminal error
  */
  if((httpcode != 401) && (httpcode != 407))
    return TRUE;

  /*
  ** All we have left to deal with is 401 and 407
  */
  DEBUGASSERT((httpcode == 401) || (httpcode == 407));

  /*
  ** Examine the current authentication state to see if this
  ** is an error.  The idea is for this function to get
  ** called after processing all the headers in a response
  ** message.  So, if we've been to asked to authenticate a
  ** particular stage, and we've done it, we're OK.  But, if
  ** we're already completely authenticated, it's not OK to
  ** get another 401 or 407.
  **
  ** It is possible for authentication to go stale such that
  ** the client needs to reauthenticate.  Once that info is
  ** available, use it here.
  */

  /*
  ** Either we're not authenticating, or we're supposed to
  ** be authenticating something else.  This is an error.
  */
  if((httpcode == 401) && !data->state.aptr.user)
    return TRUE;
#ifndef CURL_DISABLE_PROXY
  if((httpcode == 407) && !data->conn->bits.proxy_user_passwd)
    return TRUE;
#endif

  return data->state.authproblem;
}

/*
 * readmoredata() is a "fread() emulation" to provide POST and/or request
 * data. It is used when a huge POST is to be made and the entire chunk wasn't
 * sent in the first send(). This function will then be called from the
 * transfer.c loop when more data is to be sent to the peer.
 *
 * Returns the amount of bytes it filled the buffer with.
 */
static size_t readmoredata(char *buffer,
                           size_t size,
                           size_t nitems,
                           void *userp)
{
  struct HTTP *http = (struct HTTP *)userp;
  struct Curl_easy *data = http->backup.data;
  size_t fullsize = size * nitems;

  if(!http->postsize)
    /* nothing to return */
    return 0;

  /* make sure that an HTTP request is never sent away chunked! */
  data->req.forbidchunk = (http->sending == HTTPSEND_REQUEST)?TRUE:FALSE;

  if(data->set.max_send_speed &&
     (data->set.max_send_speed < (curl_off_t)fullsize) &&
     (data->set.max_send_speed < http->postsize))
    /* speed limit */
    fullsize = (size_t)data->set.max_send_speed;

  else if(http->postsize <= (curl_off_t)fullsize) {
    memcpy(buffer, http->postdata, (size_t)http->postsize);
    fullsize = (size_t)http->postsize;

    if(http->backup.postsize) {
      /* move backup data into focus and continue on that */
      http->postdata = http->backup.postdata;
      http->postsize = http->backup.postsize;
      data->state.fread_func = http->backup.fread_func;
      data->state.in = http->backup.fread_in;

      http->sending++; /* move one step up */

      http->backup.postsize = 0;
    }
    else
      http->postsize = 0;

    return fullsize;
  }

  memcpy(buffer, http->postdata, fullsize);
  http->postdata += fullsize;
  http->postsize -= fullsize;

  return fullsize;
}

/*
 * Curl_buffer_send() sends a header buffer and frees all associated
 * memory.  Body data may be appended to the header data if desired.
 *
 * Returns CURLcode
 */
CURLcode Curl_buffer_send(struct dynbuf *in,
                          struct Curl_easy *data,
                          struct HTTP *http,
                          /* add the number of sent bytes to this
                             counter */
                          curl_off_t *bytes_written,
                          /* how much of the buffer contains body data */
                          curl_off_t included_body_bytes,
                          int socketindex)
{
  ssize_t amount;
  CURLcode result;
  char *ptr;
  size_t size;
  struct connectdata *conn = data->conn;
  size_t sendsize;
  curl_socket_t sockfd;
  size_t headersize;

  DEBUGASSERT(socketindex <= SECONDARYSOCKET);

  sockfd = Curl_conn_get_socket(data, socketindex);

  /* The looping below is required since we use non-blocking sockets, but due
     to the circumstances we will just loop and try again and again etc */

  ptr = Curl_dyn_ptr(in);
  size = Curl_dyn_len(in);

  headersize = size - (size_t)included_body_bytes; /* the initial part that
                                                      isn't body is header */

  DEBUGASSERT(size > (size_t)included_body_bytes);

  if((conn->handler->flags & PROTOPT_SSL
#ifndef CURL_DISABLE_PROXY
      || IS_HTTPS_PROXY(conn->http_proxy.proxytype)
#endif
       )
     && conn->httpversion != 20) {
    /* Make sure this doesn't send more body bytes than what the max send
       speed says. The request bytes do not count to the max speed.
    */
    if(data->set.max_send_speed &&
       (included_body_bytes > data->set.max_send_speed)) {
      curl_off_t overflow = included_body_bytes - data->set.max_send_speed;
      DEBUGASSERT((size_t)overflow < size);
      sendsize = size - (size_t)overflow;
    }
    else
      sendsize = size;

    /* OpenSSL is very picky and we must send the SAME buffer pointer to the
       library when we attempt to re-send this buffer. Sending the same data
       is not enough, we must use the exact same address. For this reason, we
       must copy the data to the uploadbuffer first, since that is the buffer
       we will be using if this send is retried later.
    */
    result = Curl_get_upload_buffer(data);
    if(result) {
      /* malloc failed, free memory and return to the caller */
      Curl_dyn_free(in);
      return result;
    }
    /* We never send more than upload_buffer_size bytes in one single chunk
       when we speak HTTPS, as if only a fraction of it is sent now, this data
       needs to fit into the normal read-callback buffer later on and that
       buffer is using this size.
    */
    if(sendsize > (size_t)data->set.upload_buffer_size)
      sendsize = (size_t)data->set.upload_buffer_size;

    memcpy(data->state.ulbuf, ptr, sendsize);
    ptr = data->state.ulbuf;
  }
  else {
#ifdef CURLDEBUG
    /* Allow debug builds to override this logic to force short initial
       sends
     */
    char *p = getenv("CURL_SMALLREQSEND");
    if(p) {
      size_t altsize = (size_t)strtoul(p, NULL, 10);
      if(altsize)
        sendsize = CURLMIN(size, altsize);
      else
        sendsize = size;
    }
    else
#endif
    {
      /* Make sure this doesn't send more body bytes than what the max send
         speed says. The request bytes do not count to the max speed.
      */
      if(data->set.max_send_speed &&
         (included_body_bytes > data->set.max_send_speed)) {
        curl_off_t overflow = included_body_bytes - data->set.max_send_speed;
        DEBUGASSERT((size_t)overflow < size);
        sendsize = size - (size_t)overflow;
      }
      else
        sendsize = size;
    }
  }

  result = Curl_write(data, sockfd, ptr, sendsize, &amount);

  if(!result) {
    /*
     * Note that we may not send the entire chunk at once, and we have a set
     * number of data bytes at the end of the big buffer (out of which we may
     * only send away a part).
     */
    /* how much of the header that was sent */
    size_t headlen = (size_t)amount>headersize ? headersize : (size_t)amount;
    size_t bodylen = amount - headlen;

    /* this data _may_ contain binary stuff */
    Curl_debug(data, CURLINFO_HEADER_OUT, ptr, headlen);
    if(bodylen)
      /* there was body data sent beyond the initial header part, pass that on
         to the debug callback too */
      Curl_debug(data, CURLINFO_DATA_OUT, ptr + headlen, bodylen);

    /* 'amount' can never be a very large value here so typecasting it so a
       signed 31 bit value should not cause problems even if ssize_t is
       64bit */
    *bytes_written += (long)amount;

    if(http) {
      /* if we sent a piece of the body here, up the byte counter for it
         accordingly */
      data->req.writebytecount += bodylen;
      Curl_pgrsSetUploadCounter(data, data->req.writebytecount);

      if((size_t)amount != size) {
        /* The whole request could not be sent in one system call. We must
           queue it up and send it later when we get the chance. We must not
           loop here and wait until it might work again. */

        size -= amount;

        ptr = Curl_dyn_ptr(in) + amount;

        /* backup the currently set pointers */
        http->backup.fread_func = data->state.fread_func;
        http->backup.fread_in = data->state.in;
        http->backup.postdata = http->postdata;
        http->backup.postsize = http->postsize;
        http->backup.data = data;

        /* set the new pointers for the request-sending */
        data->state.fread_func = (curl_read_callback)readmoredata;
        data->state.in = (void *)http;
        http->postdata = ptr;
        http->postsize = (curl_off_t)size;

        /* this much data is remaining header: */
        data->req.pendingheader = headersize - headlen;

        http->send_buffer = *in; /* copy the whole struct */
        http->sending = HTTPSEND_REQUEST;
        return CURLE_OK;
      }
      http->sending = HTTPSEND_BODY;
      /* the full buffer was sent, clean up and return */
    }
    else {
      if((size_t)amount != size)
        /* We have no continue-send mechanism now, fail. This can only happen
           when this function is used from the CONNECT sending function. We
           currently (stupidly) assume that the whole request is always sent
           away in the first single chunk.

           This needs FIXing.
        */
        return CURLE_SEND_ERROR;
    }
  }
  Curl_dyn_free(in);

  /* no remaining header data */
  data->req.pendingheader = 0;
  return result;
}

/* end of the add_buffer functions */
/* ------------------------------------------------------------------------- */



/*
 * Curl_compareheader()
 *
 * Returns TRUE if 'headerline' contains the 'header' with given 'content'.
 * Pass headers WITH the colon.
 */
bool
Curl_compareheader(const char *headerline, /* line to check */
                   const char *header,  /* header keyword _with_ colon */
                   const size_t hlen,   /* len of the keyword in bytes */
                   const char *content, /* content string to find */
                   const size_t clen)   /* len of the content in bytes */
{
  /* RFC2616, section 4.2 says: "Each header field consists of a name followed
   * by a colon (":") and the field value. Field names are case-insensitive.
   * The field value MAY be preceded by any amount of LWS, though a single SP
   * is preferred." */

  size_t len;
  const char *start;
  const char *end;
  DEBUGASSERT(hlen);
  DEBUGASSERT(clen);
  DEBUGASSERT(header);
  DEBUGASSERT(content);

  if(!strncasecompare(headerline, header, hlen))
    return FALSE; /* doesn't start with header */

  /* pass the header */
  start = &headerline[hlen];

  /* pass all whitespace */
  while(*start && ISSPACE(*start))
    start++;

  /* find the end of the header line */
  end = strchr(start, '\r'); /* lines end with CRLF */
  if(!end) {
    /* in case there's a non-standard compliant line here */
    end = strchr(start, '\n');

    if(!end)
      /* hm, there's no line ending here, use the zero byte! */
      end = strchr(start, '\0');
  }

  len = end-start; /* length of the content part of the input line */

  /* find the content string in the rest of the line */
  for(; len >= clen; len--, start++) {
    if(strncasecompare(start, content, clen))
      return TRUE; /* match! */
  }

  return FALSE; /* no match */
}

/*
 * Curl_http_connect() performs HTTP stuff to do at connect-time, called from
 * the generic Curl_connect().
 */
CURLcode Curl_http_connect(struct Curl_easy *data, bool *done)
{
  struct connectdata *conn = data->conn;

  /* We default to persistent connections. We set this already in this connect
     function to make the re-use checks properly be able to check this bit. */
  connkeep(conn, "HTTP default");

  return Curl_conn_connect(data, FIRSTSOCKET, FALSE, done);
}

/* this returns the socket to wait for in the DO and DOING state for the multi
   interface and then we're always _sending_ a request and thus we wait for
   the single socket to become writable only */
static int http_getsock_do(struct Curl_easy *data,
                           struct connectdata *conn,
                           curl_socket_t *socks)
{
  /* write mode */
  (void)conn;
  socks[0] = Curl_conn_get_socket(data, FIRSTSOCKET);
  return GETSOCK_WRITESOCK(0);
}

/*
 * Curl_http_done() gets called after a single HTTP request has been
 * performed.
 */

CURLcode Curl_http_done(struct Curl_easy *data,
                        CURLcode status, bool premature)
{
  struct connectdata *conn = data->conn;
  struct HTTP *http = data->req.p.http;

  /* Clear multipass flag. If authentication isn't done yet, then it will get
   * a chance to be set back to true when we output the next auth header */
  data->state.authhost.multipass = FALSE;
  data->state.authproxy.multipass = FALSE;

  Curl_unencode_cleanup(data);

  /* set the proper values (possibly modified on POST) */
  conn->seek_func = data->set.seek_func; /* restore */
  conn->seek_client = data->set.seek_client; /* restore */

  if(!http)
    return CURLE_OK;

  Curl_dyn_free(&http->send_buffer);
  Curl_mime_cleanpart(&http->form);
  Curl_dyn_reset(&data->state.headerb);
  Curl_hyper_done(data);
  Curl_ws_done(data);

  if(status)
    return status;

  if(!premature && /* this check is pointless when DONE is called before the
                      entire operation is complete */
     !conn->bits.retry &&
     !data->set.connect_only &&
     (data->req.bytecount +
      data->req.headerbytecount -
      data->req.deductheadercount) <= 0) {
    /* If this connection isn't simply closed to be retried, AND nothing was
       read from the HTTP server (that counts), this can't be right so we
       return an error here */
    failf(data, "Empty reply from server");
    /* Mark it as closed to avoid the "left intact" message */
    streamclose(conn, "Empty reply from server");
    return CURLE_GOT_NOTHING;
  }

  return CURLE_OK;
}

/*
 * Determine if we should use HTTP 1.1 (OR BETTER) for this request. Reasons
 * to avoid it include:
 *
 * - if the user specifically requested HTTP 1.0
 * - if the server we are connected to only supports 1.0
 * - if any server previously contacted to handle this request only supports
 * 1.0.
 */
bool Curl_use_http_1_1plus(const struct Curl_easy *data,
                           const struct connectdata *conn)
{
  if((data->state.httpversion == 10) || (conn->httpversion == 10))
    return FALSE;
  if((data->state.httpwant == CURL_HTTP_VERSION_1_0) &&
     (conn->httpversion <= 10))
    return FALSE;
  return ((data->state.httpwant == CURL_HTTP_VERSION_NONE) ||
          (data->state.httpwant >= CURL_HTTP_VERSION_1_1));
}

#ifndef USE_HYPER
static const char *get_http_string(const struct Curl_easy *data,
                                   const struct connectdata *conn)
{
  if(Curl_conn_is_http3(data, conn, FIRSTSOCKET))
    return "3";
  if(Curl_conn_is_http2(data, conn, FIRSTSOCKET))
    return "2";
  if(Curl_use_http_1_1plus(data, conn))
    return "1.1";

  return "1.0";
}
#endif

/* check and possibly add an Expect: header */
static CURLcode expect100(struct Curl_easy *data,
                          struct connectdata *conn,
                          struct dynbuf *req)
{
  CURLcode result = CURLE_OK;
  data->state.expect100header = FALSE; /* default to false unless it is set
                                          to TRUE below */
  if(!data->state.disableexpect && Curl_use_http_1_1plus(data, conn) &&
     (conn->httpversion < 20)) {
    /* if not doing HTTP 1.0 or version 2, or disabled explicitly, we add an
       Expect: 100-continue to the headers which actually speeds up post
       operations (as there is one packet coming back from the web server) */
    const char *ptr = Curl_checkheaders(data, STRCONST("Expect"));
    if(ptr) {
      data->state.expect100header =
        Curl_compareheader(ptr, STRCONST("Expect:"), STRCONST("100-continue"));
    }
    else {
      result = Curl_dyn_addn(req, STRCONST("Expect: 100-continue\r\n"));
      if(!result)
        data->state.expect100header = TRUE;
    }
  }

  return result;
}

enum proxy_use {
  HEADER_SERVER,  /* direct to server */
  HEADER_PROXY,   /* regular request to proxy */
  HEADER_CONNECT  /* sending CONNECT to a proxy */
};

/* used to compile the provided trailers into one buffer
   will return an error code if one of the headers is
   not formatted correctly */
CURLcode Curl_http_compile_trailers(struct curl_slist *trailers,
                                    struct dynbuf *b,
                                    struct Curl_easy *handle)
{
  char *ptr = NULL;
  CURLcode result = CURLE_OK;
  const char *endofline_native = NULL;
  const char *endofline_network = NULL;

  if(
#ifdef CURL_DO_LINEEND_CONV
     (handle->state.prefer_ascii) ||
#endif
     (handle->set.crlf)) {
    /* \n will become \r\n later on */
    endofline_native  = "\n";
    endofline_network = "\x0a";
  }
  else {
    endofline_native  = "\r\n";
    endofline_network = "\x0d\x0a";
  }

  while(trailers) {
    /* only add correctly formatted trailers */
    ptr = strchr(trailers->data, ':');
    if(ptr && *(ptr + 1) == ' ') {
      result = Curl_dyn_add(b, trailers->data);
      if(result)
        return result;
      result = Curl_dyn_add(b, endofline_native);
      if(result)
        return result;
    }
    else
      infof(handle, "Malformatted trailing header, skipping trailer");
    trailers = trailers->next;
  }
  result = Curl_dyn_add(b, endofline_network);
  return result;
}

static bool hd_name_eq(const char *n1, size_t n1len,
                       const char *n2, size_t n2len)
{
  if(n1len == n2len) {
    return strncasecompare(n1, n2, n1len);
  }
  return FALSE;
}

CURLcode Curl_dynhds_add_custom(struct Curl_easy *data,
                                bool is_connect,
                                struct dynhds *hds)
{
  struct connectdata *conn = data->conn;
  char *ptr;
  struct curl_slist *h[2];
  struct curl_slist *headers;
  int numlists = 1; /* by default */
  int i;

#ifndef CURL_DISABLE_PROXY
  enum proxy_use proxy;

  if(is_connect)
    proxy = HEADER_CONNECT;
  else
    proxy = conn->bits.httpproxy && !conn->bits.tunnel_proxy?
      HEADER_PROXY:HEADER_SERVER;

  switch(proxy) {
  case HEADER_SERVER:
    h[0] = data->set.headers;
    break;
  case HEADER_PROXY:
    h[0] = data->set.headers;
    if(data->set.sep_headers) {
      h[1] = data->set.proxyheaders;
      numlists++;
    }
    break;
  case HEADER_CONNECT:
    if(data->set.sep_headers)
      h[0] = data->set.proxyheaders;
    else
      h[0] = data->set.headers;
    break;
  }
#else
  (void)is_connect;
  h[0] = data->set.headers;
#endif

  /* loop through one or two lists */
  for(i = 0; i < numlists; i++) {
    for(headers = h[i]; headers; headers = headers->next) {
      const char *name, *value;
      size_t namelen, valuelen;

      /* There are 2 quirks in place for custom headers:
       * 1. setting only 'name:' to suppress a header from being sent
       * 2. setting only 'name;' to send an empty (illegal) header
       */
      ptr = strchr(headers->data, ':');
      if(ptr) {
        name = headers->data;
        namelen = ptr - headers->data;
        ptr++; /* pass the colon */
        while(*ptr && ISSPACE(*ptr))
          ptr++;
        if(*ptr) {
          value = ptr;
          valuelen = strlen(value);
        }
        else {
          /* quirk #1, suppress this header */
          continue;
        }
      }
      else {
        ptr = strchr(headers->data, ';');

        if(!ptr) {
          /* neither : nor ; in provided header value. We seem
           * to ignore this silently */
          continue;
        }

        name = headers->data;
        namelen = ptr - headers->data;
        ptr++; /* pass the semicolon */
        while(*ptr && ISSPACE(*ptr))
          ptr++;
        if(!*ptr) {
          /* quirk #2, send an empty header */
          value = "";
          valuelen = 0;
        }
        else {
          /* this may be used for something else in the future,
           * ignore this for now */
          continue;
        }
      }

      DEBUGASSERT(name && value);
      if(data->state.aptr.host &&
         /* a Host: header was sent already, don't pass on any custom Host:
            header as that will produce *two* in the same request! */
         hd_name_eq(name, namelen, STRCONST("Host:")))
        ;
      else if(data->state.httpreq == HTTPREQ_POST_FORM &&
              /* this header (extended by formdata.c) is sent later */
              hd_name_eq(name, namelen, STRCONST("Content-Type:")))
        ;
      else if(data->state.httpreq == HTTPREQ_POST_MIME &&
              /* this header is sent later */
              hd_name_eq(name, namelen, STRCONST("Content-Type:")))
        ;
      else if(conn->bits.authneg &&
              /* while doing auth neg, don't allow the custom length since
                 we will force length zero then */
              hd_name_eq(name, namelen, STRCONST("Content-Length:")))
        ;
      else if(data->state.aptr.te &&
              /* when asking for Transfer-Encoding, don't pass on a custom
                 Connection: */
              hd_name_eq(name, namelen, STRCONST("Connection:")))
        ;
      else if((conn->httpversion >= 20) &&
              hd_name_eq(name, namelen, STRCONST("Transfer-Encoding:")))
        /* HTTP/2 doesn't support chunked requests */
        ;
      else if((hd_name_eq(name, namelen, STRCONST("Authorization:")) ||
               hd_name_eq(name, namelen, STRCONST("Cookie:"))) &&
              /* be careful of sending this potentially sensitive header to
                 other hosts */
              !Curl_auth_allowed_to_host(data))
        ;
      else {
        CURLcode result;

        result = Curl_dynhds_add(hds, name, namelen, value, valuelen);
        if(result)
          return result;
      }
    }
  }

  return CURLE_OK;
}

CURLcode Curl_add_custom_headers(struct Curl_easy *data,
                                 bool is_connect,
#ifndef USE_HYPER
                                 struct dynbuf *req
#else
                                 void *req
#endif
  )
{
  struct connectdata *conn = data->conn;
  char *ptr;
  struct curl_slist *h[2];
  struct curl_slist *headers;
  int numlists = 1; /* by default */
  int i;

#ifndef CURL_DISABLE_PROXY
  enum proxy_use proxy;

  if(is_connect)
    proxy = HEADER_CONNECT;
  else
    proxy = conn->bits.httpproxy && !conn->bits.tunnel_proxy?
      HEADER_PROXY:HEADER_SERVER;

  switch(proxy) {
  case HEADER_SERVER:
    h[0] = data->set.headers;
    break;
  case HEADER_PROXY:
    h[0] = data->set.headers;
    if(data->set.sep_headers) {
      h[1] = data->set.proxyheaders;
      numlists++;
    }
    break;
  case HEADER_CONNECT:
    if(data->set.sep_headers)
      h[0] = data->set.proxyheaders;
    else
      h[0] = data->set.headers;
    break;
  }
#else
  (void)is_connect;
  h[0] = data->set.headers;
#endif

  /* loop through one or two lists */
  for(i = 0; i < numlists; i++) {
    headers = h[i];

    while(headers) {
      char *semicolonp = NULL;
      ptr = strchr(headers->data, ':');
      if(!ptr) {
        char *optr;
        /* no colon, semicolon? */
        ptr = strchr(headers->data, ';');
        if(ptr) {
          optr = ptr;
          ptr++; /* pass the semicolon */
          while(*ptr && ISSPACE(*ptr))
            ptr++;

          if(*ptr) {
            /* this may be used for something else in the future */
            optr = NULL;
          }
          else {
            if(*(--ptr) == ';') {
              /* copy the source */
              semicolonp = strdup(headers->data);
              if(!semicolonp) {
#ifndef USE_HYPER
                Curl_dyn_free(req);
#endif
                return CURLE_OUT_OF_MEMORY;
              }
              /* put a colon where the semicolon is */
              semicolonp[ptr - headers->data] = ':';
              /* point at the colon */
              optr = &semicolonp [ptr - headers->data];
            }
          }
          ptr = optr;
        }
      }
      if(ptr && (ptr != headers->data)) {
        /* we require a colon for this to be a true header */

        ptr++; /* pass the colon */
        while(*ptr && ISSPACE(*ptr))
          ptr++;

        if(*ptr || semicolonp) {
          /* only send this if the contents was non-blank or done special */
          CURLcode result = CURLE_OK;
          char *compare = semicolonp ? semicolonp : headers->data;

          if(data->state.aptr.host &&
             /* a Host: header was sent already, don't pass on any custom Host:
                header as that will produce *two* in the same request! */
             checkprefix("Host:", compare))
            ;
          else if(data->state.httpreq == HTTPREQ_POST_FORM &&
                  /* this header (extended by formdata.c) is sent later */
                  checkprefix("Content-Type:", compare))
            ;
          else if(data->state.httpreq == HTTPREQ_POST_MIME &&
                  /* this header is sent later */
                  checkprefix("Content-Type:", compare))
            ;
          else if(conn->bits.authneg &&
                  /* while doing auth neg, don't allow the custom length since
                     we will force length zero then */
                  checkprefix("Content-Length:", compare))
            ;
          else if(data->state.aptr.te &&
                  /* when asking for Transfer-Encoding, don't pass on a custom
                     Connection: */
                  checkprefix("Connection:", compare))
            ;
          else if((conn->httpversion >= 20) &&
                  checkprefix("Transfer-Encoding:", compare))
            /* HTTP/2 doesn't support chunked requests */
            ;
          else if((checkprefix("Authorization:", compare) ||
                   checkprefix("Cookie:", compare)) &&
                  /* be careful of sending this potentially sensitive header to
                     other hosts */
                  !Curl_auth_allowed_to_host(data))
            ;
          else {
#ifdef USE_HYPER
            result = Curl_hyper_header(data, req, compare);
#else
            result = Curl_dyn_addf(req, "%s\r\n", compare);
#endif
          }
          if(semicolonp)
            free(semicolonp);
          if(result)
            return result;
        }
      }
      headers = headers->next;
    }
  }

  return CURLE_OK;
}

#ifndef CURL_DISABLE_PARSEDATE
CURLcode Curl_add_timecondition(struct Curl_easy *data,
#ifndef USE_HYPER
                                struct dynbuf *req
#else
                                void *req
#endif
  )
{
  const struct tm *tm;
  struct tm keeptime;
  CURLcode result;
  char datestr[80];
  const char *condp;
  size_t len;

  if(data->set.timecondition == CURL_TIMECOND_NONE)
    /* no condition was asked for */
    return CURLE_OK;

  result = Curl_gmtime(data->set.timevalue, &keeptime);
  if(result) {
    failf(data, "Invalid TIMEVALUE");
    return result;
  }
  tm = &keeptime;

  switch(data->set.timecondition) {
  default:
    return CURLE_BAD_FUNCTION_ARGUMENT;

  case CURL_TIMECOND_IFMODSINCE:
    condp = "If-Modified-Since";
    len = 17;
    break;
  case CURL_TIMECOND_IFUNMODSINCE:
    condp = "If-Unmodified-Since";
    len = 19;
    break;
  case CURL_TIMECOND_LASTMOD:
    condp = "Last-Modified";
    len = 13;
    break;
  }

  if(Curl_checkheaders(data, condp, len)) {
    /* A custom header was specified; it will be sent instead. */
    return CURLE_OK;
  }

  /* The If-Modified-Since header family should have their times set in
   * GMT as RFC2616 defines: "All HTTP date/time stamps MUST be
   * represented in Greenwich Mean Time (GMT), without exception. For the
   * purposes of HTTP, GMT is exactly equal to UTC (Coordinated Universal
   * Time)." (see page 20 of RFC2616).
   */

  /* format: "Tue, 15 Nov 1994 12:45:26 GMT" */
  msnprintf(datestr, sizeof(datestr),
            "%s: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n",
            condp,
            Curl_wkday[tm->tm_wday?tm->tm_wday-1:6],
            tm->tm_mday,
            Curl_month[tm->tm_mon],
            tm->tm_year + 1900,
            tm->tm_hour,
            tm->tm_min,
            tm->tm_sec);

#ifndef USE_HYPER
  result = Curl_dyn_add(req, datestr);
#else
  result = Curl_hyper_header(data, req, datestr);
#endif

  return result;
}
#else
/* disabled */
CURLcode Curl_add_timecondition(struct Curl_easy *data,
                                struct dynbuf *req)
{
  (void)data;
  (void)req;
  return CURLE_OK;
}
#endif

void Curl_http_method(struct Curl_easy *data, struct connectdata *conn,
                      const char **method, Curl_HttpReq *reqp)
{
  Curl_HttpReq httpreq = (Curl_HttpReq)data->state.httpreq;
  const char *request;
  if((conn->handler->protocol&(PROTO_FAMILY_HTTP|CURLPROTO_FTP)) &&
     data->state.upload)
    httpreq = HTTPREQ_PUT;

  /* Now set the 'request' pointer to the proper request string */
  if(data->set.str[STRING_CUSTOMREQUEST])
    request = data->set.str[STRING_CUSTOMREQUEST];
  else {
    if(data->req.no_body)
      request = "HEAD";
    else {
      DEBUGASSERT((httpreq >= HTTPREQ_GET) && (httpreq <= HTTPREQ_HEAD));
      switch(httpreq) {
      case HTTPREQ_POST:
      case HTTPREQ_POST_FORM:
      case HTTPREQ_POST_MIME:
        request = "POST";
        break;
      case HTTPREQ_PUT:
        request = "PUT";
        break;
      default: /* this should never happen */
      case HTTPREQ_GET:
        request = "GET";
        break;
      case HTTPREQ_HEAD:
        request = "HEAD";
        break;
      }
    }
  }
  *method = request;
  *reqp = httpreq;
}

CURLcode Curl_http_useragent(struct Curl_easy *data)
{
  /* The User-Agent string might have been allocated in url.c already, because
     it might have been used in the proxy connect, but if we have got a header
     with the user-agent string specified, we erase the previously made string
     here. */
  if(Curl_checkheaders(data, STRCONST("User-Agent"))) {
    free(data->state.aptr.uagent);
    data->state.aptr.uagent = NULL;
  }
  return CURLE_OK;
}


CURLcode Curl_http_host(struct Curl_easy *data, struct connectdata *conn)
{
  const char *ptr;
  struct dynamically_allocated_data *aptr = &data->state.aptr;
  if(!data->state.this_is_a_follow) {
    /* Free to avoid leaking memory on multiple requests */
    free(data->state.first_host);

    data->state.first_host = strdup(conn->host.name);
    if(!data->state.first_host)
      return CURLE_OUT_OF_MEMORY;

    data->state.first_remote_port = conn->remote_port;
    data->state.first_remote_protocol = conn->handler->protocol;
  }
  Curl_safefree(aptr->host);

  ptr = Curl_checkheaders(data, STRCONST("Host"));
  if(ptr && (!data->state.this_is_a_follow ||
             strcasecompare(data->state.first_host, conn->host.name))) {
#if !defined(CURL_DISABLE_COOKIES)
    /* If we have a given custom Host: header, we extract the host name in
       order to possibly use it for cookie reasons later on. We only allow the
       custom Host: header if this is NOT a redirect, as setting Host: in the
       redirected request is being out on thin ice. Except if the host name
       is the same as the first one! */
    char *cookiehost = Curl_copy_header_value(ptr);
    if(!cookiehost)
      return CURLE_OUT_OF_MEMORY;
    if(!*cookiehost)
      /* ignore empty data */
      free(cookiehost);
    else {
      /* If the host begins with '[', we start searching for the port after
         the bracket has been closed */
      if(*cookiehost == '[') {
        char *closingbracket;
        /* since the 'cookiehost' is an allocated memory area that will be
           freed later we cannot simply increment the pointer */
        memmove(cookiehost, cookiehost + 1, strlen(cookiehost) - 1);
        closingbracket = strchr(cookiehost, ']');
        if(closingbracket)
          *closingbracket = 0;
      }
      else {
        int startsearch = 0;
        char *colon = strchr(cookiehost + startsearch, ':');
        if(colon)
          *colon = 0; /* The host must not include an embedded port number */
      }
      Curl_safefree(aptr->cookiehost);
      aptr->cookiehost = cookiehost;
    }
#endif

    if(strcmp("Host:", ptr)) {
      aptr->host = aprintf("Host:%s\r\n", &ptr[5]);
      if(!aptr->host)
        return CURLE_OUT_OF_MEMORY;
    }
  }
  else {
    /* When building Host: headers, we must put the host name within
       [brackets] if the host name is a plain IPv6-address. RFC2732-style. */
    const char *host = conn->host.name;

    if(((conn->given->protocol&(CURLPROTO_HTTPS|CURLPROTO_WSS)) &&
        (conn->remote_port == PORT_HTTPS)) ||
       ((conn->given->protocol&(CURLPROTO_HTTP|CURLPROTO_WS)) &&
        (conn->remote_port == PORT_HTTP)) )
      /* if(HTTPS on port 443) OR (HTTP on port 80) then don't include
         the port number in the host string */
      aptr->host = aprintf("Host: %s%s%s\r\n", conn->bits.ipv6_ip?"[":"",
                           host, conn->bits.ipv6_ip?"]":"");
    else
      aptr->host = aprintf("Host: %s%s%s:%d\r\n", conn->bits.ipv6_ip?"[":"",
                           host, conn->bits.ipv6_ip?"]":"",
                           conn->remote_port);

    if(!aptr->host)
      /* without Host: we can't make a nice request */
      return CURLE_OUT_OF_MEMORY;
  }
  return CURLE_OK;
}

/*
 * Append the request-target to the HTTP request
 */
CURLcode Curl_http_target(struct Curl_easy *data,
                          struct connectdata *conn,
                          struct dynbuf *r)
{
  CURLcode result = CURLE_OK;
  const char *path = data->state.up.path;
  const char *query = data->state.up.query;

  if(data->set.str[STRING_TARGET]) {
    path = data->set.str[STRING_TARGET];
    query = NULL;
  }

#ifndef CURL_DISABLE_PROXY
  if(conn->bits.httpproxy && !conn->bits.tunnel_proxy) {
    /* Using a proxy but does not tunnel through it */

    /* The path sent to the proxy is in fact the entire URL. But if the remote
       host is a IDN-name, we must make sure that the request we produce only
       uses the encoded host name! */

    /* and no fragment part */
    CURLUcode uc;
    char *url;
    CURLU *h = curl_url_dup(data->state.uh);
    if(!h)
      return CURLE_OUT_OF_MEMORY;

    if(conn->host.dispname != conn->host.name) {
      uc = curl_url_set(h, CURLUPART_HOST, conn->host.name, 0);
      if(uc) {
        curl_url_cleanup(h);
        return CURLE_OUT_OF_MEMORY;
      }
    }
    uc = curl_url_set(h, CURLUPART_FRAGMENT, NULL, 0);
    if(uc) {
      curl_url_cleanup(h);
      return CURLE_OUT_OF_MEMORY;
    }

    if(strcasecompare("http", data->state.up.scheme)) {
      /* when getting HTTP, we don't want the userinfo the URL */
      uc = curl_url_set(h, CURLUPART_USER, NULL, 0);
      if(uc) {
        curl_url_cleanup(h);
        return CURLE_OUT_OF_MEMORY;
      }
      uc = curl_url_set(h, CURLUPART_PASSWORD, NULL, 0);
      if(uc) {
        curl_url_cleanup(h);
        return CURLE_OUT_OF_MEMORY;
      }
    }
    /* Extract the URL to use in the request. Store in STRING_TEMP_URL for
       clean-up reasons if the function returns before the free() further
       down. */
    uc = curl_url_get(h, CURLUPART_URL, &url, CURLU_NO_DEFAULT_PORT);
    if(uc) {
      curl_url_cleanup(h);
      return CURLE_OUT_OF_MEMORY;
    }

    curl_url_cleanup(h);

    /* target or url */
    result = Curl_dyn_add(r, data->set.str[STRING_TARGET]?
      data->set.str[STRING_TARGET]:url);
    free(url);
    if(result)
      return (result);

    if(strcasecompare("ftp", data->state.up.scheme)) {
      if(data->set.proxy_transfer_mode) {
        /* when doing ftp, append ;type=<a|i> if not present */
        char *type = strstr(path, ";type=");
        if(type && type[6] && type[7] == 0) {
          switch(Curl_raw_toupper(type[6])) {
          case 'A':
          case 'D':
          case 'I':
            break;
          default:
            type = NULL;
          }
        }
        if(!type) {
          result = Curl_dyn_addf(r, ";type=%c",
                                 data->state.prefer_ascii ? 'a' : 'i');
          if(result)
            return result;
        }
      }
    }
  }

  else
#else
    (void)conn; /* not used in disabled-proxy builds */
#endif
  {
    result = Curl_dyn_add(r, path);
    if(result)
      return result;
    if(query)
      result = Curl_dyn_addf(r, "?%s", query);
  }

  return result;
}

CURLcode Curl_http_body(struct Curl_easy *data, struct connectdata *conn,
                        Curl_HttpReq httpreq, const char **tep)
{
  CURLcode result = CURLE_OK;
  const char *ptr;
  struct HTTP *http = data->req.p.http;
  http->postsize = 0;

  switch(httpreq) {
  case HTTPREQ_POST_MIME:
    http->sendit = &data->set.mimepost;
    break;
  case HTTPREQ_POST_FORM:
    /* Convert the form structure into a mime structure. */
    Curl_mime_cleanpart(&http->form);
    result = Curl_getformdata(data, &http->form, data->set.httppost,
                              data->state.fread_func);
    if(result)
      return result;
    http->sendit = &http->form;
    break;
  default:
    http->sendit = NULL;
  }

#ifndef CURL_DISABLE_MIME
  if(http->sendit) {
    const char *cthdr = Curl_checkheaders(data, STRCONST("Content-Type"));

    /* Read and seek body only. */
    http->sendit->flags |= MIME_BODY_ONLY;

    /* Prepare the mime structure headers & set content type. */

    if(cthdr)
      for(cthdr += 13; *cthdr == ' '; cthdr++)
        ;
    else if(http->sendit->kind == MIMEKIND_MULTIPART)
      cthdr = "multipart/form-data";

    curl_mime_headers(http->sendit, data->set.headers, 0);
    result = Curl_mime_prepare_headers(data, http->sendit, cthdr,
                                       NULL, MIMESTRATEGY_FORM);
    curl_mime_headers(http->sendit, NULL, 0);
    if(!result)
      result = Curl_mime_rewind(http->sendit);
    if(result)
      return result;
    http->postsize = Curl_mime_size(http->sendit);
  }
#endif

  ptr = Curl_checkheaders(data, STRCONST("Transfer-Encoding"));
  if(ptr) {
    /* Some kind of TE is requested, check if 'chunked' is chosen */
    data->req.upload_chunky =
      Curl_compareheader(ptr,
                         STRCONST("Transfer-Encoding:"), STRCONST("chunked"));
  }
  else {
    if((conn->handler->protocol & PROTO_FAMILY_HTTP) &&
       (((httpreq == HTTPREQ_POST_MIME || httpreq == HTTPREQ_POST_FORM) &&
         http->postsize < 0) ||
        ((data->state.upload || httpreq == HTTPREQ_POST) &&
         data->state.infilesize == -1))) {
      if(conn->bits.authneg)
        /* don't enable chunked during auth neg */
        ;
      else if(Curl_use_http_1_1plus(data, conn)) {
        if(conn->httpversion < 20)
          /* HTTP, upload, unknown file size and not HTTP 1.0 */
          data->req.upload_chunky = TRUE;
      }
      else {
        failf(data, "Chunky upload is not supported by HTTP 1.0");
        return CURLE_UPLOAD_FAILED;
      }
    }
    else {
      /* else, no chunky upload */
      data->req.upload_chunky = FALSE;
    }

    if(data->req.upload_chunky)
      *tep = "Transfer-Encoding: chunked\r\n";
  }
  return result;
}

CURLcode Curl_http_bodysend(struct Curl_easy *data, struct connectdata *conn,
                            struct dynbuf *r, Curl_HttpReq httpreq)
{
#ifndef USE_HYPER
  /* Hyper always handles the body separately */
  curl_off_t included_body = 0;
#else
  /* from this point down, this function should not be used */
#define Curl_buffer_send(a,b,c,d,e,f) CURLE_OK
#endif
  CURLcode result = CURLE_OK;
  struct HTTP *http = data->req.p.http;
  const char *ptr;

  /* If 'authdone' is FALSE, we must not set the write socket index to the
     Curl_transfer() call below, as we're not ready to actually upload any
     data yet. */

  switch(httpreq) {

  case HTTPREQ_PUT: /* Let's PUT the data to the server! */

    if(conn->bits.authneg)
      http->postsize = 0;
    else
      http->postsize = data->state.infilesize;

    if((http->postsize != -1) && !data->req.upload_chunky &&
       (conn->bits.authneg ||
        !Curl_checkheaders(data, STRCONST("Content-Length")))) {
      /* only add Content-Length if not uploading chunked */
      result = Curl_dyn_addf(r, "Content-Length: %" CURL_FORMAT_CURL_OFF_T
                             "\r\n", http->postsize);
      if(result)
        return result;
    }

    /* For really small puts we don't use Expect: headers at all, and for
       the somewhat bigger ones we allow the app to disable it. Just make
       sure that the expect100header is always set to the preferred value
       here. */
    ptr = Curl_checkheaders(data, STRCONST("Expect"));
    if(ptr) {
      data->state.expect100header =
        Curl_compareheader(ptr, STRCONST("Expect:"), STRCONST("100-continue"));
    }
    else if(http->postsize > EXPECT_100_THRESHOLD || http->postsize < 0) {
      result = expect100(data, conn, r);
      if(result)
        return result;
    }

    /* end of headers */
    result = Curl_dyn_addn(r, STRCONST("\r\n"));
    if(result)
      return result;

    /* set the upload size to the progress meter */
    Curl_pgrsSetUploadSize(data, http->postsize);

    /* this sends the buffer and frees all the buffer resources */
    result = Curl_buffer_send(r, data, data->req.p.http,
                              &data->info.request_size, 0,
                              FIRSTSOCKET);
    if(result)
      failf(data, "Failed sending PUT request");
    else
      /* prepare for transfer */
      Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE,
                          http->postsize?FIRSTSOCKET:-1);
    if(result)
      return result;
    break;

  case HTTPREQ_POST_FORM:
  case HTTPREQ_POST_MIME:
    /* This is form posting using mime data. */
    if(conn->bits.authneg) {
      /* nothing to post! */
      result = Curl_dyn_addn(r, STRCONST("Content-Length: 0\r\n\r\n"));
      if(result)
        return result;

      result = Curl_buffer_send(r, data, data->req.p.http,
                                &data->info.request_size, 0,
                                FIRSTSOCKET);
      if(result)
        failf(data, "Failed sending POST request");
      else
        /* setup variables for the upcoming transfer */
        Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE, -1);
      break;
    }

    data->state.infilesize = http->postsize;

    /* We only set Content-Length and allow a custom Content-Length if
       we don't upload data chunked, as RFC2616 forbids us to set both
       kinds of headers (Transfer-Encoding: chunked and Content-Length) */
    if(http->postsize != -1 && !data->req.upload_chunky &&
       (!Curl_checkheaders(data, STRCONST("Content-Length")))) {
      /* we allow replacing this header if not during auth negotiation,
         although it isn't very wise to actually set your own */
      result = Curl_dyn_addf(r,
                             "Content-Length: %" CURL_FORMAT_CURL_OFF_T
                             "\r\n", http->postsize);
      if(result)
        return result;
    }

#ifndef CURL_DISABLE_MIME
    /* Output mime-generated headers. */
    {
      struct curl_slist *hdr;

      for(hdr = http->sendit->curlheaders; hdr; hdr = hdr->next) {
        result = Curl_dyn_addf(r, "%s\r\n", hdr->data);
        if(result)
          return result;
      }
    }
#endif

    /* For really small posts we don't use Expect: headers at all, and for
       the somewhat bigger ones we allow the app to disable it. Just make
       sure that the expect100header is always set to the preferred value
       here. */
    ptr = Curl_checkheaders(data, STRCONST("Expect"));
    if(ptr) {
      data->state.expect100header =
        Curl_compareheader(ptr, STRCONST("Expect:"), STRCONST("100-continue"));
    }
    else if(http->postsize > EXPECT_100_THRESHOLD || http->postsize < 0) {
      result = expect100(data, conn, r);
      if(result)
        return result;
    }
    else
      data->state.expect100header = FALSE;

    /* make the request end in a true CRLF */
    result = Curl_dyn_addn(r, STRCONST("\r\n"));
    if(result)
      return result;

    /* set the upload size to the progress meter */
    Curl_pgrsSetUploadSize(data, http->postsize);

    /* Read from mime structure. */
    data->state.fread_func = (curl_read_callback) Curl_mime_read;
    data->state.in = (void *) http->sendit;
    http->sending = HTTPSEND_BODY;

    /* this sends the buffer and frees all the buffer resources */
    result = Curl_buffer_send(r, data, data->req.p.http,
                              &data->info.request_size, 0,
                              FIRSTSOCKET);
    if(result)
      failf(data, "Failed sending POST request");
    else
      /* prepare for transfer */
      Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE,
                          http->postsize?FIRSTSOCKET:-1);
    if(result)
      return result;

    break;

  case HTTPREQ_POST:
    /* this is the simple POST, using x-www-form-urlencoded style */

    if(conn->bits.authneg)
      http->postsize = 0;
    else
      /* the size of the post body */
      http->postsize = data->state.infilesize;

    /* We only set Content-Length and allow a custom Content-Length if
       we don't upload data chunked, as RFC2616 forbids us to set both
       kinds of headers (Transfer-Encoding: chunked and Content-Length) */
    if((http->postsize != -1) && !data->req.upload_chunky &&
       (conn->bits.authneg ||
        !Curl_checkheaders(data, STRCONST("Content-Length")))) {
      /* we allow replacing this header if not during auth negotiation,
         although it isn't very wise to actually set your own */
      result = Curl_dyn_addf(r, "Content-Length: %" CURL_FORMAT_CURL_OFF_T
                             "\r\n", http->postsize);
      if(result)
        return result;
    }

    if(!Curl_checkheaders(data, STRCONST("Content-Type"))) {
      result = Curl_dyn_addn(r, STRCONST("Content-Type: application/"
                                         "x-www-form-urlencoded\r\n"));
      if(result)
        return result;
    }

    /* For really small posts we don't use Expect: headers at all, and for
       the somewhat bigger ones we allow the app to disable it. Just make
       sure that the expect100header is always set to the preferred value
       here. */
    ptr = Curl_checkheaders(data, STRCONST("Expect"));
    if(ptr) {
      data->state.expect100header =
        Curl_compareheader(ptr, STRCONST("Expect:"), STRCONST("100-continue"));
    }
    else if(http->postsize > EXPECT_100_THRESHOLD || http->postsize < 0) {
      result = expect100(data, conn, r);
      if(result)
        return result;
    }
    else
      data->state.expect100header = FALSE;

#ifndef USE_HYPER
    /* With Hyper the body is always passed on separately */
    if(data->set.postfields) {

      /* In HTTP2, we send request body in DATA frame regardless of
         its size. */
      if(conn->httpversion < 20 &&
         !data->state.expect100header &&
         (http->postsize < MAX_INITIAL_POST_SIZE)) {
        /* if we don't use expect: 100  AND
           postsize is less than MAX_INITIAL_POST_SIZE

           then append the post data to the HTTP request header. This limit
           is no magic limit but only set to prevent really huge POSTs to
           get the data duplicated with malloc() and family. */

        /* end of headers! */
        result = Curl_dyn_addn(r, STRCONST("\r\n"));
        if(result)
          return result;

        if(!data->req.upload_chunky) {
          /* We're not sending it 'chunked', append it to the request
             already now to reduce the number if send() calls */
          result = Curl_dyn_addn(r, data->set.postfields,
                                 (size_t)http->postsize);
          included_body = http->postsize;
        }
        else {
          if(http->postsize) {
            char chunk[16];
            /* Append the POST data chunky-style */
            msnprintf(chunk, sizeof(chunk), "%x\r\n", (int)http->postsize);
            result = Curl_dyn_add(r, chunk);
            if(!result) {
              included_body = http->postsize + strlen(chunk);
              result = Curl_dyn_addn(r, data->set.postfields,
                                     (size_t)http->postsize);
              if(!result)
                result = Curl_dyn_addn(r, STRCONST("\r\n"));
              included_body += 2;
            }
          }
          if(!result) {
            result = Curl_dyn_addn(r, STRCONST("\x30\x0d\x0a\x0d\x0a"));
            /* 0  CR  LF  CR  LF */
            included_body += 5;
          }
        }
        if(result)
          return result;
        /* Make sure the progress information is accurate */
        Curl_pgrsSetUploadSize(data, http->postsize);
      }
      else {
        /* A huge POST coming up, do data separate from the request */
        http->postdata = data->set.postfields;
        http->sending = HTTPSEND_BODY;
        http->backup.data = data;
        data->state.fread_func = (curl_read_callback)readmoredata;
        data->state.in = (void *)http;

        /* set the upload size to the progress meter */
        Curl_pgrsSetUploadSize(data, http->postsize);

        /* end of headers! */
        result = Curl_dyn_addn(r, STRCONST("\r\n"));
        if(result)
          return result;
      }
    }
    else
#endif
    {
       /* end of headers! */
      result = Curl_dyn_addn(r, STRCONST("\r\n"));
      if(result)
        return result;

      if(data->req.upload_chunky && conn->bits.authneg) {
        /* Chunky upload is selected and we're negotiating auth still, send
           end-of-data only */
        result = Curl_dyn_addn(r, (char *)STRCONST("\x30\x0d\x0a\x0d\x0a"));
        /* 0  CR  LF  CR  LF */
        if(result)
          return result;
      }

      else if(data->state.infilesize) {
        /* set the upload size to the progress meter */
        Curl_pgrsSetUploadSize(data, http->postsize?http->postsize:-1);

        /* set the pointer to mark that we will send the post body using the
           read callback, but only if we're not in authenticate negotiation */
        if(!conn->bits.authneg)
          http->postdata = (char *)&http->postdata;
      }
    }
    /* issue the request */
    result = Curl_buffer_send(r, data, data->req.p.http,
                              &data->info.request_size, included_body,
                              FIRSTSOCKET);

    if(result)
      failf(data, "Failed sending HTTP POST request");
    else
      Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE,
                          http->postdata?FIRSTSOCKET:-1);
    break;

  default:
    result = Curl_dyn_addn(r, STRCONST("\r\n"));
    if(result)
      return result;

    /* issue the request */
    result = Curl_buffer_send(r, data, data->req.p.http,
                              &data->info.request_size, 0,
                              FIRSTSOCKET);
    if(result)
      failf(data, "Failed sending HTTP request");
#ifdef USE_WEBSOCKETS
    else if((conn->handler->protocol & (CURLPROTO_WS|CURLPROTO_WSS)) &&
            !(data->set.connect_only))
      /* Set up the transfer for two-way since without CONNECT_ONLY set, this
         request probably wants to send data too post upgrade */
      Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE, FIRSTSOCKET);
#endif
    else
      /* HTTP GET/HEAD download: */
      Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE, -1);
  }

  return result;
}

#if !defined(CURL_DISABLE_COOKIES)

CURLcode Curl_http_cookies(struct Curl_easy *data,
                           struct connectdata *conn,
                           struct dynbuf *r)
{
  CURLcode result = CURLE_OK;
  char *addcookies = NULL;
  bool linecap = FALSE;
  if(data->set.str[STRING_COOKIE] &&
     !Curl_checkheaders(data, STRCONST("Cookie")))
    addcookies = data->set.str[STRING_COOKIE];

  if(data->cookies || addcookies) {
    struct Cookie *co = NULL; /* no cookies from start */
    int count = 0;

    if(data->cookies && data->state.cookie_engine) {
      const char *host = data->state.aptr.cookiehost ?
        data->state.aptr.cookiehost : conn->host.name;
      const bool secure_context =
        conn->handler->protocol&(CURLPROTO_HTTPS|CURLPROTO_WSS) ||
        strcasecompare("localhost", host) ||
        !strcmp(host, "127.0.0.1") ||
        !strcmp(host, "::1") ? TRUE : FALSE;
      Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
      co = Curl_cookie_getlist(data, data->cookies, host, data->state.up.path,
                               secure_context);
      Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
    }
    if(co) {
      struct Cookie *store = co;
      /* now loop through all cookies that matched */
      while(co) {
        if(co->value) {
          if(0 == count) {
            result = Curl_dyn_addn(r, STRCONST("Cookie: "));
            if(result)
              break;
          }
          if((Curl_dyn_len(r) + strlen(co->name) + strlen(co->value) + 1) >=
             MAX_COOKIE_HEADER_LEN) {
            infof(data, "Restricted outgoing cookies due to header size, "
                  "'%s' not sent", co->name);
            linecap = TRUE;
            break;
          }
          result = Curl_dyn_addf(r, "%s%s=%s", count?"; ":"",
                                 co->name, co->value);
          if(result)
            break;
          count++;
        }
        co = co->next; /* next cookie please */
      }
      Curl_cookie_freelist(store);
    }
    if(addcookies && !result && !linecap) {
      if(!count)
        result = Curl_dyn_addn(r, STRCONST("Cookie: "));
      if(!result) {
        result = Curl_dyn_addf(r, "%s%s", count?"; ":"", addcookies);
        count++;
      }
    }
    if(count && !result)
      result = Curl_dyn_addn(r, STRCONST("\r\n"));

    if(result)
      return result;
  }
  return result;
}
#endif

CURLcode Curl_http_range(struct Curl_easy *data,
                         Curl_HttpReq httpreq)
{
  if(data->state.use_range) {
    /*
     * A range is selected. We use different headers whether we're downloading
     * or uploading and we always let customized headers override our internal
     * ones if any such are specified.
     */
    if(((httpreq == HTTPREQ_GET) || (httpreq == HTTPREQ_HEAD)) &&
       !Curl_checkheaders(data, STRCONST("Range"))) {
      /* if a line like this was already allocated, free the previous one */
      free(data->state.aptr.rangeline);
      data->state.aptr.rangeline = aprintf("Range: bytes=%s\r\n",
                                           data->state.range);
    }
    else if((httpreq == HTTPREQ_POST || httpreq == HTTPREQ_PUT) &&
            !Curl_checkheaders(data, STRCONST("Content-Range"))) {

      /* if a line like this was already allocated, free the previous one */
      free(data->state.aptr.rangeline);

      if(data->set.set_resume_from < 0) {
        /* Upload resume was asked for, but we don't know the size of the
           remote part so we tell the server (and act accordingly) that we
           upload the whole file (again) */
        data->state.aptr.rangeline =
          aprintf("Content-Range: bytes 0-%" CURL_FORMAT_CURL_OFF_T
                  "/%" CURL_FORMAT_CURL_OFF_T "\r\n",
                  data->state.infilesize - 1, data->state.infilesize);

      }
      else if(data->state.resume_from) {
        /* This is because "resume" was selected */
        curl_off_t total_expected_size =
          data->state.resume_from + data->state.infilesize;
        data->state.aptr.rangeline =
          aprintf("Content-Range: bytes %s%" CURL_FORMAT_CURL_OFF_T
                  "/%" CURL_FORMAT_CURL_OFF_T "\r\n",
                  data->state.range, total_expected_size-1,
                  total_expected_size);
      }
      else {
        /* Range was selected and then we just pass the incoming range and
           append total size */
        data->state.aptr.rangeline =
          aprintf("Content-Range: bytes %s/%" CURL_FORMAT_CURL_OFF_T "\r\n",
                  data->state.range, data->state.infilesize);
      }
      if(!data->state.aptr.rangeline)
        return CURLE_OUT_OF_MEMORY;
    }
  }
  return CURLE_OK;
}

CURLcode Curl_http_resume(struct Curl_easy *data,
                          struct connectdata *conn,
                          Curl_HttpReq httpreq)
{
  if((HTTPREQ_POST == httpreq || HTTPREQ_PUT == httpreq) &&
     data->state.resume_from) {
    /**********************************************************************
     * Resuming upload in HTTP means that we PUT or POST and that we have
     * got a resume_from value set. The resume value has already created
     * a Range: header that will be passed along. We need to "fast forward"
     * the file the given number of bytes and decrease the assume upload
     * file size before we continue this venture in the dark lands of HTTP.
     * Resuming mime/form posting at an offset > 0 has no sense and is ignored.
     *********************************************************************/

    if(data->state.resume_from < 0) {
      /*
       * This is meant to get the size of the present remote-file by itself.
       * We don't support this now. Bail out!
       */
      data->state.resume_from = 0;
    }

    if(data->state.resume_from && !data->state.followlocation) {
      /* only act on the first request */

      /* Now, let's read off the proper amount of bytes from the
         input. */
      int seekerr = CURL_SEEKFUNC_CANTSEEK;
      if(conn->seek_func) {
        Curl_set_in_callback(data, true);
        seekerr = conn->seek_func(conn->seek_client, data->state.resume_from,
                                  SEEK_SET);
        Curl_set_in_callback(data, false);
      }

      if(seekerr != CURL_SEEKFUNC_OK) {
        curl_off_t passed = 0;

        if(seekerr != CURL_SEEKFUNC_CANTSEEK) {
          failf(data, "Could not seek stream");
          return CURLE_READ_ERROR;
        }
        /* when seekerr == CURL_SEEKFUNC_CANTSEEK (can't seek to offset) */
        do {
          size_t readthisamountnow =
            (data->state.resume_from - passed > data->set.buffer_size) ?
            (size_t)data->set.buffer_size :
            curlx_sotouz(data->state.resume_from - passed);

          size_t actuallyread =
            data->state.fread_func(data->state.buffer, 1, readthisamountnow,
                                   data->state.in);

          passed += actuallyread;
          if((actuallyread == 0) || (actuallyread > readthisamountnow)) {
            /* this checks for greater-than only to make sure that the
               CURL_READFUNC_ABORT return code still aborts */
            failf(data, "Could only read %" CURL_FORMAT_CURL_OFF_T
                  " bytes from the input", passed);
            return CURLE_READ_ERROR;
          }
        } while(passed < data->state.resume_from);
      }

      /* now, decrease the size of the read */
      if(data->state.infilesize>0) {
        data->state.infilesize -= data->state.resume_from;

        if(data->state.infilesize <= 0) {
          failf(data, "File already completely uploaded");
          return CURLE_PARTIAL_FILE;
        }
      }
      /* we've passed, proceed as normal */
    }
  }
  return CURLE_OK;
}

CURLcode Curl_http_firstwrite(struct Curl_easy *data,
                              struct connectdata *conn,
                              bool *done)
{
  struct SingleRequest *k = &data->req;

  if(data->req.newurl) {
    if(conn->bits.close) {
      /* Abort after the headers if "follow Location" is set
         and we're set to close anyway. */
      k->keepon &= ~KEEP_RECV;
      *done = TRUE;
      return CURLE_OK;
    }
    /* We have a new url to load, but since we want to be able to re-use this
       connection properly, we read the full response in "ignore more" */
    k->ignorebody = TRUE;
    infof(data, "Ignoring the response-body");
  }
  if(data->state.resume_from && !k->content_range &&
     (data->state.httpreq == HTTPREQ_GET) &&
     !k->ignorebody) {

    if(k->size == data->state.resume_from) {
      /* The resume point is at the end of file, consider this fine even if it
         doesn't allow resume from here. */
      infof(data, "The entire document is already downloaded");
      streamclose(conn, "already downloaded");
      /* Abort download */
      k->keepon &= ~KEEP_RECV;
      *done = TRUE;
      return CURLE_OK;
    }

    /* we wanted to resume a download, although the server doesn't seem to
     * support this and we did this with a GET (if it wasn't a GET we did a
     * POST or PUT resume) */
    failf(data, "HTTP server doesn't seem to support "
          "byte ranges. Cannot resume.");
    return CURLE_RANGE_ERROR;
  }

  if(data->set.timecondition && !data->state.range) {
    /* A time condition has been set AND no ranges have been requested. This
       seems to be what chapter 13.3.4 of RFC 2616 defines to be the correct
       action for an HTTP/1.1 client */

    if(!Curl_meets_timecondition(data, k->timeofdoc)) {
      *done = TRUE;
      /* We're simulating an HTTP 304 from server so we return
         what should have been returned from the server */
      data->info.httpcode = 304;
      infof(data, "Simulate an HTTP 304 response");
      /* we abort the transfer before it is completed == we ruin the
         re-use ability. Close the connection */
      streamclose(conn, "Simulated 304 handling");
      return CURLE_OK;
    }
  } /* we have a time condition */

  return CURLE_OK;
}

#ifdef HAVE_LIBZ
CURLcode Curl_transferencode(struct Curl_easy *data)
{
  if(!Curl_checkheaders(data, STRCONST("TE")) &&
     data->set.http_transfer_encoding) {
    /* When we are to insert a TE: header in the request, we must also insert
       TE in a Connection: header, so we need to merge the custom provided
       Connection: header and prevent the original to get sent. Note that if
       the user has inserted his/her own TE: header we don't do this magic
       but then assume that the user will handle it all! */
    char *cptr = Curl_checkheaders(data, STRCONST("Connection"));
#define TE_HEADER "TE: gzip\r\n"

    Curl_safefree(data->state.aptr.te);

    if(cptr) {
      cptr = Curl_copy_header_value(cptr);
      if(!cptr)
        return CURLE_OUT_OF_MEMORY;
    }

    /* Create the (updated) Connection: header */
    data->state.aptr.te = aprintf("Connection: %s%sTE\r\n" TE_HEADER,
                                cptr ? cptr : "", (cptr && *cptr) ? ", ":"");

    free(cptr);
    if(!data->state.aptr.te)
      return CURLE_OUT_OF_MEMORY;
  }
  return CURLE_OK;
}
#endif

#ifndef USE_HYPER
/*
 * Curl_http() gets called from the generic multi_do() function when an HTTP
 * request is to be performed. This creates and sends a properly constructed
 * HTTP request.
 */
CURLcode Curl_http(struct Curl_easy *data, bool *done)
{
  struct connectdata *conn = data->conn;
  CURLcode result = CURLE_OK;
  struct HTTP *http;
  Curl_HttpReq httpreq;
  const char *te = ""; /* transfer-encoding */
  const char *request;
  const char *httpstring;
  struct dynbuf req;
  char *altused = NULL;
  const char *p_accept;      /* Accept: string */

  /* Always consider the DO phase done after this function call, even if there
     may be parts of the request that are not yet sent, since we can deal with
     the rest of the request in the PERFORM phase. */
  *done = TRUE;

  switch(conn->alpn) {
  case CURL_HTTP_VERSION_3:
    DEBUGASSERT(Curl_conn_is_http3(data, conn, FIRSTSOCKET));
    break;
  case CURL_HTTP_VERSION_2:
#ifndef CURL_DISABLE_PROXY
    if(!Curl_conn_is_http2(data, conn, FIRSTSOCKET) &&
       conn->bits.proxy && !conn->bits.tunnel_proxy
      ) {
      result = Curl_http2_switch(data, conn, FIRSTSOCKET);
      if(result)
        return result;
    }
    else
#endif
      DEBUGASSERT(Curl_conn_is_http2(data, conn, FIRSTSOCKET));
    break;
  case CURL_HTTP_VERSION_1_1:
    /* continue with HTTP/1.1 when explicitly requested */
    break;
  default:
    /* Check if user wants to use HTTP/2 with clear TCP */
    if(Curl_http2_may_switch(data, conn, FIRSTSOCKET)) {
      DEBUGF(infof(data, "HTTP/2 over clean TCP"));
      result = Curl_http2_switch(data, conn, FIRSTSOCKET);
      if(result)
        return result;
    }
    break;
  }

  http = data->req.p.http;
  DEBUGASSERT(http);

  result = Curl_http_host(data, conn);
  if(result)
    return result;

  result = Curl_http_useragent(data);
  if(result)
    return result;

  Curl_http_method(data, conn, &request, &httpreq);

  /* setup the authentication headers */
  {
    char *pq = NULL;
    if(data->state.up.query) {
      pq = aprintf("%s?%s", data->state.up.path, data->state.up.query);
      if(!pq)
        return CURLE_OUT_OF_MEMORY;
    }
    result = Curl_http_output_auth(data, conn, request, httpreq,
                                   (pq ? pq : data->state.up.path), FALSE);
    free(pq);
    if(result)
      return result;
  }

  Curl_safefree(data->state.aptr.ref);
  if(data->state.referer && !Curl_checkheaders(data, STRCONST("Referer"))) {
    data->state.aptr.ref = aprintf("Referer: %s\r\n", data->state.referer);
    if(!data->state.aptr.ref)
      return CURLE_OUT_OF_MEMORY;
  }

  if(!Curl_checkheaders(data, STRCONST("Accept-Encoding")) &&
     data->set.str[STRING_ENCODING]) {
    Curl_safefree(data->state.aptr.accept_encoding);
    data->state.aptr.accept_encoding =
      aprintf("Accept-Encoding: %s\r\n", data->set.str[STRING_ENCODING]);
    if(!data->state.aptr.accept_encoding)
      return CURLE_OUT_OF_MEMORY;
  }
  else
    Curl_safefree(data->state.aptr.accept_encoding);

#ifdef HAVE_LIBZ
  /* we only consider transfer-encoding magic if libz support is built-in */
  result = Curl_transferencode(data);
  if(result)
    return result;
#endif

  result = Curl_http_body(data, conn, httpreq, &te);
  if(result)
    return result;

  p_accept = Curl_checkheaders(data,
                               STRCONST("Accept"))?NULL:"Accept: */*\r\n";

  result = Curl_http_resume(data, conn, httpreq);
  if(result)
    return result;

  result = Curl_http_range(data, httpreq);
  if(result)
    return result;

  httpstring = get_http_string(data, conn);

  /* initialize a dynamic send-buffer */
  Curl_dyn_init(&req, DYN_HTTP_REQUEST);

  /* make sure the header buffer is reset - if there are leftovers from a
     previous transfer */
  Curl_dyn_reset(&data->state.headerb);

  /* add the main request stuff */
  /* GET/HEAD/POST/PUT */
  result = Curl_dyn_addf(&req, "%s ", request);
  if(!result)
    result = Curl_http_target(data, conn, &req);
  if(result) {
    Curl_dyn_free(&req);
    return result;
  }

#ifndef CURL_DISABLE_ALTSVC
  if(conn->bits.altused && !Curl_checkheaders(data, STRCONST("Alt-Used"))) {
    altused = aprintf("Alt-Used: %s:%d\r\n",
                      conn->conn_to_host.name, conn->conn_to_port);
    if(!altused) {
      Curl_dyn_free(&req);
      return CURLE_OUT_OF_MEMORY;
    }
  }
#endif
  result =
    Curl_dyn_addf(&req,
                  " HTTP/%s\r\n" /* HTTP version */
                  "%s" /* host */
                  "%s" /* proxyuserpwd */
                  "%s" /* userpwd */
                  "%s" /* range */
                  "%s" /* user agent */
                  "%s" /* accept */
                  "%s" /* TE: */
                  "%s" /* accept-encoding */
                  "%s" /* referer */
                  "%s" /* Proxy-Connection */
                  "%s" /* transfer-encoding */
                  "%s",/* Alt-Used */

                  httpstring,
                  (data->state.aptr.host?data->state.aptr.host:""),
                  data->state.aptr.proxyuserpwd?
                  data->state.aptr.proxyuserpwd:"",
                  data->state.aptr.userpwd?data->state.aptr.userpwd:"",
                  (data->state.use_range && data->state.aptr.rangeline)?
                  data->state.aptr.rangeline:"",
                  (data->set.str[STRING_USERAGENT] &&
                   *data->set.str[STRING_USERAGENT] &&
                   data->state.aptr.uagent)?
                  data->state.aptr.uagent:"",
                  p_accept?p_accept:"",
                  data->state.aptr.te?data->state.aptr.te:"",
                  (data->set.str[STRING_ENCODING] &&
                   *data->set.str[STRING_ENCODING] &&
                   data->state.aptr.accept_encoding)?
                  data->state.aptr.accept_encoding:"",
                  (data->state.referer && data->state.aptr.ref)?
                  data->state.aptr.ref:"" /* Referer: <data> */,
#ifndef CURL_DISABLE_PROXY
                  (conn->bits.httpproxy &&
                   !conn->bits.tunnel_proxy &&
                   !Curl_checkheaders(data, STRCONST("Proxy-Connection")) &&
                   !Curl_checkProxyheaders(data,
                                           conn,
                                           STRCONST("Proxy-Connection")))?
                  "Proxy-Connection: Keep-Alive\r\n":"",
#else
                  "",
#endif
                  te,
                  altused ? altused : ""
      );

  /* clear userpwd and proxyuserpwd to avoid re-using old credentials
   * from re-used connections */
  Curl_safefree(data->state.aptr.userpwd);
  Curl_safefree(data->state.aptr.proxyuserpwd);
  free(altused);

  if(result) {
    Curl_dyn_free(&req);
    return result;
  }

  if(!(conn->handler->flags&PROTOPT_SSL) &&
     conn->httpversion < 20 &&
     (data->state.httpwant == CURL_HTTP_VERSION_2)) {
    /* append HTTP2 upgrade magic stuff to the HTTP request if it isn't done
       over SSL */
    result = Curl_http2_request_upgrade(&req, data);
    if(result) {
      Curl_dyn_free(&req);
      return result;
    }
  }

  result = Curl_http_cookies(data, conn, &req);
#ifdef USE_WEBSOCKETS
  if(!result && conn->handler->protocol&(CURLPROTO_WS|CURLPROTO_WSS))
    result = Curl_ws_request(data, &req);
#endif
  if(!result)
    result = Curl_add_timecondition(data, &req);
  if(!result)
    result = Curl_add_custom_headers(data, FALSE, &req);

  if(!result) {
    http->postdata = NULL;  /* nothing to post at this point */
    if((httpreq == HTTPREQ_GET) ||
       (httpreq == HTTPREQ_HEAD))
      Curl_pgrsSetUploadSize(data, 0); /* nothing */

    /* bodysend takes ownership of the 'req' memory on success */
    result = Curl_http_bodysend(data, conn, &req, httpreq);
  }
  if(result) {
    Curl_dyn_free(&req);
    return result;
  }

  if((http->postsize > -1) &&
     (http->postsize <= data->req.writebytecount) &&
     (http->sending != HTTPSEND_REQUEST))
    data->req.upload_done = TRUE;

  if(data->req.writebytecount) {
    /* if a request-body has been sent off, we make sure this progress is noted
       properly */
    Curl_pgrsSetUploadCounter(data, data->req.writebytecount);
    if(Curl_pgrsUpdate(data))
      result = CURLE_ABORTED_BY_CALLBACK;

    if(!http->postsize) {
      /* already sent the entire request body, mark the "upload" as
         complete */
      infof(data, "upload completely sent off: %" CURL_FORMAT_CURL_OFF_T
            " out of %" CURL_FORMAT_CURL_OFF_T " bytes",
            data->req.writebytecount, http->postsize);
      data->req.upload_done = TRUE;
      data->req.keepon &= ~KEEP_SEND; /* we're done writing */
      data->req.exp100 = EXP100_SEND_DATA; /* already sent */
      Curl_expire_done(data, EXPIRE_100_TIMEOUT);
    }
  }

  if((conn->httpversion >= 20) && data->req.upload_chunky)
    /* upload_chunky was set above to set up the request in a chunky fashion,
       but is disabled here again to avoid that the chunked encoded version is
       actually used when sending the request body over h2 */
    data->req.upload_chunky = FALSE;
  return result;
}

#endif /* USE_HYPER */

typedef enum {
  STATUS_UNKNOWN, /* not enough data to tell yet */
  STATUS_DONE, /* a status line was read */
  STATUS_BAD /* not a status line */
} statusline;


/* Check a string for a prefix. Check no more than 'len' bytes */
static bool checkprefixmax(const char *prefix, const char *buffer, size_t len)
{
  size_t ch = CURLMIN(strlen(prefix), len);
  return curl_strnequal(prefix, buffer, ch);
}

/*
 * checkhttpprefix()
 *
 * Returns TRUE if member of the list matches prefix of string
 */
static statusline
checkhttpprefix(struct Curl_easy *data,
                const char *s, size_t len)
{
  struct curl_slist *head = data->set.http200aliases;
  statusline rc = STATUS_BAD;
  statusline onmatch = len >= 5? STATUS_DONE : STATUS_UNKNOWN;

  while(head) {
    if(checkprefixmax(head->data, s, len)) {
      rc = onmatch;
      break;
    }
    head = head->next;
  }

  if((rc != STATUS_DONE) && (checkprefixmax("HTTP/", s, len)))
    rc = onmatch;

  return rc;
}

#ifndef CURL_DISABLE_RTSP
static statusline
checkrtspprefix(struct Curl_easy *data,
                const char *s, size_t len)
{
  statusline result = STATUS_BAD;
  statusline onmatch = len >= 5? STATUS_DONE : STATUS_UNKNOWN;
  (void)data; /* unused */
  if(checkprefixmax("RTSP/", s, len))
    result = onmatch;

  return result;
}
#endif /* CURL_DISABLE_RTSP */

static statusline
checkprotoprefix(struct Curl_easy *data, struct connectdata *conn,
                 const char *s, size_t len)
{
#ifndef CURL_DISABLE_RTSP
  if(conn->handler->protocol & CURLPROTO_RTSP)
    return checkrtspprefix(data, s, len);
#else
  (void)conn;
#endif /* CURL_DISABLE_RTSP */

  return checkhttpprefix(data, s, len);
}

/*
 * Curl_http_header() parses a single response header.
 */
CURLcode Curl_http_header(struct Curl_easy *data, struct connectdata *conn,
                          char *headp)
{
  CURLcode result;
  struct SingleRequest *k = &data->req;
  /* Check for Content-Length: header lines to get size */
  if(!k->http_bodyless &&
     !data->set.ignorecl && checkprefix("Content-Length:", headp)) {
    curl_off_t contentlength;
    CURLofft offt = curlx_strtoofft(headp + strlen("Content-Length:"),
                                    NULL, 10, &contentlength);

    if(offt == CURL_OFFT_OK) {
      k->size = contentlength;
      k->maxdownload = k->size;
    }
    else if(offt == CURL_OFFT_FLOW) {
      /* out of range */
      if(data->set.max_filesize) {
        failf(data, "Maximum file size exceeded");
        return CURLE_FILESIZE_EXCEEDED;
      }
      streamclose(conn, "overflow content-length");
      infof(data, "Overflow Content-Length: value");
    }
    else {
      /* negative or just rubbish - bad HTTP */
      failf(data, "Invalid Content-Length: value");
      return CURLE_WEIRD_SERVER_REPLY;
    }
  }
  /* check for Content-Type: header lines to get the MIME-type */
  else if(checkprefix("Content-Type:", headp)) {
    char *contenttype = Curl_copy_header_value(headp);
    if(!contenttype)
      return CURLE_OUT_OF_MEMORY;
    if(!*contenttype)
      /* ignore empty data */
      free(contenttype);
    else {
      Curl_safefree(data->info.contenttype);
      data->info.contenttype = contenttype;
    }
  }
#ifndef CURL_DISABLE_PROXY
  else if((conn->httpversion == 10) &&
          conn->bits.httpproxy &&
          Curl_compareheader(headp,
                             STRCONST("Proxy-Connection:"),
                             STRCONST("keep-alive"))) {
    /*
     * When an HTTP/1.0 reply comes when using a proxy, the
     * 'Proxy-Connection: keep-alive' line tells us the
     * connection will be kept alive for our pleasure.
     * Default action for 1.0 is to close.
     */
    connkeep(conn, "Proxy-Connection keep-alive"); /* don't close */
    infof(data, "HTTP/1.0 proxy connection set to keep alive");
  }
  else if((conn->httpversion == 11) &&
          conn->bits.httpproxy &&
          Curl_compareheader(headp,
                             STRCONST("Proxy-Connection:"),
                             STRCONST("close"))) {
    /*
     * We get an HTTP/1.1 response from a proxy and it says it'll
     * close down after this transfer.
     */
    connclose(conn, "Proxy-Connection: asked to close after done");
    infof(data, "HTTP/1.1 proxy connection set close");
  }
#endif
  else if((conn->httpversion == 10) &&
          Curl_compareheader(headp,
                             STRCONST("Connection:"),
                             STRCONST("keep-alive"))) {
    /*
     * An HTTP/1.0 reply with the 'Connection: keep-alive' line
     * tells us the connection will be kept alive for our
     * pleasure.  Default action for 1.0 is to close.
     *
     * [RFC2068, section 19.7.1] */
    connkeep(conn, "Connection keep-alive");
    infof(data, "HTTP/1.0 connection set to keep alive");
  }
  else if(Curl_compareheader(headp,
                             STRCONST("Connection:"), STRCONST("close"))) {
    /*
     * [RFC 2616, section 8.1.2.1]
     * "Connection: close" is HTTP/1.1 language and means that
     * the connection will close when this request has been
     * served.
     */
    streamclose(conn, "Connection: close used");
  }
  else if(!k->http_bodyless && checkprefix("Transfer-Encoding:", headp)) {
    /* One or more encodings. We check for chunked and/or a compression
       algorithm. */
    /*
     * [RFC 2616, section 3.6.1] A 'chunked' transfer encoding
     * means that the server will send a series of "chunks". Each
     * chunk starts with line with info (including size of the
     * coming block) (terminated with CRLF), then a block of data
     * with the previously mentioned size. There can be any amount
     * of chunks, and a chunk-data set to zero signals the
     * end-of-chunks. */

    result = Curl_build_unencoding_stack(data,
                                         headp + strlen("Transfer-Encoding:"),
                                         TRUE);
    if(result)
      return result;
    if(!k->chunk && data->set.http_transfer_encoding) {
      /* if this isn't chunked, only close can signal the end of this transfer
         as Content-Length is said not to be trusted for transfer-encoding! */
      connclose(conn, "HTTP/1.1 transfer-encoding without chunks");
      k->ignore_cl = TRUE;
    }
  }
  else if(!k->http_bodyless && checkprefix("Content-Encoding:", headp) &&
          data->set.str[STRING_ENCODING]) {
    /*
     * Process Content-Encoding. Look for the values: identity,
     * gzip, deflate, compress, x-gzip and x-compress. x-gzip and
     * x-compress are the same as gzip and compress. (Sec 3.5 RFC
     * 2616). zlib cannot handle compress.  However, errors are
     * handled further down when the response body is processed
     */
    result = Curl_build_unencoding_stack(data,
                                         headp + strlen("Content-Encoding:"),
                                         FALSE);
    if(result)
      return result;
  }
  else if(checkprefix("Retry-After:", headp)) {
    /* Retry-After = HTTP-date / delay-seconds */
    curl_off_t retry_after = 0; /* zero for unknown or "now" */
    /* Try it as a decimal number, if it works it is not a date */
    (void)curlx_strtoofft(headp + strlen("Retry-After:"),
                          NULL, 10, &retry_after);
    if(!retry_after) {
      time_t date = Curl_getdate_capped(headp + strlen("Retry-After:"));
      if(-1 != date)
        /* convert date to number of seconds into the future */
        retry_after = date - time(NULL);
    }
    data->info.retry_after = retry_after; /* store it */
  }
  else if(!k->http_bodyless && checkprefix("Content-Range:", headp)) {
    /* Content-Range: bytes [num]-
       Content-Range: bytes: [num]-
       Content-Range: [num]-
       Content-Range: [asterisk]/[total]

       The second format was added since Sun's webserver
       JavaWebServer/1.1.1 obviously sends the header this way!
       The third added since some servers use that!
       The fourth means the requested range was unsatisfied.
    */

    char *ptr = headp + strlen("Content-Range:");

    /* Move forward until first digit or asterisk */
    while(*ptr && !ISDIGIT(*ptr) && *ptr != '*')
      ptr++;

    /* if it truly stopped on a digit */
    if(ISDIGIT(*ptr)) {
      if(!curlx_strtoofft(ptr, NULL, 10, &k->offset)) {
        if(data->state.resume_from == k->offset)
          /* we asked for a resume and we got it */
          k->content_range = TRUE;
      }
    }
    else
      data->state.resume_from = 0; /* get everything */
  }
#if !defined(CURL_DISABLE_COOKIES)
  else if(data->cookies && data->state.cookie_engine &&
          checkprefix("Set-Cookie:", headp)) {
    /* If there is a custom-set Host: name, use it here, or else use real peer
       host name. */
    const char *host = data->state.aptr.cookiehost?
      data->state.aptr.cookiehost:conn->host.name;
    const bool secure_context =
      conn->handler->protocol&(CURLPROTO_HTTPS|CURLPROTO_WSS) ||
      strcasecompare("localhost", host) ||
      !strcmp(host, "127.0.0.1") ||
      !strcmp(host, "::1") ? TRUE : FALSE;

    Curl_share_lock(data, CURL_LOCK_DATA_COOKIE,
                    CURL_LOCK_ACCESS_SINGLE);
    Curl_cookie_add(data, data->cookies, TRUE, FALSE,
                    headp + strlen("Set-Cookie:"), host,
                    data->state.up.path, secure_context);
    Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
  }
#endif
  else if(!k->http_bodyless && checkprefix("Last-Modified:", headp) &&
          (data->set.timecondition || data->set.get_filetime) ) {
    k->timeofdoc = Curl_getdate_capped(headp + strlen("Last-Modified:"));
    if(data->set.get_filetime)
      data->info.filetime = k->timeofdoc;
  }
  else if((checkprefix("WWW-Authenticate:", headp) &&
           (401 == k->httpcode)) ||
          (checkprefix("Proxy-authenticate:", headp) &&
           (407 == k->httpcode))) {

    bool proxy = (k->httpcode == 407) ? TRUE : FALSE;
    char *auth = Curl_copy_header_value(headp);
    if(!auth)
      return CURLE_OUT_OF_MEMORY;

    result = Curl_http_input_auth(data, proxy, auth);

    free(auth);

    if(result)
      return result;
  }
#ifdef USE_SPNEGO
  else if(checkprefix("Persistent-Auth:", headp)) {
    struct negotiatedata *negdata = &conn->negotiate;
    struct auth *authp = &data->state.authhost;
    if(authp->picked == CURLAUTH_NEGOTIATE) {
      char *persistentauth = Curl_copy_header_value(headp);
      if(!persistentauth)
        return CURLE_OUT_OF_MEMORY;
      negdata->noauthpersist = checkprefix("false", persistentauth)?
        TRUE:FALSE;
      negdata->havenoauthpersist = TRUE;
      infof(data, "Negotiate: noauthpersist -> %d, header part: %s",
            negdata->noauthpersist, persistentauth);
      free(persistentauth);
    }
  }
#endif
  else if((k->httpcode >= 300 && k->httpcode < 400) &&
          checkprefix("Location:", headp) &&
          !data->req.location) {
    /* this is the URL that the server advises us to use instead */
    char *location = Curl_copy_header_value(headp);
    if(!location)
      return CURLE_OUT_OF_MEMORY;
    if(!*location)
      /* ignore empty data */
      free(location);
    else {
      data->req.location = location;

      if(data->set.http_follow_location) {
        DEBUGASSERT(!data->req.newurl);
        data->req.newurl = strdup(data->req.location); /* clone */
        if(!data->req.newurl)
          return CURLE_OUT_OF_MEMORY;

        /* some cases of POST and PUT etc needs to rewind the data
           stream at this point */
        result = http_perhapsrewind(data, conn);
        if(result)
          return result;

        /* mark the next request as a followed location: */
        data->state.this_is_a_follow = TRUE;
      }
    }
  }

#ifndef CURL_DISABLE_HSTS
  /* If enabled, the header is incoming and this is over HTTPS */
  else if(data->hsts && checkprefix("Strict-Transport-Security:", headp) &&
          ((conn->handler->flags & PROTOPT_SSL) ||
#ifdef CURLDEBUG
           /* allow debug builds to circumvent the HTTPS restriction */
           getenv("CURL_HSTS_HTTP")
#else
           0
#endif
            )) {
    CURLcode check =
      Curl_hsts_parse(data->hsts, conn->host.name,
                      headp + strlen("Strict-Transport-Security:"));
    if(check)
      infof(data, "Illegal STS header skipped");
#ifdef DEBUGBUILD
    else
      infof(data, "Parsed STS header fine (%zu entries)",
            data->hsts->list.size);
#endif
  }
#endif
#ifndef CURL_DISABLE_ALTSVC
  /* If enabled, the header is incoming and this is over HTTPS */
  else if(data->asi && checkprefix("Alt-Svc:", headp) &&
          ((conn->handler->flags & PROTOPT_SSL) ||
#ifdef CURLDEBUG
           /* allow debug builds to circumvent the HTTPS restriction */
           getenv("CURL_ALTSVC_HTTP")
#else
           0
#endif
            )) {
    /* the ALPN of the current request */
    enum alpnid id = (conn->httpversion == 30)? ALPN_h3 :
                       (conn->httpversion == 20) ? ALPN_h2 : ALPN_h1;
    result = Curl_altsvc_parse(data, data->asi,
                               headp + strlen("Alt-Svc:"),
                               id, conn->host.name,
                               curlx_uitous((unsigned int)conn->remote_port));
    if(result)
      return result;
  }
#endif
  else if(conn->handler->protocol & CURLPROTO_RTSP) {
    result = Curl_rtsp_parseheader(data, headp);
    if(result)
      return result;
  }
  return CURLE_OK;
}

/*
 * Called after the first HTTP response line (the status line) has been
 * received and parsed.
 */

CURLcode Curl_http_statusline(struct Curl_easy *data,
                              struct connectdata *conn)
{
  struct SingleRequest *k = &data->req;
  data->info.httpcode = k->httpcode;

  data->info.httpversion = conn->httpversion;
  if(!data->state.httpversion ||
     data->state.httpversion > conn->httpversion)
    /* store the lowest server version we encounter */
    data->state.httpversion = conn->httpversion;

  /*
   * This code executes as part of processing the header.  As a
   * result, it's not totally clear how to interpret the
   * response code yet as that depends on what other headers may
   * be present.  401 and 407 may be errors, but may be OK
   * depending on how authentication is working.  Other codes
   * are definitely errors, so give up here.
   */
  if(data->state.resume_from && data->state.httpreq == HTTPREQ_GET &&
     k->httpcode == 416) {
    /* "Requested Range Not Satisfiable", just proceed and
       pretend this is no error */
    k->ignorebody = TRUE; /* Avoid appending error msg to good data. */
  }

  if(conn->httpversion == 10) {
    /* Default action for HTTP/1.0 must be to close, unless
       we get one of those fancy headers that tell us the
       server keeps it open for us! */
    infof(data, "HTTP 1.0, assume close after body");
    connclose(conn, "HTTP/1.0 close after body");
  }
  else if(conn->httpversion == 20 ||
          (k->upgr101 == UPGR101_H2 && k->httpcode == 101)) {
    DEBUGF(infof(data, "HTTP/2 found, allow multiplexing"));
    /* HTTP/2 cannot avoid multiplexing since it is a core functionality
       of the protocol */
    conn->bundle->multiuse = BUNDLE_MULTIPLEX;
  }
  else if(conn->httpversion >= 11 &&
          !conn->bits.close) {
    /* If HTTP version is >= 1.1 and connection is persistent */
    DEBUGF(infof(data,
                 "HTTP 1.1 or later with persistent connection"));
  }

  k->http_bodyless = k->httpcode >= 100 && k->httpcode < 200;
  switch(k->httpcode) {
  case 304:
    /* (quote from RFC2616, section 10.3.5): The 304 response
     * MUST NOT contain a message-body, and thus is always
     * terminated by the first empty line after the header
     * fields.  */
    if(data->set.timecondition)
      data->info.timecond = TRUE;
    /* FALLTHROUGH */
  case 204:
    /* (quote from RFC2616, section 10.2.5): The server has
     * fulfilled the request but does not need to return an
     * entity-body ... The 204 response MUST NOT include a
     * message-body, and thus is always terminated by the first
     * empty line after the header fields. */
    k->size = 0;
    k->maxdownload = 0;
    k->http_bodyless = TRUE;
    break;
  default:
    break;
  }
  return CURLE_OK;
}

/* Content-Length must be ignored if any Transfer-Encoding is present in the
   response. Refer to RFC 7230 section 3.3.3 and RFC2616 section 4.4.  This is
   figured out here after all headers have been received but before the final
   call to the user's header callback, so that a valid content length can be
   retrieved by the user in the final call. */
CURLcode Curl_http_size(struct Curl_easy *data)
{
  struct SingleRequest *k = &data->req;
  if(data->req.ignore_cl || k->chunk) {
    k->size = k->maxdownload = -1;
  }
  else if(k->size != -1) {
    if(data->set.max_filesize &&
       k->size > data->set.max_filesize) {
      failf(data, "Maximum file size exceeded");
      return CURLE_FILESIZE_EXCEEDED;
    }
    Curl_pgrsSetDownloadSize(data, k->size);
    k->maxdownload = k->size;
  }
  return CURLE_OK;
}

static CURLcode verify_header(struct Curl_easy *data)
{
  struct SingleRequest *k = &data->req;
  const char *header = Curl_dyn_ptr(&data->state.headerb);
  size_t hlen = Curl_dyn_len(&data->state.headerb);
  char *ptr = memchr(header, 0x00, hlen);
  if(ptr) {
    /* this is bad, bail out */
    failf(data, "Nul byte in header");
    return CURLE_WEIRD_SERVER_REPLY;
  }
  if(k->headerline < 2)
    /* the first "header" is the status-line and it has no colon */
    return CURLE_OK;
  if(((header[0] == ' ') || (header[0] == '\t')) && k->headerline > 2)
    /* line folding, can't happen on line 2 */
    ;
  else {
    ptr = memchr(header, ':', hlen);
    if(!ptr) {
      /* this is bad, bail out */
      failf(data, "Header without colon");
      return CURLE_WEIRD_SERVER_REPLY;
    }
  }
  return CURLE_OK;
}

/*
 * Read any HTTP header lines from the server and pass them to the client app.
 */
CURLcode Curl_http_readwrite_headers(struct Curl_easy *data,
                                     struct connectdata *conn,
                                     ssize_t *nread,
                                     bool *stop_reading)
{
  CURLcode result;
  struct SingleRequest *k = &data->req;
  ssize_t onread = *nread;
  char *ostr = k->str;
  char *headp;
  char *str_start;
  char *end_ptr;

  /* header line within buffer loop */
  do {
    size_t rest_length;
    size_t full_length;
    int writetype;

    /* str_start is start of line within buf */
    str_start = k->str;

    /* data is in network encoding so use 0x0a instead of '\n' */
    end_ptr = memchr(str_start, 0x0a, *nread);

    if(!end_ptr) {
      /* Not a complete header line within buffer, append the data to
         the end of the headerbuff. */
      result = Curl_dyn_addn(&data->state.headerb, str_start, *nread);
      if(result)
        return result;

      if(!k->headerline) {
        /* check if this looks like a protocol header */
        statusline st =
          checkprotoprefix(data, conn,
                           Curl_dyn_ptr(&data->state.headerb),
                           Curl_dyn_len(&data->state.headerb));

        if(st == STATUS_BAD) {
          /* this is not the beginning of a protocol first header line */
          k->header = FALSE;
          k->badheader = HEADER_ALLBAD;
          streamclose(conn, "bad HTTP: No end-of-message indicator");
          if(!data->set.http09_allowed) {
            failf(data, "Received HTTP/0.9 when not allowed");
            return CURLE_UNSUPPORTED_PROTOCOL;
          }
          break;
        }
      }

      break; /* read more and try again */
    }

    /* decrease the size of the remaining (supposed) header line */
    rest_length = (end_ptr - k->str) + 1;
    *nread -= (ssize_t)rest_length;

    k->str = end_ptr + 1; /* move past new line */

    full_length = k->str - str_start;

    result = Curl_dyn_addn(&data->state.headerb, str_start, full_length);
    if(result)
      return result;

    /****
     * We now have a FULL header line in 'headerb'.
     *****/

    if(!k->headerline) {
      /* the first read header */
      statusline st = checkprotoprefix(data, conn,
                                       Curl_dyn_ptr(&data->state.headerb),
                                       Curl_dyn_len(&data->state.headerb));
      if(st == STATUS_BAD) {
        streamclose(conn, "bad HTTP: No end-of-message indicator");
        /* this is not the beginning of a protocol first header line */
        if(!data->set.http09_allowed) {
          failf(data, "Received HTTP/0.9 when not allowed");
          return CURLE_UNSUPPORTED_PROTOCOL;
        }
        k->header = FALSE;
        if(*nread)
          /* since there's more, this is a partial bad header */
          k->badheader = HEADER_PARTHEADER;
        else {
          /* this was all we read so it's all a bad header */
          k->badheader = HEADER_ALLBAD;
          *nread = onread;
          k->str = ostr;
          return CURLE_OK;
        }
        break;
      }
    }

    /* headers are in network encoding so use 0x0a and 0x0d instead of '\n'
       and '\r' */
    headp = Curl_dyn_ptr(&data->state.headerb);
    if((0x0a == *headp) || (0x0d == *headp)) {
      size_t headerlen;
      /* Zero-length header line means end of headers! */

      if('\r' == *headp)
        headp++; /* pass the \r byte */
      if('\n' == *headp)
        headp++; /* pass the \n byte */

      if(100 <= k->httpcode && 199 >= k->httpcode) {
        /* "A user agent MAY ignore unexpected 1xx status responses." */
        switch(k->httpcode) {
        case 100:
          /*
           * We have made an HTTP PUT or POST and this is 1.1-lingo
           * that tells us that the server is OK with this and ready
           * to receive the data.
           * However, we'll get more headers now so we must get
           * back into the header-parsing state!
           */
          k->header = TRUE;
          k->headerline = 0; /* restart the header line counter */

          /* if we did wait for this do enable write now! */
          if(k->exp100 > EXP100_SEND_DATA) {
            k->exp100 = EXP100_SEND_DATA;
            k->keepon |= KEEP_SEND;
            Curl_expire_done(data, EXPIRE_100_TIMEOUT);
          }
          break;
        case 101:
          /* Switching Protocols */
          if(k->upgr101 == UPGR101_H2) {
            /* Switching to HTTP/2 */
            infof(data, "Received 101, Switching to HTTP/2");
            k->upgr101 = UPGR101_RECEIVED;

            /* we'll get more headers (HTTP/2 response) */
            k->header = TRUE;
            k->headerline = 0; /* restart the header line counter */

            /* switch to http2 now. The bytes after response headers
               are also processed here, otherwise they are lost. */
            result = Curl_http2_upgrade(data, conn, FIRSTSOCKET,
                                        k->str, *nread);
            if(result)
              return result;
            *nread = 0;
          }
#ifdef USE_WEBSOCKETS
          else if(k->upgr101 == UPGR101_WS) {
            /* verify the response */
            result = Curl_ws_accept(data, k->str, *nread);
            if(result)
              return result;
            k->header = FALSE; /* no more header to parse! */
            if(data->set.connect_only) {
              k->keepon &= ~KEEP_RECV; /* read no more content */
              *nread = 0;
            }
          }
#endif
          else {
            /* Not switching to another protocol */
            k->header = FALSE; /* no more header to parse! */
          }
          break;
        default:
          /* the status code 1xx indicates a provisional response, so
             we'll get another set of headers */
          k->header = TRUE;
          k->headerline = 0; /* restart the header line counter */
          break;
        }
      }
      else {
        k->header = FALSE; /* no more header to parse! */

        if((k->size == -1) && !k->chunk && !conn->bits.close &&
           (conn->httpversion == 11) &&
           !(conn->handler->protocol & CURLPROTO_RTSP) &&
           data->state.httpreq != HTTPREQ_HEAD) {
          /* On HTTP 1.1, when connection is not to get closed, but no
             Content-Length nor Transfer-Encoding chunked have been
             received, according to RFC2616 section 4.4 point 5, we
             assume that the server will close the connection to
             signal the end of the document. */
          infof(data, "no chunk, no close, no size. Assume close to "
                "signal end");
          streamclose(conn, "HTTP: No end-of-message indicator");
        }
      }

      if(!k->header) {
        result = Curl_http_size(data);
        if(result)
          return result;
      }

      /* At this point we have some idea about the fate of the connection.
         If we are closing the connection it may result auth failure. */
#if defined(USE_NTLM)
      if(conn->bits.close &&
         (((data->req.httpcode == 401) &&
           (conn->http_ntlm_state == NTLMSTATE_TYPE2)) ||
          ((data->req.httpcode == 407) &&
           (conn->proxy_ntlm_state == NTLMSTATE_TYPE2)))) {
        infof(data, "Connection closure while negotiating auth (HTTP 1.0?)");
        data->state.authproblem = TRUE;
      }
#endif
#if defined(USE_SPNEGO)
      if(conn->bits.close &&
        (((data->req.httpcode == 401) &&
          (conn->http_negotiate_state == GSS_AUTHRECV)) ||
         ((data->req.httpcode == 407) &&
          (conn->proxy_negotiate_state == GSS_AUTHRECV)))) {
        infof(data, "Connection closure while negotiating auth (HTTP 1.0?)");
        data->state.authproblem = TRUE;
      }
      if((conn->http_negotiate_state == GSS_AUTHDONE) &&
         (data->req.httpcode != 401)) {
        conn->http_negotiate_state = GSS_AUTHSUCC;
      }
      if((conn->proxy_negotiate_state == GSS_AUTHDONE) &&
         (data->req.httpcode != 407)) {
        conn->proxy_negotiate_state = GSS_AUTHSUCC;
      }
#endif

      /* now, only output this if the header AND body are requested:
       */
      writetype = CLIENTWRITE_HEADER |
        (data->set.include_header ? CLIENTWRITE_BODY : 0) |
        ((k->httpcode/100 == 1) ? CLIENTWRITE_1XX : 0);

      headerlen = Curl_dyn_len(&data->state.headerb);
      result = Curl_client_write(data, writetype,
                                 Curl_dyn_ptr(&data->state.headerb),
                                 headerlen);
      if(result)
        return result;

      data->info.header_size += (long)headerlen;
      data->req.headerbytecount += (long)headerlen;

      /*
       * When all the headers have been parsed, see if we should give
       * up and return an error.
       */
      if(http_should_fail(data)) {
        failf(data, "The requested URL returned error: %d",
              k->httpcode);
        return CURLE_HTTP_RETURNED_ERROR;
      }

#ifdef USE_WEBSOCKETS
      /* All non-101 HTTP status codes are bad when wanting to upgrade to
         websockets */
      if(data->req.upgr101 == UPGR101_WS) {
        failf(data, "Refused WebSockets upgrade: %d", k->httpcode);
        return CURLE_HTTP_RETURNED_ERROR;
      }
#endif


      data->req.deductheadercount =
        (100 <= k->httpcode && 199 >= k->httpcode)?data->req.headerbytecount:0;

      /* Curl_http_auth_act() checks what authentication methods
       * that are available and decides which one (if any) to
       * use. It will set 'newurl' if an auth method was picked. */
      result = Curl_http_auth_act(data);

      if(result)
        return result;

      if(k->httpcode >= 300) {
        if((!conn->bits.authneg) && !conn->bits.close &&
           !data->state.rewindbeforesend) {
          /*
           * General treatment of errors when about to send data. Including :
           * "417 Expectation Failed", while waiting for 100-continue.
           *
           * The check for close above is done simply because of something
           * else has already deemed the connection to get closed then
           * something else should've considered the big picture and we
           * avoid this check.
           *
           * rewindbeforesend indicates that something has told libcurl to
           * continue sending even if it gets discarded
           */

          switch(data->state.httpreq) {
          case HTTPREQ_PUT:
          case HTTPREQ_POST:
          case HTTPREQ_POST_FORM:
          case HTTPREQ_POST_MIME:
            /* We got an error response. If this happened before the whole
             * request body has been sent we stop sending and mark the
             * connection for closure after we've read the entire response.
             */
            Curl_expire_done(data, EXPIRE_100_TIMEOUT);
            if(!k->upload_done) {
              if((k->httpcode == 417) && data->state.expect100header) {
                /* 417 Expectation Failed - try again without the Expect
                   header */
                infof(data, "Got 417 while waiting for a 100");
                data->state.disableexpect = TRUE;
                DEBUGASSERT(!data->req.newurl);
                data->req.newurl = strdup(data->state.url);
                Curl_done_sending(data, k);
              }
              else if(data->set.http_keep_sending_on_error) {
                infof(data, "HTTP error before end of send, keep sending");
                if(k->exp100 > EXP100_SEND_DATA) {
                  k->exp100 = EXP100_SEND_DATA;
                  k->keepon |= KEEP_SEND;
                }
              }
              else {
                infof(data, "HTTP error before end of send, stop sending");
                streamclose(conn, "Stop sending data before everything sent");
                result = Curl_done_sending(data, k);
                if(result)
                  return result;
                k->upload_done = TRUE;
                if(data->state.expect100header)
                  k->exp100 = EXP100_FAILED;
              }
            }
            break;

          default: /* default label present to avoid compiler warnings */
            break;
          }
        }

        if(data->state.rewindbeforesend &&
           (conn->writesockfd != CURL_SOCKET_BAD)) {
          /* We rewind before next send, continue sending now */
          infof(data, "Keep sending data to get tossed away");
          k->keepon |= KEEP_SEND;
        }
      }

      if(!k->header) {
        /*
         * really end-of-headers.
         *
         * If we requested a "no body", this is a good time to get
         * out and return home.
         */
        if(data->req.no_body)
          *stop_reading = TRUE;
#ifndef CURL_DISABLE_RTSP
        else if((conn->handler->protocol & CURLPROTO_RTSP) &&
                (data->set.rtspreq == RTSPREQ_DESCRIBE) &&
                (k->size <= -1))
          /* Respect section 4.4 of rfc2326: If the Content-Length header is
             absent, a length 0 must be assumed.  It will prevent libcurl from
             hanging on DESCRIBE request that got refused for whatever
             reason */
          *stop_reading = TRUE;
#endif

        /* If max download size is *zero* (nothing) we already have
           nothing and can safely return ok now!  But for HTTP/2, we'd
           like to call http2_handle_stream_close to properly close a
           stream.  In order to do this, we keep reading until we
           close the stream. */
        if(0 == k->maxdownload
           && !Curl_conn_is_http2(data, conn, FIRSTSOCKET)
           && !Curl_conn_is_http3(data, conn, FIRSTSOCKET))
          *stop_reading = TRUE;

        if(*stop_reading) {
          /* we make sure that this socket isn't read more now */
          k->keepon &= ~KEEP_RECV;
        }

        Curl_debug(data, CURLINFO_HEADER_IN, str_start, headerlen);
        break; /* exit header line loop */
      }

      /* We continue reading headers, reset the line-based header */
      Curl_dyn_reset(&data->state.headerb);
      continue;
    }

    /*
     * Checks for special headers coming up.
     */

    writetype = CLIENTWRITE_HEADER;
    if(!k->headerline++) {
      /* This is the first header, it MUST be the error code line
         or else we consider this to be the body right away! */
      bool fine_statusline = FALSE;
      if(conn->handler->protocol & PROTO_FAMILY_HTTP) {
        /*
         * https://datatracker.ietf.org/doc/html/rfc7230#section-3.1.2
         *
         * The response code is always a three-digit number in HTTP as the spec
         * says. We allow any three-digit number here, but we cannot make
         * guarantees on future behaviors since it isn't within the protocol.
         */
        int httpversion = 0;
        char *p = headp;

        while(*p && ISBLANK(*p))
          p++;
        if(!strncmp(p, "HTTP/", 5)) {
          p += 5;
          switch(*p) {
          case '1':
            p++;
            if((p[0] == '.') && (p[1] == '0' || p[1] == '1')) {
              if(ISBLANK(p[2])) {
                httpversion = 10 + (p[1] - '0');
                p += 3;
                if(ISDIGIT(p[0]) && ISDIGIT(p[1]) && ISDIGIT(p[2])) {
                  k->httpcode = (p[0] - '0') * 100 + (p[1] - '0') * 10 +
                    (p[2] - '0');
                  p += 3;
                  if(ISSPACE(*p))
                    fine_statusline = TRUE;
                }
              }
            }
            if(!fine_statusline) {
              failf(data, "Unsupported HTTP/1 subversion in response");
              return CURLE_UNSUPPORTED_PROTOCOL;
            }
            break;
          case '2':
          case '3':
            if(!ISBLANK(p[1]))
              break;
            httpversion = (*p - '0') * 10;
            p += 2;
            if(ISDIGIT(p[0]) && ISDIGIT(p[1]) && ISDIGIT(p[2])) {
              k->httpcode = (p[0] - '0') * 100 + (p[1] - '0') * 10 +
                (p[2] - '0');
              p += 3;
              if(!ISSPACE(*p))
                break;
              fine_statusline = TRUE;
            }
            break;
          default: /* unsupported */
            failf(data, "Unsupported HTTP version in response");
            return CURLE_UNSUPPORTED_PROTOCOL;
          }
        }

        if(fine_statusline) {
          if(k->httpcode < 100) {
            failf(data, "Unsupported response code in HTTP response");
            return CURLE_UNSUPPORTED_PROTOCOL;
          }
          switch(httpversion) {
          case 10:
          case 11:
#ifdef USE_HTTP2
          case 20:
#endif
#ifdef ENABLE_QUIC
          case 30:
#endif
            conn->httpversion = (unsigned char)httpversion;
            break;
          default:
            failf(data, "Unsupported HTTP version (%u.%d) in response",
                  httpversion/10, httpversion%10);
            return CURLE_UNSUPPORTED_PROTOCOL;
          }

          if(k->upgr101 == UPGR101_RECEIVED) {
            /* supposedly upgraded to http2 now */
            if(conn->httpversion != 20)
              infof(data, "Lying server, not serving HTTP/2");
          }
          if(conn->httpversion < 20) {
            conn->bundle->multiuse = BUNDLE_NO_MULTIUSE;
          }
        }
        else {
          /* If user has set option HTTP200ALIASES,
             compare header line against list of aliases
          */
          statusline check =
            checkhttpprefix(data,
                            Curl_dyn_ptr(&data->state.headerb),
                            Curl_dyn_len(&data->state.headerb));
          if(check == STATUS_DONE) {
            fine_statusline = TRUE;
            k->httpcode = 200;
            conn->httpversion = 10;
          }
        }
      }
      else if(conn->handler->protocol & CURLPROTO_RTSP) {
        char *p = headp;
        while(*p && ISBLANK(*p))
          p++;
        if(!strncmp(p, "RTSP/", 5)) {
          p += 5;
          if(ISDIGIT(*p)) {
            p++;
            if((p[0] == '.') && ISDIGIT(p[1])) {
              if(ISBLANK(p[2])) {
                p += 3;
                if(ISDIGIT(p[0]) && ISDIGIT(p[1]) && ISDIGIT(p[2])) {
                  k->httpcode = (p[0] - '0') * 100 + (p[1] - '0') * 10 +
                    (p[2] - '0');
                  p += 3;
                  if(ISSPACE(*p)) {
                    fine_statusline = TRUE;
                    conn->httpversion = 11; /* RTSP acts like HTTP 1.1 */
                  }
                }
              }
            }
          }
          if(!fine_statusline)
            return CURLE_WEIRD_SERVER_REPLY;
        }
      }

      if(fine_statusline) {
        result = Curl_http_statusline(data, conn);
        if(result)
          return result;
        writetype |= CLIENTWRITE_STATUS;
      }
      else {
        k->header = FALSE;   /* this is not a header line */
        break;
      }
    }

    result = verify_header(data);
    if(result)
      return result;

    result = Curl_http_header(data, conn, headp);
    if(result)
      return result;

    /*
     * End of header-checks. Write them to the client.
     */
    if(data->set.include_header)
      writetype |= CLIENTWRITE_BODY;
    if(k->httpcode/100 == 1)
      writetype |= CLIENTWRITE_1XX;

    Curl_debug(data, CURLINFO_HEADER_IN, headp,
               Curl_dyn_len(&data->state.headerb));

    result = Curl_client_write(data, writetype, headp,
                               Curl_dyn_len(&data->state.headerb));
    if(result)
      return result;

    data->info.header_size += Curl_dyn_len(&data->state.headerb);
    data->req.headerbytecount += Curl_dyn_len(&data->state.headerb);

    Curl_dyn_reset(&data->state.headerb);
  }
  while(*k->str); /* header line within buffer */

  /* We might have reached the end of the header part here, but
     there might be a non-header part left in the end of the read
     buffer. */

  return CURLE_OK;
}


/* Decode HTTP status code string. */
CURLcode Curl_http_decode_status(int *pstatus, const char *s, size_t len)
{
  CURLcode result = CURLE_BAD_FUNCTION_ARGUMENT;
  int status = 0;
  int i;

  if(len != 3)
    goto out;

  for(i = 0; i < 3; ++i) {
    char c = s[i];

    if(c < '0' || c > '9')
      goto out;

    status *= 10;
    status += c - '0';
  }
  result = CURLE_OK;
out:
  *pstatus = result? -1 : status;
  return result;
}

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

CURLcode Curl_http_req_make(struct http_req **preq,
                            const char *method, size_t m_len,
                            const char *scheme, size_t s_len,
                            const char *authority, size_t a_len,
                            const char *path, size_t p_len)
{
  struct http_req *req;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  DEBUGASSERT(method);
  if(m_len + 1 >= sizeof(req->method))
    return CURLE_BAD_FUNCTION_ARGUMENT;

  req = calloc(1, sizeof(*req));
  if(!req)
    goto out;
  memcpy(req->method, method, m_len);
  if(scheme) {
    req->scheme = my_strndup(scheme, s_len);
    if(!req->scheme)
      goto out;
  }
  if(authority) {
    req->authority = my_strndup(authority, a_len);
    if(!req->authority)
      goto out;
  }
  if(path) {
    req->path = my_strndup(path, p_len);
    if(!req->path)
      goto out;
  }
  Curl_dynhds_init(&req->headers, 0, DYN_H2_HEADERS);
  Curl_dynhds_init(&req->trailers, 0, DYN_H2_TRAILERS);
  result = CURLE_OK;

out:
  if(result && req)
    Curl_http_req_free(req);
  *preq = result? NULL : req;
  return result;
}

static CURLcode req_assign_url_authority(struct http_req *req, CURLU *url)
{
  char *user, *pass, *host, *port;
  struct dynbuf buf;
  CURLUcode uc;
  CURLcode result = CURLE_URL_MALFORMAT;

  user = pass = host = port = NULL;
  Curl_dyn_init(&buf, DYN_HTTP_REQUEST);

  uc = curl_url_get(url, CURLUPART_HOST, &host, 0);
  if(uc && uc != CURLUE_NO_HOST)
    goto out;
  if(!host) {
    req->authority = NULL;
    result = CURLE_OK;
    goto out;
  }

  uc = curl_url_get(url, CURLUPART_PORT, &port, CURLU_NO_DEFAULT_PORT);
  if(uc && uc != CURLUE_NO_PORT)
    goto out;
  uc = curl_url_get(url, CURLUPART_USER, &user, 0);
  if(uc && uc != CURLUE_NO_USER)
    goto out;
  if(user) {
    uc = curl_url_get(url, CURLUPART_PASSWORD, &pass, 0);
    if(uc && uc != CURLUE_NO_PASSWORD)
      goto out;
  }

  if(user) {
    result = Curl_dyn_add(&buf, user);
    if(result)
      goto out;
    if(pass) {
      result = Curl_dyn_addf(&buf, ":%s", pass);
      if(result)
        goto out;
    }
    result = Curl_dyn_add(&buf, "@");
    if(result)
      goto out;
  }
  result = Curl_dyn_add(&buf, host);
  if(result)
    goto out;
  if(port) {
    result = Curl_dyn_addf(&buf, ":%s", port);
    if(result)
      goto out;
  }
  req->authority = strdup(Curl_dyn_ptr(&buf));
  if(!req->authority)
    goto out;
  result = CURLE_OK;

out:
  free(user);
  free(pass);
  free(host);
  free(port);
  Curl_dyn_free(&buf);
  return result;
}

static CURLcode req_assign_url_path(struct http_req *req, CURLU *url)
{
  char *path, *query;
  struct dynbuf buf;
  CURLUcode uc;
  CURLcode result = CURLE_URL_MALFORMAT;

  path = query = NULL;
  Curl_dyn_init(&buf, DYN_HTTP_REQUEST);

  uc = curl_url_get(url, CURLUPART_PATH, &path, CURLU_PATH_AS_IS);
  if(uc)
    goto out;
  uc = curl_url_get(url, CURLUPART_QUERY, &query, 0);
  if(uc && uc != CURLUE_NO_QUERY)
    goto out;

  if(!path && !query) {
    req->path = NULL;
  }
  else if(path && !query) {
    req->path = path;
    path = NULL;
  }
  else {
    if(path) {
      result = Curl_dyn_add(&buf, path);
      if(result)
        goto out;
    }
    if(query) {
      result = Curl_dyn_addf(&buf, "?%s", query);
      if(result)
        goto out;
    }
    req->path = strdup(Curl_dyn_ptr(&buf));
    if(!req->path)
      goto out;
  }
  result = CURLE_OK;

out:
  free(path);
  free(query);
  Curl_dyn_free(&buf);
  return result;
}

CURLcode Curl_http_req_make2(struct http_req **preq,
                             const char *method, size_t m_len,
                             CURLU *url, const char *scheme_default)
{
  struct http_req *req;
  CURLcode result = CURLE_OUT_OF_MEMORY;
  CURLUcode uc;

  DEBUGASSERT(method);
  if(m_len + 1 >= sizeof(req->method))
    return CURLE_BAD_FUNCTION_ARGUMENT;

  req = calloc(1, sizeof(*req));
  if(!req)
    goto out;
  memcpy(req->method, method, m_len);

  uc = curl_url_get(url, CURLUPART_SCHEME, &req->scheme, 0);
  if(uc && uc != CURLUE_NO_SCHEME)
    goto out;
  if(!req->scheme && scheme_default) {
    req->scheme = strdup(scheme_default);
    if(!req->scheme)
      goto out;
  }

  result = req_assign_url_authority(req, url);
  if(result)
    goto out;
  result = req_assign_url_path(req, url);
  if(result)
    goto out;

  Curl_dynhds_init(&req->headers, 0, DYN_H2_HEADERS);
  Curl_dynhds_init(&req->trailers, 0, DYN_H2_TRAILERS);
  result = CURLE_OK;

out:
  if(result && req)
    Curl_http_req_free(req);
  *preq = result? NULL : req;
  return result;
}

void Curl_http_req_free(struct http_req *req)
{
  if(req) {
    free(req->scheme);
    free(req->authority);
    free(req->path);
    Curl_dynhds_free(&req->headers);
    Curl_dynhds_free(&req->trailers);
    free(req);
  }
}

struct name_const {
  const char *name;
  size_t namelen;
};

static struct name_const H2_NON_FIELD[] = {
  { STRCONST("Host") },
  { STRCONST("Upgrade") },
  { STRCONST("Connection") },
  { STRCONST("Keep-Alive") },
  { STRCONST("Proxy-Connection") },
  { STRCONST("Transfer-Encoding") },
};

static bool h2_non_field(const char *name, size_t namelen)
{
  size_t i;
  for(i = 0; i < sizeof(H2_NON_FIELD)/sizeof(H2_NON_FIELD[0]); ++i) {
    if(namelen < H2_NON_FIELD[i].namelen)
      return FALSE;
    if(namelen == H2_NON_FIELD[i].namelen &&
       strcasecompare(H2_NON_FIELD[i].name, name))
      return TRUE;
  }
  return FALSE;
}

CURLcode Curl_http_req_to_h2(struct dynhds *h2_headers,
                             struct http_req *req, struct Curl_easy *data)
{
  const char *scheme = NULL, *authority = NULL;
  struct dynhds_entry *e;
  size_t i;
  CURLcode result;

  DEBUGASSERT(req);
  DEBUGASSERT(h2_headers);

  if(req->scheme) {
    scheme = req->scheme;
  }
  else if(strcmp("CONNECT", req->method)) {
    scheme = Curl_checkheaders(data, STRCONST(HTTP_PSEUDO_SCHEME));
    if(scheme) {
      scheme += sizeof(HTTP_PSEUDO_SCHEME);
      while(*scheme && ISBLANK(*scheme))
        scheme++;
      infof(data, "set pseudo header %s to %s", HTTP_PSEUDO_SCHEME, scheme);
    }
    else {
      scheme = (data->conn && data->conn->handler->flags & PROTOPT_SSL)?
                "https" : "http";
    }
  }

  if(req->authority) {
    authority = req->authority;
  }
  else {
    e = Curl_dynhds_get(&req->headers, STRCONST("Host"));
    if(e)
      authority = e->value;
  }

  Curl_dynhds_reset(h2_headers);
  Curl_dynhds_set_opts(h2_headers, DYNHDS_OPT_LOWERCASE);
  result = Curl_dynhds_add(h2_headers, STRCONST(HTTP_PSEUDO_METHOD),
                           req->method, strlen(req->method));
  if(!result && scheme) {
    result = Curl_dynhds_add(h2_headers, STRCONST(HTTP_PSEUDO_SCHEME),
                             scheme, strlen(scheme));
  }
  if(!result && authority) {
    result = Curl_dynhds_add(h2_headers, STRCONST(HTTP_PSEUDO_AUTHORITY),
                             authority, strlen(authority));
  }
  if(!result && req->path) {
    result = Curl_dynhds_add(h2_headers, STRCONST(HTTP_PSEUDO_PATH),
                             req->path, strlen(req->path));
  }
  for(i = 0; !result && i < Curl_dynhds_count(&req->headers); ++i) {
    e = Curl_dynhds_getn(&req->headers, i);
    if(!h2_non_field(e->name, e->namelen)) {
      result = Curl_dynhds_add(h2_headers, e->name, e->namelen,
                               e->value, e->valuelen);
    }
  }

  return result;
}

CURLcode Curl_http_resp_make(struct http_resp **presp,
                             int status,
                             const char *description)
{
  struct http_resp *resp;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  resp = calloc(1, sizeof(*resp));
  if(!resp)
    goto out;

  resp->status = status;
  if(description) {
    resp->description = strdup(description);
    if(!resp->description)
      goto out;
  }
  Curl_dynhds_init(&resp->headers, 0, DYN_H2_HEADERS);
  Curl_dynhds_init(&resp->trailers, 0, DYN_H2_TRAILERS);
  result = CURLE_OK;

out:
  if(result && resp)
    Curl_http_resp_free(resp);
  *presp = result? NULL : resp;
  return result;
}

void Curl_http_resp_free(struct http_resp *resp)
{
  if(resp) {
    free(resp->description);
    Curl_dynhds_free(&resp->headers);
    Curl_dynhds_free(&resp->trailers);
    if(resp->prev)
      Curl_http_resp_free(resp->prev);
    free(resp);
  }
}

#endif /* CURL_DISABLE_HTTP */
