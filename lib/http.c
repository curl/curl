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

#include "urldata.h"
#include <curl/curl.h>
#include "transfer.h"
#include "sendf.h"
#include "formdata.h"
#include "mime.h"
#include "progress.h"
#include "curlx/base64.h"
#include "cookie.h"
#include "vauth/vauth.h"
#include "vtls/vtls.h"
#include "vquic/vquic.h"
#include "http_digest.h"
#include "http_ntlm.h"
#include "http_negotiate.h"
#include "http_aws_sigv4.h"
#include "url.h"
#include "urlapi-int.h"
#include "share.h"
#include "hostip.h"
#include "dynhds.h"
#include "http.h"
#include "headers.h"
#include "select.h"
#include "parsedate.h" /* for the week day and month names */
#include "multiif.h"
#include "strcase.h"
#include "content_encoding.h"
#include "http_proxy.h"
#include "curlx/warnless.h"
#include "http2.h"
#include "cfilters.h"
#include "connect.h"
#include "strdup.h"
#include "altsvc.h"
#include "hsts.h"
#include "ws.h"
#include "curl_ctype.h"
#include "curlx/strparse.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/*
 * Forward declarations.
 */

static bool http_should_fail(struct Curl_easy *data, int httpcode);
static bool http_exp100_is_waiting(struct Curl_easy *data);
static CURLcode http_exp100_add_reader(struct Curl_easy *data);
static void http_exp100_send_anyway(struct Curl_easy *data);
static bool http_exp100_is_selected(struct Curl_easy *data);
static void http_exp100_got100(struct Curl_easy *data);
static CURLcode http_firstwrite(struct Curl_easy *data);
static CURLcode http_header(struct Curl_easy *data,
                            const char *hd, size_t hdlen);
static CURLcode http_range(struct Curl_easy *data,
                           Curl_HttpReq httpreq);
static CURLcode http_req_set_TE(struct Curl_easy *data,
                                struct dynbuf *req,
                                int httpversion);
static CURLcode http_size(struct Curl_easy *data);
static CURLcode http_statusline(struct Curl_easy *data,
                                struct connectdata *conn);
static CURLcode http_target(struct Curl_easy *data, struct dynbuf *req);
static CURLcode http_useragent(struct Curl_easy *data);


/*
 * HTTP handler interface.
 */
const struct Curl_handler Curl_handler_http = {
  "http",                               /* scheme */
  Curl_http_setup_conn,                 /* setup_connection */
  Curl_http,                            /* do_it */
  Curl_http_done,                       /* done */
  ZERO_NULL,                            /* do_more */
  Curl_http_connect,                    /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_pollset */
  Curl_http_do_pollset,                 /* doing_pollset */
  ZERO_NULL,                            /* domore_pollset */
  ZERO_NULL,                            /* perform_pollset */
  ZERO_NULL,                            /* disconnect */
  Curl_http_write_resp,                 /* write_resp */
  Curl_http_write_resp_hd,              /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  Curl_http_follow,                     /* follow */
  PORT_HTTP,                            /* defport */
  CURLPROTO_HTTP,                       /* protocol */
  CURLPROTO_HTTP,                       /* family */
  PROTOPT_CREDSPERREQUEST |             /* flags */
  PROTOPT_USERPWDCTRL
};

#ifdef USE_SSL
/*
 * HTTPS handler interface.
 */
const struct Curl_handler Curl_handler_https = {
  "https",                              /* scheme */
  Curl_http_setup_conn,                 /* setup_connection */
  Curl_http,                            /* do_it */
  Curl_http_done,                       /* done */
  ZERO_NULL,                            /* do_more */
  Curl_http_connect,                    /* connect_it */
  NULL,                                 /* connecting */
  ZERO_NULL,                            /* doing */
  NULL,                                 /* proto_pollset */
  Curl_http_do_pollset,                 /* doing_pollset */
  ZERO_NULL,                            /* domore_pollset */
  ZERO_NULL,                            /* perform_pollset */
  ZERO_NULL,                            /* disconnect */
  Curl_http_write_resp,                 /* write_resp */
  Curl_http_write_resp_hd,              /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  Curl_http_follow,                     /* follow */
  PORT_HTTPS,                           /* defport */
  CURLPROTO_HTTPS,                      /* protocol */
  CURLPROTO_HTTP,                       /* family */
  PROTOPT_SSL | PROTOPT_CREDSPERREQUEST | PROTOPT_ALPN | /* flags */
  PROTOPT_USERPWDCTRL
};

#endif

void Curl_http_neg_init(struct Curl_easy *data, struct http_negotiation *neg)
{
  memset(neg, 0, sizeof(*neg));
  neg->accept_09 = data->set.http09_allowed;
  switch(data->set.httpwant) {
  case CURL_HTTP_VERSION_1_0:
    neg->wanted = neg->allowed = (CURL_HTTP_V1x);
    neg->only_10 = TRUE;
    break;
  case CURL_HTTP_VERSION_1_1:
    neg->wanted = neg->allowed = (CURL_HTTP_V1x);
    break;
  case CURL_HTTP_VERSION_2_0:
    neg->wanted = neg->allowed = (CURL_HTTP_V1x | CURL_HTTP_V2x);
    neg->h2_upgrade = TRUE;
    break;
  case CURL_HTTP_VERSION_2TLS:
    neg->wanted = neg->allowed = (CURL_HTTP_V1x | CURL_HTTP_V2x);
    break;
  case CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE:
    neg->wanted = neg->allowed = (CURL_HTTP_V2x);
    data->state.http_neg.h2_prior_knowledge = TRUE;
    break;
  case CURL_HTTP_VERSION_3:
    neg->wanted = (CURL_HTTP_V1x | CURL_HTTP_V2x | CURL_HTTP_V3x);
    neg->allowed = neg->wanted;
    break;
  case CURL_HTTP_VERSION_3ONLY:
    neg->wanted = neg->allowed = (CURL_HTTP_V3x);
    break;
  case CURL_HTTP_VERSION_NONE:
  default:
    neg->wanted = (CURL_HTTP_V1x | CURL_HTTP_V2x);
    neg->allowed = (CURL_HTTP_V1x | CURL_HTTP_V2x | CURL_HTTP_V3x);
    break;
  }
}

CURLcode Curl_http_setup_conn(struct Curl_easy *data,
                              struct connectdata *conn)
{
  /* allocate the HTTP-specific struct for the Curl_easy, only to survive
     during this request */
  connkeep(conn, "HTTP default");
  if(data->state.http_neg.wanted == CURL_HTTP_V3x) {
    /* only HTTP/3, needs to work */
    CURLcode result = Curl_conn_may_http3(data, conn, conn->transport_wanted);
    if(result)
      return result;
  }
  return CURLE_OK;
}

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
    if(curl_strnequal(head->data, thisheader, thislen) &&
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
 * Strip off leading and trailing whitespace from the value in the given HTTP
 * header line and return a strdup()ed copy. Returns NULL in case of
 * allocation failure or bad input. Returns an empty string if the header
 * value consists entirely of whitespace.
 *
 * If the header is provided as "name;", ending with a semicolon, it must
 * return a blank string.
 */
char *Curl_copy_header_value(const char *header)
{
  struct Curl_str out;

  /* find the end of the header name */
  if(!curlx_str_cspn(&header, &out, ";:") &&
     (!curlx_str_single(&header, ':') || !curlx_str_single(&header, ';'))) {
    curlx_str_untilnl(&header, &out, MAX_HTTP_RESP_HEADER_SIZE);
    curlx_str_trimblanks(&out);

    return Curl_memdup0(curlx_str(&out), curlx_strlen(&out));
  }
  /* bad input */
  return NULL;
}

#ifndef CURL_DISABLE_HTTP_AUTH

#ifndef CURL_DISABLE_BASIC_AUTH
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

  result = curlx_base64_encode(out, strlen(out), &authorization, &size);
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

#endif

#ifndef CURL_DISABLE_BEARER_AUTH
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
#ifndef CURL_DISABLE_BEARER_AUTH
  else if(avail & CURLAUTH_BEARER)
    pick->picked = CURLAUTH_BEARER;
#endif
#ifndef CURL_DISABLE_DIGEST_AUTH
  else if(avail & CURLAUTH_DIGEST)
    pick->picked = CURLAUTH_DIGEST;
#endif
  else if(avail & CURLAUTH_NTLM)
    pick->picked = CURLAUTH_NTLM;
#ifndef CURL_DISABLE_BASIC_AUTH
  else if(avail & CURLAUTH_BASIC)
    pick->picked = CURLAUTH_BASIC;
#endif
#ifndef CURL_DISABLE_AWS
  else if(avail & CURLAUTH_AWS_SIGV4)
    pick->picked = CURLAUTH_AWS_SIGV4;
#endif
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
 * The current request needs to be done again - maybe due to a follow
 * or authentication negotiation. Check if:
 * 1) a rewind of the data sent to the server is necessary
 * 2) the current transfer should continue or be stopped early
 */
static CURLcode http_perhapsrewind(struct Curl_easy *data,
                                   struct connectdata *conn)
{
  curl_off_t bytessent = data->req.writebytecount;
  curl_off_t expectsend = Curl_creader_total_length(data);
  curl_off_t upload_remain = (expectsend >= 0) ? (expectsend - bytessent) : -1;
  bool little_upload_remains = (upload_remain >= 0 && upload_remain < 2000);
  bool needs_rewind = Curl_creader_needs_rewind(data);
  /* By default, we would like to abort the transfer when little or unknown
   * amount remains. This may be overridden by authentications further
   * below! */
  bool abort_upload = (!data->req.upload_done && !little_upload_remains);
  const char *ongoing_auth = NULL;

  /* We need a rewind before uploading client read data again. The
   * checks below just influence of the upload is to be continued
   * or aborted early.
   * This depends on how much remains to be sent and in what state
   * the authentication is. Some auth schemes such as NTLM do not work
   * for a new connection. */
  if(needs_rewind) {
    infof(data, "Need to rewind upload for next request");
    Curl_creader_set_rewind(data, TRUE);
  }

  if(conn->bits.close)
    /* If we already decided to close this connection, we cannot veto. */
    return CURLE_OK;

  if(abort_upload) {
    /* We'd like to abort the upload - but should we? */
#ifdef USE_NTLM
    if((data->state.authproxy.picked == CURLAUTH_NTLM) ||
       (data->state.authhost.picked == CURLAUTH_NTLM)) {
      ongoing_auth = "NTLM";
      if((conn->http_ntlm_state != NTLMSTATE_NONE) ||
         (conn->proxy_ntlm_state != NTLMSTATE_NONE)) {
        /* The NTLM-negotiation has started, keep on sending.
         * Need to do further work on same connection */
        abort_upload = FALSE;
      }
    }
#endif
#ifdef USE_SPNEGO
    /* There is still data left to send */
    if((data->state.authproxy.picked == CURLAUTH_NEGOTIATE) ||
       (data->state.authhost.picked == CURLAUTH_NEGOTIATE)) {
      ongoing_auth = "NEGOTIATE";
      if((conn->http_negotiate_state != GSS_AUTHNONE) ||
         (conn->proxy_negotiate_state != GSS_AUTHNONE)) {
        /* The NEGOTIATE-negotiation has started, keep on sending.
         * Need to do further work on same connection */
        abort_upload = FALSE;
      }
    }
#endif
  }

  if(abort_upload) {
    if(upload_remain >= 0)
      infof(data, "%s%sclose instead of sending %" FMT_OFF_T " more bytes",
            ongoing_auth ? ongoing_auth : "",
            ongoing_auth ? " send, " : "",
            upload_remain);
    else
      infof(data, "%s%sclose instead of sending unknown amount "
            "of more bytes",
            ongoing_auth ? ongoing_auth : "",
            ongoing_auth ? " send, " : "");
    /* We decided to abort the ongoing transfer */
    streamclose(conn, "Mid-auth HTTP and much data left to send");
    data->req.size = 0; /* do not download any more than 0 bytes */
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
    return data->set.http_fail_on_error ? CURLE_HTTP_RETURNED_ERROR : CURLE_OK;

  if((data->state.aptr.user || data->set.str[STRING_BEARER]) &&
     ((data->req.httpcode == 401) ||
      (data->req.authneg && data->req.httpcode < 300))) {
    pickhost = pickoneauth(&data->state.authhost, authmask);
    if(!pickhost)
      data->state.authproblem = TRUE;
    else
      data->info.httpauthpicked = data->state.authhost.picked;
    if(data->state.authhost.picked == CURLAUTH_NTLM &&
       (data->req.httpversion_sent > 11)) {
      infof(data, "Forcing HTTP/1.1 for NTLM");
      connclose(conn, "Force HTTP/1.1 connection");
      data->state.http_neg.wanted = CURL_HTTP_V1x;
      data->state.http_neg.allowed = CURL_HTTP_V1x;
    }
  }
#ifndef CURL_DISABLE_PROXY
  if(conn->bits.proxy_user_passwd &&
     ((data->req.httpcode == 407) ||
      (data->req.authneg && data->req.httpcode < 300))) {
    pickproxy = pickoneauth(&data->state.authproxy,
                            authmask & ~CURLAUTH_BEARER);
    if(!pickproxy)
      data->state.authproblem = TRUE;
    else
      data->info.proxyauthpicked = data->state.authproxy.picked;

  }
#endif

  if(pickhost || pickproxy) {
    result = http_perhapsrewind(data, conn);
    if(result)
      return result;

    /* In case this is GSS auth, the newurl field is already allocated so
       we must make sure to free it before allocating a new one. As figured
       out in bug #2284386 */
    free(data->req.newurl);
    data->req.newurl = strdup(data->state.url); /* clone URL */
    if(!data->req.newurl)
      return CURLE_OUT_OF_MEMORY;
  }
  else if((data->req.httpcode < 300) &&
          (!data->state.authhost.done) &&
          data->req.authneg) {
    /* no (known) authentication available,
       authentication is not "done" yet and
       no authentication seems to be required and
       we did not try HEAD or GET */
    if((data->state.httpreq != HTTPREQ_GET) &&
       (data->state.httpreq != HTTPREQ_HEAD)) {
      data->req.newurl = strdup(data->state.url); /* clone URL */
      if(!data->req.newurl)
        return CURLE_OUT_OF_MEMORY;
      data->state.authhost.done = TRUE;
    }
  }
  if(http_should_fail(data, data->req.httpcode)) {
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

#ifdef CURL_DISABLE_DIGEST_AUTH
  (void)request;
  (void)path;
#endif
#ifndef CURL_DISABLE_AWS
  if((authstatus->picked == CURLAUTH_AWS_SIGV4) && !proxy) {
    /* this method is never for proxy */
    auth = "AWS_SIGV4";
    result = Curl_output_aws_sigv4(data);
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
#ifndef CURL_DISABLE_DIGEST_AUTH
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
#ifndef CURL_DISABLE_BASIC_AUTH
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
#endif
#ifndef CURL_DISABLE_BEARER_AUTH
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
#endif

  if(auth) {
#ifndef CURL_DISABLE_PROXY
    infof(data, "%s auth using %s with user '%s'",
          proxy ? "Proxy" : "Server", auth,
          proxy ? (data->state.aptr.proxyuser ?
                   data->state.aptr.proxyuser : "") :
          (data->state.aptr.user ?
           data->state.aptr.user : ""));
#else
    (void)proxy;
    infof(data, "Server auth using %s with user '%s'",
          auth, data->state.aptr.user ?
          data->state.aptr.user : "");
#endif
    authstatus->multipass = !authstatus->done;
  }
  else
    authstatus->multipass = FALSE;

  return result;
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
    data->state.aptr.user ||
#ifdef USE_SPNEGO
    authhost->want & CURLAUTH_NEGOTIATE ||
    authproxy->want & CURLAUTH_NEGOTIATE ||
#endif
    data->set.str[STRING_BEARER])
    /* continue please */;
  else {
    authhost->done = TRUE;
    authproxy->done = TRUE;
    return CURLE_OK; /* no authentication with no user or password */
  }

  if(authhost->want && !authhost->picked)
    /* The app has selected one or more methods, but none has been picked
       so far by a server round-trip. Then we set the picked one to the
       want one, and if this is one single bit it will be used instantly. */
    authhost->picked = authhost->want;

  if(authproxy->want && !authproxy->picked)
    /* The app has selected one or more methods, but none has been picked so
       far by a proxy round-trip. Then we set the picked one to the want one,
       and if this is one single bit it will be used instantly. */
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
    /* we have no proxy so let's pretend we are done authenticating
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
    data->req.authneg = TRUE;
  }
  else
    data->req.authneg = FALSE;

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

#if defined(USE_SPNEGO) || defined(USE_NTLM) || \
  !defined(CURL_DISABLE_DIGEST_AUTH) || \
  !defined(CURL_DISABLE_BASIC_AUTH) || \
  !defined(CURL_DISABLE_BEARER_AUTH)
static bool authcmp(const char *auth, const char *line)
{
  /* the auth string must not have an alnum following */
  size_t n = strlen(auth);
  return curl_strnequal(auth, line, n) && !ISALNUM(line[n]);
}
#endif

#ifdef USE_SPNEGO
static CURLcode auth_spnego(struct Curl_easy *data,
                            bool proxy,
                            const char *auth,
                            struct auth *authp,
                            unsigned long *availp)
{
  if((authp->avail & CURLAUTH_NEGOTIATE) || Curl_auth_is_spnego_supported()) {
    *availp |= CURLAUTH_NEGOTIATE;
    authp->avail |= CURLAUTH_NEGOTIATE;

    if(authp->picked == CURLAUTH_NEGOTIATE) {
      struct connectdata *conn = data->conn;
      CURLcode result = Curl_input_negotiate(data, conn, proxy, auth);
      curlnegotiate *negstate = proxy ? &conn->proxy_negotiate_state :
        &conn->http_negotiate_state;
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
  return CURLE_OK;
}
#endif

#ifdef USE_NTLM
static CURLcode auth_ntlm(struct Curl_easy *data,
                          bool proxy,
                          const char *auth,
                          struct auth *authp,
                          unsigned long *availp)
{
  /* NTLM support requires the SSL crypto libs */
  if((authp->avail & CURLAUTH_NTLM) || Curl_auth_is_ntlm_supported()) {
    *availp |= CURLAUTH_NTLM;
    authp->avail |= CURLAUTH_NTLM;

    if(authp->picked == CURLAUTH_NTLM) {
      /* NTLM authentication is picked and activated */
      CURLcode result = Curl_input_ntlm(data, proxy, auth);
      if(!result)
        data->state.authproblem = FALSE;
      else {
        infof(data, "NTLM authentication problem, ignoring.");
        data->state.authproblem = TRUE;
      }
    }
  }
  return CURLE_OK;
}
#endif

#ifndef CURL_DISABLE_DIGEST_AUTH
static CURLcode auth_digest(struct Curl_easy *data,
                            bool proxy,
                            const char *auth,
                            struct auth *authp,
                            unsigned long *availp)
{
  if(authp->avail & CURLAUTH_DIGEST)
    infof(data, "Ignoring duplicate digest auth header.");
  else if(Curl_auth_is_digest_supported()) {
    CURLcode result;

    *availp |= CURLAUTH_DIGEST;
    authp->avail |= CURLAUTH_DIGEST;

    /* We call this function on input Digest headers even if Digest
     * authentication is not activated yet, as we need to store the
     * incoming data from this header in case we are going to use
     * Digest */
    result = Curl_input_digest(data, proxy, auth);
    if(result) {
      infof(data, "Digest authentication problem, ignoring.");
      data->state.authproblem = TRUE;
    }
  }
  return CURLE_OK;
}
#endif

#ifndef CURL_DISABLE_BASIC_AUTH
static CURLcode auth_basic(struct Curl_easy *data,
                           struct auth *authp,
                           unsigned long *availp)
{
  *availp |= CURLAUTH_BASIC;
  authp->avail |= CURLAUTH_BASIC;
  if(authp->picked == CURLAUTH_BASIC) {
    /* We asked for Basic authentication but got a 40X back
       anyway, which basically means our name+password is not
       valid. */
    authp->avail = CURLAUTH_NONE;
    infof(data, "Basic authentication problem, ignoring.");
    data->state.authproblem = TRUE;
  }
  return CURLE_OK;
}
#endif

#ifndef CURL_DISABLE_BEARER_AUTH
static CURLcode auth_bearer(struct Curl_easy *data,
                            struct auth *authp,
                            unsigned long *availp)
{
  *availp |= CURLAUTH_BEARER;
  authp->avail |= CURLAUTH_BEARER;
  if(authp->picked == CURLAUTH_BEARER) {
    /* We asked for Bearer authentication but got a 40X back
       anyway, which basically means our token is not valid. */
    authp->avail = CURLAUTH_NONE;
    infof(data, "Bearer authentication problem, ignoring.");
    data->state.authproblem = TRUE;
  }
  return CURLE_OK;
}
#endif

/*
 * Curl_http_input_auth() deals with Proxy-Authenticate: and WWW-Authenticate:
 * headers. They are dealt with both in the transfer.c main loop and in the
 * proxy CONNECT loop.
 *
 * The 'auth' line ends with a null byte without CR or LF present.
 */
CURLcode Curl_http_input_auth(struct Curl_easy *data, bool proxy,
                              const char *auth) /* the first non-space */
{
  /*
   * This resource requires authentication
   */
#if defined(USE_SPNEGO) ||                      \
  defined(USE_NTLM) ||                          \
  !defined(CURL_DISABLE_DIGEST_AUTH) ||         \
  !defined(CURL_DISABLE_BASIC_AUTH) ||          \
  !defined(CURL_DISABLE_BEARER_AUTH)

  unsigned long *availp;
  struct auth *authp;
  CURLcode result = CURLE_OK;
  DEBUGASSERT(auth);
  DEBUGASSERT(data);

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
    if(authcmp("Negotiate", auth))
      result = auth_spnego(data, proxy, auth, authp, availp);
#endif
#ifdef USE_NTLM
    if(!result && authcmp("NTLM", auth))
      result = auth_ntlm(data, proxy, auth, authp, availp);
#endif
#ifndef CURL_DISABLE_DIGEST_AUTH
    if(!result && authcmp("Digest", auth))
      result = auth_digest(data, proxy, auth, authp, availp);
#endif
#ifndef CURL_DISABLE_BASIC_AUTH
    if(!result && authcmp("Basic", auth))
      result = auth_basic(data, authp, availp);
#endif
#ifndef CURL_DISABLE_BEARER_AUTH
    if(authcmp("Bearer", auth))
      result = auth_bearer(data, authp, availp);
#endif

    if(result)
      break;

    /* there may be multiple methods on one line, so keep reading */
    auth = strchr(auth, ',');
    if(auth) /* if we are on a comma, skip it */
      auth++;
    else
      break;
    curlx_str_passblanks(&auth);
  }
  return result;
#else
  (void)data;
  (void)proxy;
  (void)auth;
  /* nothing to do when disabled */
  return CURLE_OK;
#endif
}

/**
 * http_should_fail() determines whether an HTTP response code has gotten us
 * into an error state or not.
 *
 * @retval FALSE communications should continue
 *
 * @retval TRUE communications should not continue
 */
static bool http_should_fail(struct Curl_easy *data, int httpcode)
{
  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);

  /*
  ** If we have not been asked to fail on error,
  ** do not fail.
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
  ** Any code >= 400 that is not 401 or 407 is always
  ** a terminal error
  */
  if((httpcode != 401) && (httpcode != 407))
    return TRUE;

  /*
  ** All we have left to deal with is 401 and 407
  */
  DEBUGASSERT((httpcode == 401) || (httpcode == 407));

  /*
  ** Examine the current authentication state to see if this is an error. The
  ** idea is for this function to get called after processing all the headers
  ** in a response message. So, if we have been to asked to authenticate a
  ** particular stage, and we have done it, we are OK. If we are already
  ** completely authenticated, it is not OK to get another 401 or 407.
  **
  ** It is possible for authentication to go stale such that the client needs
  ** to reauthenticate. Once that info is available, use it here.
  */

  /*
  ** Either we are not authenticating, or we are supposed to be authenticating
  ** something else. This is an error.
  */
  if((httpcode == 401) && !data->state.aptr.user)
    return TRUE;
#ifndef CURL_DISABLE_PROXY
  if((httpcode == 407) && !data->conn->bits.proxy_user_passwd)
    return TRUE;
#endif

  return data->state.authproblem;
}

static void http_switch_to_get(struct Curl_easy *data, int code)
{
  const char *req = data->set.str[STRING_CUSTOMREQUEST];
  if((req || data->state.httpreq != HTTPREQ_GET) &&
     (data->set.http_follow_mode == CURLFOLLOW_OBEYCODE)) {
    infof(data, "Switch to GET because of %d response", code);
    data->state.http_ignorecustom = TRUE;
  }
  else if(req && (data->set.http_follow_mode != CURLFOLLOW_FIRSTONLY))
    infof(data, "Stick to %s instead of GET", req);

  data->state.httpreq = HTTPREQ_GET;
  Curl_creader_set_rewind(data, FALSE);
}

CURLcode Curl_http_follow(struct Curl_easy *data, const char *newurl,
                          followtype type)
{
  bool disallowport = FALSE;
  bool reachedmax = FALSE;
  char *follow_url = NULL;
  CURLUcode uc;
  CURLcode rewind_result;
  bool switch_to_get = FALSE;

  DEBUGASSERT(type != FOLLOW_NONE);

  if(type != FOLLOW_FAKE)
    data->state.requests++; /* count all real follows */
  if(type == FOLLOW_REDIR) {
    if((data->set.maxredirs != -1) &&
       (data->state.followlocation >= data->set.maxredirs)) {
      reachedmax = TRUE;
      type = FOLLOW_FAKE; /* switch to fake to store the would-be-redirected
                             to URL */
    }
    else {
      data->state.followlocation++; /* count redirect-followings, including
                                       auth reloads */

      if(data->set.http_auto_referer) {
        CURLU *u;
        char *referer = NULL;

        /* We are asked to automatically set the previous URL as the referer
           when we get the next URL. We pick the ->url field, which may or may
           not be 100% correct */

        if(data->state.referer_alloc) {
          Curl_safefree(data->state.referer);
          data->state.referer_alloc = FALSE;
        }

        /* Make a copy of the URL without credentials and fragment */
        u = curl_url();
        if(!u)
          return CURLE_OUT_OF_MEMORY;

        uc = curl_url_set(u, CURLUPART_URL, data->state.url, 0);
        if(!uc)
          uc = curl_url_set(u, CURLUPART_FRAGMENT, NULL, 0);
        if(!uc)
          uc = curl_url_set(u, CURLUPART_USER, NULL, 0);
        if(!uc)
          uc = curl_url_set(u, CURLUPART_PASSWORD, NULL, 0);
        if(!uc)
          uc = curl_url_get(u, CURLUPART_URL, &referer, 0);

        curl_url_cleanup(u);

        if(uc || !referer)
          return CURLE_OUT_OF_MEMORY;

        data->state.referer = referer;
        data->state.referer_alloc = TRUE; /* yes, free this later */
      }
    }
  }

  if((type != FOLLOW_RETRY) &&
     (data->req.httpcode != 401) && (data->req.httpcode != 407) &&
     Curl_is_absolute_url(newurl, NULL, 0, FALSE)) {
    /* If this is not redirect due to a 401 or 407 response and an absolute
       URL: do not allow a custom port number */
    disallowport = TRUE;
  }

  DEBUGASSERT(data->state.uh);
  uc = curl_url_set(data->state.uh, CURLUPART_URL, newurl, (unsigned int)
                    ((type == FOLLOW_FAKE) ? CURLU_NON_SUPPORT_SCHEME :
                     ((type == FOLLOW_REDIR) ? CURLU_URLENCODE : 0) |
                     CURLU_ALLOW_SPACE |
                     (data->set.path_as_is ? CURLU_PATH_AS_IS : 0)));
  if(uc) {
    if(type != FOLLOW_FAKE) {
      failf(data, "The redirect target URL could not be parsed: %s",
            curl_url_strerror(uc));
      return Curl_uc_to_curlcode(uc);
    }

    /* the URL could not be parsed for some reason, but since this is FAKE
       mode, just duplicate the field as-is */
    follow_url = strdup(newurl);
    if(!follow_url)
      return CURLE_OUT_OF_MEMORY;
  }
  else {
    uc = curl_url_get(data->state.uh, CURLUPART_URL, &follow_url, 0);
    if(uc)
      return Curl_uc_to_curlcode(uc);

    /* Clear auth if this redirects to a different port number or protocol,
       unless permitted */
    if(!data->set.allow_auth_to_other_hosts && (type != FOLLOW_FAKE)) {
      char *portnum;
      int port;
      bool clear = FALSE;

      if(data->set.use_port && data->state.allow_port)
        /* a custom port is used */
        port = (int)data->set.use_port;
      else {
        uc = curl_url_get(data->state.uh, CURLUPART_PORT, &portnum,
                          CURLU_DEFAULT_PORT);
        if(uc) {
          free(follow_url);
          return Curl_uc_to_curlcode(uc);
        }
        port = atoi(portnum);
        free(portnum);
      }
      if(port != data->info.conn_remote_port) {
        infof(data, "Clear auth, redirects to port from %u to %u",
              data->info.conn_remote_port, port);
        clear = TRUE;
      }
      else {
        char *scheme;
        const struct Curl_handler *p;
        uc = curl_url_get(data->state.uh, CURLUPART_SCHEME, &scheme, 0);
        if(uc) {
          free(follow_url);
          return Curl_uc_to_curlcode(uc);
        }

        p = Curl_get_scheme_handler(scheme);
        if(p && (p->protocol != data->info.conn_protocol)) {
          infof(data, "Clear auth, redirects scheme from %s to %s",
                data->info.conn_scheme, scheme);
          clear = TRUE;
        }
        free(scheme);
      }
      if(clear) {
        Curl_safefree(data->state.aptr.user);
        Curl_safefree(data->state.aptr.passwd);
      }
    }
  }
  DEBUGASSERT(follow_url);

  if(type == FOLLOW_FAKE) {
    /* we are only figuring out the new URL if we would have followed locations
       but now we are done so we can get out! */
    data->info.wouldredirect = follow_url;

    if(reachedmax) {
      failf(data, "Maximum (%d) redirects followed", data->set.maxredirs);
      return CURLE_TOO_MANY_REDIRECTS;
    }
    return CURLE_OK;
  }

  if(disallowport)
    data->state.allow_port = FALSE;

  if(data->state.url_alloc)
    Curl_safefree(data->state.url);

  data->state.url = follow_url;
  data->state.url_alloc = TRUE;
  rewind_result = Curl_req_soft_reset(&data->req, data);
  infof(data, "Issue another request to this URL: '%s'", data->state.url);
  if((data->set.http_follow_mode == CURLFOLLOW_FIRSTONLY) &&
     data->set.str[STRING_CUSTOMREQUEST] &&
     !data->state.http_ignorecustom) {
    data->state.http_ignorecustom = TRUE;
    infof(data, "Drop custom request method for next request");
  }

  /*
   * We get here when the HTTP code is 300-399 (and 401). We need to perform
   * differently based on exactly what return code there was.
   *
   * News from 7.10.6: we can also get here on a 401 or 407, in case we act on
   * an HTTP (proxy-) authentication scheme other than Basic.
   */
  switch(data->info.httpcode) {
    /* 401 - Act on a WWW-Authenticate, we keep on moving and do the
       Authorization: XXXX header in the HTTP request code snippet */
    /* 407 - Act on a Proxy-Authenticate, we keep on moving and do the
       Proxy-Authorization: XXXX header in the HTTP request code snippet */
    /* 300 - Multiple Choices */
    /* 306 - Not used */
    /* 307 - Temporary Redirect */
  default:  /* for all above (and the unknown ones) */
    /* Some codes are explicitly mentioned since I have checked RFC2616 and
     * they seem to be OK to POST to.
     */
    break;
  case 301: /* Moved Permanently */
    /* (quote from RFC7231, section 6.4.2)
     *
     * Note: For historical reasons, a user agent MAY change the request
     * method from POST to GET for the subsequent request. If this
     * behavior is undesired, the 307 (Temporary Redirect) status code
     * can be used instead.
     *
     * ----
     *
     * Many webservers expect this, so these servers often answers to a POST
     * request with an error page. To be sure that libcurl gets the page that
     * most user agents would get, libcurl has to force GET.
     *
     * This behavior is forbidden by RFC1945 and the obsolete RFC2616, and
     * can be overridden with CURLOPT_POSTREDIR.
     */
    if((data->state.httpreq == HTTPREQ_POST
        || data->state.httpreq == HTTPREQ_POST_FORM
        || data->state.httpreq == HTTPREQ_POST_MIME)
       && !(data->set.keep_post & CURL_REDIR_POST_301)) {
      http_switch_to_get(data, 301);
      switch_to_get = TRUE;
    }
    break;
  case 302: /* Found */
    /* (quote from RFC7231, section 6.4.3)
     *
     * Note: For historical reasons, a user agent MAY change the request
     * method from POST to GET for the subsequent request. If this
     * behavior is undesired, the 307 (Temporary Redirect) status code
     * can be used instead.
     *
     * ----
     *
     * Many webservers expect this, so these servers often answers to a POST
     * request with an error page. To be sure that libcurl gets the page that
     * most user agents would get, libcurl has to force GET.
     *
     * This behavior is forbidden by RFC1945 and the obsolete RFC2616, and
     * can be overridden with CURLOPT_POSTREDIR.
     */
    if((data->state.httpreq == HTTPREQ_POST
        || data->state.httpreq == HTTPREQ_POST_FORM
        || data->state.httpreq == HTTPREQ_POST_MIME)
       && !(data->set.keep_post & CURL_REDIR_POST_302)) {
      http_switch_to_get(data, 302);
      switch_to_get = TRUE;
    }
    break;

  case 303: /* See Other */
    /* 'See Other' location is not the resource but a substitute for the
     * resource. In this case we switch the method to GET/HEAD, unless the
     * method is POST and the user specified to keep it as POST.
     * https://github.com/curl/curl/issues/5237#issuecomment-614641049
     */
    if(data->state.httpreq != HTTPREQ_GET &&
       ((data->state.httpreq != HTTPREQ_POST &&
         data->state.httpreq != HTTPREQ_POST_FORM &&
         data->state.httpreq != HTTPREQ_POST_MIME) ||
        !(data->set.keep_post & CURL_REDIR_POST_303))) {
      http_switch_to_get(data, 303);
      switch_to_get = TRUE;
    }
    break;
  case 304: /* Not Modified */
    /* 304 means we did a conditional request and it was "Not modified".
     * We should not get any Location: header in this response!
     */
    break;
  case 305: /* Use Proxy */
    /* (quote from RFC2616, section 10.3.6):
     * "The requested resource MUST be accessed through the proxy given
     * by the Location field. The Location field gives the URI of the
     * proxy. The recipient is expected to repeat this single request
     * via the proxy. 305 responses MUST only be generated by origin
     * servers."
     */
    break;
  }

  /* When rewind of upload data failed and we are not switching to GET,
   * we need to fail the follow, as we cannot send the data again. */
  if(rewind_result && !switch_to_get)
    return rewind_result;

  Curl_pgrsTime(data, TIMER_REDIRECT);
  Curl_pgrsResetTransferSizes(data);

  return CURLE_OK;
}

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

  const char *p;
  struct Curl_str val;
  DEBUGASSERT(hlen);
  DEBUGASSERT(clen);
  DEBUGASSERT(header);
  DEBUGASSERT(content);

  if(!curl_strnequal(headerline, header, hlen))
    return FALSE; /* does not start with header */

  /* pass the header */
  p = &headerline[hlen];

  if(curlx_str_untilnl(&p, &val, MAX_HTTP_RESP_HEADER_SIZE))
    return FALSE;
  curlx_str_trimblanks(&val);

  /* find the content string in the rest of the line */
  if(curlx_strlen(&val) >= clen) {
    size_t len;
    p = curlx_str(&val);
    for(len = curlx_strlen(&val); len >= curlx_strlen(&val); len--, p++) {
      if(curl_strnequal(p, content, clen))
        return TRUE; /* match! */
    }
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
     function to make the reuse checks properly be able to check this bit. */
  connkeep(conn, "HTTP default");

  return Curl_conn_connect(data, FIRSTSOCKET, FALSE, done);
}

/* this returns the socket to wait for in the DO and DOING state for the multi
   interface and then we are always _sending_ a request and thus we wait for
   the single socket to become writable only */
CURLcode Curl_http_do_pollset(struct Curl_easy *data,
                              struct easy_pollset *ps)
{
  /* write mode */
  return Curl_pollset_add_out(data, ps, data->conn->sock[FIRSTSOCKET]);
}

/*
 * Curl_http_done() gets called after a single HTTP request has been
 * performed.
 */

CURLcode Curl_http_done(struct Curl_easy *data,
                        CURLcode status, bool premature)
{
  struct connectdata *conn = data->conn;

  /* Clear multipass flag. If authentication is not done yet, then it will get
   * a chance to be set back to true when we output the next auth header */
  data->state.authhost.multipass = FALSE;
  data->state.authproxy.multipass = FALSE;

  curlx_dyn_reset(&data->state.headerb);

  if(status)
    return status;

  if(!premature && /* this check is pointless when DONE is called before the
                      entire operation is complete */
     !conn->bits.retry &&
     !data->set.connect_only &&
     (data->req.bytecount +
      data->req.headerbytecount -
      data->req.deductheadercount) <= 0) {
    /* If this connection is not simply closed to be retried, AND nothing was
       read from the HTTP server (that counts), this cannot be right so we
       return an error here */
    failf(data, "Empty reply from server");
    /* Mark it as closed to avoid the "left intact" message */
    streamclose(conn, "Empty reply from server");
    return CURLE_GOT_NOTHING;
  }

  return CURLE_OK;
}

/* Determine if we may use HTTP 1.1 for this request. */
static bool http_may_use_1_1(const struct Curl_easy *data)
{
  const struct connectdata *conn = data->conn;
  /* We have seen a previous response for *this* transfer with 1.0,
   * on another connection or the same one. */
  if(data->state.http_neg.rcvd_min == 10)
    return FALSE;
  /* We have seen a previous response on *this* connection with 1.0. */
  if(conn && conn->httpversion_seen == 10)
    return FALSE;
  /* We want 1.0 and have seen no previous response on *this* connection
     with a higher version (maybe no response at all yet). */
  if((data->state.http_neg.only_10) &&
     (!conn || conn->httpversion_seen <= 10))
    return FALSE;
  /* We are not restricted to use 1.0 only. */
  return !data->state.http_neg.only_10;
}

static unsigned char http_request_version(struct Curl_easy *data)
{
  unsigned char v = Curl_conn_http_version(data, data->conn);
  if(!v) {
    /* No specific HTTP connection filter installed. */
    v = http_may_use_1_1(data) ? 11 : 10;
  }
  return v;
}

static const char *get_http_string(int httpversion)
{
  switch(httpversion) {
    case 30:
      return "3";
    case 20:
      return "2";
    case 11:
      return "1.1";
    default:
      return "1.0";
  }
}

CURLcode Curl_add_custom_headers(struct Curl_easy *data,
                                 bool is_connect, int httpversion,
                                 struct dynbuf *req)
{
  struct curl_slist *h[2];
  struct curl_slist *headers;
  int numlists = 1; /* by default */
  int i;

#ifndef CURL_DISABLE_PROXY
  enum Curl_proxy_use proxy;

  if(is_connect)
    proxy = HEADER_CONNECT;
  else
    proxy = data->conn->bits.httpproxy && !data->conn->bits.tunnel_proxy ?
      HEADER_PROXY : HEADER_SERVER;

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
      CURLcode result = CURLE_OK;
      bool blankheader = FALSE;
      struct Curl_str name;
      const char *p = headers->data;
      const char *origp = p;

      /* explicitly asked to send header without content is done by a header
         that ends with a semicolon, but there must be no colon present in the
         name */
      if(!curlx_str_until(&p, &name, MAX_HTTP_RESP_HEADER_SIZE, ';') &&
         !curlx_str_single(&p, ';') &&
         !curlx_str_single(&p, '\0') &&
         !memchr(curlx_str(&name), ':', curlx_strlen(&name)))
        blankheader = TRUE;
      else {
        p = origp;
        if(!curlx_str_until(&p, &name, MAX_HTTP_RESP_HEADER_SIZE, ':') &&
           !curlx_str_single(&p, ':')) {
          struct Curl_str val;
          curlx_str_untilnl(&p, &val, MAX_HTTP_RESP_HEADER_SIZE);
          curlx_str_trimblanks(&val);
          if(!curlx_strlen(&val))
            /* no content, don't send this */
            continue;
        }
        else
          /* no colon */
          continue;
      }

      /* only send this if the contents was non-blank or done special */

      if(data->state.aptr.host &&
         /* a Host: header was sent already, do not pass on any custom
            Host: header as that will produce *two* in the same
            request! */
         curlx_str_casecompare(&name, "Host"))
        ;
      else if(data->state.httpreq == HTTPREQ_POST_FORM &&
              /* this header (extended by formdata.c) is sent later */
              curlx_str_casecompare(&name, "Content-Type"))
        ;
      else if(data->state.httpreq == HTTPREQ_POST_MIME &&
              /* this header is sent later */
              curlx_str_casecompare(&name, "Content-Type"))
        ;
      else if(data->req.authneg &&
              /* while doing auth neg, do not allow the custom length since
                 we will force length zero then */
              curlx_str_casecompare(&name, "Content-Length"))
        ;
      else if(curlx_str_casecompare(&name, "Connection"))
        /* Normal Connection: header generation takes care of this */
        ;
      else if((httpversion >= 20) &&
              curlx_str_casecompare(&name, "Transfer-Encoding"))
        /* HTTP/2 does not support chunked requests */
        ;
      else if((curlx_str_casecompare(&name, "Authorization") ||
               curlx_str_casecompare(&name, "Cookie")) &&
              /* be careful of sending this potentially sensitive header to
                 other hosts */
              !Curl_auth_allowed_to_host(data))
        ;
      else if(blankheader)
        result = curlx_dyn_addf(req, "%.*s:\r\n", (int)curlx_strlen(&name),
                                curlx_str(&name));
      else
        result = curlx_dyn_addf(req, "%s\r\n", origp);

      if(result)
        return result;
    }
  }

  return CURLE_OK;
}

#ifndef CURL_DISABLE_PARSEDATE
CURLcode Curl_add_timecondition(struct Curl_easy *data,
                                struct dynbuf *req)
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
    DEBUGF(infof(data, "invalid time condition"));
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
            Curl_wkday[tm->tm_wday ? tm->tm_wday-1 : 6],
            tm->tm_mday,
            Curl_month[tm->tm_mon],
            tm->tm_year + 1900,
            tm->tm_hour,
            tm->tm_min,
            tm->tm_sec);

  result = curlx_dyn_add(req, datestr);
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

void Curl_http_method(struct Curl_easy *data,
                      const char **method, Curl_HttpReq *reqp)
{
  Curl_HttpReq httpreq = (Curl_HttpReq)data->state.httpreq;
  const char *request;
  if(data->conn->handler->protocol&(CURLPROTO_WS|CURLPROTO_WSS))
    httpreq = HTTPREQ_GET;
  else if((data->conn->handler->protocol&(PROTO_FAMILY_HTTP|CURLPROTO_FTP)) &&
     data->state.upload)
    httpreq = HTTPREQ_PUT;

  /* Now set the 'request' pointer to the proper request string */
  if(data->set.str[STRING_CUSTOMREQUEST] &&
     !data->state.http_ignorecustom) {
    request = data->set.str[STRING_CUSTOMREQUEST];
  }
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

static CURLcode http_useragent(struct Curl_easy *data)
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


static CURLcode http_set_aptr_host(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;
  struct dynamically_allocated_data *aptr = &data->state.aptr;
  const char *ptr;

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
             curl_strequal(data->state.first_host, conn->host.name))) {
#ifndef CURL_DISABLE_COOKIES
    /* If we have a given custom Host: header, we extract the hostname in
       order to possibly use it for cookie reasons later on. We only allow the
       custom Host: header if this is NOT a redirect, as setting Host: in the
       redirected request is being out on thin ice. Except if the hostname
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
      free(aptr->cookiehost);
      aptr->cookiehost = cookiehost;
    }
#endif

    if(!curl_strequal("Host:", ptr)) {
      aptr->host = aprintf("Host:%s\r\n", &ptr[5]);
      if(!aptr->host)
        return CURLE_OUT_OF_MEMORY;
    }
  }
  else {
    /* When building Host: headers, we must put the hostname within
       [brackets] if the hostname is a plain IPv6-address. RFC2732-style. */
    const char *host = conn->host.name;

    if(((conn->given->protocol&(CURLPROTO_HTTPS|CURLPROTO_WSS)) &&
        (conn->remote_port == PORT_HTTPS)) ||
       ((conn->given->protocol&(CURLPROTO_HTTP|CURLPROTO_WS)) &&
        (conn->remote_port == PORT_HTTP)) )
      /* if(HTTPS on port 443) OR (HTTP on port 80) then do not include
         the port number in the host string */
      aptr->host = aprintf("Host: %s%s%s\r\n", conn->bits.ipv6_ip ? "[" : "",
                           host, conn->bits.ipv6_ip ? "]" : "");
    else
      aptr->host = aprintf("Host: %s%s%s:%d\r\n",
                           conn->bits.ipv6_ip ? "[" : "",
                           host, conn->bits.ipv6_ip ? "]" : "",
                           conn->remote_port);

    if(!aptr->host)
      /* without Host: we cannot make a nice request */
      return CURLE_OUT_OF_MEMORY;
  }
  return CURLE_OK;
}

/*
 * Append the request-target to the HTTP request
 */
static CURLcode http_target(struct Curl_easy *data,
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
  if(data->conn->bits.httpproxy && !data->conn->bits.tunnel_proxy) {
    /* Using a proxy but does not tunnel through it */

    /* The path sent to the proxy is in fact the entire URL. But if the remote
       host is a IDN-name, we must make sure that the request we produce only
       uses the encoded hostname! */

    /* and no fragment part */
    CURLUcode uc;
    char *url;
    CURLU *h = curl_url_dup(data->state.uh);
    if(!h)
      return CURLE_OUT_OF_MEMORY;

    if(data->conn->host.dispname != data->conn->host.name) {
      uc = curl_url_set(h, CURLUPART_HOST, data->conn->host.name, 0);
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

    if(curl_strequal("http", data->state.up.scheme)) {
      /* when getting HTTP, we do not want the userinfo the URL */
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
    /* Extract the URL to use in the request. */
    uc = curl_url_get(h, CURLUPART_URL, &url, CURLU_NO_DEFAULT_PORT);
    if(uc) {
      curl_url_cleanup(h);
      return CURLE_OUT_OF_MEMORY;
    }

    curl_url_cleanup(h);

    /* target or URL */
    result = curlx_dyn_add(r, data->set.str[STRING_TARGET] ?
      data->set.str[STRING_TARGET] : url);
    free(url);
    if(result)
      return result;

    if(curl_strequal("ftp", data->state.up.scheme)) {
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
          result = curlx_dyn_addf(r, ";type=%c",
                                  data->state.prefer_ascii ? 'a' : 'i');
          if(result)
            return result;
        }
      }
    }
  }

  else
#endif
  {
    result = curlx_dyn_add(r, path);
    if(result)
      return result;
    if(query)
      result = curlx_dyn_addf(r, "?%s", query);
  }

  return result;
}

#if !defined(CURL_DISABLE_MIME) || !defined(CURL_DISABLE_FORM_API)
static CURLcode set_post_reader(struct Curl_easy *data, Curl_HttpReq httpreq)
{
  CURLcode result;

  switch(httpreq) {
#ifndef CURL_DISABLE_MIME
  case HTTPREQ_POST_MIME:
    data->state.mimepost = &data->set.mimepost;
    break;
#endif
#ifndef CURL_DISABLE_FORM_API
  case HTTPREQ_POST_FORM:
    /* Convert the form structure into a mime structure, then keep
       the conversion */
    if(!data->state.formp) {
      data->state.formp = calloc(1, sizeof(curl_mimepart));
      if(!data->state.formp)
        return CURLE_OUT_OF_MEMORY;
      Curl_mime_cleanpart(data->state.formp);
      result = Curl_getformdata(data, data->state.formp, data->set.httppost,
                                data->state.fread_func);
      if(result) {
        Curl_safefree(data->state.formp);
        return result;
      }
      data->state.mimepost = data->state.formp;
    }
    break;
#endif
  default:
    data->state.mimepost = NULL;
    break;
  }

  switch(httpreq) {
  case HTTPREQ_POST_FORM:
  case HTTPREQ_POST_MIME:
    /* This is form posting using mime data. */
#ifndef CURL_DISABLE_MIME
    if(data->state.mimepost) {
      const char *cthdr = Curl_checkheaders(data, STRCONST("Content-Type"));

      /* Read and seek body only. */
      data->state.mimepost->flags |= MIME_BODY_ONLY;

      /* Prepare the mime structure headers & set content type. */

      if(cthdr)
        for(cthdr += 13; *cthdr == ' '; cthdr++)
          ;
      else if(data->state.mimepost->kind == MIMEKIND_MULTIPART)
        cthdr = "multipart/form-data";

      curl_mime_headers(data->state.mimepost, data->set.headers, 0);
      result = Curl_mime_prepare_headers(data, data->state.mimepost, cthdr,
                                         NULL, MIMESTRATEGY_FORM);
      if(result)
        return result;
      curl_mime_headers(data->state.mimepost, NULL, 0);
      result = Curl_creader_set_mime(data, data->state.mimepost);
      if(result)
        return result;
    }
    else
#endif
    {
      result = Curl_creader_set_null(data);
    }
    data->state.infilesize = Curl_creader_total_length(data);
    return result;

  default:
    return Curl_creader_set_null(data);
  }
  /* never reached */
}
#endif

static CURLcode set_reader(struct Curl_easy *data, Curl_HttpReq httpreq)
{
  CURLcode result = CURLE_OK;
  curl_off_t postsize = data->state.infilesize;

  DEBUGASSERT(data->conn);

  if(data->req.authneg) {
    return Curl_creader_set_null(data);
  }

  switch(httpreq) {
  case HTTPREQ_PUT: /* Let's PUT the data to the server! */
    return postsize ? Curl_creader_set_fread(data, postsize) :
      Curl_creader_set_null(data);

#if !defined(CURL_DISABLE_MIME) || !defined(CURL_DISABLE_FORM_API)
  case HTTPREQ_POST_FORM:
  case HTTPREQ_POST_MIME:
    return set_post_reader(data, httpreq);
#endif

  case HTTPREQ_POST:
    /* this is the simple POST, using x-www-form-urlencoded style */
    /* the size of the post body */
    if(!postsize) {
      result = Curl_creader_set_null(data);
    }
    else if(data->set.postfields) {
      if(postsize > 0)
        result = Curl_creader_set_buf(data, data->set.postfields,
                                      (size_t)postsize);
      else
        result = Curl_creader_set_null(data);
    }
    else {
      /* we read the bytes from the callback. In case "chunked" encoding
       * is forced by the application, we disregard `postsize`. This is
       * a backward compatibility decision to earlier versions where
       * chunking disregarded this. See issue #13229. */
      bool chunked = FALSE;
      char *ptr = Curl_checkheaders(data, STRCONST("Transfer-Encoding"));
      if(ptr) {
        /* Some kind of TE is requested, check if 'chunked' is chosen */
        chunked = Curl_compareheader(ptr, STRCONST("Transfer-Encoding:"),
                                     STRCONST("chunked"));
      }
      result = Curl_creader_set_fread(data, chunked ? -1 : postsize);
    }
    return result;

  default:
    /* HTTP GET/HEAD download, has no body, needs no Content-Length */
    data->state.infilesize = 0;
    return Curl_creader_set_null(data);
  }
  /* not reached */
}

static CURLcode http_resume(struct Curl_easy *data, Curl_HttpReq httpreq)
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
       * We do not support this now. Bail out!
       */
      data->state.resume_from = 0;
    }

    if(data->state.resume_from && !data->req.authneg) {
      /* only act on the first request */
      CURLcode result;
      result = Curl_creader_resume_from(data, data->state.resume_from);
      if(result) {
        failf(data, "Unable to resume from offset %" FMT_OFF_T,
              data->state.resume_from);
        return result;
      }
    }
  }
  return CURLE_OK;
}

static CURLcode http_req_set_TE(struct Curl_easy *data,
                                struct dynbuf *req,
                                int httpversion)
{
  CURLcode result = CURLE_OK;
  const char *ptr;

  ptr = Curl_checkheaders(data, STRCONST("Transfer-Encoding"));
  if(ptr) {
    /* Some kind of TE is requested, check if 'chunked' is chosen */
    data->req.upload_chunky =
      Curl_compareheader(ptr,
                         STRCONST("Transfer-Encoding:"), STRCONST("chunked"));
    if(data->req.upload_chunky && (httpversion >= 20)) {
      infof(data, "suppressing chunked transfer encoding on connection "
            "using HTTP version 2 or higher");
      data->req.upload_chunky = FALSE;
    }
  }
  else {
    curl_off_t req_clen = Curl_creader_total_length(data);

    if(req_clen < 0) {
      /* indeterminate request content length */
      if(httpversion > 10) {
        /* On HTTP/1.1, enable chunked, on HTTP/2 and later we do not
         * need it */
        data->req.upload_chunky = (httpversion < 20);
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
      result = curlx_dyn_add(req, "Transfer-Encoding: chunked\r\n");
  }
  return result;
}

static CURLcode addexpect(struct Curl_easy *data, struct dynbuf *r,
                          int httpversion, bool *announced_exp100)
{
  CURLcode result;
  char *ptr;

  *announced_exp100 = FALSE;
  /* Avoid Expect: 100-continue if Upgrade: is used */
  if(data->req.upgr101 != UPGR101_INIT)
    return CURLE_OK;

  /* For really small puts we do not use Expect: headers at all, and for
     the somewhat bigger ones we allow the app to disable it. Just make
     sure that the expect100header is always set to the preferred value
     here. */
  ptr = Curl_checkheaders(data, STRCONST("Expect"));
  if(ptr) {
    *announced_exp100 =
      Curl_compareheader(ptr, STRCONST("Expect:"), STRCONST("100-continue"));
  }
  else if(!data->state.disableexpect && (httpversion == 11)) {
    /* if not doing HTTP 1.0 or version 2, or disabled explicitly, we add an
       Expect: 100-continue to the headers which actually speeds up post
       operations (as there is one packet coming back from the web server) */
    curl_off_t client_len = Curl_creader_client_length(data);
    if(client_len > EXPECT_100_THRESHOLD || client_len < 0) {
      result = curlx_dyn_addn(r, STRCONST("Expect: 100-continue\r\n"));
      if(result)
        return result;
      *announced_exp100 = TRUE;
    }
  }
  return CURLE_OK;
}

static CURLcode http_add_content_hds(struct Curl_easy *data,
                                     struct dynbuf *r,
                                     int httpversion,
                                     Curl_HttpReq httpreq)
{
  CURLcode result = CURLE_OK;
  curl_off_t req_clen;
  bool announced_exp100 = FALSE;

  DEBUGASSERT(data->conn);
  if(data->req.upload_chunky) {
    result = Curl_httpchunk_add_reader(data);
    if(result)
      return result;
  }

  /* Get the request body length that has been set up */
  req_clen = Curl_creader_total_length(data);
  switch(httpreq) {
  case HTTPREQ_PUT:
  case HTTPREQ_POST:
#if !defined(CURL_DISABLE_MIME) || !defined(CURL_DISABLE_FORM_API)
  case HTTPREQ_POST_FORM:
  case HTTPREQ_POST_MIME:
#endif
    /* We only set Content-Length and allow a custom Content-Length if
       we do not upload data chunked, as RFC2616 forbids us to set both
       kinds of headers (Transfer-Encoding: chunked and Content-Length).
       We do not override a custom "Content-Length" header, but during
       authentication negotiation that header is suppressed.
     */
    if(req_clen >= 0 && !data->req.upload_chunky &&
       (data->req.authneg ||
        !Curl_checkheaders(data, STRCONST("Content-Length")))) {
      /* we allow replacing this header if not during auth negotiation,
         although it is not very wise to actually set your own */
      result = curlx_dyn_addf(r, "Content-Length: %" FMT_OFF_T "\r\n",
                              req_clen);
    }
    if(result)
      goto out;

#ifndef CURL_DISABLE_MIME
    /* Output mime-generated headers. */
    if(data->state.mimepost &&
       ((httpreq == HTTPREQ_POST_FORM) || (httpreq == HTTPREQ_POST_MIME))) {
      struct curl_slist *hdr;

      for(hdr = data->state.mimepost->curlheaders; hdr; hdr = hdr->next) {
        result = curlx_dyn_addf(r, "%s\r\n", hdr->data);
        if(result)
          goto out;
      }
    }
#endif
    if(httpreq == HTTPREQ_POST) {
      if(!Curl_checkheaders(data, STRCONST("Content-Type"))) {
        result = curlx_dyn_addn(r, STRCONST("Content-Type: application/"
                                            "x-www-form-urlencoded\r\n"));
        if(result)
          goto out;
      }
    }
    result = addexpect(data, r, httpversion, &announced_exp100);
    if(result)
      goto out;
    break;
  default:
    break;
  }

  Curl_pgrsSetUploadSize(data, req_clen);
  if(announced_exp100)
    result = http_exp100_add_reader(data);

out:
  return result;
}

#ifndef CURL_DISABLE_COOKIES

static CURLcode http_cookies(struct Curl_easy *data,
                             struct dynbuf *r)
{
  CURLcode result = CURLE_OK;
  char *addcookies = NULL;
  bool linecap = FALSE;
  if(data->set.str[STRING_COOKIE] &&
     !Curl_checkheaders(data, STRCONST("Cookie")))
    addcookies = data->set.str[STRING_COOKIE];

  if(data->cookies || addcookies) {
    struct Curl_llist list;
    int count = 0;

    if(data->cookies && data->state.cookie_engine) {
      const char *host = data->state.aptr.cookiehost ?
        data->state.aptr.cookiehost : data->conn->host.name;
      Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
      if(!Curl_cookie_getlist(data, data->conn, host, &list)) {
        struct Curl_llist_node *n;
        size_t clen = 8; /* hold the size of the generated Cookie: header */

        /* loop through all cookies that matched */
        for(n = Curl_llist_head(&list); n; n = Curl_node_next(n)) {
          struct Cookie *co = Curl_node_elem(n);
          if(co->value) {
            size_t add;
            if(!count) {
              result = curlx_dyn_addn(r, STRCONST("Cookie: "));
              if(result)
                break;
            }
            add = strlen(co->name) + strlen(co->value) + 1;
            if(clen + add >= MAX_COOKIE_HEADER_LEN) {
              infof(data, "Restricted outgoing cookies due to header size, "
                    "'%s' not sent", co->name);
              linecap = TRUE;
              break;
            }
            result = curlx_dyn_addf(r, "%s%s=%s", count ? "; " : "",
                                    co->name, co->value);
            if(result)
              break;
            clen += add + (count ? 2 : 0);
            count++;
          }
        }
        Curl_llist_destroy(&list, NULL);
      }
      Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
    }
    if(addcookies && !result && !linecap) {
      if(!count)
        result = curlx_dyn_addn(r, STRCONST("Cookie: "));
      if(!result) {
        result = curlx_dyn_addf(r, "%s%s", count ? "; " : "", addcookies);
        count++;
      }
    }
    if(count && !result)
      result = curlx_dyn_addn(r, STRCONST("\r\n"));

    if(result)
      return result;
  }
  return result;
}
#else
#define http_cookies(a,b) CURLE_OK
#endif

static CURLcode http_range(struct Curl_easy *data,
                           Curl_HttpReq httpreq)
{
  if(data->state.use_range) {
    /*
     * A range is selected. We use different headers whether we are downloading
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
      curl_off_t req_clen = Curl_creader_total_length(data);
      /* if a line like this was already allocated, free the previous one */
      free(data->state.aptr.rangeline);

      if(data->set.set_resume_from < 0) {
        /* Upload resume was asked for, but we do not know the size of the
           remote part so we tell the server (and act accordingly) that we
           upload the whole file (again) */
        data->state.aptr.rangeline =
          aprintf("Content-Range: bytes 0-%" FMT_OFF_T "/%" FMT_OFF_T "\r\n",
                  req_clen - 1, req_clen);

      }
      else if(data->state.resume_from) {
        /* This is because "resume" was selected */
        /* Not sure if we want to send this header during authentication
         * negotiation, but test1084 checks for it. In which case we have a
         * "null" client reader installed that gives an unexpected length. */
        curl_off_t total_len = data->req.authneg ?
                               data->state.infilesize :
                               (data->state.resume_from + req_clen);
        data->state.aptr.rangeline =
          aprintf("Content-Range: bytes %s%" FMT_OFF_T "/%" FMT_OFF_T "\r\n",
                  data->state.range, total_len-1, total_len);
      }
      else {
        /* Range was selected and then we just pass the incoming range and
           append total size */
        data->state.aptr.rangeline =
          aprintf("Content-Range: bytes %s/%" FMT_OFF_T "\r\n",
                  data->state.range, req_clen);
      }
      if(!data->state.aptr.rangeline)
        return CURLE_OUT_OF_MEMORY;
    }
  }
  return CURLE_OK;
}

static CURLcode http_firstwrite(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;
  struct SingleRequest *k = &data->req;

  if(data->req.newurl) {
    if(conn->bits.close) {
      /* Abort after the headers if "follow Location" is set
         and we are set to close anyway. */
      k->keepon &= ~KEEP_RECV;
      k->done = TRUE;
      return CURLE_OK;
    }
    /* We have a new URL to load, but since we want to be able to reuse this
       connection properly, we read the full response in "ignore more" */
    k->ignorebody = TRUE;
    infof(data, "Ignoring the response-body");
  }
  if(data->state.resume_from && !k->content_range &&
     (data->state.httpreq == HTTPREQ_GET) &&
     !k->ignorebody) {

    if(k->size == data->state.resume_from) {
      /* The resume point is at the end of file, consider this fine even if it
         does not allow resume from here. */
      infof(data, "The entire document is already downloaded");
      streamclose(conn, "already downloaded");
      /* Abort download */
      k->keepon &= ~KEEP_RECV;
      k->done = TRUE;
      return CURLE_OK;
    }

    /* we wanted to resume a download, although the server does not seem to
     * support this and we did this with a GET (if it was not a GET we did a
     * POST or PUT resume) */
    failf(data, "HTTP server does not seem to support "
          "byte ranges. Cannot resume.");
    return CURLE_RANGE_ERROR;
  }

  if(data->set.timecondition && !data->state.range) {
    /* A time condition has been set AND no ranges have been requested. This
       seems to be what chapter 13.3.4 of RFC 2616 defines to be the correct
       action for an HTTP/1.1 client */

    if(!Curl_meets_timecondition(data, k->timeofdoc)) {
      k->done = TRUE;
      /* We are simulating an HTTP 304 from server so we return
         what should have been returned from the server */
      data->info.httpcode = 304;
      infof(data, "Simulate an HTTP 304 response");
      /* we abort the transfer before it is completed == we ruin the
         reuse ability. Close the connection */
      streamclose(conn, "Simulated 304 handling");
      return CURLE_OK;
    }
  } /* we have a time condition */

  return CURLE_OK;
}

static CURLcode http_check_new_conn(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;
  const char *info_version = NULL;
  const char *alpn;
  CURLcode result;

  alpn = Curl_conn_get_alpn_negotiated(data, conn);
  if(alpn && !strcmp("h3", alpn)) {
    DEBUGASSERT(Curl_conn_http_version(data, conn) == 30);
    info_version = "HTTP/3";
  }
  else if(alpn && !strcmp("h2", alpn)) {
#ifndef CURL_DISABLE_PROXY
    if((Curl_conn_http_version(data, conn) != 20) &&
       conn->bits.proxy && !conn->bits.tunnel_proxy) {
      result = Curl_http2_switch(data);
      if(result)
        return result;
    }
    else
#endif
    DEBUGASSERT(Curl_conn_http_version(data, conn) == 20);
    info_version = "HTTP/2";
  }
  else {
    /* Check if user wants to use HTTP/2 with clear TCP */
    if(Curl_http2_may_switch(data)) {
      DEBUGF(infof(data, "HTTP/2 over clean TCP"));
      result = Curl_http2_switch(data);
      if(result)
        return result;
      info_version = "HTTP/2";
      /* There is no ALPN here, but the connection is now definitely h2 */
      conn->httpversion_seen = 20;
    }
    else
      info_version = "HTTP/1.x";
  }

  if(info_version)
    infof(data, "using %s", info_version);
  return CURLE_OK;
}

static CURLcode http_add_connection_hd(struct Curl_easy *data,
                                       struct dynbuf *req)
{
  char *custom = Curl_checkheaders(data, STRCONST("Connection"));
  char *custom_val = custom ? Curl_copy_header_value(custom) : NULL;
  const char *sep = (custom_val && *custom_val) ? ", " : "Connection: ";
  CURLcode result = CURLE_OK;
  size_t rlen = curlx_dyn_len(req);

  if(custom && !custom_val)
    return CURLE_OUT_OF_MEMORY;

  if(custom_val && *custom_val)
    result = curlx_dyn_addf(req, "Connection: %s", custom_val);
  if(!result && data->state.http_hd_te) {
    result = curlx_dyn_addf(req, "%s%s", sep, "TE");
    sep = ", ";
  }
  if(!result && data->state.http_hd_upgrade) {
    result = curlx_dyn_addf(req, "%s%s", sep, "Upgrade");
    sep = ", ";
  }
  if(!result && data->state.http_hd_h2_settings) {
    result = curlx_dyn_addf(req, "%s%s", sep, "HTTP2-Settings");
  }
  if(!result && (rlen < curlx_dyn_len(req)))
    result = curlx_dyn_addn(req, STRCONST("\r\n"));

  free(custom_val);
  return result;
}

/* Header identifier in order we send them by default */
typedef enum {
  H1_HD_REQUEST,
  H1_HD_HOST,
#ifndef CURL_DISABLE_PROXY
  H1_HD_PROXY_AUTH,
#endif
  H1_HD_USER_AUTH,
  H1_HD_RANGE,
  H1_HD_USER_AGENT,
  H1_HD_ACCEPT,
  H1_HD_TE,
  H1_HD_ACCEPT_ENCODING,
  H1_HD_REFERER,
#ifndef CURL_DISABLE_PROXY
  H1_HD_PROXY_CONNECTION,
#endif
  H1_HD_TRANSFER_ENCODING,
#ifndef CURL_DISABLE_ALTSVC
  H1_HD_ALT_USED,
#endif
  H1_HD_UPGRADE,
  H1_HD_COOKIES,
  H1_HD_CONDITIONALS,
  H1_HD_CUSTOM,
  H1_HD_CONTENT,
  H1_HD_CONNECTION,
  H1_HD_LAST  /* the last, empty header line */
} http_hd_t;

static CURLcode http_add_hd(struct Curl_easy *data,
                            struct dynbuf *req,
                            http_hd_t id,
                            unsigned char httpversion,
                            const char *method,
                            Curl_HttpReq httpreq)
{
  CURLcode result = CURLE_OK;
  switch(id) {
  case H1_HD_REQUEST:
    /* add the main request stuff */
    /* GET/HEAD/POST/PUT */
    result = curlx_dyn_addf(req, "%s ", method);
    if(!result)
      result = http_target(data, req);
    if(!result)
      result = curlx_dyn_addf(req, " HTTP/%s\r\n",
                              get_http_string(httpversion));
    break;

  case H1_HD_HOST:
    if(data->state.aptr.host)
      result = curlx_dyn_add(req, data->state.aptr.host);
    break;

#ifndef CURL_DISABLE_PROXY
  case H1_HD_PROXY_AUTH:
    if(data->state.aptr.proxyuserpwd)
      result = curlx_dyn_add(req, data->state.aptr.proxyuserpwd);
    break;
#endif

  case H1_HD_USER_AUTH:
    if(data->state.aptr.userpwd)
      result = curlx_dyn_add(req, data->state.aptr.userpwd);
    break;

  case H1_HD_RANGE:
    if(data->state.use_range && data->state.aptr.rangeline)
      result = curlx_dyn_add(req, data->state.aptr.rangeline);
    break;

  case H1_HD_USER_AGENT:
    if(data->set.str[STRING_USERAGENT] && /* User-Agent: */
       *data->set.str[STRING_USERAGENT] &&
       data->state.aptr.uagent)
      result = curlx_dyn_add(req, data->state.aptr.uagent);
    break;

  case H1_HD_ACCEPT:
    if(!Curl_checkheaders(data, STRCONST("Accept")))
      result = curlx_dyn_add(req, "Accept: */*\r\n");
    break;

  case H1_HD_TE:
#ifdef HAVE_LIBZ
    if(!Curl_checkheaders(data, STRCONST("TE")) &&
       data->set.http_transfer_encoding) {
      data->state.http_hd_te = TRUE;
      result = curlx_dyn_add(req, "TE: gzip\r\n");
    }
#endif
    break;

  case H1_HD_ACCEPT_ENCODING:
    Curl_safefree(data->state.aptr.accept_encoding);
    if(!Curl_checkheaders(data, STRCONST("Accept-Encoding")) &&
       data->set.str[STRING_ENCODING])
      result = curlx_dyn_addf(req, "Accept-Encoding: %s\r\n",
                              data->set.str[STRING_ENCODING]);
    break;

  case H1_HD_REFERER:
    Curl_safefree(data->state.aptr.ref);
    if(data->state.referer && !Curl_checkheaders(data, STRCONST("Referer")))
      result = curlx_dyn_addf(req, "Referer: %s\r\n", data->state.referer);
    break;

#ifndef CURL_DISABLE_PROXY
  case H1_HD_PROXY_CONNECTION:
    if(data->conn->bits.httpproxy &&
       !data->conn->bits.tunnel_proxy &&
       !Curl_checkheaders(data, STRCONST("Proxy-Connection")) &&
       !Curl_checkProxyheaders(data, data->conn, STRCONST("Proxy-Connection")))
      result = curlx_dyn_add(req, "Proxy-Connection: Keep-Alive\r\n");
    break;
#endif

  case H1_HD_TRANSFER_ENCODING:
    result = http_req_set_TE(data, req, httpversion);
    break;

#ifndef CURL_DISABLE_ALTSVC
  case H1_HD_ALT_USED:
    if(data->conn->bits.altused &&
       !Curl_checkheaders(data, STRCONST("Alt-Used")))
      result = curlx_dyn_addf(req, "Alt-Used: %s:%d\r\n",
                              data->conn->conn_to_host.name,
                              data->conn->conn_to_port);
    break;
#endif

  case H1_HD_UPGRADE:
    if(!Curl_conn_is_ssl(data->conn, FIRSTSOCKET) && (httpversion < 20) &&
       (data->state.http_neg.wanted & CURL_HTTP_V2x) &&
       data->state.http_neg.h2_upgrade) {
      /* append HTTP2 upgrade magic stuff to the HTTP request if it is not done
         over SSL */
      result = Curl_http2_request_upgrade(req, data);
    }
#ifndef CURL_DISABLE_WEBSOCKETS
    if(!result && data->conn->handler->protocol&(CURLPROTO_WS|CURLPROTO_WSS))
      result = Curl_ws_request(data, req);
#endif
    break;

  case H1_HD_COOKIES:
    result = http_cookies(data, req);
    break;

  case H1_HD_CONDITIONALS:
    result = Curl_add_timecondition(data, req);
    break;

  case H1_HD_CUSTOM:
    result = Curl_add_custom_headers(data, FALSE, httpversion, req);
    break;

  case H1_HD_CONTENT:
    result = http_add_content_hds(data, req, httpversion, httpreq);
    break;

  case H1_HD_CONNECTION: {
    result = http_add_connection_hd(data, req);
    break;
  }

  case H1_HD_LAST:
    result = curlx_dyn_addn(req, STRCONST("\r\n"));
    break;
  }
  return result;
}

/*
 * Curl_http() gets called from the generic multi_do() function when an HTTP
 * request is to be performed. This creates and sends a properly constructed
 * HTTP request.
 */
CURLcode Curl_http(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  Curl_HttpReq httpreq;
  const char *method;
  struct dynbuf req;
  unsigned char httpversion;
  size_t hd_id;

  /* Always consider the DO phase done after this function call, even if there
     may be parts of the request that are not yet sent, since we can deal with
     the rest of the request in the PERFORM phase. */
  *done = TRUE;
  /* initialize a dynamic send-buffer */
  curlx_dyn_init(&req, DYN_HTTP_REQUEST);
  /* make sure the header buffer is reset - if there are leftovers from a
     previous transfer */
  curlx_dyn_reset(&data->state.headerb);

  if(!data->conn->bits.reuse) {
    result = http_check_new_conn(data);
    if(result)
      goto out;
  }

  /* Add collecting of headers written to client. For a new connection,
   * we might have done that already, but reuse
   * or multiplex needs it here as well. */
  result = Curl_headers_init(data);
  if(result)
    goto out;

  data->state.http_hd_te = FALSE;
  data->state.http_hd_upgrade = FALSE;
  data->state.http_hd_h2_settings = FALSE;

  /* what kind of request do we need to send? */
  Curl_http_method(data, &method, &httpreq);

  /* select host to send */
  result = http_set_aptr_host(data);
  if(!result) {
    /* setup the authentication headers, how that method and host are known */
    char *pq = NULL;
    if(data->state.up.query) {
      pq = aprintf("%s?%s", data->state.up.path, data->state.up.query);
      if(!pq)
        return CURLE_OUT_OF_MEMORY;
    }
    result = Curl_http_output_auth(data, data->conn, method, httpreq,
                                   (pq ? pq : data->state.up.path), FALSE);
    free(pq);
  }
  if(result)
    goto out;

  result = http_useragent(data);
  if(result)
    goto out;

  /* Setup input reader, resume information and ranges */
  result = set_reader(data, httpreq);
  if(!result)
    result = http_resume(data, httpreq);
  if(!result)
    result = http_range(data, httpreq);
  if(result)
    goto out;

  httpversion = http_request_version(data);
  /* Add request line and all headers to `req` */
  for(hd_id = 0; hd_id <= H1_HD_LAST; ++hd_id) {
    result = http_add_hd(data, &req, (http_hd_t)hd_id,
                         httpversion, method, httpreq);
    if(result)
      goto out;
  }

  /* setup variables for the upcoming transfer and send */
  Curl_xfer_setup_sendrecv(data, FIRSTSOCKET, -1);
  result = Curl_req_send(data, &req, httpversion);

  if((httpversion >= 20) && data->req.upload_chunky)
    /* upload_chunky was set above to set up the request in a chunky fashion,
       but is disabled here again to avoid that the chunked encoded version is
       actually used when sending the request body over h2 */
    data->req.upload_chunky = FALSE;

out:
  if(CURLE_TOO_LARGE == result)
    failf(data, "HTTP request too large");

  /* clear userpwd and proxyuserpwd to avoid reusing old credentials
   * from reused connections */
  Curl_safefree(data->state.aptr.userpwd);
#ifndef CURL_DISABLE_PROXY
  Curl_safefree(data->state.aptr.proxyuserpwd);
#endif
  curlx_dyn_free(&req);
  return result;
}

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
  statusline onmatch = len >= 5 ? STATUS_DONE : STATUS_UNKNOWN;

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
  statusline onmatch = len >= 5 ? STATUS_DONE : STATUS_UNKNOWN;
  (void)data;
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

/* HTTP header has field name `n` (a string constant) */
#define HD_IS(hd, hdlen, n) \
  (((hdlen) >= (sizeof(n)-1)) && curl_strnequal((n), (hd), (sizeof(n)-1)))

#define HD_VAL(hd, hdlen, n) \
  ((((hdlen) >= (sizeof(n)-1)) && \
    curl_strnequal((n), (hd), (sizeof(n)-1)))? (hd + (sizeof(n)-1)) : NULL)

/* HTTP header has field name `n` (a string constant) and contains `v`
 * (a string constant) in its value(s) */
#define HD_IS_AND_SAYS(hd, hdlen, n, v) \
  (HD_IS(hd, hdlen, n) && \
   ((hdlen) > ((sizeof(n)-1) + (sizeof(v)-1))) && \
   Curl_compareheader(hd, STRCONST(n), STRCONST(v)))

/*
 * http_header_a() parses a single response header starting with A.
 */
static CURLcode http_header_a(struct Curl_easy *data,
                              const char *hd, size_t hdlen)
{
#ifndef CURL_DISABLE_ALTSVC
  const char *v;
  struct connectdata *conn = data->conn;
  v = (data->asi &&
       (Curl_conn_is_ssl(data->conn, FIRSTSOCKET) ||
#ifdef DEBUGBUILD
        /* allow debug builds to circumvent the HTTPS restriction */
        getenv("CURL_ALTSVC_HTTP")
#else
        0
#endif
         )) ? HD_VAL(hd, hdlen, "Alt-Svc:") : NULL;
  if(v) {
    /* the ALPN of the current request */
    struct SingleRequest *k = &data->req;
    enum alpnid id = (k->httpversion == 30) ? ALPN_h3 :
      (k->httpversion == 20) ? ALPN_h2 : ALPN_h1;
    return Curl_altsvc_parse(data, data->asi, v, id, conn->host.name,
                             curlx_uitous((unsigned int)conn->remote_port));
  }
#else
  (void)data;
  (void)hd;
  (void)hdlen;
#endif
  return CURLE_OK;
}

/*
 * http_header_c() parses a single response header starting with C.
 */
static CURLcode http_header_c(struct Curl_easy *data,
                              const char *hd, size_t hdlen)
{
  struct connectdata *conn = data->conn;
  struct SingleRequest *k = &data->req;
  const char *v;

  /* Check for Content-Length: header lines to get size */
  v = (!k->http_bodyless && !data->set.ignorecl) ?
    HD_VAL(hd, hdlen, "Content-Length:") : NULL;
  if(v) {
    curl_off_t contentlength;
    int offt = curlx_str_numblanks(&v, &contentlength);

    if(offt == STRE_OK) {
      k->size = contentlength;
      k->maxdownload = k->size;
    }
    else if(offt == STRE_OVERFLOW) {
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
    return CURLE_OK;
  }
  v = (!k->http_bodyless && data->set.str[STRING_ENCODING]) ?
    HD_VAL(hd, hdlen, "Content-Encoding:") : NULL;
  if(v) {
    /*
     * Process Content-Encoding. Look for the values: identity,
     * gzip, deflate, compress, x-gzip and x-compress. x-gzip and
     * x-compress are the same as gzip and compress. (Sec 3.5 RFC
     * 2616). zlib cannot handle compress. However, errors are
     * handled further down when the response body is processed
     */
    return Curl_build_unencoding_stack(data, v, FALSE);
  }
  /* check for Content-Type: header lines to get the MIME-type */
  v = HD_VAL(hd, hdlen, "Content-Type:");
  if(v) {
    char *contenttype = Curl_copy_header_value(hd);
    if(!contenttype)
      return CURLE_OUT_OF_MEMORY;
    if(!*contenttype)
      /* ignore empty data */
      free(contenttype);
    else {
      free(data->info.contenttype);
      data->info.contenttype = contenttype;
    }
    return CURLE_OK;
  }
  if(HD_IS_AND_SAYS(hd, hdlen, "Connection:", "close")) {
    /*
     * [RFC 2616, section 8.1.2.1]
     * "Connection: close" is HTTP/1.1 language and means that
     * the connection will close when this request has been
     * served.
     */
    streamclose(conn, "Connection: close used");
    return CURLE_OK;
  }
  if((k->httpversion == 10) &&
     HD_IS_AND_SAYS(hd, hdlen, "Connection:", "keep-alive")) {
    /*
     * An HTTP/1.0 reply with the 'Connection: keep-alive' line
     * tells us the connection will be kept alive for our
     * pleasure. Default action for 1.0 is to close.
     *
     * [RFC2068, section 19.7.1] */
    connkeep(conn, "Connection keep-alive");
    infof(data, "HTTP/1.0 connection set to keep alive");
    return CURLE_OK;
  }
  v = !k->http_bodyless ? HD_VAL(hd, hdlen, "Content-Range:") : NULL;
  if(v) {
    /* Content-Range: bytes [num]-
       Content-Range: bytes: [num]-
       Content-Range: [num]-
       Content-Range: [asterisk]/[total]

       The second format was added since Sun's webserver
       JavaWebServer/1.1.1 obviously sends the header this way!
       The third added since some servers use that!
       The fourth means the requested range was unsatisfied.
    */

    const char *ptr = v;

    /* Move forward until first digit or asterisk */
    while(*ptr && !ISDIGIT(*ptr) && *ptr != '*')
      ptr++;

    /* if it truly stopped on a digit */
    if(ISDIGIT(*ptr)) {
      if(!curlx_str_number(&ptr, &k->offset, CURL_OFF_T_MAX) &&
         (data->state.resume_from == k->offset))
        /* we asked for a resume and we got it */
        k->content_range = TRUE;
    }
    else if(k->httpcode < 300)
      data->state.resume_from = 0; /* get everything */
  }
  return CURLE_OK;
}

/*
 * http_header_l() parses a single response header starting with L.
 */
static CURLcode http_header_l(struct Curl_easy *data,
                              const char *hd, size_t hdlen)
{
  struct connectdata *conn = data->conn;
  struct SingleRequest *k = &data->req;
  const char *v = (!k->http_bodyless &&
                   (data->set.timecondition || data->set.get_filetime)) ?
    HD_VAL(hd, hdlen, "Last-Modified:") : NULL;
  if(v) {
    if(Curl_getdate_capped(v, &k->timeofdoc))
      k->timeofdoc = 0;
    if(data->set.get_filetime)
      data->info.filetime = k->timeofdoc;
    return CURLE_OK;
  }
  if((k->httpcode >= 300 && k->httpcode < 400) &&
     HD_IS(hd, hdlen, "Location:") &&
     !data->req.location) {
    /* this is the URL that the server advises us to use instead */
    char *location = Curl_copy_header_value(hd);
    if(!location)
      return CURLE_OUT_OF_MEMORY;
    if(!*location)
      /* ignore empty data */
      free(location);
    else {
      data->req.location = location;

      if(data->set.http_follow_mode) {
        CURLcode result;
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
  return CURLE_OK;
}

/*
 * http_header_p() parses a single response header starting with P.
 */
static CURLcode http_header_p(struct Curl_easy *data,
                              const char *hd, size_t hdlen)
{
  struct SingleRequest *k = &data->req;

#ifndef CURL_DISABLE_PROXY
  const char *v = HD_VAL(hd, hdlen, "Proxy-Connection:");
  if(v) {
    struct connectdata *conn = data->conn;
    if((k->httpversion == 10) && conn->bits.httpproxy &&
       HD_IS_AND_SAYS(hd, hdlen, "Proxy-Connection:", "keep-alive")) {
      /*
       * When an HTTP/1.0 reply comes when using a proxy, the
       * 'Proxy-Connection: keep-alive' line tells us the
       * connection will be kept alive for our pleasure.
       * Default action for 1.0 is to close.
       */
      connkeep(conn, "Proxy-Connection keep-alive"); /* do not close */
      infof(data, "HTTP/1.0 proxy connection set to keep alive");
    }
    else if((k->httpversion == 11) && conn->bits.httpproxy &&
            HD_IS_AND_SAYS(hd, hdlen, "Proxy-Connection:", "close")) {
      /*
       * We get an HTTP/1.1 response from a proxy and it says it will
       * close down after this transfer.
       */
      connclose(conn, "Proxy-Connection: asked to close after done");
      infof(data, "HTTP/1.1 proxy connection set close");
    }
    return CURLE_OK;
  }
#endif
  if((407 == k->httpcode) && HD_IS(hd, hdlen, "Proxy-authenticate:")) {
    char *auth = Curl_copy_header_value(hd);
    CURLcode result;
    if(!auth)
      return CURLE_OUT_OF_MEMORY;
    result = Curl_http_input_auth(data, TRUE, auth);
    free(auth);
    return result;
  }
#ifdef USE_SPNEGO
  if(HD_IS(hd, hdlen, "Persistent-Auth:")) {
    struct connectdata *conn = data->conn;
    struct negotiatedata *negdata = Curl_auth_nego_get(conn, FALSE);
    struct auth *authp = &data->state.authhost;
    if(!negdata)
      return CURLE_OUT_OF_MEMORY;
    if(authp->picked == CURLAUTH_NEGOTIATE) {
      char *persistentauth = Curl_copy_header_value(hd);
      if(!persistentauth)
        return CURLE_OUT_OF_MEMORY;
      negdata->noauthpersist = !!checkprefix("false", persistentauth);
      negdata->havenoauthpersist = TRUE;
      infof(data, "Negotiate: noauthpersist -> %d, header part: %s",
            negdata->noauthpersist, persistentauth);
      free(persistentauth);
    }
  }
#endif
  return CURLE_OK;
}

/*
 * http_header_r() parses a single response header starting with R.
 */
static CURLcode http_header_r(struct Curl_easy *data,
                              const char *hd, size_t hdlen)
{
  const char *v = HD_VAL(hd, hdlen, "Retry-After:");
  if(v) {
    /* Retry-After = HTTP-date / delay-seconds */
    curl_off_t retry_after = 0; /* zero for unknown or "now" */
    time_t date = 0;
    curlx_str_passblanks(&v);

    /* try it as a date first, because a date can otherwise start with and
       get treated as a number */
    if(!Curl_getdate_capped(v, &date)) {
      time_t current = time(NULL);
      if(date >= current)
        /* convert date to number of seconds into the future */
        retry_after = date - current;
    }
    else
      /* Try it as a decimal number, ignore errors */
      (void)curlx_str_number(&v, &retry_after, CURL_OFF_T_MAX);
    /* limit to 6 hours max. this is not documented so that it can be changed
       in the future if necessary. */
    if(retry_after > 21600)
      retry_after = 21600;
    data->info.retry_after = retry_after;
  }
  return CURLE_OK;
}

/*
 * http_header_s() parses a single response header starting with S.
 */
static CURLcode http_header_s(struct Curl_easy *data,
                              const char *hd, size_t hdlen)
{
#if !defined(CURL_DISABLE_COOKIES) || !defined(CURL_DISABLE_HSTS)
  struct connectdata *conn = data->conn;
  const char *v;
#else
  (void)data;
  (void)hd;
  (void)hdlen;
#endif

#ifndef CURL_DISABLE_COOKIES
  v = (data->cookies && data->state.cookie_engine) ?
    HD_VAL(hd, hdlen, "Set-Cookie:") : NULL;
  if(v) {
    /* If there is a custom-set Host: name, use it here, or else use
     * real peer hostname. */
    const char *host = data->state.aptr.cookiehost ?
      data->state.aptr.cookiehost : conn->host.name;
    const bool secure_context = Curl_secure_context(conn, host);
    Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
    Curl_cookie_add(data, data->cookies, TRUE, FALSE, v, host,
                    data->state.up.path, secure_context);
    Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
    return CURLE_OK;
  }
#endif
#ifndef CURL_DISABLE_HSTS
  /* If enabled, the header is incoming and this is over HTTPS */
  v = (data->hsts &&
       (Curl_conn_is_ssl(conn, FIRSTSOCKET) ||
#ifdef DEBUGBUILD
        /* allow debug builds to circumvent the HTTPS restriction */
        getenv("CURL_HSTS_HTTP")
#else
        0
#endif
         )
    ) ? HD_VAL(hd, hdlen, "Strict-Transport-Security:") : NULL;
  if(v) {
    CURLcode check =
      Curl_hsts_parse(data->hsts, conn->host.name, v);
    if(check)
      infof(data, "Illegal STS header skipped");
#ifdef DEBUGBUILD
    else
      infof(data, "Parsed STS header fine (%zu entries)",
            Curl_llist_count(&data->hsts->list));
#endif
  }
#endif

  return CURLE_OK;
}

/*
 * http_header_t() parses a single response header starting with T.
 */
static CURLcode http_header_t(struct Curl_easy *data,
                              const char *hd, size_t hdlen)
{
  struct connectdata *conn = data->conn;
  struct SingleRequest *k = &data->req;

  /* RFC 9112, ch. 6.1
   * "Transfer-Encoding MAY be sent in a response to a HEAD request or
   *  in a 304 (Not Modified) response (Section 15.4.5 of [HTTP]) to a
   *  GET request, neither of which includes a message body, to indicate
   *  that the origin server would have applied a transfer coding to the
   *  message body if the request had been an unconditional GET."
   *
   * Read: in these cases the 'Transfer-Encoding' does not apply
   * to any data following the response headers. Do not add any decoders.
   */
  const char *v = (!k->http_bodyless &&
                   (data->state.httpreq != HTTPREQ_HEAD) &&
                   (k->httpcode != 304)) ?
    HD_VAL(hd, hdlen, "Transfer-Encoding:") : NULL;
  if(v) {
    /* One or more encodings. We check for chunked and/or a compression
       algorithm. */
    CURLcode result = Curl_build_unencoding_stack(data, v, TRUE);
    if(result)
      return result;
    if(!k->chunk && data->set.http_transfer_encoding) {
      /* if this is not chunked, only close can signal the end of this
       * transfer as Content-Length is said not to be trusted for
       * transfer-encoding! */
      connclose(conn, "HTTP/1.1 transfer-encoding without chunks");
      k->ignore_cl = TRUE;
    }
    return CURLE_OK;
  }
  v = HD_VAL(hd, hdlen, "Trailer:");
  if(v) {
    data->req.resp_trailer = TRUE;
    return CURLE_OK;
  }
  return CURLE_OK;
}

/*
 * http_header_w() parses a single response header starting with W.
 */
static CURLcode http_header_w(struct Curl_easy *data,
                              const char *hd, size_t hdlen)
{
  struct SingleRequest *k = &data->req;
  CURLcode result = CURLE_OK;

  if((401 == k->httpcode) && HD_IS(hd, hdlen, "WWW-Authenticate:")) {
    char *auth = Curl_copy_header_value(hd);
    if(!auth)
      return CURLE_OUT_OF_MEMORY;
    result = Curl_http_input_auth(data, FALSE, auth);
    free(auth);
  }
  return result;
}

/*
 * http_header() parses a single response header.
 */
static CURLcode http_header(struct Curl_easy *data,
                            const char *hd, size_t hdlen)
{
  CURLcode result = CURLE_OK;

  switch(hd[0]) {
  case 'a':
  case 'A':
    result = http_header_a(data, hd, hdlen);
    break;
  case 'c':
  case 'C':
    result = http_header_c(data, hd, hdlen);
    break;
  case 'l':
  case 'L':
    result = http_header_l(data, hd, hdlen);
    break;
  case 'p':
  case 'P':
    result = http_header_p(data, hd, hdlen);
    break;
  case 'r':
  case 'R':
    result = http_header_r(data, hd, hdlen);
    break;
  case 's':
  case 'S':
    result = http_header_s(data, hd, hdlen);
    break;
  case 't':
  case 'T':
    result = http_header_t(data, hd, hdlen);
    break;
  case 'w':
  case 'W':
    result = http_header_w(data, hd, hdlen);
    break;
  }

  if(!result) {
    struct connectdata *conn = data->conn;
    if(conn->handler->protocol & CURLPROTO_RTSP)
      result = Curl_rtsp_parseheader(data, hd);
  }
  return result;
}

/*
 * Called after the first HTTP response line (the status line) has been
 * received and parsed.
 */
static CURLcode http_statusline(struct Curl_easy *data,
                                struct connectdata *conn)
{
  struct SingleRequest *k = &data->req;

  switch(k->httpversion) {
  case 10:
  case 11:
#ifdef USE_HTTP2
  case 20:
#endif
#ifdef USE_HTTP3
  case 30:
#endif
    /* no major version switch mid-connection */
    if(k->httpversion_sent &&
       (k->httpversion/10 != k->httpversion_sent/10)) {
      failf(data, "Version mismatch (from HTTP/%u to HTTP/%u)",
            k->httpversion_sent/10, k->httpversion/10);
      return CURLE_WEIRD_SERVER_REPLY;
    }
    break;
  default:
    failf(data, "Unsupported HTTP version (%u.%d) in response",
          k->httpversion/10, k->httpversion%10);
    return CURLE_UNSUPPORTED_PROTOCOL;
  }

  data->info.httpcode = k->httpcode;
  data->info.httpversion = k->httpversion;
  conn->httpversion_seen = (unsigned char)k->httpversion;

  if(!data->state.http_neg.rcvd_min ||
     data->state.http_neg.rcvd_min > k->httpversion)
    /* store the lowest server version we encounter */
    data->state.http_neg.rcvd_min = (unsigned char)k->httpversion;

  /*
   * This code executes as part of processing the header. As a
   * result, it is not totally clear how to interpret the
   * response code yet as that depends on what other headers may
   * be present. 401 and 407 may be errors, but may be OK
   * depending on how authentication is working. Other codes
   * are definitely errors, so give up here.
   */
  if(data->state.resume_from && data->state.httpreq == HTTPREQ_GET &&
     k->httpcode == 416) {
    /* "Requested Range Not Satisfiable", just proceed and
       pretend this is no error */
    k->ignorebody = TRUE; /* Avoid appending error msg to good data. */
  }

  if(k->httpversion == 10) {
    /* Default action for HTTP/1.0 must be to close, unless
       we get one of those fancy headers that tell us the
       server keeps it open for us! */
    infof(data, "HTTP 1.0, assume close after body");
    connclose(conn, "HTTP/1.0 close after body");
  }
  else if(k->httpversion == 20 ||
          (k->upgr101 == UPGR101_H2 && k->httpcode == 101)) {
    DEBUGF(infof(data, "HTTP/2 found, allow multiplexing"));
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
    FALLTHROUGH();
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
   response. Refer to RFC 7230 section 3.3.3 and RFC2616 section 4.4. This is
   figured out here after all headers have been received but before the final
   call to the user's header callback, so that a valid content length can be
   retrieved by the user in the final call. */
static CURLcode http_size(struct Curl_easy *data)
{
  struct SingleRequest *k = &data->req;
  if(data->req.ignore_cl || k->chunk) {
    k->size = k->maxdownload = -1;
  }
  else if(k->size != -1) {
    if(data->set.max_filesize &&
       !k->ignorebody &&
       (k->size > data->set.max_filesize)) {
      failf(data, "Maximum file size exceeded");
      return CURLE_FILESIZE_EXCEEDED;
    }
    if(k->ignorebody)
      infof(data, "setting size while ignoring");
    Curl_pgrsSetDownloadSize(data, k->size);
    k->maxdownload = k->size;
  }
  return CURLE_OK;
}

static CURLcode verify_header(struct Curl_easy *data,
                              const char *hd, size_t hdlen)
{
  struct SingleRequest *k = &data->req;
  char *ptr = memchr(hd, 0x00, hdlen);
  if(ptr) {
    /* this is bad, bail out */
    failf(data, "Nul byte in header");
    return CURLE_WEIRD_SERVER_REPLY;
  }
  if(k->headerline < 2)
    /* the first "header" is the status-line and it has no colon */
    return CURLE_OK;
  if(((hd[0] == ' ') || (hd[0] == '\t')) && k->headerline > 2)
    /* line folding, cannot happen on line 2 */
    ;
  else {
    ptr = memchr(hd, ':', hdlen);
    if(!ptr) {
      /* this is bad, bail out */
      failf(data, "Header without colon");
      return CURLE_WEIRD_SERVER_REPLY;
    }
  }
  return CURLE_OK;
}

CURLcode Curl_bump_headersize(struct Curl_easy *data,
                              size_t delta,
                              bool connect_only)
{
  size_t bad = 0;
  unsigned int max = MAX_HTTP_RESP_HEADER_SIZE;
  if(delta < MAX_HTTP_RESP_HEADER_SIZE) {
    data->info.header_size += (unsigned int)delta;
    data->req.allheadercount += (unsigned int)delta;
    if(!connect_only)
      data->req.headerbytecount += (unsigned int)delta;
    if(data->req.allheadercount > max)
      bad = data->req.allheadercount;
    else if(data->info.header_size > (max * 20)) {
      bad = data->info.header_size;
      max *= 20;
    }
  }
  else
    bad = data->req.allheadercount + delta;
  if(bad) {
    failf(data, "Too large response headers: %zu > %u", bad, max);
    return CURLE_RECV_ERROR;
  }
  return CURLE_OK;
}

static CURLcode http_write_header(struct Curl_easy *data,
                                  const char *hd, size_t hdlen)
{
  CURLcode result;
  int writetype;

  /* now, only output this if the header AND body are requested:
   */
  Curl_debug(data, CURLINFO_HEADER_IN, hd, hdlen);

  writetype = CLIENTWRITE_HEADER |
    ((data->req.httpcode/100 == 1) ? CLIENTWRITE_1XX : 0);

  result = Curl_client_write(data, writetype, hd, hdlen);
  if(result)
    return result;

  result = Curl_bump_headersize(data, hdlen, FALSE);
  if(result)
    return result;

  data->req.deductheadercount = (100 <= data->req.httpcode &&
                                 199 >= data->req.httpcode) ?
    data->req.headerbytecount : 0;
  return result;
}

static CURLcode http_on_response(struct Curl_easy *data,
                                 const char *last_hd, size_t last_hd_len,
                                 const char *buf, size_t blen,
                                 size_t *pconsumed)
{
  struct connectdata *conn = data->conn;
  CURLcode result = CURLE_OK;
  struct SingleRequest *k = &data->req;

  (void)buf; /* not used without HTTP2 enabled */
  *pconsumed = 0;

  if(k->upgr101 == UPGR101_RECEIVED) {
    /* supposedly upgraded to http2 now */
    if(data->req.httpversion != 20)
      infof(data, "Lying server, not serving HTTP/2");
  }

  if(k->httpcode < 200 && last_hd) {
    /* Intermediate responses might trigger processing of more
     * responses, write the last header to the client before
     * proceeding. */
    result = http_write_header(data, last_hd, last_hd_len);
    last_hd = NULL; /* handled it */
    if(result)
      goto out;
  }

  if(k->httpcode < 100) {
    failf(data, "Unsupported response code in HTTP response");
    result = CURLE_UNSUPPORTED_PROTOCOL;
    goto out;
  }
  else if(k->httpcode < 200) {
    /* "A user agent MAY ignore unexpected 1xx status responses."
     * By default, we expect to get more responses after this one. */
    k->header = TRUE;
    k->headerline = 0; /* restart the header line counter */

    switch(k->httpcode) {
    case 100:
      /*
       * We have made an HTTP PUT or POST and this is 1.1-lingo
       * that tells us that the server is OK with this and ready
       * to receive the data.
       */
      http_exp100_got100(data);
      break;
    case 101:
      /* Switching Protocols only allowed from HTTP/1.1 */
      if(k->httpversion_sent != 11) {
        /* invalid for other HTTP versions */
        failf(data, "unexpected 101 response code");
        result = CURLE_WEIRD_SERVER_REPLY;
        goto out;
      }
      if(k->upgr101 == UPGR101_H2) {
        /* Switching to HTTP/2, where we will get more responses */
        infof(data, "Received 101, Switching to HTTP/2");
        k->upgr101 = UPGR101_RECEIVED;
        data->conn->bits.asks_multiplex = FALSE;
        /* We expect more response from HTTP/2 later */
        k->header = TRUE;
        k->headerline = 0; /* restart the header line counter */
        k->httpversion_sent = 20; /* It's an HTTP/2 request now */
        /* Any remaining `buf` bytes are already HTTP/2 and passed to
         * be processed. */
        result = Curl_http2_upgrade(data, conn, FIRSTSOCKET, buf, blen);
        if(result)
          goto out;
        *pconsumed += blen;
      }
#ifndef CURL_DISABLE_WEBSOCKETS
      else if(k->upgr101 == UPGR101_WS) {
        /* verify the response. Any passed `buf` bytes are already in
         * WebSockets format and taken in by the protocol handler. */
        result = Curl_ws_accept(data, buf, blen);
        if(result)
          goto out;
        *pconsumed += blen; /* ws accept handled the data */
      }
#endif
      else {
        /* We silently accept this as the final response. What are we
         * switching to if we did not ask for an Upgrade? Maybe the
         * application provided an `Upgrade: xxx` header? */
        k->header = FALSE;
      }
      break;
    default:
      /* The server may send us other 1xx responses, like informative
       * 103. This have no influence on request processing and we expect
       * to receive a final response eventually. */
      break;
    }
    goto out;
  }

  /* k->httpcode >= 200, final response */
  k->header = FALSE;

  if(k->upgr101 == UPGR101_H2) {
    /* A requested upgrade was denied, poke the multi handle to possibly
       allow a pending pipewait to continue */
    data->conn->bits.asks_multiplex = FALSE;
    Curl_multi_connchanged(data->multi);
  }

  if((k->size == -1) && !k->chunk && !conn->bits.close &&
     (k->httpversion == 11) &&
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

  /* At this point we have some idea about the fate of the connection.
     If we are closing the connection it may result auth failure. */
#ifdef USE_NTLM
  if(conn->bits.close &&
     (((data->req.httpcode == 401) &&
       (conn->http_ntlm_state == NTLMSTATE_TYPE2)) ||
      ((data->req.httpcode == 407) &&
       (conn->proxy_ntlm_state == NTLMSTATE_TYPE2)))) {
    infof(data, "Connection closure while negotiating auth (HTTP 1.0?)");
    data->state.authproblem = TRUE;
  }
#endif
#ifdef USE_SPNEGO
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

#ifndef CURL_DISABLE_WEBSOCKETS
  /* All >=200 HTTP status codes are errors when wanting WebSockets */
  if(data->req.upgr101 == UPGR101_WS) {
    failf(data, "Refused WebSockets upgrade: %d", k->httpcode);
    result = CURLE_HTTP_RETURNED_ERROR;
    goto out;
  }
#endif

  /* Check if this response means the transfer errored. */
  if(http_should_fail(data, data->req.httpcode)) {
    failf(data, "The requested URL returned error: %d",
          k->httpcode);
    result = CURLE_HTTP_RETURNED_ERROR;
    goto out;
  }

  /* Curl_http_auth_act() checks what authentication methods
   * that are available and decides which one (if any) to
   * use. It will set 'newurl' if an auth method was picked. */
  result = Curl_http_auth_act(data);
  if(result)
    goto out;

  if(k->httpcode >= 300) {
    if((!data->req.authneg) && !conn->bits.close &&
       !Curl_creader_will_rewind(data)) {
      /*
       * General treatment of errors when about to send data. Including :
       * "417 Expectation Failed", while waiting for 100-continue.
       *
       * The check for close above is done simply because of something
       * else has already deemed the connection to get closed then
       * something else should've considered the big picture and we
       * avoid this check.
       *
       */

      switch(data->state.httpreq) {
      case HTTPREQ_PUT:
      case HTTPREQ_POST:
      case HTTPREQ_POST_FORM:
      case HTTPREQ_POST_MIME:
        /* We got an error response. If this happened before the whole
         * request body has been sent we stop sending and mark the
         * connection for closure after we have read the entire response.
         */
        if(!Curl_req_done_sending(data)) {
          if((k->httpcode == 417) && http_exp100_is_selected(data)) {
            /* 417 Expectation Failed - try again without the Expect
               header */
            if(!k->writebytecount && http_exp100_is_waiting(data)) {
              infof(data, "Got HTTP failure 417 while waiting for a 100");
            }
            else {
              infof(data, "Got HTTP failure 417 while sending data");
              streamclose(conn,
                          "Stop sending data before everything sent");
              result = http_perhapsrewind(data, conn);
              if(result)
                goto out;
            }
            data->state.disableexpect = TRUE;
            DEBUGASSERT(!data->req.newurl);
            data->req.newurl = strdup(data->state.url);
            Curl_req_abort_sending(data);
          }
          else if(data->set.http_keep_sending_on_error) {
            infof(data, "HTTP error before end of send, keep sending");
            http_exp100_send_anyway(data);
          }
          else {
            infof(data, "HTTP error before end of send, stop sending");
            streamclose(conn, "Stop sending data before everything sent");
            result = Curl_req_abort_sending(data);
            if(result)
              goto out;
          }
        }
        break;

      default: /* default label present to avoid compiler warnings */
        break;
      }
    }

    if(Curl_creader_will_rewind(data) && !Curl_req_done_sending(data)) {
      /* We rewind before next send, continue sending now */
      infof(data, "Keep sending data to get tossed away");
      k->keepon |= KEEP_SEND;
    }

  }

  /* If we requested a "no body", this is a good time to get
   * out and return home.
   */
  if(data->req.no_body)
    k->download_done = TRUE;

  /* If max download size is *zero* (nothing) we already have
     nothing and can safely return ok now!  But for HTTP/2, we would
     like to call http2_handle_stream_close to properly close a
     stream. In order to do this, we keep reading until we
     close the stream. */
  if((k->maxdownload == 0) && (k->httpversion_sent < 20))
    k->download_done = TRUE;

  /* final response without error, prepare to receive the body */
  result = http_firstwrite(data);

  if(!result)
    /* This is the last response that we get for the current request.
     * Check on the body size and determine if the response is complete.
     */
    result = http_size(data);

out:
  if(last_hd) {
    /* if not written yet, write it now */
    result = Curl_1st_err(
      result, http_write_header(data, last_hd, last_hd_len));
  }
  return result;
}

static CURLcode http_rw_hd(struct Curl_easy *data,
                           const char *hd, size_t hdlen,
                           const char *buf_remain, size_t blen,
                           size_t *pconsumed)
{
  CURLcode result = CURLE_OK;
  struct SingleRequest *k = &data->req;
  int writetype;

  *pconsumed = 0;
  if((0x0a == *hd) || (0x0d == *hd)) {
    /* Empty header line means end of headers! */
    struct dynbuf last_header;
    size_t consumed;

    curlx_dyn_init(&last_header, hdlen + 1);
    result = curlx_dyn_addn(&last_header, hd, hdlen);
    if(result)
      return result;

    /* analyze the response to find out what to do. */
    /* Caveat: we clear anything in the header brigade, because a
     * response might switch HTTP version which may call use recursively.
     * Not nice, but that is currently the way of things. */
    curlx_dyn_reset(&data->state.headerb);
    result = http_on_response(data, curlx_dyn_ptr(&last_header),
                              curlx_dyn_len(&last_header),
                              buf_remain, blen, &consumed);
    *pconsumed += consumed;
    curlx_dyn_free(&last_header);
    return result;
  }

  /*
   * Checks for special headers coming up.
   */

  writetype = CLIENTWRITE_HEADER;
  if(!k->headerline++) {
    /* This is the first header, it MUST be the error code line
       or else we consider this to be the body right away! */
    bool fine_statusline = FALSE;

    k->httpversion = 0; /* Do not know yet */
    if(data->conn->handler->protocol & PROTO_FAMILY_HTTP) {
      /*
       * https://datatracker.ietf.org/doc/html/rfc7230#section-3.1.2
       *
       * The response code is always a three-digit number in HTTP as the spec
       * says. We allow any three-digit number here, but we cannot make
       * guarantees on future behaviors since it is not within the protocol.
       */
      const char *p = hd;

      curlx_str_passblanks(&p);
      if(!strncmp(p, "HTTP/", 5)) {
        p += 5;
        switch(*p) {
        case '1':
          p++;
          if((p[0] == '.') && (p[1] == '0' || p[1] == '1')) {
            if(ISBLANK(p[2])) {
              k->httpversion = (unsigned char)(10 + (p[1] - '0'));
              p += 3;
              if(ISDIGIT(p[0]) && ISDIGIT(p[1]) && ISDIGIT(p[2])) {
                k->httpcode = (p[0] - '0') * 100 + (p[1] - '0') * 10 +
                  (p[2] - '0');
                /* RFC 9112 requires a single space following the status code,
                   but the browsers don't so let's not insist */
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
          k->httpversion = (unsigned char)((*p - '0') * 10);
          p += 2;
          if(ISDIGIT(p[0]) && ISDIGIT(p[1]) && ISDIGIT(p[2])) {
            k->httpcode = (p[0] - '0') * 100 + (p[1] - '0') * 10 +
              (p[2] - '0');
            p += 3;
            if(!ISBLANK(*p))
              break;
            fine_statusline = TRUE;
          }
          break;
        default: /* unsupported */
          failf(data, "Unsupported HTTP version in response");
          return CURLE_UNSUPPORTED_PROTOCOL;
        }
      }

      if(!fine_statusline) {
        /* If user has set option HTTP200ALIASES,
           compare header line against list of aliases
        */
        statusline check = checkhttpprefix(data, hd, hdlen);
        if(check == STATUS_DONE) {
          fine_statusline = TRUE;
          k->httpcode = 200;
          k->httpversion = 10;
        }
      }
    }
    else if(data->conn->handler->protocol & CURLPROTO_RTSP) {
      const char *p = hd;
      struct Curl_str ver;
      curl_off_t status;
      /* we set the max string a little excessive to forgive some leading
         spaces */
      if(!curlx_str_until(&p, &ver, 32, ' ') &&
         !curlx_str_single(&p, ' ') &&
         !curlx_str_number(&p, &status, 999)) {
        curlx_str_trimblanks(&ver);
        if(curlx_str_cmp(&ver, "RTSP/1.0")) {
          k->httpcode = (int)status;
          fine_statusline = TRUE;
          k->httpversion = 11; /* RTSP acts like HTTP 1.1 */
        }
      }
      if(!fine_statusline)
        return CURLE_WEIRD_SERVER_REPLY;
    }

    if(fine_statusline) {
      result = http_statusline(data, data->conn);
      if(result)
        return result;
      writetype |= CLIENTWRITE_STATUS;
    }
    else {
      k->header = FALSE;   /* this is not a header line */
      return CURLE_WEIRD_SERVER_REPLY;
    }
  }

  result = verify_header(data, hd, hdlen);
  if(result)
    return result;

  result = http_header(data, hd, hdlen);
  if(result)
    return result;

  /*
   * Taken in one (more) header. Write it to the client.
   */
  Curl_debug(data, CURLINFO_HEADER_IN, hd, hdlen);

  if(k->httpcode/100 == 1)
    writetype |= CLIENTWRITE_1XX;
  result = Curl_client_write(data, writetype, hd, hdlen);
  if(result)
    return result;

  result = Curl_bump_headersize(data, hdlen, FALSE);
  if(result)
    return result;

  return CURLE_OK;
}

/*
 * Read any HTTP header lines from the server and pass them to the client app.
 */
static CURLcode http_parse_headers(struct Curl_easy *data,
                                   const char *buf, size_t blen,
                                   size_t *pconsumed)
{
  struct connectdata *conn = data->conn;
  CURLcode result = CURLE_OK;
  struct SingleRequest *k = &data->req;
  char *end_ptr;
  bool leftover_body = FALSE;

  /* header line within buffer loop */
  *pconsumed = 0;
  while(blen && k->header) {
    size_t consumed;

    end_ptr = memchr(buf, '\n', blen);
    if(!end_ptr) {
      /* Not a complete header line within buffer, append the data to
         the end of the headerbuff. */
      result = curlx_dyn_addn(&data->state.headerb, buf, blen);
      if(result)
        return result;
      *pconsumed += blen;

      if(!k->headerline) {
        /* check if this looks like a protocol header */
        statusline st =
          checkprotoprefix(data, conn,
                           curlx_dyn_ptr(&data->state.headerb),
                           curlx_dyn_len(&data->state.headerb));

        if(st == STATUS_BAD) {
          /* this is not the beginning of a protocol first header line.
           * Cannot be 0.9 if version was detected or connection was reused. */
          k->header = FALSE;
          streamclose(conn, "bad HTTP: No end-of-message indicator");
          if((k->httpversion >= 10) || conn->bits.reuse) {
            failf(data, "Invalid status line");
            return CURLE_WEIRD_SERVER_REPLY;
          }
          if(!data->state.http_neg.accept_09) {
            failf(data, "Received HTTP/0.9 when not allowed");
            return CURLE_UNSUPPORTED_PROTOCOL;
          }
          leftover_body = TRUE;
          goto out;
        }
      }
      goto out; /* read more and try again */
    }

    /* decrease the size of the remaining (supposed) header line */
    consumed = (end_ptr - buf) + 1;
    result = curlx_dyn_addn(&data->state.headerb, buf, consumed);
    if(result)
      return result;
    blen -= consumed;
    buf += consumed;
    *pconsumed += consumed;

    /****
     * We now have a FULL header line in 'headerb'.
     *****/

    if(!k->headerline) {
      /* the first read header */
      statusline st = checkprotoprefix(data, conn,
                                       curlx_dyn_ptr(&data->state.headerb),
                                       curlx_dyn_len(&data->state.headerb));
      if(st == STATUS_BAD) {
        streamclose(conn, "bad HTTP: No end-of-message indicator");
        /* this is not the beginning of a protocol first header line.
         * Cannot be 0.9 if version was detected or connection was reused. */
        if((k->httpversion >= 10) || conn->bits.reuse) {
          failf(data, "Invalid status line");
          return CURLE_WEIRD_SERVER_REPLY;
        }
        if(!data->state.http_neg.accept_09) {
          failf(data, "Received HTTP/0.9 when not allowed");
          return CURLE_UNSUPPORTED_PROTOCOL;
        }
        k->header = FALSE;
        leftover_body = TRUE;
        goto out;
      }
    }

    result = http_rw_hd(data, curlx_dyn_ptr(&data->state.headerb),
                        curlx_dyn_len(&data->state.headerb),
                        buf, blen, &consumed);
    /* We are done with this line. We reset because response
     * processing might switch to HTTP/2 and that might call us
     * directly again. */
    curlx_dyn_reset(&data->state.headerb);
    if(consumed) {
      blen -= consumed;
      buf += consumed;
      *pconsumed += consumed;
    }
    if(result)
      return result;
  }

  /* We might have reached the end of the header part here, but
     there might be a non-header part left in the end of the read
     buffer. */
out:
  if(!k->header && !leftover_body) {
    curlx_dyn_free(&data->state.headerb);
  }
  return CURLE_OK;
}

CURLcode Curl_http_write_resp_hd(struct Curl_easy *data,
                                 const char *hd, size_t hdlen,
                                 bool is_eos)
{
  CURLcode result;
  size_t consumed;
  char tmp = 0;

  result = http_rw_hd(data, hd, hdlen, &tmp, 0, &consumed);
  if(!result && is_eos) {
    result = Curl_client_write(data, (CLIENTWRITE_BODY|CLIENTWRITE_EOS),
                               &tmp, 0);
  }
  return result;
}

/*
 * HTTP protocol `write_resp` implementation. Will parse headers
 * when not done yet and otherwise return without consuming data.
 */
CURLcode Curl_http_write_resp_hds(struct Curl_easy *data,
                                  const char *buf, size_t blen,
                                  size_t *pconsumed)
{
  if(!data->req.header) {
    *pconsumed = 0;
    return CURLE_OK;
  }
  else {
    CURLcode result;

    result = http_parse_headers(data, buf, blen, pconsumed);
    if(!result && !data->req.header) {
      if(!data->req.no_body && curlx_dyn_len(&data->state.headerb)) {
        /* leftover from parsing something that turned out not
         * to be a header, only happens if we allow for
         * HTTP/0.9 like responses */
        result = Curl_client_write(data, CLIENTWRITE_BODY,
                                   curlx_dyn_ptr(&data->state.headerb),
                                   curlx_dyn_len(&data->state.headerb));
      }
      curlx_dyn_free(&data->state.headerb);
    }
    return result;
  }
}

CURLcode Curl_http_write_resp(struct Curl_easy *data,
                              const char *buf, size_t blen,
                              bool is_eos)
{
  CURLcode result;
  size_t consumed;
  int flags;

  result = Curl_http_write_resp_hds(data, buf, blen, &consumed);
  if(result || data->req.done)
    goto out;

  DEBUGASSERT(consumed <= blen);
  blen -= consumed;
  buf += consumed;
  /* either all was consumed in header parsing, or we have data left
   * and are done with headers, e.g. it is BODY data */
  DEBUGASSERT(!blen || !data->req.header);
  if(!data->req.header && (blen || is_eos)) {
    /* BODY data after header been parsed, write and consume */
    flags = CLIENTWRITE_BODY;
    if(is_eos)
      flags |= CLIENTWRITE_EOS;
    result = Curl_client_write(data, flags, buf, blen);
  }
out:
  return result;
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
  *pstatus = result ? -1 : status;
  return result;
}

CURLcode Curl_http_req_make(struct httpreq **preq,
                            const char *method, size_t m_len,
                            const char *scheme, size_t s_len,
                            const char *authority, size_t a_len,
                            const char *path, size_t p_len)
{
  struct httpreq *req;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  DEBUGASSERT(method && m_len);

  req = calloc(1, sizeof(*req) + m_len);
  if(!req)
    goto out;
#if defined(__GNUC__) && __GNUC__ >= 13
#pragma GCC diagnostic push
/* error: 'memcpy' offset [137, 142] from the object at 'req' is out of
   the bounds of referenced subobject 'method' with type 'char[1]' at
   offset 136 */
#pragma GCC diagnostic ignored "-Warray-bounds"
#endif
  memcpy(req->method, method, m_len);
#if defined(__GNUC__) && __GNUC__ >= 13
#pragma GCC diagnostic pop
#endif
  if(scheme) {
    req->scheme = Curl_memdup0(scheme, s_len);
    if(!req->scheme)
      goto out;
  }
  if(authority) {
    req->authority = Curl_memdup0(authority, a_len);
    if(!req->authority)
      goto out;
  }
  if(path) {
    req->path = Curl_memdup0(path, p_len);
    if(!req->path)
      goto out;
  }
  Curl_dynhds_init(&req->headers, 0, DYN_HTTP_REQUEST);
  Curl_dynhds_init(&req->trailers, 0, DYN_HTTP_REQUEST);
  result = CURLE_OK;

out:
  if(result && req)
    Curl_http_req_free(req);
  *preq = result ? NULL : req;
  return result;
}

static CURLcode req_assign_url_authority(struct httpreq *req, CURLU *url)
{
  char *user, *pass, *host, *port;
  struct dynbuf buf;
  CURLUcode uc;
  CURLcode result = CURLE_URL_MALFORMAT;

  user = pass = host = port = NULL;
  curlx_dyn_init(&buf, DYN_HTTP_REQUEST);

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
    result = curlx_dyn_add(&buf, user);
    if(result)
      goto out;
    if(pass) {
      result = curlx_dyn_addf(&buf, ":%s", pass);
      if(result)
        goto out;
    }
    result = curlx_dyn_add(&buf, "@");
    if(result)
      goto out;
  }
  result = curlx_dyn_add(&buf, host);
  if(result)
    goto out;
  if(port) {
    result = curlx_dyn_addf(&buf, ":%s", port);
    if(result)
      goto out;
  }
  req->authority = strdup(curlx_dyn_ptr(&buf));
  if(!req->authority)
    goto out;
  result = CURLE_OK;

out:
  free(user);
  free(pass);
  free(host);
  free(port);
  curlx_dyn_free(&buf);
  return result;
}

static CURLcode req_assign_url_path(struct httpreq *req, CURLU *url)
{
  char *path, *query;
  struct dynbuf buf;
  CURLUcode uc;
  CURLcode result = CURLE_URL_MALFORMAT;

  path = query = NULL;
  curlx_dyn_init(&buf, DYN_HTTP_REQUEST);

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
      result = curlx_dyn_add(&buf, path);
      if(result)
        goto out;
    }
    if(query) {
      result = curlx_dyn_addf(&buf, "?%s", query);
      if(result)
        goto out;
    }
    req->path = strdup(curlx_dyn_ptr(&buf));
    if(!req->path)
      goto out;
  }
  result = CURLE_OK;

out:
  free(path);
  free(query);
  curlx_dyn_free(&buf);
  return result;
}

CURLcode Curl_http_req_make2(struct httpreq **preq,
                             const char *method, size_t m_len,
                             CURLU *url, const char *scheme_default)
{
  struct httpreq *req;
  CURLcode result = CURLE_OUT_OF_MEMORY;
  CURLUcode uc;

  DEBUGASSERT(method && m_len);

  req = calloc(1, sizeof(*req) + m_len);
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

  Curl_dynhds_init(&req->headers, 0, DYN_HTTP_REQUEST);
  Curl_dynhds_init(&req->trailers, 0, DYN_HTTP_REQUEST);
  result = CURLE_OK;

out:
  if(result && req)
    Curl_http_req_free(req);
  *preq = result ? NULL : req;
  return result;
}

void Curl_http_req_free(struct httpreq *req)
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

/* keep them sorted by length! */
static const struct name_const H2_NON_FIELD[] = {
  { STRCONST("Host") },
  { STRCONST("Upgrade") },
  { STRCONST("Connection") },
  { STRCONST("Keep-Alive") },
  { STRCONST("Proxy-Connection") },
  { STRCONST("Transfer-Encoding") },
};

static bool h2_permissible_field(struct dynhds_entry *e)
{
  size_t i;
  for(i = 0; i < CURL_ARRAYSIZE(H2_NON_FIELD); ++i) {
    if(e->namelen < H2_NON_FIELD[i].namelen)
      return TRUE;
    if(e->namelen == H2_NON_FIELD[i].namelen &&
       curl_strequal(H2_NON_FIELD[i].name, e->name))
      return FALSE;
  }
  return TRUE;
}

static bool http_TE_has_token(const char *fvalue, const char *token)
{
  while(*fvalue) {
    struct Curl_str name;

    /* skip to first token */
    while(ISBLANK(*fvalue) || *fvalue == ',')
      fvalue++;
    if(curlx_str_cspn(&fvalue, &name, " \t\r;,"))
      return FALSE;
    if(curlx_str_casecompare(&name, token))
      return TRUE;

    /* skip any remainder after token, e.g. parameters with quoted strings */
    while(*fvalue && *fvalue != ',') {
      if(*fvalue == '"') {
        struct Curl_str qw;
        /* if we do not cleanly find a quoted word here, the header value
         * does not follow HTTP syntax and we reject */
        if(curlx_str_quotedword(&fvalue, &qw, CURL_MAX_HTTP_HEADER))
          return FALSE;
      }
      else
        fvalue++;
    }
  }
  return FALSE;
}

CURLcode Curl_http_req_to_h2(struct dynhds *h2_headers,
                             struct httpreq *req, struct Curl_easy *data)
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
      curlx_str_passblanks(&scheme);
      infof(data, "set pseudo header %s to %s", HTTP_PSEUDO_SCHEME, scheme);
    }
    else {
      scheme = Curl_conn_is_ssl(data->conn, FIRSTSOCKET) ?
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
    /* "TE" is special in that it is only permissible when it
     * has only value "trailers". RFC 9113 ch. 8.2.2 */
    if(e->namelen == 2 && curl_strequal("TE", e->name)) {
      if(http_TE_has_token(e->value, "trailers"))
        result = Curl_dynhds_add(h2_headers, e->name, e->namelen,
                                 "trailers", sizeof("trailers") - 1);
    }
    else if(h2_permissible_field(e)) {
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
  Curl_dynhds_init(&resp->headers, 0, DYN_HTTP_REQUEST);
  Curl_dynhds_init(&resp->trailers, 0, DYN_HTTP_REQUEST);
  result = CURLE_OK;

out:
  if(result && resp)
    Curl_http_resp_free(resp);
  *presp = result ? NULL : resp;
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

struct cr_exp100_ctx {
  struct Curl_creader super;
  struct curltime start; /* time started waiting */
  enum expect100 state;
};

/* Expect: 100-continue client reader, blocking uploads */

static void http_exp100_continue(struct Curl_easy *data,
                                 struct Curl_creader *reader)
{
  struct cr_exp100_ctx *ctx = reader->ctx;
  if(ctx->state > EXP100_SEND_DATA) {
    ctx->state = EXP100_SEND_DATA;
    data->req.keepon |= KEEP_SEND;
    data->req.keepon &= ~KEEP_SEND_TIMED;
    Curl_expire_done(data, EXPIRE_100_TIMEOUT);
  }
}

static CURLcode cr_exp100_read(struct Curl_easy *data,
                               struct Curl_creader *reader,
                               char *buf, size_t blen,
                               size_t *nread, bool *eos)
{
  struct cr_exp100_ctx *ctx = reader->ctx;
  timediff_t ms;

  switch(ctx->state) {
  case EXP100_SENDING_REQUEST:
    if(!Curl_req_sendbuf_empty(data)) {
      /* The initial request data has not been fully sent yet. Do
       * not start the timer yet. */
      DEBUGF(infof(data, "cr_exp100_read, request not full sent yet"));
      *nread = 0;
      *eos = FALSE;
      return CURLE_OK;
    }
    /* We are now waiting for a reply from the server or
     * a timeout on our side IFF the request has been fully sent. */
    DEBUGF(infof(data, "cr_exp100_read, start AWAITING_CONTINUE, "
           "timeout %dms", data->set.expect_100_timeout));
    ctx->state = EXP100_AWAITING_CONTINUE;
    ctx->start = curlx_now();
    Curl_expire(data, data->set.expect_100_timeout, EXPIRE_100_TIMEOUT);
    data->req.keepon &= ~KEEP_SEND;
    data->req.keepon |= KEEP_SEND_TIMED;
    *nread = 0;
    *eos = FALSE;
    return CURLE_OK;
  case EXP100_FAILED:
    DEBUGF(infof(data, "cr_exp100_read, expectation failed, error"));
    *nread = 0;
    *eos = FALSE;
    return CURLE_READ_ERROR;
  case EXP100_AWAITING_CONTINUE:
    ms = curlx_timediff(curlx_now(), ctx->start);
    if(ms < data->set.expect_100_timeout) {
      DEBUGF(infof(data, "cr_exp100_read, AWAITING_CONTINUE, not expired"));
      data->req.keepon &= ~KEEP_SEND;
      data->req.keepon |= KEEP_SEND_TIMED;
      *nread = 0;
      *eos = FALSE;
      return CURLE_OK;
    }
    /* we have waited long enough, continue anyway */
    http_exp100_continue(data, reader);
    infof(data, "Done waiting for 100-continue");
    FALLTHROUGH();
  default:
    DEBUGF(infof(data, "cr_exp100_read, pass through"));
    return Curl_creader_read(data, reader->next, buf, blen, nread, eos);
  }
}

static void cr_exp100_done(struct Curl_easy *data,
                           struct Curl_creader *reader, int premature)
{
  struct cr_exp100_ctx *ctx = reader->ctx;
  ctx->state = premature ? EXP100_FAILED : EXP100_SEND_DATA;
  data->req.keepon &= ~KEEP_SEND_TIMED;
  Curl_expire_done(data, EXPIRE_100_TIMEOUT);
}

static const struct Curl_crtype cr_exp100 = {
  "cr-exp100",
  Curl_creader_def_init,
  cr_exp100_read,
  Curl_creader_def_close,
  Curl_creader_def_needs_rewind,
  Curl_creader_def_total_length,
  Curl_creader_def_resume_from,
  Curl_creader_def_cntrl,
  Curl_creader_def_is_paused,
  cr_exp100_done,
  sizeof(struct cr_exp100_ctx)
};

static CURLcode http_exp100_add_reader(struct Curl_easy *data)
{
  struct Curl_creader *reader = NULL;
  CURLcode result;

  result = Curl_creader_create(&reader, data, &cr_exp100,
                               CURL_CR_PROTOCOL);
  if(!result)
    result = Curl_creader_add(data, reader);
  if(!result) {
    struct cr_exp100_ctx *ctx = reader->ctx;
    ctx->state = EXP100_SENDING_REQUEST;
  }

  if(result && reader)
    Curl_creader_free(data, reader);
  return result;
}

static void http_exp100_got100(struct Curl_easy *data)
{
  struct Curl_creader *r = Curl_creader_get_by_type(data, &cr_exp100);
  if(r)
    http_exp100_continue(data, r);
}

static bool http_exp100_is_waiting(struct Curl_easy *data)
{
  struct Curl_creader *r = Curl_creader_get_by_type(data, &cr_exp100);
  if(r) {
    struct cr_exp100_ctx *ctx = r->ctx;
    return ctx->state == EXP100_AWAITING_CONTINUE;
  }
  return FALSE;
}

static void http_exp100_send_anyway(struct Curl_easy *data)
{
  struct Curl_creader *r = Curl_creader_get_by_type(data, &cr_exp100);
  if(r)
    http_exp100_continue(data, r);
}

static bool http_exp100_is_selected(struct Curl_easy *data)
{
  struct Curl_creader *r = Curl_creader_get_by_type(data, &cr_exp100);
  return !!r;
}

#endif /* CURL_DISABLE_HTTP */
