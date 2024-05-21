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
#include "http_negotiate.h"
#include "http_aws_sigv4.h"
#include "url.h"
#include "share.h"
#include "hostip.h"
#include "dynhds.h"
#include "http.h"
#include "headers.h"
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

static bool http_should_fail(struct Curl_easy *data, int httpcode);
static bool http_exp100_is_waiting(struct Curl_easy *data);
static CURLcode http_exp100_add_reader(struct Curl_easy *data);
static void http_exp100_send_anyway(struct Curl_easy *data);

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
  ZERO_NULL,                            /* proto_getsock */
  Curl_http_getsock_do,                 /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  Curl_http_write_resp,                 /* write_resp */
  Curl_http_write_resp_hd,              /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
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
  NULL,                                 /* proto_getsock */
  Curl_http_getsock_do,                 /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  Curl_http_write_resp,                 /* write_resp */
  Curl_http_write_resp_hd,              /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_HTTPS,                           /* defport */
  CURLPROTO_HTTPS,                      /* protocol */
  CURLPROTO_HTTP,                       /* family */
  PROTOPT_SSL | PROTOPT_CREDSPERREQUEST | PROTOPT_ALPN | /* flags */
  PROTOPT_USERPWDCTRL
};

#endif

CURLcode Curl_http_setup_conn(struct Curl_easy *data,
                              struct connectdata *conn)
{
  /* allocate the HTTP-specific struct for the Curl_easy, only to survive
     during this request */
  struct HTTP *http;
  DEBUGASSERT(data->req.p.http == NULL);

  http = calloc(1, sizeof(struct HTTP));
  if(!http)
    return CURLE_OUT_OF_MEMORY;

  data->req.p.http = http;
  connkeep(conn, "HTTP default");

  if(data->state.httpwant == CURL_HTTP_VERSION_3ONLY) {
    CURLcode result = Curl_conn_may_http3(data, conn);
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

  return Curl_memdup0(start, len);
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
  curl_off_t upload_remain = (expectsend >= 0)? (expectsend - bytessent) : -1;
  bool little_upload_remains = (upload_remain >= 0 && upload_remain < 2000);
  bool needs_rewind = Curl_creader_needs_rewind(data);
  /* By default, we'd like to abort the transfer when little or
   * unknown amount remains. But this may be overridden by authentications
   * further below! */
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
#if defined(USE_NTLM)
    if((data->state.authproxy.picked == CURLAUTH_NTLM) ||
       (data->state.authhost.picked == CURLAUTH_NTLM)) {
      ongoing_auth = "NTML";
      if((conn->http_ntlm_state != NTLMSTATE_NONE) ||
         (conn->proxy_ntlm_state != NTLMSTATE_NONE)) {
        /* The NTLM-negotiation has started, keep on sending.
         * Need to do further work on same connection */
        abort_upload = FALSE;
      }
    }
#endif
#if defined(USE_SPNEGO)
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
      infof(data, "%s%sclose instead of sending %"
        CURL_FORMAT_CURL_OFF_T " more bytes",
        ongoing_auth? ongoing_auth : "",
        ongoing_auth? " send, " : "",
        upload_remain);
    else
      infof(data, "%s%sclose instead of sending unknown amount "
        "of more bytes",
        ongoing_auth? ongoing_auth : "",
        ongoing_auth? " send, " : "");
    /* We decided to abort the ongoing transfer */
    streamclose(conn, "Mid-auth HTTP and much data left to send");
    /* FIXME: questionable manipulation here, can we do this differently? */
    data->req.size = 0; /* don't download any more than 0 bytes */
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
      (data->req.authneg && data->req.httpcode < 300))) {
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
      (data->req.authneg && data->req.httpcode < 300))) {
    pickproxy = pickoneauth(&data->state.authproxy,
                            authmask & ~CURLAUTH_BEARER);
    if(!pickproxy)
      data->state.authproblem = TRUE;
  }
#endif

  if(pickhost || pickproxy) {
    result = http_perhapsrewind(data, conn);
    if(result)
      return result;

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
          data->req.authneg) {
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
    authstatus->multipass = (!authstatus->done) ? TRUE : FALSE;
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
static int is_valid_auth_separator(char ch)
{
  return ch == '\0' || ch == ',' || ISSPACE(ch);
}
#endif

/*
 * Curl_http_input_auth() deals with Proxy-Authenticate: and WWW-Authenticate:
 * headers. They are dealt with both in the transfer.c main loop and in the
 * proxy CONNECT loop.
 */
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
#if defined(USE_SPNEGO) || \
  defined(USE_NTLM) || \
  !defined(CURL_DISABLE_DIGEST_AUTH) || \
  !defined(CURL_DISABLE_BASIC_AUTH) || \
  !defined(CURL_DISABLE_BEARER_AUTH)

  unsigned long *availp;
  struct auth *authp;

  if(proxy) {
    availp = &data->info.proxyauthavail;
    authp = &data->state.authproxy;
  }
  else {
    availp = &data->info.httpauthavail;
    authp = &data->state.authhost;
  }
#else
  (void) proxy;
#endif

  (void) conn; /* In case conditionals make it unused. */

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
           Curl_auth_is_ntlm_supported()) {
          *availp |= CURLAUTH_NTLM;
          authp->avail |= CURLAUTH_NTLM;

          if(authp->picked == CURLAUTH_NTLM) {
            /* NTLM authentication is picked and activated */
            CURLcode result = Curl_input_ntlm(data, proxy, auth);
            if(!result) {
              data->state.authproblem = FALSE;
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
#ifndef CURL_DISABLE_DIGEST_AUTH
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
#ifndef CURL_DISABLE_BASIC_AUTH
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
#endif
#ifndef CURL_DISABLE_BEARER_AUTH
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
#else
            {
              /*
               * Empty block to terminate the if-else chain correctly.
               *
               * A semicolon would yield the same result here, but can cause a
               * compiler warning when -Wextra is enabled.
               */
            }
#endif

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
     function to make the reuse checks properly be able to check this bit. */
  connkeep(conn, "HTTP default");

  return Curl_conn_connect(data, FIRSTSOCKET, FALSE, done);
}

/* this returns the socket to wait for in the DO and DOING state for the multi
   interface and then we're always _sending_ a request and thus we wait for
   the single socket to become writable only */
int Curl_http_getsock_do(struct Curl_easy *data,
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

  if(!http)
    return CURLE_OK;

  Curl_dyn_reset(&data->state.headerb);
  Curl_hyper_done(data);

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

enum proxy_use {
  HEADER_SERVER,  /* direct to server */
  HEADER_PROXY,   /* regular request to proxy */
  HEADER_CONNECT  /* sending CONNECT to a proxy */
};

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
      else if(data->req.authneg &&
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
          else if(data->req.authneg &&
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

    if(!strcasecompare("Host:", ptr)) {
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
    /* Extract the URL to use in the request. */
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
    if(!postsize)
      result = Curl_creader_set_null(data);
    else
      result = Curl_creader_set_fread(data, postsize);
    return result;

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
      result = Curl_creader_set_fread(data, chunked? -1 : postsize);
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
       * We don't support this now. Bail out!
       */
      data->state.resume_from = 0;
    }

    if(data->state.resume_from && !data->req.authneg) {
      /* only act on the first request */
      CURLcode result;
      result = Curl_creader_resume_from(data, data->state.resume_from);
      if(result) {
        failf(data, "Unable to resume from offset %" CURL_FORMAT_CURL_OFF_T,
              data->state.resume_from);
        return result;
      }
    }
  }
  return CURLE_OK;
}

CURLcode Curl_http_req_set_reader(struct Curl_easy *data,
                                  Curl_HttpReq httpreq,
                                  const char **tep)
{
  CURLcode result = CURLE_OK;
  const char *ptr;

  result = set_reader(data, httpreq);
  if(result)
    return result;

  result = http_resume(data, httpreq);
  if(result)
    return result;

  ptr = Curl_checkheaders(data, STRCONST("Transfer-Encoding"));
  if(ptr) {
    /* Some kind of TE is requested, check if 'chunked' is chosen */
    data->req.upload_chunky =
      Curl_compareheader(ptr,
                         STRCONST("Transfer-Encoding:"), STRCONST("chunked"));
    if(data->req.upload_chunky &&
       Curl_use_http_1_1plus(data, data->conn) &&
       (data->conn->httpversion >= 20)) {
       infof(data, "suppressing chunked transfer encoding on connection "
             "using HTTP version 2 or higher");
       data->req.upload_chunky = FALSE;
    }
  }
  else {
    curl_off_t req_clen = Curl_creader_total_length(data);

    if(req_clen < 0) {
      /* indeterminate request content length */
      if(Curl_use_http_1_1plus(data, data->conn)) {
        /* On HTTP/1.1, enable chunked, on HTTP/2 and later we do not
         * need it */
        data->req.upload_chunky = (data->conn->httpversion < 20);
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

static CURLcode addexpect(struct Curl_easy *data, struct dynbuf *r,
                          bool *announced_exp100)
{
  CURLcode result;
  char *ptr;

  *announced_exp100 = FALSE;
  /* Avoid Expect: 100-continue if Upgrade: is used */
  if(data->req.upgr101 != UPGR101_INIT)
    return CURLE_OK;

  /* For really small puts we don't use Expect: headers at all, and for
     the somewhat bigger ones we allow the app to disable it. Just make
     sure that the expect100header is always set to the preferred value
     here. */
  ptr = Curl_checkheaders(data, STRCONST("Expect"));
  if(ptr) {
    *announced_exp100 =
      Curl_compareheader(ptr, STRCONST("Expect:"), STRCONST("100-continue"));
  }
  else if(!data->state.disableexpect &&
          Curl_use_http_1_1plus(data, data->conn) &&
          (data->conn->httpversion < 20)) {
    /* if not doing HTTP 1.0 or version 2, or disabled explicitly, we add an
       Expect: 100-continue to the headers which actually speeds up post
       operations (as there is one packet coming back from the web server) */
    curl_off_t client_len = Curl_creader_client_length(data);
    if(client_len > EXPECT_100_THRESHOLD || client_len < 0) {
      result = Curl_dyn_addn(r, STRCONST("Expect: 100-continue\r\n"));
      if(result)
        return result;
      *announced_exp100 = TRUE;
    }
  }
  return CURLE_OK;
}

CURLcode Curl_http_req_complete(struct Curl_easy *data,
                                struct dynbuf *r, Curl_HttpReq httpreq)
{
  CURLcode result = CURLE_OK;
  curl_off_t req_clen;
  bool announced_exp100 = FALSE;

  DEBUGASSERT(data->conn);
#ifndef USE_HYPER
  if(data->req.upload_chunky) {
    result = Curl_httpchunk_add_reader(data);
    if(result)
      return result;
  }
#endif

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
       we don't upload data chunked, as RFC2616 forbids us to set both
       kinds of headers (Transfer-Encoding: chunked and Content-Length).
       We do not override a custom "Content-Length" header, but during
       authentication negotiation that header is suppressed.
     */
    if(req_clen >= 0 && !data->req.upload_chunky &&
       (data->req.authneg ||
        !Curl_checkheaders(data, STRCONST("Content-Length")))) {
      /* we allow replacing this header if not during auth negotiation,
         although it isn't very wise to actually set your own */
      result = Curl_dyn_addf(r,
                             "Content-Length: %" CURL_FORMAT_CURL_OFF_T
                             "\r\n", req_clen);
    }
    if(result)
      goto out;

#ifndef CURL_DISABLE_MIME
    /* Output mime-generated headers. */
    if(data->state.mimepost &&
       ((httpreq == HTTPREQ_POST_FORM) || (httpreq == HTTPREQ_POST_MIME))) {
      struct curl_slist *hdr;

      for(hdr = data->state.mimepost->curlheaders; hdr; hdr = hdr->next) {
        result = Curl_dyn_addf(r, "%s\r\n", hdr->data);
        if(result)
          goto out;
      }
    }
#endif
    if(httpreq == HTTPREQ_POST) {
      if(!Curl_checkheaders(data, STRCONST("Content-Type"))) {
        result = Curl_dyn_addn(r, STRCONST("Content-Type: application/"
                                           "x-www-form-urlencoded\r\n"));
        if(result)
          goto out;
      }
    }
    result = addexpect(data, r, &announced_exp100);
    if(result)
      goto out;
    break;
  default:
    break;
  }

  /* end of headers */
  result = Curl_dyn_addn(r, STRCONST("\r\n"));
  if(!result) {
    Curl_pgrsSetUploadSize(data, req_clen);
    if(announced_exp100)
      result = http_exp100_add_reader(data);
  }

out:
  if(!result) {
    /* setup variables for the upcoming transfer */
    Curl_xfer_setup(data, FIRSTSOCKET, -1, TRUE, FIRSTSOCKET);
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
      size_t clen = 8; /* hold the size of the generated Cookie: header */
      /* now loop through all cookies that matched */
      while(co) {
        if(co->value) {
          size_t add;
          if(!count) {
            result = Curl_dyn_addn(r, STRCONST("Cookie: "));
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
          result = Curl_dyn_addf(r, "%s%s=%s", count?"; ":"",
                                 co->name, co->value);
          if(result)
            break;
          clen += add + (count ? 2 : 0);
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
      curl_off_t req_clen = Curl_creader_total_length(data);
      /* if a line like this was already allocated, free the previous one */
      free(data->state.aptr.rangeline);

      if(data->set.set_resume_from < 0) {
        /* Upload resume was asked for, but we don't know the size of the
           remote part so we tell the server (and act accordingly) that we
           upload the whole file (again) */
        data->state.aptr.rangeline =
          aprintf("Content-Range: bytes 0-%" CURL_FORMAT_CURL_OFF_T
                  "/%" CURL_FORMAT_CURL_OFF_T "\r\n",
                  req_clen - 1, req_clen);

      }
      else if(data->state.resume_from) {
        /* This is because "resume" was selected */
        /* TODO: not sure if we want to send this header during authentication
         * negotiation, but test1084 checks for it. In which case we have a
         * "null" client reader installed that gives an unexpected length. */
        curl_off_t total_len = data->req.authneg?
                               data->state.infilesize :
                               (data->state.resume_from + req_clen);
        data->state.aptr.rangeline =
          aprintf("Content-Range: bytes %s%" CURL_FORMAT_CURL_OFF_T
                  "/%" CURL_FORMAT_CURL_OFF_T "\r\n",
                  data->state.range, total_len-1, total_len);
      }
      else {
        /* Range was selected and then we just pass the incoming range and
           append total size */
        data->state.aptr.rangeline =
          aprintf("Content-Range: bytes %s/%" CURL_FORMAT_CURL_OFF_T "\r\n",
                  data->state.range, req_clen);
      }
      if(!data->state.aptr.rangeline)
        return CURLE_OUT_OF_MEMORY;
    }
  }
  return CURLE_OK;
}

CURLcode Curl_http_firstwrite(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;
  struct SingleRequest *k = &data->req;

  if(data->req.newurl) {
    if(conn->bits.close) {
      /* Abort after the headers if "follow Location" is set
         and we're set to close anyway. */
      k->keepon &= ~KEEP_RECV;
      k->done = TRUE;
      return CURLE_OK;
    }
    /* We have a new url to load, but since we want to be able to reuse this
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
      k->done = TRUE;
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
      k->done = TRUE;
      /* We're simulating an HTTP 304 from server so we return
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
        goto fail;
    }
    else
#endif
      DEBUGASSERT(Curl_conn_is_http2(data, conn, FIRSTSOCKET));
    break;
  case CURL_HTTP_VERSION_1_1:
    /* continue with HTTP/1.x when explicitly requested */
    break;
  default:
    /* Check if user wants to use HTTP/2 with clear TCP */
    if(Curl_http2_may_switch(data, conn, FIRSTSOCKET)) {
      DEBUGF(infof(data, "HTTP/2 over clean TCP"));
      result = Curl_http2_switch(data, conn, FIRSTSOCKET);
      if(result)
        goto fail;
    }
    break;
  }

  /* Add collecting of headers written to client. For a new connection,
   * we might have done that already, but reuse
   * or multiplex needs it here as well. */
  result = Curl_headers_init(data);
  if(result)
    goto fail;

  result = Curl_http_host(data, conn);
  if(result)
    goto fail;

  result = Curl_http_useragent(data);
  if(result)
    goto fail;

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
      goto fail;
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
    goto fail;
#endif

  result = Curl_http_req_set_reader(data, httpreq, &te);
  if(result)
    goto fail;

  p_accept = Curl_checkheaders(data,
                               STRCONST("Accept"))?NULL:"Accept: */*\r\n";

  result = Curl_http_range(data, httpreq);
  if(result)
    goto fail;

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
    goto fail;
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
#ifndef CURL_DISABLE_PROXY
                  data->state.aptr.proxyuserpwd?
                  data->state.aptr.proxyuserpwd:"",
#else
                  "",
#endif
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

  /* clear userpwd and proxyuserpwd to avoid reusing old credentials
   * from reused connections */
  Curl_safefree(data->state.aptr.userpwd);
#ifndef CURL_DISABLE_PROXY
  Curl_safefree(data->state.aptr.proxyuserpwd);
#endif
  free(altused);

  if(result) {
    Curl_dyn_free(&req);
    goto fail;
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
    /* req_send takes ownership of the 'req' memory on success */
    result = Curl_http_req_complete(data, &req, httpreq);
    if(!result)
      result = Curl_req_send(data, &req);
  }
  Curl_dyn_free(&req);
  if(result)
    goto fail;

  if((conn->httpversion >= 20) && data->req.upload_chunky)
    /* upload_chunky was set above to set up the request in a chunky fashion,
       but is disabled here again to avoid that the chunked encoded version is
       actually used when sending the request body over h2 */
    data->req.upload_chunky = FALSE;
fail:
  if(CURLE_TOO_LARGE == result)
    failf(data, "HTTP request too large");
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
 * Curl_http_header() parses a single response header.
 */
CURLcode Curl_http_header(struct Curl_easy *data,
                          const char *hd, size_t hdlen)
{
  struct connectdata *conn = data->conn;
  CURLcode result;
  struct SingleRequest *k = &data->req;
  const char *v;

  switch(hd[0]) {
  case 'a':
  case 'A':
#ifndef CURL_DISABLE_ALTSVC
    v = (data->asi &&
         ((data->conn->handler->flags & PROTOPT_SSL) ||
#ifdef CURLDEBUG
          /* allow debug builds to circumvent the HTTPS restriction */
          getenv("CURL_ALTSVC_HTTP")
#else
          0
#endif
        ))? HD_VAL(hd, hdlen, "Alt-Svc:") : NULL;
    if(v) {
      /* the ALPN of the current request */
      enum alpnid id = (conn->httpversion == 30)? ALPN_h3 :
                         (conn->httpversion == 20) ? ALPN_h2 : ALPN_h1;
      return Curl_altsvc_parse(data, data->asi, v, id, conn->host.name,
                               curlx_uitous((unsigned int)conn->remote_port));
    }
#endif
    break;
  case 'c':
  case 'C':
    /* Check for Content-Length: header lines to get size */
    v = (!k->http_bodyless && !data->set.ignorecl)?
        HD_VAL(hd, hdlen, "Content-Length:") : NULL;
    if(v) {
      curl_off_t contentlength;
      CURLofft offt = curlx_strtoofft(v, NULL, 10, &contentlength);

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
      return CURLE_OK;
    }
    v = (!k->http_bodyless && data->set.str[STRING_ENCODING])?
        HD_VAL(hd, hdlen, "Content-Encoding:") : NULL;
    if(v) {
      /*
       * Process Content-Encoding. Look for the values: identity,
       * gzip, deflate, compress, x-gzip and x-compress. x-gzip and
       * x-compress are the same as gzip and compress. (Sec 3.5 RFC
       * 2616). zlib cannot handle compress.  However, errors are
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
        Curl_safefree(data->info.contenttype);
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
    if((conn->httpversion == 10) &&
       HD_IS_AND_SAYS(hd, hdlen, "Connection:", "keep-alive")) {
      /*
       * An HTTP/1.0 reply with the 'Connection: keep-alive' line
       * tells us the connection will be kept alive for our
       * pleasure.  Default action for 1.0 is to close.
       *
       * [RFC2068, section 19.7.1] */
      connkeep(conn, "Connection keep-alive");
      infof(data, "HTTP/1.0 connection set to keep alive");
      return CURLE_OK;
    }
    v = !k->http_bodyless? HD_VAL(hd, hdlen, "Content-Range:") : NULL;
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
        if(!curlx_strtoofft(ptr, NULL, 10, &k->offset)) {
          if(data->state.resume_from == k->offset)
            /* we asked for a resume and we got it */
            k->content_range = TRUE;
        }
      }
      else if(k->httpcode < 300)
        data->state.resume_from = 0; /* get everything */
    }
    break;
  case 'l':
  case 'L':
    v = (!k->http_bodyless &&
         (data->set.timecondition || data->set.get_filetime))?
        HD_VAL(hd, hdlen, "Last-Modified:") : NULL;
    if(v) {
      k->timeofdoc = Curl_getdate_capped(v);
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
    break;
  case 'p':
  case 'P':
#ifndef CURL_DISABLE_PROXY
    v = HD_VAL(hd, hdlen, "Proxy-Connection:");
    if(v) {
      if((conn->httpversion == 10) && conn->bits.httpproxy &&
         HD_IS_AND_SAYS(hd, hdlen, "Proxy-Connection:", "keep-alive")) {
        /*
         * When an HTTP/1.0 reply comes when using a proxy, the
         * 'Proxy-Connection: keep-alive' line tells us the
         * connection will be kept alive for our pleasure.
         * Default action for 1.0 is to close.
         */
        connkeep(conn, "Proxy-Connection keep-alive"); /* don't close */
        infof(data, "HTTP/1.0 proxy connection set to keep alive");
      }
      else if((conn->httpversion == 11) && conn->bits.httpproxy &&
              HD_IS_AND_SAYS(hd, hdlen, "Proxy-Connection:", "close")) {
        /*
         * We get an HTTP/1.1 response from a proxy and it says it'll
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
      if(!auth)
        return CURLE_OUT_OF_MEMORY;
      result = Curl_http_input_auth(data, TRUE, auth);
      free(auth);
      return result;
    }
#ifdef USE_SPNEGO
    if(HD_IS(hd, hdlen, "Persistent-Auth:")) {
      struct negotiatedata *negdata = &conn->negotiate;
      struct auth *authp = &data->state.authhost;
      if(authp->picked == CURLAUTH_NEGOTIATE) {
        char *persistentauth = Curl_copy_header_value(hd);
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
    break;
  case 'r':
  case 'R':
    v = HD_VAL(hd, hdlen, "Retry-After:");
    if(v) {
      /* Retry-After = HTTP-date / delay-seconds */
      curl_off_t retry_after = 0; /* zero for unknown or "now" */
      /* Try it as a decimal number, if it works it is not a date */
      (void)curlx_strtoofft(v, NULL, 10, &retry_after);
      if(!retry_after) {
        time_t date = Curl_getdate_capped(v);
        if(-1 != date)
          /* convert date to number of seconds into the future */
          retry_after = date - time(NULL);
      }
      data->info.retry_after = retry_after; /* store it */
      return CURLE_OK;
    }
    break;
  case 's':
  case 'S':
#if !defined(CURL_DISABLE_COOKIES)
    v = (data->cookies && data->state.cookie_engine)?
        HD_VAL(hd, hdlen, "Set-Cookie:") : NULL;
    if(v) {
      /* If there is a custom-set Host: name, use it here, or else use
       * real peer host name. */
      const char *host = data->state.aptr.cookiehost?
        data->state.aptr.cookiehost:conn->host.name;
      const bool secure_context =
        conn->handler->protocol&(CURLPROTO_HTTPS|CURLPROTO_WSS) ||
        strcasecompare("localhost", host) ||
        !strcmp(host, "127.0.0.1") ||
        !strcmp(host, "::1") ? TRUE : FALSE;

      Curl_share_lock(data, CURL_LOCK_DATA_COOKIE,
                      CURL_LOCK_ACCESS_SINGLE);
      Curl_cookie_add(data, data->cookies, TRUE, FALSE, v, host,
                      data->state.up.path, secure_context);
      Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
      return CURLE_OK;
    }
#endif
#ifndef CURL_DISABLE_HSTS
    /* If enabled, the header is incoming and this is over HTTPS */
    v = (data->hsts &&
         ((conn->handler->flags & PROTOPT_SSL) ||
#ifdef CURLDEBUG
           /* allow debug builds to circumvent the HTTPS restriction */
           getenv("CURL_HSTS_HTTP")
#else
           0
#endif
            )
        )? HD_VAL(hd, hdlen, "Strict-Transport-Security:") : NULL;
    if(v) {
      CURLcode check =
        Curl_hsts_parse(data->hsts, conn->host.name, v);
      if(check)
        infof(data, "Illegal STS header skipped");
#ifdef DEBUGBUILD
      else
        infof(data, "Parsed STS header fine (%zu entries)",
              data->hsts->list.size);
#endif
    }
#endif
    break;
  case 't':
  case 'T':
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
    v = (!k->http_bodyless &&
         (data->state.httpreq != HTTPREQ_HEAD) &&
         (k->httpcode != 304))?
        HD_VAL(hd, hdlen, "Transfer-Encoding:") : NULL;
    if(v) {
      /* One or more encodings. We check for chunked and/or a compression
         algorithm. */
      result = Curl_build_unencoding_stack(data, v, TRUE);
      if(result)
        return result;
      if(!k->chunk && data->set.http_transfer_encoding) {
        /* if this isn't chunked, only close can signal the end of this
         * transfer as Content-Length is said not to be trusted for
         * transfer-encoding! */
        connclose(conn, "HTTP/1.1 transfer-encoding without chunks");
        k->ignore_cl = TRUE;
      }
      return CURLE_OK;
    }
    break;
  case 'w':
  case 'W':
    if((401 == k->httpcode) && HD_IS(hd, hdlen, "WWW-Authenticate:")) {
      char *auth = Curl_copy_header_value(hd);
      if(!auth)
        return CURLE_OUT_OF_MEMORY;
      result = Curl_http_input_auth(data, FALSE, auth);
      free(auth);
      return result;
    }
    break;
  }

  if(conn->handler->protocol & CURLPROTO_RTSP) {
    result = Curl_rtsp_parseheader(data, hd);
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
    if(conn->httpversion &&
       (k->httpversion/10 != conn->httpversion/10)) {
      failf(data, "Version mismatch (from HTTP/%u to HTTP/%u)",
            conn->httpversion/10, k->httpversion/10);
      return CURLE_UNSUPPORTED_PROTOCOL;
    }
    break;
  default:
    failf(data, "Unsupported HTTP version (%u.%d) in response",
          k->httpversion/10, k->httpversion%10);
    return CURLE_UNSUPPORTED_PROTOCOL;
  }

  data->info.httpcode = k->httpcode;
  data->info.httpversion = k->httpversion;
  conn->httpversion = (unsigned char)k->httpversion;

  if(!data->state.httpversion || data->state.httpversion > k->httpversion)
    /* store the lowest server version we encounter */
    data->state.httpversion = (unsigned char)k->httpversion;

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
    /* HTTP/2 cannot avoid multiplexing since it is a core functionality
       of the protocol */
    conn->bundle->multiuse = BUNDLE_MULTIPLEX;
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
    /* line folding, can't happen on line 2 */
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


static CURLcode http_on_response(struct Curl_easy *data,
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
    if(conn->httpversion != 20)
      infof(data, "Lying server, not serving HTTP/2");
  }
  if(conn->httpversion < 20) {
    conn->bundle->multiuse = BUNDLE_NO_MULTIUSE;
  }

  if(k->httpcode < 100) {
    failf(data, "Unsupported response code in HTTP response");
    return CURLE_UNSUPPORTED_PROTOCOL;
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
      Curl_http_exp100_got100(data);
      break;
    case 101:
      /* Switching Protocols only allowed from HTTP/1.1 */
      if(conn->httpversion != 11) {
        /* invalid for other HTTP versions */
        failf(data, "unexpected 101 response code");
        return CURLE_WEIRD_SERVER_REPLY;
      }
      if(k->upgr101 == UPGR101_H2) {
        /* Switching to HTTP/2, where we will get more responses */
        infof(data, "Received 101, Switching to HTTP/2");
        k->upgr101 = UPGR101_RECEIVED;
        /* We expect more response from HTTP/2 later */
        k->header = TRUE;
        k->headerline = 0; /* restart the header line counter */
        /* Any remaining `buf` bytes are already HTTP/2 and passed to
         * be processed. */
        result = Curl_http2_upgrade(data, conn, FIRSTSOCKET, buf, blen);
        if(result)
          return result;
        *pconsumed += blen;
      }
#ifdef USE_WEBSOCKETS
      else if(k->upgr101 == UPGR101_WS) {
        /* verify the response. Any passed `buf` bytes are already in
         * WebSockets format and taken in by the protocol handler. */
        result = Curl_ws_accept(data, buf, blen);
        if(result)
          return result;
        *pconsumed += blen; /* ws accept handled the data */
        k->header = FALSE; /* we will not get more responses */
        if(data->set.connect_only)
          k->keepon &= ~KEEP_RECV; /* read no more content */
      }
#endif
      else {
        /* We silently accept this as the final response.
         * TODO: this looks, uhm, wrong. What are we switching to if we
         * did not ask for an Upgrade? Maybe the application provided an
         * `Upgrade: xxx` header? */
        k->header = FALSE;
      }
      break;
    default:
      /* The server may send us other 1xx responses, like informative
       * 103. This have no influence on request processing and we expect
       * to receive a final response eventually. */
      break;
    }
    return result;
  }

  /* k->httpcode >= 200, final response */
  k->header = FALSE;

  if(k->upgr101 == UPGR101_H2) {
    /* A requested upgrade was denied, poke the multi handle to possibly
       allow a pending pipewait to continue */
    Curl_multi_connchanged(data->multi);
  }

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

#ifdef USE_WEBSOCKETS
  /* All >=200 HTTP status codes are errors when wanting websockets */
  if(data->req.upgr101 == UPGR101_WS) {
    failf(data, "Refused WebSockets upgrade: %d", k->httpcode);
    return CURLE_HTTP_RETURNED_ERROR;
  }
#endif

  /* Check if this response means the transfer errored. */
  if(http_should_fail(data, data->req.httpcode)) {
    failf(data, "The requested URL returned error: %d",
          k->httpcode);
    return CURLE_HTTP_RETURNED_ERROR;
  }

  /* Curl_http_auth_act() checks what authentication methods
   * that are available and decides which one (if any) to
   * use. It will set 'newurl' if an auth method was picked. */
  result = Curl_http_auth_act(data);
  if(result)
    return result;

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
         * connection for closure after we've read the entire response.
         */
        if(!Curl_req_done_sending(data)) {
          if((k->httpcode == 417) && Curl_http_exp100_is_selected(data)) {
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
                return result;
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
              return result;
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

  /* This is the last response that we will got for the current request.
   * Check on the body size and determine if the response is complete.
   */
  result = Curl_http_size(data);
  if(result)
    return result;

  /* If we requested a "no body", this is a good time to get
   * out and return home.
   */
  if(data->req.no_body)
    k->download_done = TRUE;

  /* If max download size is *zero* (nothing) we already have
     nothing and can safely return ok now!  But for HTTP/2, we'd
     like to call http2_handle_stream_close to properly close a
     stream.  In order to do this, we keep reading until we
     close the stream. */
  if(0 == k->maxdownload
     && !Curl_conn_is_http2(data, conn, FIRSTSOCKET)
     && !Curl_conn_is_http3(data, conn, FIRSTSOCKET))
    k->download_done = TRUE;

  /* final response without error, prepare to receive the body */
  return Curl_http_firstwrite(data);
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
    size_t consumed;

    /* now, only output this if the header AND body are requested:
     */
    Curl_debug(data, CURLINFO_HEADER_IN, (char *)hd, hdlen);

    writetype = CLIENTWRITE_HEADER |
      ((k->httpcode/100 == 1) ? CLIENTWRITE_1XX : 0);

    result = Curl_client_write(data, writetype, hd, hdlen);
    if(result)
      return result;

    result = Curl_bump_headersize(data, hdlen, FALSE);
    if(result)
      return result;

    data->req.deductheadercount =
      (100 <= k->httpcode && 199 >= k->httpcode)?data->req.headerbytecount:0;

    /* analyze the response to find out what to do. */
    /* Caveat: we clear anything in the header brigade, because a
     * response might switch HTTP version which may call use recursively.
     * Not nice, but that is currently the way of things. */
    Curl_dyn_reset(&data->state.headerb);
    result = http_on_response(data, buf_remain, blen, &consumed);
    if(result)
      return result;
    *pconsumed += consumed;
    return CURLE_OK;
  }

  /*
   * Checks for special headers coming up.
   */

  writetype = CLIENTWRITE_HEADER;
  if(!k->headerline++) {
    /* This is the first header, it MUST be the error code line
       or else we consider this to be the body right away! */
    bool fine_statusline = FALSE;

    k->httpversion = 0; /* Don't know yet */
    if(data->conn->handler->protocol & PROTO_FAMILY_HTTP) {
      /*
       * https://datatracker.ietf.org/doc/html/rfc7230#section-3.1.2
       *
       * The response code is always a three-digit number in HTTP as the spec
       * says. We allow any three-digit number here, but we cannot make
       * guarantees on future behaviors since it isn't within the protocol.
       */
      const char *p = hd;

      while(*p && ISBLANK(*p))
        p++;
      if(!strncmp(p, "HTTP/", 5)) {
        p += 5;
        switch(*p) {
        case '1':
          p++;
          if((p[0] == '.') && (p[1] == '0' || p[1] == '1')) {
            if(ISBLANK(p[2])) {
              k->httpversion = 10 + (p[1] - '0');
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
          k->httpversion = (*p - '0') * 10;
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
                  k->httpversion = 11; /* RTSP acts like HTTP 1.1 */
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
      result = Curl_http_statusline(data, data->conn);
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

  result = Curl_http_header(data, hd, hdlen);
  if(result)
    return result;

  /*
   * Taken in one (more) header. Write it to the client.
   */
  Curl_debug(data, CURLINFO_HEADER_IN, (char *)hd, hdlen);

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
      result = Curl_dyn_addn(&data->state.headerb, buf, blen);
      if(result)
        return result;
      *pconsumed += blen;

      if(!k->headerline) {
        /* check if this looks like a protocol header */
        statusline st =
          checkprotoprefix(data, conn,
                           Curl_dyn_ptr(&data->state.headerb),
                           Curl_dyn_len(&data->state.headerb));

        if(st == STATUS_BAD) {
          /* this is not the beginning of a protocol first header line */
          k->header = FALSE;
          streamclose(conn, "bad HTTP: No end-of-message indicator");
          if(conn->httpversion >= 10) {
            failf(data, "Invalid status line");
            return CURLE_WEIRD_SERVER_REPLY;
          }
          if(!data->set.http09_allowed) {
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
    result = Curl_dyn_addn(&data->state.headerb, buf, consumed);
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
                                       Curl_dyn_ptr(&data->state.headerb),
                                       Curl_dyn_len(&data->state.headerb));
      if(st == STATUS_BAD) {
        streamclose(conn, "bad HTTP: No end-of-message indicator");
        /* this is not the beginning of a protocol first header line */
        if(conn->httpversion >= 10) {
          failf(data, "Invalid status line");
          return CURLE_WEIRD_SERVER_REPLY;
        }
        if(!data->set.http09_allowed) {
          failf(data, "Received HTTP/0.9 when not allowed");
          return CURLE_UNSUPPORTED_PROTOCOL;
        }
        k->header = FALSE;
        leftover_body = TRUE;
        goto out;
      }
    }

    result = http_rw_hd(data, Curl_dyn_ptr(&data->state.headerb),
                        Curl_dyn_len(&data->state.headerb),
                        buf, blen, &consumed);
    /* We are done with this line. We reset because response
     * processing might switch to HTTP/2 and that might call us
     * directly again. */
    Curl_dyn_reset(&data->state.headerb);
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
    Curl_dyn_free(&data->state.headerb);
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
      if(!data->req.no_body && Curl_dyn_len(&data->state.headerb)) {
        /* leftover from parsing something that turned out not
         * to be a header, only happens if we allow for
         * HTTP/0.9 like responses */
        result = Curl_client_write(data, CLIENTWRITE_BODY,
                                   Curl_dyn_ptr(&data->state.headerb),
                                   Curl_dyn_len(&data->state.headerb));
      }
      Curl_dyn_free(&data->state.headerb);
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
    result = Curl_client_write(data, flags, (char *)buf, blen);
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
  *pstatus = result? -1 : status;
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

  DEBUGASSERT(method);
  if(m_len + 1 > sizeof(req->method))
    return CURLE_BAD_FUNCTION_ARGUMENT;

  req = calloc(1, sizeof(*req));
  if(!req)
    goto out;
  memcpy(req->method, method, m_len);
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
  *preq = result? NULL : req;
  return result;
}

static CURLcode req_assign_url_authority(struct httpreq *req, CURLU *url)
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

static CURLcode req_assign_url_path(struct httpreq *req, CURLU *url)
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

CURLcode Curl_http_req_make2(struct httpreq **preq,
                             const char *method, size_t m_len,
                             CURLU *url, const char *scheme_default)
{
  struct httpreq *req;
  CURLcode result = CURLE_OUT_OF_MEMORY;
  CURLUcode uc;

  DEBUGASSERT(method);
  if(m_len + 1 > sizeof(req->method))
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

  Curl_dynhds_init(&req->headers, 0, DYN_HTTP_REQUEST);
  Curl_dynhds_init(&req->trailers, 0, DYN_HTTP_REQUEST);
  result = CURLE_OK;

out:
  if(result && req)
    Curl_http_req_free(req);
  *preq = result? NULL : req;
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
  Curl_dynhds_init(&resp->headers, 0, DYN_HTTP_REQUEST);
  Curl_dynhds_init(&resp->trailers, 0, DYN_HTTP_REQUEST);
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
    /* We are now waiting for a reply from the server or
     * a timeout on our side */
    DEBUGF(infof(data, "cr_exp100_read, start AWAITING_CONTINUE"));
    ctx->state = EXP100_AWAITING_CONTINUE;
    ctx->start = Curl_now();
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
    ms = Curl_timediff(Curl_now(), ctx->start);
    if(ms < data->set.expect_100_timeout) {
      DEBUGF(infof(data, "cr_exp100_read, AWAITING_CONTINUE, not expired"));
      data->req.keepon &= ~KEEP_SEND;
      data->req.keepon |= KEEP_SEND_TIMED;
      *nread = 0;
      *eos = FALSE;
      return CURLE_OK;
    }
    /* we've waited long enough, continue anyway */
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
  ctx->state = premature? EXP100_FAILED : EXP100_SEND_DATA;
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
  Curl_creader_def_rewind,
  Curl_creader_def_unpause,
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

void Curl_http_exp100_got100(struct Curl_easy *data)
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
    return (ctx->state == EXP100_AWAITING_CONTINUE);
  }
  return FALSE;
}

static void http_exp100_send_anyway(struct Curl_easy *data)
{
  struct Curl_creader *r = Curl_creader_get_by_type(data, &cr_exp100);
  if(r)
    http_exp100_continue(data, r);
}

bool Curl_http_exp100_is_selected(struct Curl_easy *data)
{
  struct Curl_creader *r = Curl_creader_get_by_type(data, &cr_exp100);
  return r? TRUE : FALSE;
}

#endif /* CURL_DISABLE_HTTP */
