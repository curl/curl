/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "curl_base64.h"
#include "cookie.h"
#include "vauth/vauth.h"
#include "vtls/vtls.h"
#include "http_digest.h"
#include "http_ntlm.h"
#include "curl_ntlm_wb.h"
#include "http_negotiate.h"
#include "url.h"
#include "share.h"
#include "hostip.h"
#include "http.h"
#include "select.h"
#include "parsedate.h" /* for the week day and month names */
#include "strtoofft.h"
#include "multiif.h"
#include "strcase.h"
#include "content_encoding.h"
#include "http_proxy.h"
#include "warnless.h"
#include "non-ascii.h"
#include "http2.h"
#include "connect.h"
#include "strdup.h"
#include "altsvc.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/*
 * Forward declarations.
 */

static int http_getsock_do(struct connectdata *conn,
                           curl_socket_t *socks,
                           int numsocks);
static int http_should_fail(struct connectdata *conn);

#ifndef CURL_DISABLE_PROXY
static CURLcode add_haproxy_protocol_header(struct connectdata *conn);
#endif

#ifdef USE_SSL
static CURLcode https_connecting(struct connectdata *conn, bool *done);
static int https_getsock(struct connectdata *conn,
                         curl_socket_t *socks,
                         int numsocks);
#else
#define https_connecting(x,y) CURLE_COULDNT_CONNECT
#endif
static CURLcode http_setup_conn(struct connectdata *conn);

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
  PORT_HTTP,                            /* defport */
  CURLPROTO_HTTP,                       /* protocol */
  PROTOPT_CREDSPERREQUEST               /* flags */
};

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
  https_connecting,                     /* connecting */
  ZERO_NULL,                            /* doing */
  https_getsock,                        /* proto_getsock */
  http_getsock_do,                      /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* readwrite */
  ZERO_NULL,                            /* connection_check */
  PORT_HTTPS,                           /* defport */
  CURLPROTO_HTTPS,                      /* protocol */
  PROTOPT_SSL | PROTOPT_CREDSPERREQUEST | PROTOPT_ALPN_NPN /* flags */
};
#endif

static CURLcode http_setup_conn(struct connectdata *conn)
{
  /* allocate the HTTP-specific struct for the Curl_easy, only to survive
     during this request */
  struct HTTP *http;
  struct Curl_easy *data = conn->data;
  DEBUGASSERT(data->req.protop == NULL);

  http = calloc(1, sizeof(struct HTTP));
  if(!http)
    return CURLE_OUT_OF_MEMORY;

  Curl_mime_initpart(&http->form, conn->data);
  data->req.protop = http;

  if(!CONN_INUSE(conn))
    /* if not already multi-using, setup connection details */
    Curl_http2_setup_conn(conn);
  Curl_http2_setup_req(data);
  return CURLE_OK;
}

#ifndef CURL_DISABLE_PROXY
/*
 * checkProxyHeaders() checks the linked list of custom proxy headers
 * if proxy headers are not available, then it will lookup into http header
 * link list
 *
 * It takes a connectdata struct as input instead of the Curl_easy simply to
 * know if this is a proxy request or not, as it then might check a different
 * header list. Provide the header prefix without colon!.
 */
char *Curl_checkProxyheaders(const struct connectdata *conn,
                             const char *thisheader)
{
  struct curl_slist *head;
  size_t thislen = strlen(thisheader);
  struct Curl_easy *data = conn->data;

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
#define Curl_checkProxyheaders(x,y) NULL
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
  value[len] = 0; /* zero terminate */

  return value;
}

#ifndef CURL_DISABLE_HTTP_AUTH
/*
 * http_output_basic() sets up an Authorization: header (or the proxy version)
 * for HTTP Basic authentication.
 *
 * Returns CURLcode.
 */
static CURLcode http_output_basic(struct connectdata *conn, bool proxy)
{
  size_t size = 0;
  char *authorization = NULL;
  struct Curl_easy *data = conn->data;
  char **userp;
  const char *user;
  const char *pwd;
  CURLcode result;
  char *out;

  if(proxy) {
    userp = &conn->allocptr.proxyuserpwd;
    user = conn->http_proxy.user;
    pwd = conn->http_proxy.passwd;
  }
  else {
    userp = &conn->allocptr.userpwd;
    user = conn->user;
    pwd = conn->passwd;
  }

  out = aprintf("%s:%s", user, pwd);
  if(!out)
    return CURLE_OUT_OF_MEMORY;

  result = Curl_base64_encode(data, out, strlen(out), &authorization, &size);
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
static CURLcode http_output_bearer(struct connectdata *conn)
{
  char **userp;
  CURLcode result = CURLE_OK;

  userp = &conn->allocptr.userpwd;
  free(*userp);
  *userp = aprintf("Authorization: Bearer %s\r\n",
                   conn->oauth_bearer);

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
  else {
    pick->picked = CURLAUTH_PICKNONE; /* we select to use nothing */
    picked = FALSE;
  }
  pick->avail = CURLAUTH_NONE; /* clear it here */

  return picked;
}

/*
 * Curl_http_perhapsrewind()
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
static CURLcode http_perhapsrewind(struct connectdata *conn)
{
  struct Curl_easy *data = conn->data;
  struct HTTP *http = data->req.protop;
  curl_off_t bytessent;
  curl_off_t expectsend = -1; /* default is unknown */

  if(!http)
    /* If this is still NULL, we have not reach very far and we can safely
       skip this rewinding stuff */
    return CURLE_OK;

  switch(data->set.httpreq) {
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
    switch(data->set.httpreq) {
    case HTTPREQ_POST:
      if(data->state.infilesize != -1)
        expectsend = data->state.infilesize;
      break;
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

  conn->bits.rewindaftersend = FALSE; /* default */

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
          conn->bits.rewindaftersend = TRUE;
          infof(data, "Rewind stream after send\n");
        }

        return CURLE_OK;
      }

      if(conn->bits.close)
        /* this is already marked to get closed */
        return CURLE_OK;

      infof(data, "NTLM send, close instead of sending %"
            CURL_FORMAT_CURL_OFF_T " bytes\n",
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
          conn->bits.rewindaftersend = TRUE;
          infof(data, "Rewind stream after send\n");
        }

        return CURLE_OK;
      }

      if(conn->bits.close)
        /* this is already marked to get closed */
        return CURLE_OK;

      infof(data, "NEGOTIATE send, close instead of sending %"
        CURL_FORMAT_CURL_OFF_T " bytes\n",
        (curl_off_t)(expectsend - bytessent));
    }
#endif

    /* This is not NEGOTIATE/NTLM or many bytes left to send: close */
    streamclose(conn, "Mid-auth HTTP and much data left to send");
    data->req.size = 0; /* don't download any more than 0 bytes */

    /* There still is data left to send, but this connection is marked for
       closure so we can safely do the rewind right now */
  }

  if(bytessent)
    /* we rewind now at once since if we already sent something */
    return Curl_readrewind(conn);

  return CURLE_OK;
}

/*
 * Curl_http_auth_act() gets called when all HTTP headers have been received
 * and it checks what authentication methods that are available and decides
 * which one (if any) to use. It will set 'newurl' if an auth method was
 * picked.
 */

CURLcode Curl_http_auth_act(struct connectdata *conn)
{
  struct Curl_easy *data = conn->data;
  bool pickhost = FALSE;
  bool pickproxy = FALSE;
  CURLcode result = CURLE_OK;
  unsigned long authmask = ~0ul;

  if(!conn->oauth_bearer)
    authmask &= (unsigned long)~CURLAUTH_BEARER;

  if(100 <= data->req.httpcode && 199 >= data->req.httpcode)
    /* this is a transient response code, ignore */
    return CURLE_OK;

  if(data->state.authproblem)
    return data->set.http_fail_on_error?CURLE_HTTP_RETURNED_ERROR:CURLE_OK;

  if((conn->bits.user_passwd || conn->oauth_bearer) &&
     ((data->req.httpcode == 401) ||
      (conn->bits.authneg && data->req.httpcode < 300))) {
    pickhost = pickoneauth(&data->state.authhost, authmask);
    if(!pickhost)
      data->state.authproblem = TRUE;
    if(data->state.authhost.picked == CURLAUTH_NTLM &&
       conn->httpversion > 11) {
      infof(data, "Forcing HTTP/1.1 for NTLM");
      connclose(conn, "Force HTTP/1.1 connection");
      conn->data->set.httpversion = CURL_HTTP_VERSION_1_1;
    }
  }
  if(conn->bits.proxy_user_passwd &&
     ((data->req.httpcode == 407) ||
      (conn->bits.authneg && data->req.httpcode < 300))) {
    pickproxy = pickoneauth(&data->state.authproxy,
                            authmask & ~CURLAUTH_BEARER);
    if(!pickproxy)
      data->state.authproblem = TRUE;
  }

  if(pickhost || pickproxy) {
    if((data->set.httpreq != HTTPREQ_GET) &&
       (data->set.httpreq != HTTPREQ_HEAD) &&
       !conn->bits.rewindaftersend) {
      result = http_perhapsrewind(conn);
      if(result)
        return result;
    }
    /* In case this is GSS auth, the newurl field is already allocated so
       we must make sure to free it before allocating a new one. As figured
       out in bug #2284386 */
    Curl_safefree(data->req.newurl);
    data->req.newurl = strdup(data->change.url); /* clone URL */
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
    if((data->set.httpreq != HTTPREQ_GET) &&
       (data->set.httpreq != HTTPREQ_HEAD)) {
      data->req.newurl = strdup(data->change.url); /* clone URL */
      if(!data->req.newurl)
        return CURLE_OUT_OF_MEMORY;
      data->state.authhost.done = TRUE;
    }
  }
  if(http_should_fail(conn)) {
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
output_auth_headers(struct connectdata *conn,
                    struct auth *authstatus,
                    const char *request,
                    const char *path,
                    bool proxy)
{
  const char *auth = NULL;
  CURLcode result = CURLE_OK;
#if !defined(CURL_DISABLE_VERBOSE_STRINGS) || defined(USE_SPNEGO)
  struct Curl_easy *data = conn->data;
#endif

#ifdef CURL_DISABLE_CRYPTO_AUTH
  (void)request;
  (void)path;
#endif

#ifdef USE_SPNEGO
  if((authstatus->picked == CURLAUTH_NEGOTIATE)) {
    auth = "Negotiate";
    result = Curl_output_negotiate(conn, proxy);
    if(result)
      return result;
  }
  else
#endif
#ifdef USE_NTLM
  if(authstatus->picked == CURLAUTH_NTLM) {
    auth = "NTLM";
    result = Curl_output_ntlm(conn, proxy);
    if(result)
      return result;
  }
  else
#endif
#if defined(USE_NTLM) && defined(NTLM_WB_ENABLED)
  if(authstatus->picked == CURLAUTH_NTLM_WB) {
    auth = "NTLM_WB";
    result = Curl_output_ntlm_wb(conn, proxy);
    if(result)
      return result;
  }
  else
#endif
#ifndef CURL_DISABLE_CRYPTO_AUTH
  if(authstatus->picked == CURLAUTH_DIGEST) {
    auth = "Digest";
    result = Curl_output_digest(conn,
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
    if((proxy && conn->bits.proxy_user_passwd &&
        !Curl_checkProxyheaders(conn, "Proxy-authorization")) ||
       (!proxy && conn->bits.user_passwd &&
        !Curl_checkheaders(conn, "Authorization"))) {
      auth = "Basic";
      result = http_output_basic(conn, proxy);
      if(result)
        return result;
    }

    /* NOTE: this function should set 'done' TRUE, as the other auth
       functions work that way */
    authstatus->done = TRUE;
  }
  if(authstatus->picked == CURLAUTH_BEARER) {
    /* Bearer */
    if((!proxy && conn->oauth_bearer &&
        !Curl_checkheaders(conn, "Authorization:"))) {
      auth = "Bearer";
      result = http_output_bearer(conn);
      if(result)
        return result;
    }

    /* NOTE: this function should set 'done' TRUE, as the other auth
       functions work that way */
    authstatus->done = TRUE;
  }

  if(auth) {
    infof(data, "%s auth using %s with user '%s'\n",
          proxy ? "Proxy" : "Server", auth,
          proxy ? (conn->http_proxy.user ? conn->http_proxy.user : "") :
                  (conn->user ? conn->user : ""));
    authstatus->multipass = (!authstatus->done) ? TRUE : FALSE;
  }
  else
    authstatus->multipass = FALSE;

  return CURLE_OK;
}

/**
 * Curl_http_output_auth() setups the authentication headers for the
 * host/proxy and the correct authentication
 * method. conn->data->state.authdone is set to TRUE when authentication is
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
Curl_http_output_auth(struct connectdata *conn,
                      const char *request,
                      const char *path,
                      bool proxytunnel) /* TRUE if this is the request setting
                                           up the proxy tunnel */
{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
  struct auth *authhost;
  struct auth *authproxy;

  DEBUGASSERT(data);

  authhost = &data->state.authhost;
  authproxy = &data->state.authproxy;

  if((conn->bits.httpproxy && conn->bits.proxy_user_passwd) ||
     conn->bits.user_passwd || conn->oauth_bearer)
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
    result = output_auth_headers(conn, authproxy, request, path, TRUE);
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

  /* To prevent the user+password to get sent to other than the original
     host due to a location-follow, we do some weirdo checks here */
  if(!data->state.this_is_a_follow ||
     conn->bits.netrc ||
     !data->state.first_host ||
     data->set.allow_auth_to_other_hosts ||
     strcasecompare(data->state.first_host, conn->host.name)) {
    result = output_auth_headers(conn, authhost, request, path, FALSE);
  }
  else
    authhost->done = TRUE;

  return result;
}

#else
/* when disabled */
CURLcode
Curl_http_output_auth(struct connectdata *conn,
                      const char *request,
                      const char *path,
                      bool proxytunnel)
{
  (void)conn;
  (void)request;
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

CURLcode Curl_http_input_auth(struct connectdata *conn, bool proxy,
                              const char *auth) /* the first non-space */
{
  /*
   * This resource requires authentication
   */
  struct Curl_easy *data = conn->data;

#ifdef USE_SPNEGO
  curlnegotiate *negstate = proxy ? &conn->proxy_negotiate_state :
                                    &conn->http_negotiate_state;
#endif
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
    if(checkprefix("Negotiate", auth)) {
      if((authp->avail & CURLAUTH_NEGOTIATE) ||
         Curl_auth_is_spnego_supported()) {
        *availp |= CURLAUTH_NEGOTIATE;
        authp->avail |= CURLAUTH_NEGOTIATE;

        if(authp->picked == CURLAUTH_NEGOTIATE) {
          CURLcode result = Curl_input_negotiate(conn, proxy, auth);
          if(!result) {
            DEBUGASSERT(!data->req.newurl);
            data->req.newurl = strdup(data->change.url);
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
      if(checkprefix("NTLM", auth)) {
        if((authp->avail & CURLAUTH_NTLM) ||
           (authp->avail & CURLAUTH_NTLM_WB) ||
           Curl_auth_is_ntlm_supported()) {
          *availp |= CURLAUTH_NTLM;
          authp->avail |= CURLAUTH_NTLM;

          if(authp->picked == CURLAUTH_NTLM ||
             authp->picked == CURLAUTH_NTLM_WB) {
            /* NTLM authentication is picked and activated */
            CURLcode result = Curl_input_ntlm(conn, proxy, auth);
            if(!result) {
              data->state.authproblem = FALSE;
#ifdef NTLM_WB_ENABLED
              if(authp->picked == CURLAUTH_NTLM_WB) {
                *availp &= ~CURLAUTH_NTLM;
                authp->avail &= ~CURLAUTH_NTLM;
                *availp |= CURLAUTH_NTLM_WB;
                authp->avail |= CURLAUTH_NTLM_WB;

                result = Curl_input_ntlm_wb(conn, proxy, auth);
                if(result) {
                  infof(data, "Authentication problem. Ignoring this.\n");
                  data->state.authproblem = TRUE;
                }
              }
#endif
            }
            else {
              infof(data, "Authentication problem. Ignoring this.\n");
              data->state.authproblem = TRUE;
            }
          }
        }
      }
      else
#endif
#ifndef CURL_DISABLE_CRYPTO_AUTH
        if(checkprefix("Digest", auth)) {
          if((authp->avail & CURLAUTH_DIGEST) != 0)
            infof(data, "Ignoring duplicate digest auth header.\n");
          else if(Curl_auth_is_digest_supported()) {
            CURLcode result;

            *availp |= CURLAUTH_DIGEST;
            authp->avail |= CURLAUTH_DIGEST;

            /* We call this function on input Digest headers even if Digest
             * authentication isn't activated yet, as we need to store the
             * incoming data from this header in case we are going to use
             * Digest */
            result = Curl_input_digest(conn, proxy, auth);
            if(result) {
              infof(data, "Authentication problem. Ignoring this.\n");
              data->state.authproblem = TRUE;
            }
          }
        }
        else
#endif
          if(checkprefix("Basic", auth)) {
            *availp |= CURLAUTH_BASIC;
            authp->avail |= CURLAUTH_BASIC;
            if(authp->picked == CURLAUTH_BASIC) {
              /* We asked for Basic authentication but got a 40X back
                 anyway, which basically means our name+password isn't
                 valid. */
              authp->avail = CURLAUTH_NONE;
              infof(data, "Authentication problem. Ignoring this.\n");
              data->state.authproblem = TRUE;
            }
          }
          else
            if(checkprefix("Bearer", auth)) {
              *availp |= CURLAUTH_BEARER;
              authp->avail |= CURLAUTH_BEARER;
              if(authp->picked == CURLAUTH_BEARER) {
                /* We asked for Bearer authentication but got a 40X back
                  anyway, which basically means our token isn't valid. */
                authp->avail = CURLAUTH_NONE;
                infof(data, "Authentication problem. Ignoring this.\n");
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
 * @retval 0 communications should continue
 *
 * @retval 1 communications should not continue
 */
static int http_should_fail(struct connectdata *conn)
{
  struct Curl_easy *data;
  int httpcode;

  DEBUGASSERT(conn);
  data = conn->data;
  DEBUGASSERT(data);

  httpcode = data->req.httpcode;

  /*
  ** If we haven't been asked to fail on error,
  ** don't fail.
  */
  if(!data->set.http_fail_on_error)
    return 0;

  /*
  ** Any code < 400 is never terminal.
  */
  if(httpcode < 400)
    return 0;

  /*
  ** Any code >= 400 that's not 401 or 407 is always
  ** a terminal error
  */
  if((httpcode != 401) && (httpcode != 407))
    return 1;

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
  if((httpcode == 401) && !conn->bits.user_passwd)
    return TRUE;
  if((httpcode == 407) && !conn->bits.proxy_user_passwd)
    return TRUE;

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
  struct connectdata *conn = (struct connectdata *)userp;
  struct HTTP *http = conn->data->req.protop;
  size_t fullsize = size * nitems;

  if(!http->postsize)
    /* nothing to return */
    return 0;

  /* make sure that a HTTP request is never sent away chunked! */
  conn->data->req.forbidchunk = (http->sending == HTTPSEND_REQUEST)?TRUE:FALSE;

  if(http->postsize <= (curl_off_t)fullsize) {
    memcpy(buffer, http->postdata, (size_t)http->postsize);
    fullsize = (size_t)http->postsize;

    if(http->backup.postsize) {
      /* move backup data into focus and continue on that */
      http->postdata = http->backup.postdata;
      http->postsize = http->backup.postsize;
      conn->data->state.fread_func = http->backup.fread_func;
      conn->data->state.in = http->backup.fread_in;

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

/* ------------------------------------------------------------------------- */
/* add_buffer functions */

/*
 * Curl_add_buffer_init() sets up and returns a fine buffer struct
 */
Curl_send_buffer *Curl_add_buffer_init(void)
{
  return calloc(1, sizeof(Curl_send_buffer));
}

/*
 * Curl_add_buffer_free() frees all associated resources.
 */
void Curl_add_buffer_free(Curl_send_buffer **inp)
{
  Curl_send_buffer *in = *inp;
  if(in) /* deal with NULL input */
    free(in->buffer);
  free(in);
  *inp = NULL;
}

/*
 * Curl_add_buffer_send() sends a header buffer and frees all associated
 * memory.  Body data may be appended to the header data if desired.
 *
 * Returns CURLcode
 */
CURLcode Curl_add_buffer_send(Curl_send_buffer **inp,
                              struct connectdata *conn,

                              /* add the number of sent bytes to this
                                 counter */
                              curl_off_t *bytes_written,

                              /* how much of the buffer contains body data */
                              size_t included_body_bytes,
                              int socketindex)
{
  ssize_t amount;
  CURLcode result;
  char *ptr;
  size_t size;
  struct Curl_easy *data = conn->data;
  struct HTTP *http = data->req.protop;
  size_t sendsize;
  curl_socket_t sockfd;
  size_t headersize;
  Curl_send_buffer *in = *inp;

  DEBUGASSERT(socketindex <= SECONDARYSOCKET);

  sockfd = conn->sock[socketindex];

  /* The looping below is required since we use non-blocking sockets, but due
     to the circumstances we will just loop and try again and again etc */

  ptr = in->buffer;
  size = in->size_used;

  headersize = size - included_body_bytes; /* the initial part that isn't body
                                              is header */

  DEBUGASSERT(size > included_body_bytes);

  result = Curl_convert_to_network(data, ptr, headersize);
  /* Curl_convert_to_network calls failf if unsuccessful */
  if(result) {
    /* conversion failed, free memory and return to the caller */
    Curl_add_buffer_free(inp);
    return result;
  }

  if((conn->handler->flags & PROTOPT_SSL ||
     conn->http_proxy.proxytype == CURLPROXY_HTTPS)
     && conn->httpversion != 20) {
    /* We never send more than CURL_MAX_WRITE_SIZE bytes in one single chunk
       when we speak HTTPS, as if only a fraction of it is sent now, this data
       needs to fit into the normal read-callback buffer later on and that
       buffer is using this size.
    */

    sendsize = CURLMIN(size, CURL_MAX_WRITE_SIZE);

    /* OpenSSL is very picky and we must send the SAME buffer pointer to the
       library when we attempt to re-send this buffer. Sending the same data
       is not enough, we must use the exact same address. For this reason, we
       must copy the data to the uploadbuffer first, since that is the buffer
       we will be using if this send is retried later.
    */
    result = Curl_get_upload_buffer(data);
    if(result) {
      /* malloc failed, free memory and return to the caller */
      Curl_add_buffer_free(&in);
      return result;
    }
    memcpy(data->state.ulbuf, ptr, sendsize);
    ptr = data->state.ulbuf;
  }
  else
    sendsize = size;

  result = Curl_write(conn, sockfd, ptr, sendsize, &amount);

  if(!result) {
    /*
     * Note that we may not send the entire chunk at once, and we have a set
     * number of data bytes at the end of the big buffer (out of which we may
     * only send away a part).
     */
    /* how much of the header that was sent */
    size_t headlen = (size_t)amount>headersize ? headersize : (size_t)amount;
    size_t bodylen = amount - headlen;

    if(data->set.verbose) {
      /* this data _may_ contain binary stuff */
      Curl_debug(data, CURLINFO_HEADER_OUT, ptr, headlen);
      if(bodylen) {
        /* there was body data sent beyond the initial header part, pass that
           on to the debug callback too */
        Curl_debug(data, CURLINFO_DATA_OUT,
                   ptr + headlen, bodylen);
      }
    }

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

        ptr = in->buffer + amount;

        /* backup the currently set pointers */
        http->backup.fread_func = data->state.fread_func;
        http->backup.fread_in = data->state.in;
        http->backup.postdata = http->postdata;
        http->backup.postsize = http->postsize;

        /* set the new pointers for the request-sending */
        data->state.fread_func = (curl_read_callback)readmoredata;
        data->state.in = (void *)conn;
        http->postdata = ptr;
        http->postsize = (curl_off_t)size;

        http->send_buffer = in;
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
  Curl_add_buffer_free(&in);

  return result;
}


/*
 * add_bufferf() add the formatted input to the buffer.
 */
CURLcode Curl_add_bufferf(Curl_send_buffer **inp, const char *fmt, ...)
{
  char *s;
  va_list ap;
  Curl_send_buffer *in = *inp;
  va_start(ap, fmt);
  s = vaprintf(fmt, ap); /* this allocs a new string to append */
  va_end(ap);

  if(s) {
    CURLcode result = Curl_add_buffer(inp, s, strlen(s));
    free(s);
    return result;
  }
  /* If we failed, we cleanup the whole buffer and return error */
  free(in->buffer);
  free(in);
  *inp = NULL;
  return CURLE_OUT_OF_MEMORY;
}

/*
 * Curl_add_buffer() appends a memory chunk to the existing buffer
 */
CURLcode Curl_add_buffer(Curl_send_buffer **inp, const void *inptr,
                         size_t size)
{
  char *new_rb;
  Curl_send_buffer *in = *inp;

  if(~size < in->size_used) {
    /* If resulting used size of send buffer would wrap size_t, cleanup
       the whole buffer and return error. Otherwise the required buffer
       size will fit into a single allocatable memory chunk */
    Curl_safefree(in->buffer);
    free(in);
    *inp = NULL;
    return CURLE_OUT_OF_MEMORY;
  }

  if(!in->buffer ||
     ((in->size_used + size) > (in->size_max - 1))) {
    /* If current buffer size isn't enough to hold the result, use a
       buffer size that doubles the required size. If this new size
       would wrap size_t, then just use the largest possible one */
    size_t new_size;

    if((size > (size_t)-1 / 2) || (in->size_used > (size_t)-1 / 2) ||
       (~(size * 2) < (in->size_used * 2)))
      new_size = (size_t)-1;
    else
      new_size = (in->size_used + size) * 2;

    if(in->buffer)
      /* we have a buffer, enlarge the existing one */
      new_rb = Curl_saferealloc(in->buffer, new_size);
    else
      /* create a new buffer */
      new_rb = malloc(new_size);

    if(!new_rb) {
      /* If we failed, we cleanup the whole buffer and return error */
      free(in);
      *inp = NULL;
      return CURLE_OUT_OF_MEMORY;
    }

    in->buffer = new_rb;
    in->size_max = new_size;
  }
  memcpy(&in->buffer[in->size_used], inptr, size);

  in->size_used += size;

  return CURLE_OK;
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
                   const char *content) /* content string to find */
{
  /* RFC2616, section 4.2 says: "Each header field consists of a name followed
   * by a colon (":") and the field value. Field names are case-insensitive.
   * The field value MAY be preceded by any amount of LWS, though a single SP
   * is preferred." */

  size_t hlen = strlen(header);
  size_t clen;
  size_t len;
  const char *start;
  const char *end;

  if(!strncasecompare(headerline, header, hlen))
    return FALSE; /* doesn't start with header */

  /* pass the header */
  start = &headerline[hlen];

  /* pass all white spaces */
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
  clen = strlen(content); /* length of the word to find */

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
CURLcode Curl_http_connect(struct connectdata *conn, bool *done)
{
  CURLcode result;

  /* We default to persistent connections. We set this already in this connect
     function to make the re-use checks properly be able to check this bit. */
  connkeep(conn, "HTTP default");

  /* the CONNECT procedure might not have been completed */
  result = Curl_proxy_connect(conn, FIRSTSOCKET);
  if(result)
    return result;

  if(conn->bits.proxy_connect_closed)
    /* this is not an error, just part of the connection negotiation */
    return CURLE_OK;

  if(CONNECT_FIRSTSOCKET_PROXY_SSL())
    return CURLE_OK; /* wait for HTTPS proxy SSL initialization to complete */

  if(Curl_connect_ongoing(conn))
    /* nothing else to do except wait right now - we're not done here. */
    return CURLE_OK;

#ifndef CURL_DISABLE_PROXY
  if(conn->data->set.haproxyprotocol) {
    /* add HAProxy PROXY protocol header */
    result = add_haproxy_protocol_header(conn);
    if(result)
      return result;
  }
#endif

  if(conn->given->protocol & CURLPROTO_HTTPS) {
    /* perform SSL initialization */
    result = https_connecting(conn, done);
    if(result)
      return result;
  }
  else
    *done = TRUE;

  return CURLE_OK;
}

/* this returns the socket to wait for in the DO and DOING state for the multi
   interface and then we're always _sending_ a request and thus we wait for
   the single socket to become writable only */
static int http_getsock_do(struct connectdata *conn,
                           curl_socket_t *socks,
                           int numsocks)
{
  /* write mode */
  (void)numsocks; /* unused, we trust it to be at least 1 */
  socks[0] = conn->sock[FIRSTSOCKET];
  return GETSOCK_WRITESOCK(0);
}

#ifndef CURL_DISABLE_PROXY
static CURLcode add_haproxy_protocol_header(struct connectdata *conn)
{
  char proxy_header[128];
  Curl_send_buffer *req_buffer;
  CURLcode result;
  char tcp_version[5];

  /* Emit the correct prefix for IPv6 */
  if(conn->bits.ipv6) {
    strcpy(tcp_version, "TCP6");
  }
  else {
    strcpy(tcp_version, "TCP4");
  }

  msnprintf(proxy_header,
            sizeof(proxy_header),
            "PROXY %s %s %s %li %li\r\n",
            tcp_version,
            conn->data->info.conn_local_ip,
            conn->data->info.conn_primary_ip,
            conn->data->info.conn_local_port,
            conn->data->info.conn_primary_port);

  req_buffer = Curl_add_buffer_init();
  if(!req_buffer)
    return CURLE_OUT_OF_MEMORY;

  result = Curl_add_bufferf(&req_buffer, proxy_header);
  if(result)
    return result;

  result = Curl_add_buffer_send(&req_buffer,
                                conn,
                                &conn->data->info.request_size,
                                0,
                                FIRSTSOCKET);

  return result;
}
#endif

#ifdef USE_SSL
static CURLcode https_connecting(struct connectdata *conn, bool *done)
{
  CURLcode result;
  DEBUGASSERT((conn) && (conn->handler->flags & PROTOPT_SSL));

  /* perform SSL initialization for this socket */
  result = Curl_ssl_connect_nonblocking(conn, FIRSTSOCKET, done);
  if(result)
    connclose(conn, "Failed HTTPS connection");

  return result;
}

static int https_getsock(struct connectdata *conn,
                         curl_socket_t *socks,
                         int numsocks)
{
  if(conn->handler->flags & PROTOPT_SSL)
    return Curl_ssl_getsock(conn, socks, numsocks);
  return GETSOCK_BLANK;
}
#endif /* USE_SSL */

/*
 * Curl_http_done() gets called after a single HTTP request has been
 * performed.
 */

CURLcode Curl_http_done(struct connectdata *conn,
                        CURLcode status, bool premature)
{
  struct Curl_easy *data = conn->data;
  struct HTTP *http = data->req.protop;

  /* Clear multipass flag. If authentication isn't done yet, then it will get
   * a chance to be set back to true when we output the next auth header */
  data->state.authhost.multipass = FALSE;
  data->state.authproxy.multipass = FALSE;

  Curl_unencode_cleanup(conn);

  /* set the proper values (possibly modified on POST) */
  conn->seek_func = data->set.seek_func; /* restore */
  conn->seek_client = data->set.seek_client; /* restore */

  if(!http)
    return CURLE_OK;

  if(http->send_buffer) {
    Curl_add_buffer_free(&http->send_buffer);
  }

  Curl_http2_done(conn, premature);

  Curl_mime_cleanpart(&http->form);

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
static bool use_http_1_1plus(const struct Curl_easy *data,
                             const struct connectdata *conn)
{
  if((data->state.httpversion == 10) || (conn->httpversion == 10))
    return FALSE;
  if((data->set.httpversion == CURL_HTTP_VERSION_1_0) &&
     (conn->httpversion <= 10))
    return FALSE;
  return ((data->set.httpversion == CURL_HTTP_VERSION_NONE) ||
          (data->set.httpversion >= CURL_HTTP_VERSION_1_1));
}

static const char *get_http_string(const struct Curl_easy *data,
                                   const struct connectdata *conn)
{
#ifdef USE_NGHTTP2
  if(conn->proto.httpc.h2)
    return "2";
#endif

  if(use_http_1_1plus(data, conn))
    return "1.1";

  return "1.0";
}

/* check and possibly add an Expect: header */
static CURLcode expect100(struct Curl_easy *data,
                          struct connectdata *conn,
                          Curl_send_buffer *req_buffer)
{
  CURLcode result = CURLE_OK;
  data->state.expect100header = FALSE; /* default to false unless it is set
                                          to TRUE below */
  if(use_http_1_1plus(data, conn) &&
     (conn->httpversion != 20)) {
    /* if not doing HTTP 1.0 or version 2, or disabled explicitly, we add an
       Expect: 100-continue to the headers which actually speeds up post
       operations (as there is one packet coming back from the web server) */
    const char *ptr = Curl_checkheaders(conn, "Expect");
    if(ptr) {
      data->state.expect100header =
        Curl_compareheader(ptr, "Expect:", "100-continue");
    }
    else {
      result = Curl_add_bufferf(&req_buffer,
                                "Expect: 100-continue\r\n");
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
                                    Curl_send_buffer *buffer,
                                    struct Curl_easy *handle)
{
  char *ptr = NULL;
  CURLcode result = CURLE_OK;
  const char *endofline_native = NULL;
  const char *endofline_network = NULL;

  if(
#ifdef CURL_DO_LINEEND_CONV
     (handle->set.prefer_ascii) ||
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
      result = Curl_add_bufferf(&buffer, "%s%s", trailers->data,
                                endofline_native);
      if(result)
        return result;
    }
    else
      infof(handle, "Malformatted trailing header ! Skipping trailer.");
    trailers = trailers->next;
  }
  result = Curl_add_buffer(&buffer, endofline_network,
                           strlen(endofline_network));
  return result;
}

CURLcode Curl_add_custom_headers(struct connectdata *conn,
                                 bool is_connect,
                                 Curl_send_buffer *req_buffer)
{
  char *ptr;
  struct curl_slist *h[2];
  struct curl_slist *headers;
  int numlists = 1; /* by default */
  struct Curl_easy *data = conn->data;
  int i;

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
                Curl_add_buffer_free(&req_buffer);
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
      if(ptr) {
        /* we require a colon for this to be a true header */

        ptr++; /* pass the colon */
        while(*ptr && ISSPACE(*ptr))
          ptr++;

        if(*ptr || semicolonp) {
          /* only send this if the contents was non-blank or done special */
          CURLcode result = CURLE_OK;
          char *compare = semicolonp ? semicolonp : headers->data;

          if(conn->allocptr.host &&
             /* a Host: header was sent already, don't pass on any custom Host:
                header as that will produce *two* in the same request! */
             checkprefix("Host:", compare))
            ;
          else if(data->set.httpreq == HTTPREQ_POST_FORM &&
                  /* this header (extended by formdata.c) is sent later */
                  checkprefix("Content-Type:", compare))
            ;
          else if(data->set.httpreq == HTTPREQ_POST_MIME &&
                  /* this header is sent later */
                  checkprefix("Content-Type:", compare))
            ;
          else if(conn->bits.authneg &&
                  /* while doing auth neg, don't allow the custom length since
                     we will force length zero then */
                  checkprefix("Content-Length:", compare))
            ;
          else if(conn->allocptr.te &&
                  /* when asking for Transfer-Encoding, don't pass on a custom
                     Connection: */
                  checkprefix("Connection:", compare))
            ;
          else if((conn->httpversion == 20) &&
                  checkprefix("Transfer-Encoding:", compare))
            /* HTTP/2 doesn't support chunked requests */
            ;
          else if((checkprefix("Authorization:", compare) ||
                   checkprefix("Cookie:", compare)) &&
                  /* be careful of sending this potentially sensitive header to
                     other hosts */
                  (data->state.this_is_a_follow &&
                   data->state.first_host &&
                   !data->set.allow_auth_to_other_hosts &&
                   !strcasecompare(data->state.first_host, conn->host.name)))
            ;
          else {
            result = Curl_add_bufferf(&req_buffer, "%s\r\n", compare);
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
                                Curl_send_buffer *req_buffer)
{
  const struct tm *tm;
  struct tm keeptime;
  CURLcode result;
  char datestr[80];
  const char *condp;

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
    break;
  case CURL_TIMECOND_IFUNMODSINCE:
    condp = "If-Unmodified-Since";
    break;
  case CURL_TIMECOND_LASTMOD:
    condp = "Last-Modified";
    break;
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

  result = Curl_add_buffer(&req_buffer, datestr, strlen(datestr));

  return result;
}
#else
/* disabled */
CURLcode Curl_add_timecondition(struct Curl_easy *data,
                                Curl_send_buffer *req_buffer)
{
  (void)data;
  (void)req_buffer;
  return CURLE_OK;
}
#endif

/*
 * Curl_http() gets called from the generic multi_do() function when a HTTP
 * request is to be performed. This creates and sends a properly constructed
 * HTTP request.
 */
CURLcode Curl_http(struct connectdata *conn, bool *done)
{
  struct Curl_easy *data = conn->data;
  CURLcode result = CURLE_OK;
  struct HTTP *http;
  const char *path = data->state.up.path;
  const char *query = data->state.up.query;
  bool paste_ftp_userpwd = FALSE;
  char ftp_typecode[sizeof("/;type=?")] = "";
  const char *host = conn->host.name;
  const char *te = ""; /* transfer-encoding */
  const char *ptr;
  const char *request;
  Curl_HttpReq httpreq = data->set.httpreq;
#if !defined(CURL_DISABLE_COOKIES)
  char *addcookies = NULL;
#endif
  curl_off_t included_body = 0;
  const char *httpstring;
  Curl_send_buffer *req_buffer;
  curl_off_t postsize = 0; /* curl_off_t to handle large file sizes */

  /* Always consider the DO phase done after this function call, even if there
     may be parts of the request that is not yet sent, since we can deal with
     the rest of the request in the PERFORM phase. */
  *done = TRUE;

  if(conn->httpversion < 20) { /* unless the connection is re-used and already
                                  http2 */
    switch(conn->negnpn) {
    case CURL_HTTP_VERSION_2:
      conn->httpversion = 20; /* we know we're on HTTP/2 now */

      result = Curl_http2_switched(conn, NULL, 0);
      if(result)
        return result;
      break;
    case CURL_HTTP_VERSION_1_1:
      /* continue with HTTP/1.1 when explicitly requested */
      break;
    default:
      /* Check if user wants to use HTTP/2 with clear TCP*/
#ifdef USE_NGHTTP2
      if(conn->data->set.httpversion ==
         CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE) {
        if(conn->bits.httpproxy && !conn->bits.tunnel_proxy) {
          /* We don't support HTTP/2 proxies yet. Also it's debatable whether
             or not this setting should apply to HTTP/2 proxies. */
          infof(data, "Ignoring HTTP/2 prior knowledge due to proxy\n");
          break;
        }

        DEBUGF(infof(data, "HTTP/2 over clean TCP\n"));
        conn->httpversion = 20;

        result = Curl_http2_switched(conn, NULL, 0);
        if(result)
          return result;
      }
#endif
      break;
    }
  }
  else {
    /* prepare for a http2 request */
    result = Curl_http2_setup(conn);
    if(result)
      return result;
  }

  http = data->req.protop;
  DEBUGASSERT(http);

  if(!data->state.this_is_a_follow) {
    /* Free to avoid leaking memory on multiple requests*/
    free(data->state.first_host);

    data->state.first_host = strdup(conn->host.name);
    if(!data->state.first_host)
      return CURLE_OUT_OF_MEMORY;

    data->state.first_remote_port = conn->remote_port;
  }

  if((conn->handler->protocol&(PROTO_FAMILY_HTTP|CURLPROTO_FTP)) &&
     data->set.upload) {
    httpreq = HTTPREQ_PUT;
  }

  /* Now set the 'request' pointer to the proper request string */
  if(data->set.str[STRING_CUSTOMREQUEST])
    request = data->set.str[STRING_CUSTOMREQUEST];
  else {
    if(data->set.opt_no_body)
      request = "HEAD";
    else {
      DEBUGASSERT((httpreq > HTTPREQ_NONE) && (httpreq < HTTPREQ_LAST));
      switch(httpreq) {
      case HTTPREQ_POST:
      case HTTPREQ_POST_FORM:
      case HTTPREQ_POST_MIME:
        request = "POST";
        break;
      case HTTPREQ_PUT:
        request = "PUT";
        break;
      case HTTPREQ_OPTIONS:
        request = "OPTIONS";
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

  /* The User-Agent string might have been allocated in url.c already, because
     it might have been used in the proxy connect, but if we have got a header
     with the user-agent string specified, we erase the previously made string
     here. */
  if(Curl_checkheaders(conn, "User-Agent")) {
    free(conn->allocptr.uagent);
    conn->allocptr.uagent = NULL;
  }

  /* setup the authentication headers */
  {
    char *pq = NULL;
    if(query && *query) {
      pq = aprintf("%s?%s", path, query);
      if(!pq)
        return CURLE_OUT_OF_MEMORY;
    }
    result = Curl_http_output_auth(conn, request, (pq ? pq : path), FALSE);
    free(pq);
    if(result)
      return result;
  }

  if(((data->state.authhost.multipass && !data->state.authhost.done)
      || (data->state.authproxy.multipass && !data->state.authproxy.done)) &&
     (httpreq != HTTPREQ_GET) &&
     (httpreq != HTTPREQ_HEAD)) {
    /* Auth is required and we are not authenticated yet. Make a PUT or POST
       with content-length zero as a "probe". */
    conn->bits.authneg = TRUE;
  }
  else
    conn->bits.authneg = FALSE;

  Curl_safefree(conn->allocptr.ref);
  if(data->change.referer && !Curl_checkheaders(conn, "Referer")) {
    conn->allocptr.ref = aprintf("Referer: %s\r\n", data->change.referer);
    if(!conn->allocptr.ref)
      return CURLE_OUT_OF_MEMORY;
  }
  else
    conn->allocptr.ref = NULL;

#if !defined(CURL_DISABLE_COOKIES)
  if(data->set.str[STRING_COOKIE] && !Curl_checkheaders(conn, "Cookie"))
    addcookies = data->set.str[STRING_COOKIE];
#endif

  if(!Curl_checkheaders(conn, "Accept-Encoding") &&
     data->set.str[STRING_ENCODING]) {
    Curl_safefree(conn->allocptr.accept_encoding);
    conn->allocptr.accept_encoding =
      aprintf("Accept-Encoding: %s\r\n", data->set.str[STRING_ENCODING]);
    if(!conn->allocptr.accept_encoding)
      return CURLE_OUT_OF_MEMORY;
  }
  else {
    Curl_safefree(conn->allocptr.accept_encoding);
    conn->allocptr.accept_encoding = NULL;
  }

#ifdef HAVE_LIBZ
  /* we only consider transfer-encoding magic if libz support is built-in */

  if(!Curl_checkheaders(conn, "TE") &&
     data->set.http_transfer_encoding) {
    /* When we are to insert a TE: header in the request, we must also insert
       TE in a Connection: header, so we need to merge the custom provided
       Connection: header and prevent the original to get sent. Note that if
       the user has inserted his/hers own TE: header we don't do this magic
       but then assume that the user will handle it all! */
    char *cptr = Curl_checkheaders(conn, "Connection");
#define TE_HEADER "TE: gzip\r\n"

    Curl_safefree(conn->allocptr.te);

    if(cptr) {
      cptr = Curl_copy_header_value(cptr);
      if(!cptr)
        return CURLE_OUT_OF_MEMORY;
    }

    /* Create the (updated) Connection: header */
    conn->allocptr.te = aprintf("Connection: %s%sTE\r\n" TE_HEADER,
                                cptr ? cptr : "", (cptr && *cptr) ? ", ":"");

    free(cptr);
    if(!conn->allocptr.te)
      return CURLE_OUT_OF_MEMORY;
  }
#endif

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
    const char *cthdr = Curl_checkheaders(conn, "Content-Type");

    /* Read and seek body only. */
    http->sendit->flags |= MIME_BODY_ONLY;

    /* Prepare the mime structure headers & set content type. */

    if(cthdr)
      for(cthdr += 13; *cthdr == ' '; cthdr++)
        ;
    else if(http->sendit->kind == MIMEKIND_MULTIPART)
      cthdr = "multipart/form-data";

    curl_mime_headers(http->sendit, data->set.headers, 0);
    result = Curl_mime_prepare_headers(http->sendit, cthdr,
                                       NULL, MIMESTRATEGY_FORM);
    curl_mime_headers(http->sendit, NULL, 0);
    if(!result)
      result = Curl_mime_rewind(http->sendit);
    if(result)
      return result;
    http->postsize = Curl_mime_size(http->sendit);
  }
#endif

  ptr = Curl_checkheaders(conn, "Transfer-Encoding");
  if(ptr) {
    /* Some kind of TE is requested, check if 'chunked' is chosen */
    data->req.upload_chunky =
      Curl_compareheader(ptr, "Transfer-Encoding:", "chunked");
  }
  else {
    if((conn->handler->protocol & PROTO_FAMILY_HTTP) &&
       (((httpreq == HTTPREQ_POST_MIME || httpreq == HTTPREQ_POST_FORM) &&
       http->postsize < 0) ||
       (data->set.upload && data->state.infilesize == -1))) {
      if(conn->bits.authneg)
        /* don't enable chunked during auth neg */
        ;
      else if(use_http_1_1plus(data, conn)) {
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
      te = "Transfer-Encoding: chunked\r\n";
  }

  Curl_safefree(conn->allocptr.host);

  ptr = Curl_checkheaders(conn, "Host");
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
      Curl_safefree(conn->allocptr.cookiehost);
      conn->allocptr.cookiehost = cookiehost;
    }
#endif

    if(strcmp("Host:", ptr)) {
      conn->allocptr.host = aprintf("Host:%s\r\n", &ptr[5]);
      if(!conn->allocptr.host)
        return CURLE_OUT_OF_MEMORY;
    }
    else
      /* when clearing the header */
      conn->allocptr.host = NULL;
  }
  else {
    /* When building Host: headers, we must put the host name within
       [brackets] if the host name is a plain IPv6-address. RFC2732-style. */

    if(((conn->given->protocol&CURLPROTO_HTTPS) &&
        (conn->remote_port == PORT_HTTPS)) ||
       ((conn->given->protocol&CURLPROTO_HTTP) &&
        (conn->remote_port == PORT_HTTP)) )
      /* if(HTTPS on port 443) OR (HTTP on port 80) then don't include
         the port number in the host string */
      conn->allocptr.host = aprintf("Host: %s%s%s\r\n",
                                    conn->bits.ipv6_ip?"[":"",
                                    host,
                                    conn->bits.ipv6_ip?"]":"");
    else
      conn->allocptr.host = aprintf("Host: %s%s%s:%d\r\n",
                                    conn->bits.ipv6_ip?"[":"",
                                    host,
                                    conn->bits.ipv6_ip?"]":"",
                                    conn->remote_port);

    if(!conn->allocptr.host)
      /* without Host: we can't make a nice request */
      return CURLE_OUT_OF_MEMORY;
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
    /* now extract the new version of the URL */
    uc = curl_url_get(h, CURLUPART_URL, &url, 0);
    if(uc) {
      curl_url_cleanup(h);
      return CURLE_OUT_OF_MEMORY;
    }

    if(data->change.url_alloc)
      free(data->change.url);

    data->change.url = url;
    data->change.url_alloc = TRUE;

    curl_url_cleanup(h);

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
          char *p = ftp_typecode;
          /* avoid sending invalid URLs like ftp://example.com;type=i if the
           * user specified ftp://example.com without the slash */
          if(!*data->state.up.path && path[strlen(path) - 1] != '/') {
            *p++ = '/';
          }
          msnprintf(p, sizeof(ftp_typecode) - 1, ";type=%c",
                    data->set.prefer_ascii ? 'a' : 'i');
        }
      }
      if(conn->bits.user_passwd && !conn->bits.userpwd_in_url)
        paste_ftp_userpwd = TRUE;
    }
  }
#endif /* CURL_DISABLE_PROXY */

  http->p_accept = Curl_checkheaders(conn, "Accept")?NULL:"Accept: */*\r\n";

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

    if(data->state.resume_from && !data->state.this_is_a_follow) {
      /* do we still game? */

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
  if(data->state.use_range) {
    /*
     * A range is selected. We use different headers whether we're downloading
     * or uploading and we always let customized headers override our internal
     * ones if any such are specified.
     */
    if(((httpreq == HTTPREQ_GET) || (httpreq == HTTPREQ_HEAD)) &&
       !Curl_checkheaders(conn, "Range")) {
      /* if a line like this was already allocated, free the previous one */
      free(conn->allocptr.rangeline);
      conn->allocptr.rangeline = aprintf("Range: bytes=%s\r\n",
                                         data->state.range);
    }
    else if((httpreq == HTTPREQ_POST || httpreq == HTTPREQ_PUT) &&
            !Curl_checkheaders(conn, "Content-Range")) {

      /* if a line like this was already allocated, free the previous one */
      free(conn->allocptr.rangeline);

      if(data->set.set_resume_from < 0) {
        /* Upload resume was asked for, but we don't know the size of the
           remote part so we tell the server (and act accordingly) that we
           upload the whole file (again) */
        conn->allocptr.rangeline =
          aprintf("Content-Range: bytes 0-%" CURL_FORMAT_CURL_OFF_T
                  "/%" CURL_FORMAT_CURL_OFF_T "\r\n",
                  data->state.infilesize - 1, data->state.infilesize);

      }
      else if(data->state.resume_from) {
        /* This is because "resume" was selected */
        curl_off_t total_expected_size =
          data->state.resume_from + data->state.infilesize;
        conn->allocptr.rangeline =
          aprintf("Content-Range: bytes %s%" CURL_FORMAT_CURL_OFF_T
                  "/%" CURL_FORMAT_CURL_OFF_T "\r\n",
                  data->state.range, total_expected_size-1,
                  total_expected_size);
      }
      else {
        /* Range was selected and then we just pass the incoming range and
           append total size */
        conn->allocptr.rangeline =
          aprintf("Content-Range: bytes %s/%" CURL_FORMAT_CURL_OFF_T "\r\n",
                  data->state.range, data->state.infilesize);
      }
      if(!conn->allocptr.rangeline)
        return CURLE_OUT_OF_MEMORY;
    }
  }

  httpstring = get_http_string(data, conn);

  /* initialize a dynamic send-buffer */
  req_buffer = Curl_add_buffer_init();

  if(!req_buffer)
    return CURLE_OUT_OF_MEMORY;

  /* add the main request stuff */
  /* GET/HEAD/POST/PUT */
  result = Curl_add_bufferf(&req_buffer, "%s ", request);
  if(result)
    return result;

  if(data->set.str[STRING_TARGET]) {
    path = data->set.str[STRING_TARGET];
    query = NULL;
  }

  /* url */
  if(conn->bits.httpproxy && !conn->bits.tunnel_proxy) {
    char *url = data->change.url;
    result = Curl_add_buffer(&req_buffer, url, strlen(url));
  }
  else if(paste_ftp_userpwd)
    result = Curl_add_bufferf(&req_buffer, "ftp://%s:%s@%s",
                              conn->user, conn->passwd,
                              path + sizeof("ftp://") - 1);
  else {
    result = Curl_add_buffer(&req_buffer, path, strlen(path));
    if(result)
      return result;
    if(query)
      result = Curl_add_bufferf(&req_buffer, "?%s", query);
  }
  if(result)
    return result;

  result =
    Curl_add_bufferf(&req_buffer,
                     "%s" /* ftp typecode (;type=x) */
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
                     "%s",/* transfer-encoding */

                     ftp_typecode,
                     httpstring,
                     (conn->allocptr.host?conn->allocptr.host:""),
                     conn->allocptr.proxyuserpwd?
                     conn->allocptr.proxyuserpwd:"",
                     conn->allocptr.userpwd?conn->allocptr.userpwd:"",
                     (data->state.use_range && conn->allocptr.rangeline)?
                     conn->allocptr.rangeline:"",
                     (data->set.str[STRING_USERAGENT] &&
                      *data->set.str[STRING_USERAGENT] &&
                      conn->allocptr.uagent)?
                     conn->allocptr.uagent:"",
                     http->p_accept?http->p_accept:"",
                     conn->allocptr.te?conn->allocptr.te:"",
                     (data->set.str[STRING_ENCODING] &&
                      *data->set.str[STRING_ENCODING] &&
                      conn->allocptr.accept_encoding)?
                     conn->allocptr.accept_encoding:"",
                     (data->change.referer && conn->allocptr.ref)?
                     conn->allocptr.ref:"" /* Referer: <data> */,
                     (conn->bits.httpproxy &&
                      !conn->bits.tunnel_proxy &&
                      !Curl_checkProxyheaders(conn, "Proxy-Connection"))?
                     "Proxy-Connection: Keep-Alive\r\n":"",
                     te
      );

  /* clear userpwd and proxyuserpwd to avoid re-using old credentials
   * from re-used connections */
  Curl_safefree(conn->allocptr.userpwd);
  Curl_safefree(conn->allocptr.proxyuserpwd);

  if(result)
    return result;

  if(!(conn->handler->flags&PROTOPT_SSL) &&
     conn->httpversion != 20 &&
     (data->set.httpversion == CURL_HTTP_VERSION_2)) {
    /* append HTTP2 upgrade magic stuff to the HTTP request if it isn't done
       over SSL */
    result = Curl_http2_request_upgrade(req_buffer, conn);
    if(result)
      return result;
  }

#if !defined(CURL_DISABLE_COOKIES)
  if(data->cookies || addcookies) {
    struct Cookie *co = NULL; /* no cookies from start */
    int count = 0;

    if(data->cookies) {
      Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
      co = Curl_cookie_getlist(data->cookies,
                               conn->allocptr.cookiehost?
                               conn->allocptr.cookiehost:host,
                               data->state.up.path,
                               (conn->handler->protocol&CURLPROTO_HTTPS)?
                               TRUE:FALSE);
      Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
    }
    if(co) {
      struct Cookie *store = co;
      /* now loop through all cookies that matched */
      while(co) {
        if(co->value) {
          if(0 == count) {
            result = Curl_add_bufferf(&req_buffer, "Cookie: ");
            if(result)
              break;
          }
          result = Curl_add_bufferf(&req_buffer,
                                    "%s%s=%s", count?"; ":"",
                                    co->name, co->value);
          if(result)
            break;
          count++;
        }
        co = co->next; /* next cookie please */
      }
      Curl_cookie_freelist(store);
    }
    if(addcookies && !result) {
      if(!count)
        result = Curl_add_bufferf(&req_buffer, "Cookie: ");
      if(!result) {
        result = Curl_add_bufferf(&req_buffer, "%s%s", count?"; ":"",
                                  addcookies);
        count++;
      }
    }
    if(count && !result)
      result = Curl_add_buffer(&req_buffer, "\r\n", 2);

    if(result)
      return result;
  }
#endif

  result = Curl_add_timecondition(data, req_buffer);
  if(result)
    return result;

  result = Curl_add_custom_headers(conn, FALSE, req_buffer);
  if(result)
    return result;

  http->postdata = NULL;  /* nothing to post at this point */
  Curl_pgrsSetUploadSize(data, -1); /* upload size is unknown atm */

  /* If 'authdone' is FALSE, we must not set the write socket index to the
     Curl_transfer() call below, as we're not ready to actually upload any
     data yet. */

  switch(httpreq) {

  case HTTPREQ_PUT: /* Let's PUT the data to the server! */

    if(conn->bits.authneg)
      postsize = 0;
    else
      postsize = data->state.infilesize;

    if((postsize != -1) && !data->req.upload_chunky &&
       (conn->bits.authneg || !Curl_checkheaders(conn, "Content-Length"))) {
      /* only add Content-Length if not uploading chunked */
      result = Curl_add_bufferf(&req_buffer,
                                "Content-Length: %" CURL_FORMAT_CURL_OFF_T
                                "\r\n", postsize);
      if(result)
        return result;
    }

    if(postsize != 0) {
      result = expect100(data, conn, req_buffer);
      if(result)
        return result;
    }

    result = Curl_add_buffer(&req_buffer, "\r\n", 2); /* end of headers */
    if(result)
      return result;

    /* set the upload size to the progress meter */
    Curl_pgrsSetUploadSize(data, postsize);

    /* this sends the buffer and frees all the buffer resources */
    result = Curl_add_buffer_send(&req_buffer, conn,
                                  &data->info.request_size, 0, FIRSTSOCKET);
    if(result)
      failf(data, "Failed sending PUT request");
    else
      /* prepare for transfer */
      Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE,
                          postsize?FIRSTSOCKET:-1);
    if(result)
      return result;
    break;

  case HTTPREQ_POST_FORM:
  case HTTPREQ_POST_MIME:
    /* This is form posting using mime data. */
    if(conn->bits.authneg) {
      /* nothing to post! */
      result = Curl_add_bufferf(&req_buffer, "Content-Length: 0\r\n\r\n");
      if(result)
        return result;

      result = Curl_add_buffer_send(&req_buffer, conn,
                                    &data->info.request_size, 0, FIRSTSOCKET);
      if(result)
        failf(data, "Failed sending POST request");
      else
        /* setup variables for the upcoming transfer */
        Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE, -1);
      break;
    }

    data->state.infilesize = postsize = http->postsize;

    /* We only set Content-Length and allow a custom Content-Length if
       we don't upload data chunked, as RFC2616 forbids us to set both
       kinds of headers (Transfer-Encoding: chunked and Content-Length) */
    if(postsize != -1 && !data->req.upload_chunky &&
       (conn->bits.authneg || !Curl_checkheaders(conn, "Content-Length"))) {
      /* we allow replacing this header if not during auth negotiation,
         although it isn't very wise to actually set your own */
      result = Curl_add_bufferf(&req_buffer,
                                "Content-Length: %" CURL_FORMAT_CURL_OFF_T
                                "\r\n", postsize);
      if(result)
        return result;
    }

#ifndef CURL_DISABLE_MIME
    /* Output mime-generated headers. */
    {
      struct curl_slist *hdr;

      for(hdr = http->sendit->curlheaders; hdr; hdr = hdr->next) {
        result = Curl_add_bufferf(&req_buffer, "%s\r\n", hdr->data);
        if(result)
          return result;
      }
    }
#endif

    /* For really small posts we don't use Expect: headers at all, and for
       the somewhat bigger ones we allow the app to disable it. Just make
       sure that the expect100header is always set to the preferred value
       here. */
    ptr = Curl_checkheaders(conn, "Expect");
    if(ptr) {
      data->state.expect100header =
        Curl_compareheader(ptr, "Expect:", "100-continue");
    }
    else if(postsize > EXPECT_100_THRESHOLD || postsize < 0) {
      result = expect100(data, conn, req_buffer);
      if(result)
        return result;
    }
    else
      data->state.expect100header = FALSE;

    /* make the request end in a true CRLF */
    result = Curl_add_buffer(&req_buffer, "\r\n", 2);
    if(result)
      return result;

    /* set the upload size to the progress meter */
    Curl_pgrsSetUploadSize(data, postsize);

    /* Read from mime structure. */
    data->state.fread_func = (curl_read_callback) Curl_mime_read;
    data->state.in = (void *) http->sendit;
    http->sending = HTTPSEND_BODY;

    /* this sends the buffer and frees all the buffer resources */
    result = Curl_add_buffer_send(&req_buffer, conn,
                                  &data->info.request_size, 0, FIRSTSOCKET);
    if(result)
      failf(data, "Failed sending POST request");
    else
      /* prepare for transfer */
      Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE,
                          postsize?FIRSTSOCKET:-1);
    if(result)
      return result;

    break;

  case HTTPREQ_POST:
    /* this is the simple POST, using x-www-form-urlencoded style */

    if(conn->bits.authneg)
      postsize = 0;
    else
      /* the size of the post body */
      postsize = data->state.infilesize;

    /* We only set Content-Length and allow a custom Content-Length if
       we don't upload data chunked, as RFC2616 forbids us to set both
       kinds of headers (Transfer-Encoding: chunked and Content-Length) */
    if((postsize != -1) && !data->req.upload_chunky &&
       (conn->bits.authneg || !Curl_checkheaders(conn, "Content-Length"))) {
      /* we allow replacing this header if not during auth negotiation,
         although it isn't very wise to actually set your own */
      result = Curl_add_bufferf(&req_buffer,
                                "Content-Length: %" CURL_FORMAT_CURL_OFF_T
                                "\r\n", postsize);
      if(result)
        return result;
    }

    if(!Curl_checkheaders(conn, "Content-Type")) {
      result = Curl_add_bufferf(&req_buffer,
                                "Content-Type: application/"
                                "x-www-form-urlencoded\r\n");
      if(result)
        return result;
    }

    /* For really small posts we don't use Expect: headers at all, and for
       the somewhat bigger ones we allow the app to disable it. Just make
       sure that the expect100header is always set to the preferred value
       here. */
    ptr = Curl_checkheaders(conn, "Expect");
    if(ptr) {
      data->state.expect100header =
        Curl_compareheader(ptr, "Expect:", "100-continue");
    }
    else if(postsize > EXPECT_100_THRESHOLD || postsize < 0) {
      result = expect100(data, conn, req_buffer);
      if(result)
        return result;
    }
    else
      data->state.expect100header = FALSE;

    if(data->set.postfields) {

      /* In HTTP2, we send request body in DATA frame regardless of
         its size. */
      if(conn->httpversion != 20 &&
         !data->state.expect100header &&
         (postsize < MAX_INITIAL_POST_SIZE)) {
        /* if we don't use expect: 100  AND
           postsize is less than MAX_INITIAL_POST_SIZE

           then append the post data to the HTTP request header. This limit
           is no magic limit but only set to prevent really huge POSTs to
           get the data duplicated with malloc() and family. */

        result = Curl_add_buffer(&req_buffer, "\r\n", 2); /* end of headers! */
        if(result)
          return result;

        if(!data->req.upload_chunky) {
          /* We're not sending it 'chunked', append it to the request
             already now to reduce the number if send() calls */
          result = Curl_add_buffer(&req_buffer, data->set.postfields,
                                   (size_t)postsize);
          included_body = postsize;
        }
        else {
          if(postsize) {
            /* Append the POST data chunky-style */
            result = Curl_add_bufferf(&req_buffer, "%x\r\n", (int)postsize);
            if(!result) {
              result = Curl_add_buffer(&req_buffer, data->set.postfields,
                                       (size_t)postsize);
              if(!result)
                result = Curl_add_buffer(&req_buffer, "\r\n", 2);
              included_body = postsize + 2;
            }
          }
          if(!result)
            result = Curl_add_buffer(&req_buffer, "\x30\x0d\x0a\x0d\x0a", 5);
          /* 0  CR  LF  CR  LF */
          included_body += 5;
        }
        if(result)
          return result;
        /* Make sure the progress information is accurate */
        Curl_pgrsSetUploadSize(data, postsize);
      }
      else {
        /* A huge POST coming up, do data separate from the request */
        http->postsize = postsize;
        http->postdata = data->set.postfields;

        http->sending = HTTPSEND_BODY;

        data->state.fread_func = (curl_read_callback)readmoredata;
        data->state.in = (void *)conn;

        /* set the upload size to the progress meter */
        Curl_pgrsSetUploadSize(data, http->postsize);

        result = Curl_add_buffer(&req_buffer, "\r\n", 2); /* end of headers! */
        if(result)
          return result;
      }
    }
    else {
      result = Curl_add_buffer(&req_buffer, "\r\n", 2); /* end of headers! */
      if(result)
        return result;

      if(data->req.upload_chunky && conn->bits.authneg) {
        /* Chunky upload is selected and we're negotiating auth still, send
           end-of-data only */
        result = Curl_add_buffer(&req_buffer,
                                 "\x30\x0d\x0a\x0d\x0a", 5);
        /* 0  CR  LF  CR  LF */
        if(result)
          return result;
      }

      else if(data->state.infilesize) {
        /* set the upload size to the progress meter */
        Curl_pgrsSetUploadSize(data, postsize?postsize:-1);

        /* set the pointer to mark that we will send the post body using the
           read callback, but only if we're not in authenticate
           negotiation  */
        if(!conn->bits.authneg) {
          http->postdata = (char *)&http->postdata;
          http->postsize = postsize;
        }
      }
    }
    /* issue the request */
    result = Curl_add_buffer_send(&req_buffer, conn, &data->info.request_size,
                                  (size_t)included_body, FIRSTSOCKET);

    if(result)
      failf(data, "Failed sending HTTP POST request");
    else
      Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE,
                          http->postdata?FIRSTSOCKET:-1);
    break;

  default:
    result = Curl_add_buffer(&req_buffer, "\r\n", 2);
    if(result)
      return result;

    /* issue the request */
    result = Curl_add_buffer_send(&req_buffer, conn,
                                  &data->info.request_size, 0, FIRSTSOCKET);

    if(result)
      failf(data, "Failed sending HTTP request");
    else
      /* HTTP GET/HEAD download: */
      Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE,
                          http->postdata?FIRSTSOCKET:-1);
  }
  if(result)
    return result;

  if(data->req.writebytecount) {
    /* if a request-body has been sent off, we make sure this progress is noted
       properly */
    Curl_pgrsSetUploadCounter(data, data->req.writebytecount);
    if(Curl_pgrsUpdate(conn))
      result = CURLE_ABORTED_BY_CALLBACK;

    if(data->req.writebytecount >= postsize) {
      /* already sent the entire request body, mark the "upload" as
         complete */
      infof(data, "upload completely sent off: %" CURL_FORMAT_CURL_OFF_T
            " out of %" CURL_FORMAT_CURL_OFF_T " bytes\n",
            data->req.writebytecount, postsize);
      data->req.upload_done = TRUE;
      data->req.keepon &= ~KEEP_SEND; /* we're done writing */
      data->req.exp100 = EXP100_SEND_DATA; /* already sent */
      Curl_expire_done(data, EXPIRE_100_TIMEOUT);
    }
  }

  if((conn->httpversion == 20) && data->req.upload_chunky)
    /* upload_chunky was set above to set up the request in a chunky fashion,
       but is disabled here again to avoid that the chunked encoded version is
       actually used when sending the request body over h2 */
    data->req.upload_chunky = FALSE;
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
  statusline onmatch = len >= 5? STATUS_DONE : STATUS_UNKNOWN;
#ifdef CURL_DOES_CONVERSIONS
  /* convert from the network encoding using a scratch area */
  char *scratch = strdup(s);
  if(NULL == scratch) {
    failf(data, "Failed to allocate memory for conversion!");
    return FALSE; /* can't return CURLE_OUT_OF_MEMORY so return FALSE */
  }
  if(CURLE_OK != Curl_convert_from_network(data, scratch, strlen(s) + 1)) {
    /* Curl_convert_from_network calls failf if unsuccessful */
    free(scratch);
    return FALSE; /* can't return CURLE_foobar so return FALSE */
  }
  s = scratch;
#endif /* CURL_DOES_CONVERSIONS */

  while(head) {
    if(checkprefixmax(head->data, s, len)) {
      rc = onmatch;
      break;
    }
    head = head->next;
  }

  if((rc != STATUS_DONE) && (checkprefixmax("HTTP/", s, len)))
    rc = onmatch;

#ifdef CURL_DOES_CONVERSIONS
  free(scratch);
#endif /* CURL_DOES_CONVERSIONS */
  return rc;
}

#ifndef CURL_DISABLE_RTSP
static statusline
checkrtspprefix(struct Curl_easy *data,
                const char *s, size_t len)
{
  statusline result = STATUS_BAD;
  statusline onmatch = len >= 5? STATUS_DONE : STATUS_UNKNOWN;

#ifdef CURL_DOES_CONVERSIONS
  /* convert from the network encoding using a scratch area */
  char *scratch = strdup(s);
  if(NULL == scratch) {
    failf(data, "Failed to allocate memory for conversion!");
    return FALSE; /* can't return CURLE_OUT_OF_MEMORY so return FALSE */
  }
  if(CURLE_OK != Curl_convert_from_network(data, scratch, strlen(s) + 1)) {
    /* Curl_convert_from_network calls failf if unsuccessful */
    result = FALSE; /* can't return CURLE_foobar so return FALSE */
  }
  else if(checkprefixmax("RTSP/", scratch, len))
    result = onmatch;
  free(scratch);
#else
  (void)data; /* unused */
  if(checkprefixmax("RTSP/", s, len))
    result = onmatch;
#endif /* CURL_DOES_CONVERSIONS */

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
 * header_append() copies a chunk of data to the end of the already received
 * header. We make sure that the full string fit in the allocated header
 * buffer, or else we enlarge it.
 */
static CURLcode header_append(struct Curl_easy *data,
                              struct SingleRequest *k,
                              size_t length)
{
  size_t newsize = k->hbuflen + length;
  if(newsize > CURL_MAX_HTTP_HEADER) {
    /* The reason to have a max limit for this is to avoid the risk of a bad
       server feeding libcurl with a never-ending header that will cause
       reallocs infinitely */
    failf(data, "Rejected %zu bytes header (max is %d)!", newsize,
          CURL_MAX_HTTP_HEADER);
    return CURLE_OUT_OF_MEMORY;
  }
  if(newsize >= data->state.headersize) {
    /* We enlarge the header buffer as it is too small */
    char *newbuff;
    size_t hbufp_index;

    newsize = CURLMAX((k->hbuflen + length) * 3 / 2, data->state.headersize*2);
    hbufp_index = k->hbufp - data->state.headerbuff;
    newbuff = realloc(data->state.headerbuff, newsize);
    if(!newbuff) {
      failf(data, "Failed to alloc memory for big header!");
      return CURLE_OUT_OF_MEMORY;
    }
    data->state.headersize = newsize;
    data->state.headerbuff = newbuff;
    k->hbufp = data->state.headerbuff + hbufp_index;
  }
  memcpy(k->hbufp, k->str_start, length);
  k->hbufp += length;
  k->hbuflen += length;
  *k->hbufp = 0;

  return CURLE_OK;
}

static void print_http_error(struct Curl_easy *data)
{
  struct SingleRequest *k = &data->req;
  char *beg = k->p;

  /* make sure that data->req.p points to the HTTP status line */
  if(!strncmp(beg, "HTTP", 4)) {

    /* skip to HTTP status code */
    beg = strchr(beg, ' ');
    if(beg && *++beg) {

      /* find trailing CR */
      char end_char = '\r';
      char *end = strchr(beg, end_char);
      if(!end) {
        /* try to find LF (workaround for non-compliant HTTP servers) */
        end_char = '\n';
        end = strchr(beg, end_char);
      }

      if(end) {
        /* temporarily replace CR or LF by NUL and print the error message */
        *end = '\0';
        failf(data, "The requested URL returned error: %s", beg);

        /* restore the previously replaced CR or LF */
        *end = end_char;
        return;
      }
    }
  }

  /* fall-back to printing the HTTP status code only */
  failf(data, "The requested URL returned error: %d", k->httpcode);
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

  /* header line within buffer loop */
  do {
    size_t rest_length;
    size_t full_length;
    int writetype;

    /* str_start is start of line within buf */
    k->str_start = k->str;

    /* data is in network encoding so use 0x0a instead of '\n' */
    k->end_ptr = memchr(k->str_start, 0x0a, *nread);

    if(!k->end_ptr) {
      /* Not a complete header line within buffer, append the data to
         the end of the headerbuff. */
      result = header_append(data, k, *nread);
      if(result)
        return result;

      if(!k->headerline) {
        /* check if this looks like a protocol header */
        statusline st = checkprotoprefix(data, conn, data->state.headerbuff,
                                         k->hbuflen);
        if(st == STATUS_BAD) {
          /* this is not the beginning of a protocol first header line */
          k->header = FALSE;
          k->badheader = HEADER_ALLBAD;
          streamclose(conn, "bad HTTP: No end-of-message indicator");
          if(!data->set.http09_allowed) {
            failf(data, "Received HTTP/0.9 when not allowed\n");
            return CURLE_UNSUPPORTED_PROTOCOL;
          }
          break;
        }
      }

      break; /* read more and try again */
    }

    /* decrease the size of the remaining (supposed) header line */
    rest_length = (k->end_ptr - k->str) + 1;
    *nread -= (ssize_t)rest_length;

    k->str = k->end_ptr + 1; /* move past new line */

    full_length = k->str - k->str_start;

    result = header_append(data, k, full_length);
    if(result)
      return result;

    k->end_ptr = k->hbufp;
    k->p = data->state.headerbuff;

    /****
     * We now have a FULL header line that p points to
     *****/

    if(!k->headerline) {
      /* the first read header */
      statusline st = checkprotoprefix(data, conn, data->state.headerbuff,
                                       k->hbuflen);
      if(st == STATUS_BAD) {
        streamclose(conn, "bad HTTP: No end-of-message indicator");
        /* this is not the beginning of a protocol first header line */
        if(!data->set.http09_allowed) {
          failf(data, "Received HTTP/0.9 when not allowed\n");
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

    /* headers are in network encoding so
       use 0x0a and 0x0d instead of '\n' and '\r' */
    if((0x0a == *k->p) || (0x0d == *k->p)) {
      size_t headerlen;
      /* Zero-length header line means end of headers! */

#ifdef CURL_DOES_CONVERSIONS
      if(0x0d == *k->p) {
        *k->p = '\r'; /* replace with CR in host encoding */
        k->p++;       /* pass the CR byte */
      }
      if(0x0a == *k->p) {
        *k->p = '\n'; /* replace with LF in host encoding */
        k->p++;       /* pass the LF byte */
      }
#else
      if('\r' == *k->p)
        k->p++; /* pass the \r byte */
      if('\n' == *k->p)
        k->p++; /* pass the \n byte */
#endif /* CURL_DOES_CONVERSIONS */

      if(100 <= k->httpcode && 199 >= k->httpcode) {
        /* "A user agent MAY ignore unexpected 1xx status responses." */
        switch(k->httpcode) {
        case 100:
          /*
           * We have made a HTTP PUT or POST and this is 1.1-lingo
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
          if(k->upgr101 == UPGR101_REQUESTED) {
            /* Switching to HTTP/2 */
            infof(data, "Received 101\n");
            k->upgr101 = UPGR101_RECEIVED;

            /* we'll get more headers (HTTP/2 response) */
            k->header = TRUE;
            k->headerline = 0; /* restart the header line counter */

            /* switch to http2 now. The bytes after response headers
               are also processed here, otherwise they are lost. */
            result = Curl_http2_switched(conn, k->str, *nread);
            if(result)
              return result;
            *nread = 0;
          }
          else {
            /* Switching to another protocol (e.g. WebSocket) */
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
           data->set.httpreq != HTTPREQ_HEAD) {
          /* On HTTP 1.1, when connection is not to get closed, but no
             Content-Length nor Transfer-Encoding chunked have been
             received, according to RFC2616 section 4.4 point 5, we
             assume that the server will close the connection to
             signal the end of the document. */
          infof(data, "no chunk, no close, no size. Assume close to "
                "signal end\n");
          streamclose(conn, "HTTP: No end-of-message indicator");
        }
      }

      /* At this point we have some idea about the fate of the connection.
         If we are closing the connection it may result auth failure. */
#if defined(USE_NTLM)
      if(conn->bits.close &&
         (((data->req.httpcode == 401) &&
           (conn->http_ntlm_state == NTLMSTATE_TYPE2)) ||
          ((data->req.httpcode == 407) &&
           (conn->proxy_ntlm_state == NTLMSTATE_TYPE2)))) {
        infof(data, "Connection closure while negotiating auth (HTTP 1.0?)\n");
        data->state.authproblem = TRUE;
      }
#endif
#if defined(USE_SPNEGO)
      if(conn->bits.close &&
        (((data->req.httpcode == 401) &&
          (conn->http_negotiate_state == GSS_AUTHRECV)) ||
         ((data->req.httpcode == 407) &&
          (conn->proxy_negotiate_state == GSS_AUTHRECV)))) {
        infof(data, "Connection closure while negotiating auth (HTTP 1.0?)\n");
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
      /*
       * When all the headers have been parsed, see if we should give
       * up and return an error.
       */
      if(http_should_fail(conn)) {
        failf(data, "The requested URL returned error: %d",
              k->httpcode);
        return CURLE_HTTP_RETURNED_ERROR;
      }

      /* now, only output this if the header AND body are requested:
       */
      writetype = CLIENTWRITE_HEADER;
      if(data->set.include_header)
        writetype |= CLIENTWRITE_BODY;

      headerlen = k->p - data->state.headerbuff;

      result = Curl_client_write(conn, writetype,
                                 data->state.headerbuff,
                                 headerlen);
      if(result)
        return result;

      data->info.header_size += (long)headerlen;
      data->req.headerbytecount += (long)headerlen;

      data->req.deductheadercount =
        (100 <= k->httpcode && 199 >= k->httpcode)?data->req.headerbytecount:0;

      /* Curl_http_auth_act() checks what authentication methods
       * that are available and decides which one (if any) to
       * use. It will set 'newurl' if an auth method was picked. */
      result = Curl_http_auth_act(conn);

      if(result)
        return result;

      if(k->httpcode >= 300) {
        if((!conn->bits.authneg) && !conn->bits.close &&
           !conn->bits.rewindaftersend) {
          /*
           * General treatment of errors when about to send data. Including :
           * "417 Expectation Failed", while waiting for 100-continue.
           *
           * The check for close above is done simply because of something
           * else has already deemed the connection to get closed then
           * something else should've considered the big picture and we
           * avoid this check.
           *
           * rewindaftersend indicates that something has told libcurl to
           * continue sending even if it gets discarded
           */

          switch(data->set.httpreq) {
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
              if(data->set.http_keep_sending_on_error) {
                infof(data, "HTTP error before end of send, keep sending\n");
                if(k->exp100 > EXP100_SEND_DATA) {
                  k->exp100 = EXP100_SEND_DATA;
                  k->keepon |= KEEP_SEND;
                }
              }
              else {
                infof(data, "HTTP error before end of send, stop sending\n");
                streamclose(conn, "Stop sending data before everything sent");
                k->upload_done = TRUE;
                k->keepon &= ~KEEP_SEND; /* don't send */
                if(data->state.expect100header)
                  k->exp100 = EXP100_FAILED;
              }
            }
            break;

          default: /* default label present to avoid compiler warnings */
            break;
          }
        }

        if(conn->bits.rewindaftersend) {
          /* We rewind after a complete send, so thus we continue
             sending now */
          infof(data, "Keep sending data to get tossed away!\n");
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
        if(data->set.opt_no_body)
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
        else {
          /* If we know the expected size of this document, we set the
             maximum download size to the size of the expected
             document or else, we won't know when to stop reading!

             Note that we set the download maximum even if we read a
             "Connection: close" header, to make sure that
             "Content-Length: 0" still prevents us from attempting to
             read the (missing) response-body.
          */
          /* According to RFC2616 section 4.4, we MUST ignore
             Content-Length: headers if we are now receiving data
             using chunked Transfer-Encoding.
          */
          if(k->chunk)
            k->maxdownload = k->size = -1;
        }
        if(-1 != k->size) {
          /* We do this operation even if no_body is true, since this
             data might be retrieved later with curl_easy_getinfo()
             and its CURLINFO_CONTENT_LENGTH_DOWNLOAD option. */

          Curl_pgrsSetDownloadSize(data, k->size);
          k->maxdownload = k->size;
        }

        /* If max download size is *zero* (nothing) we already have
           nothing and can safely return ok now!  But for HTTP/2, we'd
           like to call http2_handle_stream_close to properly close a
           stream.  In order to do this, we keep reading until we
           close the stream. */
        if(0 == k->maxdownload
#if defined(USE_NGHTTP2)
           && !((conn->handler->protocol & PROTO_FAMILY_HTTP) &&
                conn->httpversion == 20)
#endif
           )
          *stop_reading = TRUE;

        if(*stop_reading) {
          /* we make sure that this socket isn't read more now */
          k->keepon &= ~KEEP_RECV;
        }

        if(data->set.verbose)
          Curl_debug(data, CURLINFO_HEADER_IN,
                     k->str_start, headerlen);
        break;          /* exit header line loop */
      }

      /* We continue reading headers, so reset the line-based
         header parsing variables hbufp && hbuflen */
      k->hbufp = data->state.headerbuff;
      k->hbuflen = 0;
      continue;
    }

    /*
     * Checks for special headers coming up.
     */

    if(!k->headerline++) {
      /* This is the first header, it MUST be the error code line
         or else we consider this to be the body right away! */
      int httpversion_major;
      int rtspversion_major;
      int nc = 0;
#ifdef CURL_DOES_CONVERSIONS
#define HEADER1 scratch
#define SCRATCHSIZE 21
      CURLcode res;
      char scratch[SCRATCHSIZE + 1]; /* "HTTP/major.minor 123" */
      /* We can't really convert this yet because we
         don't know if it's the 1st header line or the body.
         So we do a partial conversion into a scratch area,
         leaving the data at k->p as-is.
      */
      strncpy(&scratch[0], k->p, SCRATCHSIZE);
      scratch[SCRATCHSIZE] = 0; /* null terminate */
      res = Curl_convert_from_network(data,
                                      &scratch[0],
                                      SCRATCHSIZE);
      if(res)
        /* Curl_convert_from_network calls failf if unsuccessful */
        return res;
#else
#define HEADER1 k->p /* no conversion needed, just use k->p */
#endif /* CURL_DOES_CONVERSIONS */

      if(conn->handler->protocol & PROTO_FAMILY_HTTP) {
        /*
         * https://tools.ietf.org/html/rfc7230#section-3.1.2
         *
         * The response code is always a three-digit number in HTTP as the spec
         * says. We try to allow any number here, but we cannot make
         * guarantees on future behaviors since it isn't within the protocol.
         */
        char separator;
        nc = sscanf(HEADER1,
                    " HTTP/%1d.%1d%c%3d",
                    &httpversion_major,
                    &conn->httpversion,
                    &separator,
                    &k->httpcode);

        if(nc == 1 && httpversion_major == 2 &&
           1 == sscanf(HEADER1, " HTTP/2 %d", &k->httpcode)) {
          conn->httpversion = 0;
          nc = 4;
          separator = ' ';
        }

        if((nc == 4) && (' ' == separator)) {
          conn->httpversion += 10 * httpversion_major;

          if(k->upgr101 == UPGR101_RECEIVED) {
            /* supposedly upgraded to http2 now */
            if(conn->httpversion != 20)
              infof(data, "Lying server, not serving HTTP/2\n");
          }
          if(conn->httpversion < 20) {
            conn->bundle->multiuse = BUNDLE_NO_MULTIUSE;
            infof(data, "Mark bundle as not supporting multiuse\n");
          }
        }
        else if(!nc) {
          /* this is the real world, not a Nirvana
             NCSA 1.5.x returns this crap when asked for HTTP/1.1
          */
          nc = sscanf(HEADER1, " HTTP %3d", &k->httpcode);
          conn->httpversion = 10;

          /* If user has set option HTTP200ALIASES,
             compare header line against list of aliases
          */
          if(!nc) {
            if(checkhttpprefix(data, k->p, k->hbuflen) == STATUS_DONE) {
              nc = 1;
              k->httpcode = 200;
              conn->httpversion = 10;
            }
          }
        }
        else {
          failf(data, "Unsupported HTTP version in response\n");
          return CURLE_UNSUPPORTED_PROTOCOL;
        }
      }
      else if(conn->handler->protocol & CURLPROTO_RTSP) {
        char separator;
        nc = sscanf(HEADER1,
                    " RTSP/%1d.%1d%c%3d",
                    &rtspversion_major,
                    &conn->rtspversion,
                    &separator,
                    &k->httpcode);
        if((nc == 4) && (' ' == separator)) {
          conn->rtspversion += 10 * rtspversion_major;
          conn->httpversion = 11; /* For us, RTSP acts like HTTP 1.1 */
        }
        else {
          nc = 0;
        }
      }

      if(nc) {
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
        if(data->state.resume_from && data->set.httpreq == HTTPREQ_GET &&
             k->httpcode == 416) {
          /* "Requested Range Not Satisfiable", just proceed and
             pretend this is no error */
          k->ignorebody = TRUE; /* Avoid appending error msg to good data. */
        }
        else if(data->set.http_fail_on_error && (k->httpcode >= 400) &&
           ((k->httpcode != 401) || !conn->bits.user_passwd) &&
           ((k->httpcode != 407) || !conn->bits.proxy_user_passwd) ) {
          /* serious error, go home! */
          print_http_error(data);
          return CURLE_HTTP_RETURNED_ERROR;
        }

        if(conn->httpversion == 10) {
          /* Default action for HTTP/1.0 must be to close, unless
             we get one of those fancy headers that tell us the
             server keeps it open for us! */
          infof(data, "HTTP 1.0, assume close after body\n");
          connclose(conn, "HTTP/1.0 close after body");
        }
        else if(conn->httpversion == 20 ||
                (k->upgr101 == UPGR101_REQUESTED && k->httpcode == 101)) {
          DEBUGF(infof(data, "HTTP/2 found, allow multiplexing\n"));

          /* HTTP/2 cannot blacklist multiplexing since it is a core
             functionality of the protocol */
          conn->bundle->multiuse = BUNDLE_MULTIPLEX;
        }
        else if(conn->httpversion >= 11 &&
                !conn->bits.close) {
          /* If HTTP version is >= 1.1 and connection is persistent */
          DEBUGF(infof(data,
                       "HTTP 1.1 or later with persistent connection\n"));
        }

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
          k->ignorecl = TRUE; /* ignore Content-Length headers */
          break;
        default:
          /* nothing */
          break;
        }
      }
      else {
        k->header = FALSE;   /* this is not a header line */
        break;
      }
    }

    result = Curl_convert_from_network(data, k->p, strlen(k->p));
    /* Curl_convert_from_network calls failf if unsuccessful */
    if(result)
      return result;

    /* Check for Content-Length: header lines to get size */
    if(!k->ignorecl && !data->set.ignorecl &&
       checkprefix("Content-Length:", k->p)) {
      curl_off_t contentlength;
      CURLofft offt = curlx_strtoofft(k->p + 15, NULL, 10, &contentlength);

      if(offt == CURL_OFFT_OK) {
        if(data->set.max_filesize &&
           contentlength > data->set.max_filesize) {
          failf(data, "Maximum file size exceeded");
          return CURLE_FILESIZE_EXCEEDED;
        }
        k->size = contentlength;
        k->maxdownload = k->size;
        /* we set the progress download size already at this point
           just to make it easier for apps/callbacks to extract this
           info as soon as possible */
        Curl_pgrsSetDownloadSize(data, k->size);
      }
      else if(offt == CURL_OFFT_FLOW) {
        /* out of range */
        if(data->set.max_filesize) {
          failf(data, "Maximum file size exceeded");
          return CURLE_FILESIZE_EXCEEDED;
        }
        streamclose(conn, "overflow content-length");
        infof(data, "Overflow Content-Length: value!\n");
      }
      else {
        /* negative or just rubbish - bad HTTP */
        failf(data, "Invalid Content-Length: value");
        return CURLE_WEIRD_SERVER_REPLY;
      }
    }
    /* check for Content-Type: header lines to get the MIME-type */
    else if(checkprefix("Content-Type:", k->p)) {
      char *contenttype = Curl_copy_header_value(k->p);
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
    else if((conn->httpversion == 10) &&
            conn->bits.httpproxy &&
            Curl_compareheader(k->p,
                               "Proxy-Connection:", "keep-alive")) {
      /*
       * When a HTTP/1.0 reply comes when using a proxy, the
       * 'Proxy-Connection: keep-alive' line tells us the
       * connection will be kept alive for our pleasure.
       * Default action for 1.0 is to close.
       */
      connkeep(conn, "Proxy-Connection keep-alive"); /* don't close */
      infof(data, "HTTP/1.0 proxy connection set to keep alive!\n");
    }
    else if((conn->httpversion == 11) &&
            conn->bits.httpproxy &&
            Curl_compareheader(k->p,
                               "Proxy-Connection:", "close")) {
      /*
       * We get a HTTP/1.1 response from a proxy and it says it'll
       * close down after this transfer.
       */
      connclose(conn, "Proxy-Connection: asked to close after done");
      infof(data, "HTTP/1.1 proxy connection set close!\n");
    }
    else if((conn->httpversion == 10) &&
            Curl_compareheader(k->p, "Connection:", "keep-alive")) {
      /*
       * A HTTP/1.0 reply with the 'Connection: keep-alive' line
       * tells us the connection will be kept alive for our
       * pleasure.  Default action for 1.0 is to close.
       *
       * [RFC2068, section 19.7.1] */
      connkeep(conn, "Connection keep-alive");
      infof(data, "HTTP/1.0 connection set to keep alive!\n");
    }
    else if(Curl_compareheader(k->p, "Connection:", "close")) {
      /*
       * [RFC 2616, section 8.1.2.1]
       * "Connection: close" is HTTP/1.1 language and means that
       * the connection will close when this request has been
       * served.
       */
      streamclose(conn, "Connection: close used");
    }
    else if(checkprefix("Transfer-Encoding:", k->p)) {
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

      result = Curl_build_unencoding_stack(conn, k->p + 18, TRUE);
      if(result)
        return result;
    }
    else if(checkprefix("Content-Encoding:", k->p) &&
            data->set.str[STRING_ENCODING]) {
      /*
       * Process Content-Encoding. Look for the values: identity,
       * gzip, deflate, compress, x-gzip and x-compress. x-gzip and
       * x-compress are the same as gzip and compress. (Sec 3.5 RFC
       * 2616). zlib cannot handle compress.  However, errors are
       * handled further down when the response body is processed
       */
      result = Curl_build_unencoding_stack(conn, k->p + 17, FALSE);
      if(result)
        return result;
    }
    else if(checkprefix("Content-Range:", k->p)) {
      /* Content-Range: bytes [num]-
         Content-Range: bytes: [num]-
         Content-Range: [num]-
         Content-Range: [asterisk]/[total]

         The second format was added since Sun's webserver
         JavaWebServer/1.1.1 obviously sends the header this way!
         The third added since some servers use that!
         The forth means the requested range was unsatisfied.
      */

      char *ptr = k->p + 14;

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
    else if(data->cookies &&
            checkprefix("Set-Cookie:", k->p)) {
      Curl_share_lock(data, CURL_LOCK_DATA_COOKIE,
                      CURL_LOCK_ACCESS_SINGLE);
      Curl_cookie_add(data,
                      data->cookies, TRUE, FALSE, k->p + 11,
                      /* If there is a custom-set Host: name, use it
                         here, or else use real peer host name. */
                      conn->allocptr.cookiehost?
                      conn->allocptr.cookiehost:conn->host.name,
                      data->state.up.path,
                      (conn->handler->protocol&CURLPROTO_HTTPS)?
                      TRUE:FALSE);
      Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
    }
#endif
    else if(checkprefix("Last-Modified:", k->p) &&
            (data->set.timecondition || data->set.get_filetime) ) {
      time_t secs = time(NULL);
      k->timeofdoc = curl_getdate(k->p + strlen("Last-Modified:"),
                                  &secs);
      if(data->set.get_filetime)
        data->info.filetime = k->timeofdoc;
    }
    else if((checkprefix("WWW-Authenticate:", k->p) &&
             (401 == k->httpcode)) ||
            (checkprefix("Proxy-authenticate:", k->p) &&
             (407 == k->httpcode))) {

      bool proxy = (k->httpcode == 407) ? TRUE : FALSE;
      char *auth = Curl_copy_header_value(k->p);
      if(!auth)
        return CURLE_OUT_OF_MEMORY;

      result = Curl_http_input_auth(conn, proxy, auth);

      free(auth);

      if(result)
        return result;
    }
  #ifdef USE_SPNEGO
    else if(checkprefix("Persistent-Auth", k->p)) {
      struct negotiatedata *negdata = &conn->negotiate;
      struct auth *authp = &data->state.authhost;
      if(authp->picked == CURLAUTH_NEGOTIATE) {
        char *persistentauth = Curl_copy_header_value(k->p);
        if(!persistentauth)
          return CURLE_OUT_OF_MEMORY;
        negdata->noauthpersist = checkprefix("false", persistentauth);
        negdata->havenoauthpersist = TRUE;
        infof(data, "Negotiate: noauthpersist -> %d, header part: %s",
          negdata->noauthpersist, persistentauth);
        free(persistentauth);
      }
    }
  #endif
    else if((k->httpcode >= 300 && k->httpcode < 400) &&
            checkprefix("Location:", k->p) &&
            !data->req.location) {
      /* this is the URL that the server advises us to use instead */
      char *location = Curl_copy_header_value(k->p);
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
          result = http_perhapsrewind(conn);
          if(result)
            return result;
        }
      }
    }
#ifdef USE_ALTSVC
    /* If enabled, the header is incoming and this is over HTTPS */
    else if(data->asi && checkprefix("Alt-Svc:", k->p) &&
            ((conn->handler->flags & PROTOPT_SSL) ||
#ifdef CURLDEBUG
             /* allow debug builds to circumvent the HTTPS restriction */
             getenv("CURL_ALTSVC_HTTP")
#else
             0
#endif
              )) {
      /* the ALPN of the current request */
      enum alpnid id = (conn->httpversion == 20) ? ALPN_h2 : ALPN_h1;
      result = Curl_altsvc_parse(data, data->asi,
                                 &k->p[ strlen("Alt-Svc:") ],
                                 id, conn->host.name,
                                 curlx_uitous(conn->remote_port));
      if(result)
        return result;
    }
#endif
    else if(conn->handler->protocol & CURLPROTO_RTSP) {
      result = Curl_rtsp_parseheader(conn, k->p);
      if(result)
        return result;
    }

    /*
     * End of header-checks. Write them to the client.
     */

    writetype = CLIENTWRITE_HEADER;
    if(data->set.include_header)
      writetype |= CLIENTWRITE_BODY;

    if(data->set.verbose)
      Curl_debug(data, CURLINFO_HEADER_IN, k->p, (size_t)k->hbuflen);

    result = Curl_client_write(conn, writetype, k->p, k->hbuflen);
    if(result)
      return result;

    data->info.header_size += (long)k->hbuflen;
    data->req.headerbytecount += (long)k->hbuflen;

    /* reset hbufp pointer && hbuflen */
    k->hbufp = data->state.headerbuff;
    k->hbuflen = 0;
  }
  while(*k->str); /* header line within buffer */

  /* We might have reached the end of the header part here, but
     there might be a non-header part left in the end of the read
     buffer. */

  return CURLE_OK;
}

#endif /* CURL_DISABLE_HTTP */
