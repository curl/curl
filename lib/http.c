/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

#include "setup.h"

#ifndef CURL_DISABLE_HTTP
/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef WIN32
#include <time.h>
#include <io.h>
#else
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_TIME_H
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <netdb.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#include <sys/ioctl.h>
#include <signal.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#endif

#include "urldata.h"
#include <curl/curl.h>
#include "transfer.h"
#include "sendf.h"
#include "easyif.h" /* for Curl_convert_... prototypes */
#include "formdata.h"
#include "progress.h"
#include "base64.h"
#include "cookie.h"
#include "strequal.h"
#include "sslgen.h"
#include "http_digest.h"
#include "http_ntlm.h"
#include "http_negotiate.h"
#include "url.h"
#include "share.h"
#include "hostip.h"
#include "http.h"
#include "memory.h"
#include "select.h"
#include "parsedate.h" /* for the week day and month names */
#include "strtoofft.h"
#include "multiif.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

/*
 * checkheaders() checks the linked list of custom HTTP headers for a
 * particular header (prefix).
 *
 * Returns a pointer to the first matching header or NULL if none matched.
 */
static char *checkheaders(struct SessionHandle *data, const char *thisheader)
{
  struct curl_slist *head;
  size_t thislen = strlen(thisheader);

  for(head = data->set.headers; head; head=head->next) {
    if(strnequal(head->data, thisheader, thislen))
      return head->data;
  }
  return NULL;
}

/*
 * Curl_output_basic() sets up an Authorization: header (or the proxy version)
 * for HTTP Basic authentication.
 *
 * Returns CURLcode.
 */
static CURLcode Curl_output_basic(struct connectdata *conn, bool proxy)
{
  char *authorization;
  struct SessionHandle *data=conn->data;
  char **userp;
  char *user;
  char *pwd;

  if(proxy) {
    userp = &conn->allocptr.proxyuserpwd;
    user = conn->proxyuser;
    pwd = conn->proxypasswd;
  }
  else {
    userp = &conn->allocptr.userpwd;
    user = conn->user;
    pwd = conn->passwd;
  }

  snprintf(data->state.buffer, sizeof(data->state.buffer), "%s:%s", user, pwd);
  if(Curl_base64_encode(data, data->state.buffer,
                        strlen(data->state.buffer),
                        &authorization) > 0) {
    if(*userp)
      free(*userp);
    *userp = aprintf( "%sAuthorization: Basic %s\r\n",
                      proxy?"Proxy-":"",
                      authorization);
    free(authorization);
  }
  else
    return CURLE_OUT_OF_MEMORY;
  return CURLE_OK;
}

/* pickoneauth() selects the most favourable authentication method from the
 * ones available and the ones we want.
 *
 * return TRUE if one was picked
 */
static bool pickoneauth(struct auth *pick)
{
  bool picked;
  /* only deal with authentication we want */
  long avail = pick->avail & pick->want;
  picked = TRUE;

  /* The order of these checks is highly relevant, as this will be the order
     of preference in case of the existance of multiple accepted types. */
  if(avail & CURLAUTH_GSSNEGOTIATE)
    pick->picked = CURLAUTH_GSSNEGOTIATE;
  else if(avail & CURLAUTH_DIGEST)
    pick->picked = CURLAUTH_DIGEST;
  else if(avail & CURLAUTH_NTLM)
    pick->picked = CURLAUTH_NTLM;
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
 * perhapsrewind()
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
static CURLcode perhapsrewind(struct connectdata *conn)
{
  struct SessionHandle *data = conn->data;
  struct HTTP *http = data->reqdata.proto.http;
  struct Curl_transfer_keeper *k = &data->reqdata.keep;
  curl_off_t bytessent;
  curl_off_t expectsend = -1; /* default is unknown */

  if(!http)
    /* If this is still NULL, we have not reach very far and we can
       safely skip this rewinding stuff */
    return CURLE_OK;

  bytessent = http->writebytecount;

  if(conn->bits.authneg)
    /* This is a state where we are known to be negotiating and we don't send
       any data then. */
    expectsend = 0;
  else {
    /* figure out how much data we are expected to send */
    switch(data->set.httpreq) {
    case HTTPREQ_POST:
      if(data->set.postfieldsize != -1)
        expectsend = data->set.postfieldsize;
      break;
    case HTTPREQ_PUT:
      if(data->set.infilesize != -1)
        expectsend = data->set.infilesize;
      break;
    case HTTPREQ_POST_FORM:
      expectsend = http->postsize;
      break;
    default:
      break;
    }
  }

  conn->bits.rewindaftersend = FALSE; /* default */

  if((expectsend == -1) || (expectsend > bytessent)) {
    /* There is still data left to send */
    if((data->state.authproxy.picked == CURLAUTH_NTLM) ||
       (data->state.authhost.picked == CURLAUTH_NTLM)) {
      if(((expectsend - bytessent) < 2000) ||
         (conn->ntlm.state != NTLMSTATE_NONE)) {
        /* The NTLM-negotiation has started *OR* there is just a little (<2K)
           data left to send, keep on sending. */

        /* rewind data when completely done sending! */
        if(!conn->bits.authneg)
          conn->bits.rewindaftersend = TRUE;

        return CURLE_OK;
      }
      if(conn->bits.close)
        /* this is already marked to get closed */
        return CURLE_OK;

      infof(data, "NTLM send, close instead of sending %" FORMAT_OFF_T
            " bytes\n", (curl_off_t)(expectsend - bytessent));
    }

    /* This is not NTLM or NTLM with many bytes left to send: close
     */
    conn->bits.close = TRUE;
    k->size = 0; /* don't download any more than 0 bytes */
  }

  if(bytessent)
    return Curl_readrewind(conn);

  return CURLE_OK;
}

/*
 * Curl_http_auth_act() gets called when a all HTTP headers have been received
 * and it checks what authentication methods that are available and decides
 * which one (if any) to use. It will set 'newurl' if an auth metod was
 * picked.
 */

CURLcode Curl_http_auth_act(struct connectdata *conn)
{
  struct SessionHandle *data = conn->data;
  bool pickhost = FALSE;
  bool pickproxy = FALSE;
  CURLcode code = CURLE_OK;

  if(100 == data->reqdata.keep.httpcode)
    /* this is a transient response code, ignore */
    return CURLE_OK;

  if(data->state.authproblem)
    return data->set.http_fail_on_error?CURLE_HTTP_RETURNED_ERROR:CURLE_OK;

  if(conn->bits.user_passwd &&
     ((data->reqdata.keep.httpcode == 401) ||
      (conn->bits.authneg && data->reqdata.keep.httpcode < 300))) {
    pickhost = pickoneauth(&data->state.authhost);
    if(!pickhost)
      data->state.authproblem = TRUE;
  }
  if(conn->bits.proxy_user_passwd &&
     ((data->reqdata.keep.httpcode == 407) ||
      (conn->bits.authneg && data->reqdata.keep.httpcode < 300))) {
    pickproxy = pickoneauth(&data->state.authproxy);
    if(!pickproxy)
      data->state.authproblem = TRUE;
  }

  if(pickhost || pickproxy) {
    data->reqdata.newurl = strdup(data->change.url); /* clone URL */

    if((data->set.httpreq != HTTPREQ_GET) &&
       (data->set.httpreq != HTTPREQ_HEAD) &&
       !conn->bits.rewindaftersend) {
      code = perhapsrewind(conn);
      if(code)
        return code;
    }
  }

  else if((data->reqdata.keep.httpcode < 300) &&
          (!data->state.authhost.done) &&
          conn->bits.authneg) {
    /* no (known) authentication available,
       authentication is not "done" yet and
       no authentication seems to be required and
       we didn't try HEAD or GET */
    if((data->set.httpreq != HTTPREQ_GET) &&
       (data->set.httpreq != HTTPREQ_HEAD)) {
      data->reqdata.newurl = strdup(data->change.url); /* clone URL */
      data->state.authhost.done = TRUE;
    }
  }
  if (Curl_http_should_fail(conn)) {
    failf (data, "The requested URL returned error: %d",
           data->reqdata.keep.httpcode);
    code = CURLE_HTTP_RETURNED_ERROR;
  }

  return code;
}

/**
 * Curl_http_output_auth() setups the authentication headers for the
 * host/proxy and the correct authentication
 * method. conn->data->state.authdone is set to TRUE when authentication is
 * done.
 *
 * @param conn all information about the current connection
 * @param request pointer to the request keyword
 * @param path pointer to the requested path
 * @param proxytunnel boolean if this is the request setting up a "proxy
 * tunnel"
 *
 * @returns CURLcode
 */
static CURLcode
Curl_http_output_auth(struct connectdata *conn,
                      char *request,
                      char *path,
                      bool proxytunnel) /* TRUE if this is the request setting
                                           up the proxy tunnel */
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  char *auth=NULL;
  struct auth *authhost;
  struct auth *authproxy;

  curlassert(data);

  authhost = &data->state.authhost;
  authproxy = &data->state.authproxy;

  if((conn->bits.httpproxy && conn->bits.proxy_user_passwd) ||
     conn->bits.user_passwd)
    /* continue please */ ;
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

  /* Send proxy authentication header if needed */
  if (conn->bits.httpproxy &&
      (conn->bits.tunnel_proxy == proxytunnel)) {
#ifdef USE_NTLM
    if(authproxy->picked == CURLAUTH_NTLM) {
      auth=(char *)"NTLM";
      result = Curl_output_ntlm(conn, TRUE);
      if(result)
        return result;
    }
    else
#endif
      if(authproxy->picked == CURLAUTH_BASIC) {
        /* Basic */
        if(conn->bits.proxy_user_passwd &&
           !checkheaders(data, "Proxy-authorization:")) {
          auth=(char *)"Basic";
          result = Curl_output_basic(conn, TRUE);
          if(result)
            return result;
        }
        /* NOTE: Curl_output_basic() should set 'done' TRUE, as the other auth
           functions work that way */
        authproxy->done = TRUE;
      }
#ifndef CURL_DISABLE_CRYPTO_AUTH
      else if(authproxy->picked == CURLAUTH_DIGEST) {
        auth=(char *)"Digest";
        result = Curl_output_digest(conn,
                                    TRUE, /* proxy */
                                    (unsigned char *)request,
                                    (unsigned char *)path);
        if(result)
          return result;
      }
#endif
      if(auth) {
        infof(data, "Proxy auth using %s with user '%s'\n",
              auth, conn->proxyuser?conn->proxyuser:"");
        authproxy->multi = (bool)(!authproxy->done);
      }
      else
        authproxy->multi = FALSE;
    }
  else
    /* we have no proxy so let's pretend we're done authenticating
       with it */
    authproxy->done = TRUE;

  /* To prevent the user+password to get sent to other than the original
     host due to a location-follow, we do some weirdo checks here */
  if(!data->state.this_is_a_follow ||
     conn->bits.netrc ||
     !data->state.first_host ||
     curl_strequal(data->state.first_host, conn->host.name) ||
     data->set.http_disable_hostname_check_before_authentication) {

    /* Send web authentication header if needed */
    {
      auth = NULL;
#ifdef HAVE_GSSAPI
      if((authhost->picked == CURLAUTH_GSSNEGOTIATE) &&
         data->state.negotiate.context &&
         !GSS_ERROR(data->state.negotiate.status)) {
        auth=(char *)"GSS-Negotiate";
        result = Curl_output_negotiate(conn);
        if (result)
          return result;
        authhost->done = TRUE;
      }
      else
#endif
#ifdef USE_NTLM
      if(authhost->picked == CURLAUTH_NTLM) {
        auth=(char *)"NTLM";
        result = Curl_output_ntlm(conn, FALSE);
        if(result)
          return result;
      }
      else
#endif
      {
#ifndef CURL_DISABLE_CRYPTO_AUTH
        if(authhost->picked == CURLAUTH_DIGEST) {
          auth=(char *)"Digest";
          result = Curl_output_digest(conn,
                                      FALSE, /* not a proxy */
                                      (unsigned char *)request,
                                      (unsigned char *)path);
          if(result)
            return result;
        } else
#endif
        if(authhost->picked == CURLAUTH_BASIC) {
          if(conn->bits.user_passwd &&
             !checkheaders(data, "Authorization:")) {
            auth=(char *)"Basic";
            result = Curl_output_basic(conn, FALSE);
            if(result)
              return result;
          }
          /* basic is always ready */
          authhost->done = TRUE;
        }
      }
      if(auth) {
        infof(data, "Server auth using %s with user '%s'\n",
              auth, conn->user);

        authhost->multi = (bool)(!authhost->done);
      }
      else
        authhost->multi = FALSE;
    }
  }
  else
    authhost->done = TRUE;

  return result;
}


/*
 * Curl_http_input_auth() deals with Proxy-Authenticate: and WWW-Authenticate:
 * headers. They are dealt with both in the transfer.c main loop and in the
 * proxy CONNECT loop.
 */

CURLcode Curl_http_input_auth(struct connectdata *conn,
                              int httpcode,
                              char *header) /* the first non-space */
{
  /*
   * This resource requires authentication
   */
  struct SessionHandle *data = conn->data;

  long *availp;
  char *start;
  struct auth *authp;

  if (httpcode == 407) {
    start = header+strlen("Proxy-authenticate:");
    availp = &data->info.proxyauthavail;
    authp = &data->state.authproxy;
  }
  else {
    start = header+strlen("WWW-Authenticate:");
    availp = &data->info.httpauthavail;
    authp = &data->state.authhost;
  }

  /* pass all white spaces */
  while(*start && ISSPACE(*start))
    start++;

  /*
   * Here we check if we want the specific single authentication (using ==) and
   * if we do, we initiate usage of it.
   *
   * If the provided authentication is wanted as one out of several accepted
   * types (using &), we OR this authentication type to the authavail
   * variable.
   */

#ifdef HAVE_GSSAPI
  if (checkprefix("GSS-Negotiate", start) ||
      checkprefix("Negotiate", start)) {
    *availp |= CURLAUTH_GSSNEGOTIATE;
    authp->avail |= CURLAUTH_GSSNEGOTIATE;
    if(authp->picked == CURLAUTH_GSSNEGOTIATE) {
      /* if exactly this is wanted, go */
      int neg = Curl_input_negotiate(conn, start);
      if (neg == 0) {
        data->reqdata.newurl = strdup(data->change.url);
        data->state.authproblem = (data->reqdata.newurl == NULL);
      }
      else {
        infof(data, "Authentication problem. Ignoring this.\n");
        data->state.authproblem = TRUE;
      }
    }
  }
  else
#endif
#ifdef USE_NTLM
    /* NTLM support requires the SSL crypto libs */
    if(checkprefix("NTLM", start)) {
      *availp |= CURLAUTH_NTLM;
      authp->avail |= CURLAUTH_NTLM;
      if(authp->picked == CURLAUTH_NTLM) {
        /* NTLM authentication is picked and activated */
        CURLntlm ntlm =
          Curl_input_ntlm(conn, (bool)(httpcode == 407), start);

        if(CURLNTLM_BAD != ntlm)
          data->state.authproblem = FALSE;
        else {
          infof(data, "Authentication problem. Ignoring this.\n");
          data->state.authproblem = TRUE;
        }
      }
    }
    else
#endif
#ifndef CURL_DISABLE_CRYPTO_AUTH
      if(checkprefix("Digest", start)) {
        if((authp->avail & CURLAUTH_DIGEST) != 0) {
          infof(data, "Ignoring duplicate digest auth header.\n");
        }
        else {
          CURLdigest dig;
          *availp |= CURLAUTH_DIGEST;
          authp->avail |= CURLAUTH_DIGEST;

          /* We call this function on input Digest headers even if Digest
           * authentication isn't activated yet, as we need to store the
           * incoming data from this header in case we are gonna use Digest. */
          dig = Curl_input_digest(conn, (bool)(httpcode == 407), start);

          if(CURLDIGEST_FINE != dig) {
            infof(data, "Authentication problem. Ignoring this.\n");
            data->state.authproblem = TRUE;
          }
        }
      }
      else
#endif
      if(checkprefix("Basic", start)) {
        *availp |= CURLAUTH_BASIC;
        authp->avail |= CURLAUTH_BASIC;
        if(authp->picked == CURLAUTH_BASIC) {
          /* We asked for Basic authentication but got a 40X back
             anyway, which basicly means our name+password isn't
             valid. */
          authp->avail = CURLAUTH_NONE;
          infof(data, "Authentication problem. Ignoring this.\n");
          data->state.authproblem = TRUE;
        }
      }

  return CURLE_OK;
}

/**
 * Curl_http_should_fail() determines whether an HTTP response has gotten us
 * into an error state or not.
 *
 * @param conn all information about the current connection
 *
 * @retval 0 communications should continue
 *
 * @retval 1 communications should not continue
 */
int Curl_http_should_fail(struct connectdata *conn)
{
  struct SessionHandle *data;
  struct Curl_transfer_keeper *k;

  curlassert(conn);
  data = conn->data;
  curlassert(data);

  /*
  ** For readability
  */
  k = &data->reqdata.keep;

  /*
  ** If we haven't been asked to fail on error,
  ** don't fail.
  */
  if (!data->set.http_fail_on_error)
    return 0;

  /*
  ** Any code < 400 is never terminal.
  */
  if (k->httpcode < 400)
    return 0;

  if (data->reqdata.resume_from &&
      (data->set.httpreq==HTTPREQ_GET) &&
      (k->httpcode == 416)) {
    /* "Requested Range Not Satisfiable", just proceed and
       pretend this is no error */
    return 0;
  }

  /*
  ** Any code >= 400 that's not 401 or 407 is always
  ** a terminal error
  */
  if ((k->httpcode != 401) &&
      (k->httpcode != 407))
    return 1;

  /*
  ** All we have left to deal with is 401 and 407
  */
  curlassert((k->httpcode == 401) || (k->httpcode == 407));

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
#if 0 /* set to 1 when debugging this functionality */
  infof(data,"%s: authstage = %d\n",__FUNCTION__,data->state.authstage);
  infof(data,"%s: authwant = 0x%08x\n",__FUNCTION__,data->state.authwant);
  infof(data,"%s: authavail = 0x%08x\n",__FUNCTION__,data->state.authavail);
  infof(data,"%s: httpcode = %d\n",__FUNCTION__,k->httpcode);
  infof(data,"%s: authdone = %d\n",__FUNCTION__,data->state.authdone);
  infof(data,"%s: newurl = %s\n",__FUNCTION__,data->reqdata.newurl ? data->reqdata.newurl : "(null)");
  infof(data,"%s: authproblem = %d\n",__FUNCTION__,data->state.authproblem);
#endif

  /*
  ** Either we're not authenticating, or we're supposed to
  ** be authenticating something else.  This is an error.
  */
  if((k->httpcode == 401) && !conn->bits.user_passwd)
    return TRUE;
  if((k->httpcode == 407) && !conn->bits.proxy_user_passwd)
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
  struct HTTP *http = conn->data->reqdata.proto.http;
  size_t fullsize = size * nitems;

  if(0 == http->postsize)
    /* nothing to return */
    return 0;

  /* make sure that a HTTP request is never sent away chunked! */
  conn->bits.forbidchunk = (bool)(http->sending == HTTPSEND_REQUEST);

  if(http->postsize <= (curl_off_t)fullsize) {
    memcpy(buffer, http->postdata, (size_t)http->postsize);
    fullsize = (size_t)http->postsize;

    if(http->backup.postsize) {
      /* move backup data into focus and continue on that */
      http->postdata = http->backup.postdata;
      http->postsize = http->backup.postsize;
      conn->fread =    http->backup.fread;
      conn->fread_in = http->backup.fread_in;

      http->sending++; /* move one step up */

      http->backup.postsize=0;
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
/*
 * The add_buffer series of functions are used to build one large memory chunk
 * from repeated function invokes. Used so that the entire HTTP request can
 * be sent in one go.
 */

struct send_buffer {
  char *buffer;
  size_t size_max;
  size_t size_used;
};
typedef struct send_buffer send_buffer;

static CURLcode add_custom_headers(struct connectdata *conn,
                                   send_buffer *req_buffer);
static CURLcode
 add_buffer(send_buffer *in, const void *inptr, size_t size);

/*
 * add_buffer_init() sets up and returns a fine buffer struct
 */
static
send_buffer *add_buffer_init(void)
{
  send_buffer *blonk;
  blonk=(send_buffer *)malloc(sizeof(send_buffer));
  if(blonk) {
    memset(blonk, 0, sizeof(send_buffer));
    return blonk;
  }
  return NULL; /* failed, go home */
}

/*
 * add_buffer_send() sends a header buffer and frees all associated memory.
 * Body data may be appended to the header data if desired.
 *
 * Returns CURLcode
 */
static
CURLcode add_buffer_send(send_buffer *in,
                         struct connectdata *conn,
                         long *bytes_written, /* add the number of sent
                                                 bytes to this counter */
                         size_t included_body_bytes, /* how much of the buffer
                                        contains body data (for log tracing) */
                         int socketindex)

{
  ssize_t amount;
  CURLcode res;
  char *ptr;
  size_t size;
  struct HTTP *http = conn->data->reqdata.proto.http;
  size_t sendsize;
  curl_socket_t sockfd;

  curlassert(socketindex <= SECONDARYSOCKET);

  sockfd = conn->sock[socketindex];

  /* The looping below is required since we use non-blocking sockets, but due
     to the circumstances we will just loop and try again and again etc */

  ptr = in->buffer;
  size = in->size_used;

#ifdef CURL_DOES_CONVERSIONS
  if(size - included_body_bytes > 0) {
    res = Curl_convert_to_network(conn->data, ptr, size - included_body_bytes);
    /* Curl_convert_to_network calls failf if unsuccessful */
    if(res != CURLE_OK) {
      /* conversion failed, free memory and return to the caller */
      if(in->buffer)
        free(in->buffer);
      free(in);
      return res;
    }
  }
#endif /* CURL_DOES_CONVERSIONS */

  if(conn->protocol & PROT_HTTPS) {
    /* We never send more than CURL_MAX_WRITE_SIZE bytes in one single chunk
       when we speak HTTPS, as if only a fraction of it is sent now, this data
       needs to fit into the normal read-callback buffer later on and that
       buffer is using this size.
    */

    sendsize= (size > CURL_MAX_WRITE_SIZE)?CURL_MAX_WRITE_SIZE:size;

    /* OpenSSL is very picky and we must send the SAME buffer pointer to the
       library when we attempt to re-send this buffer. Sending the same data
       is not enough, we must use the exact same address. For this reason, we
       must copy the data to the uploadbuffer first, since that is the buffer
       we will be using if this send is retried later.
    */
    memcpy(conn->data->state.uploadbuffer, ptr, sendsize);
    ptr = conn->data->state.uploadbuffer;
  }
  else
    sendsize = size;

  res = Curl_write(conn, sockfd, ptr, sendsize, &amount);

  if(CURLE_OK == res) {

    if(conn->data->set.verbose) {
      /* this data _may_ contain binary stuff */
      Curl_debug(conn->data, CURLINFO_HEADER_OUT, ptr,
                 (size_t)(amount-included_body_bytes), conn);
      if (included_body_bytes)
        Curl_debug(conn->data, CURLINFO_DATA_OUT,
                   ptr+amount-included_body_bytes,
                   (size_t)included_body_bytes, conn);
    }

    *bytes_written += amount;

    if(http) {
      if((size_t)amount != size) {
        /* The whole request could not be sent in one system call. We must
           queue it up and send it later when we get the chance. We must not
           loop here and wait until it might work again. */

        size -= amount;

        ptr = in->buffer + amount;

        /* backup the currently set pointers */
        http->backup.fread = conn->fread;
        http->backup.fread_in = conn->fread_in;
        http->backup.postdata = http->postdata;
        http->backup.postsize = http->postsize;

        /* set the new pointers for the request-sending */
        conn->fread = (curl_read_callback)readmoredata;
        conn->fread_in = (void *)conn;
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
      else
        conn->writechannel_inuse = FALSE;
    }
  }
  if(in->buffer)
    free(in->buffer);
  free(in);

  return res;
}


/*
 * add_bufferf() add the formatted input to the buffer.
 */
static
CURLcode add_bufferf(send_buffer *in, const char *fmt, ...)
{
  char *s;
  va_list ap;
  va_start(ap, fmt);
  s = vaprintf(fmt, ap); /* this allocs a new string to append */
  va_end(ap);

  if(s) {
    CURLcode result = add_buffer(in, s, strlen(s));
    free(s);
    if(CURLE_OK == result)
      return CURLE_OK;
  }
  /* If we failed, we cleanup the whole buffer and return error */
  if(in->buffer)
    free(in->buffer);
  free(in);
  return CURLE_OUT_OF_MEMORY;
}

/*
 * add_buffer() appends a memory chunk to the existing buffer
 */
static
CURLcode add_buffer(send_buffer *in, const void *inptr, size_t size)
{
  char *new_rb;
  size_t new_size;

  if(!in->buffer ||
     ((in->size_used + size) > (in->size_max - 1))) {
    new_size = (in->size_used+size)*2;
    if(in->buffer)
      /* we have a buffer, enlarge the existing one */
      new_rb = (char *)realloc(in->buffer, new_size);
    else
      /* create a new buffer */
      new_rb = (char *)malloc(new_size);

    if(!new_rb)
      return CURLE_OUT_OF_MEMORY;

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
Curl_compareheader(char *headerline,    /* line to check */
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
  char *start;
  char *end;

  if(!strnequal(headerline, header, hlen))
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
  for(;len>=clen;len--, start++) {
    if(strnequal(start, content, clen))
      return TRUE; /* match! */
  }

  return FALSE; /* no match */
}

/*
 * Curl_proxyCONNECT() requires that we're connected to a HTTP proxy. This
 * function will issue the necessary commands to get a seamless tunnel through
 * this proxy. After that, the socket can be used just as a normal socket.
 *
 * This badly needs to be rewritten. CONNECT should be sent and dealt with
 * like any ordinary HTTP request, and not specially crafted like this. This
 * function only remains here like this for now since the rewrite is a bit too
 * much work to do at the moment.
 *
 * This function is BLOCKING which is nasty for all multi interface using apps.
 */

CURLcode Curl_proxyCONNECT(struct connectdata *conn,
                           int sockindex,
                           char *hostname,
                           int remote_port)
{
  int subversion=0;
  struct SessionHandle *data=conn->data;
  struct Curl_transfer_keeper *k = &data->reqdata.keep;
  CURLcode result;
  int res;
  size_t nread;   /* total size read */
  int perline; /* count bytes per line */
  int keepon=TRUE;
  ssize_t gotbytes;
  char *ptr;
  long timeout =
    data->set.timeout?data->set.timeout:3600; /* in seconds */
  char *line_start;
  char *host_port;
  curl_socket_t tunnelsocket = conn->sock[sockindex];
  send_buffer *req_buffer;
  curl_off_t cl=0;
  bool closeConnection = FALSE;

#define SELECT_OK      0
#define SELECT_ERROR   1
#define SELECT_TIMEOUT 2
  int error = SELECT_OK;

  infof(data, "Establish HTTP proxy tunnel to %s:%d\n", hostname, remote_port);
  conn->bits.proxy_connect_closed = FALSE;

  do {
    if(data->reqdata.newurl) {
      /* This only happens if we've looped here due to authentication reasons,
         and we don't really use the newly cloned URL here then. Just free()
         it. */
      free(data->reqdata.newurl);
      data->reqdata.newurl = NULL;
    }

    /* initialize a dynamic send-buffer */
    req_buffer = add_buffer_init();

    if(!req_buffer)
      return CURLE_OUT_OF_MEMORY;

    host_port = aprintf("%s:%d", hostname, remote_port);
    if(!host_port)
      return CURLE_OUT_OF_MEMORY;

    /* Setup the proxy-authorization header, if any */
    result = Curl_http_output_auth(conn, (char *)"CONNECT", host_port, TRUE);

    if(CURLE_OK == result) {
      char *host=(char *)"";
      const char *proxyconn="";
      const char *useragent="";

      if(!checkheaders(data, "Host:")) {
        host = aprintf("Host: %s\r\n", host_port);
        if(!host)
          result = CURLE_OUT_OF_MEMORY;
      }
      if(!checkheaders(data, "Proxy-Connection:"))
        proxyconn = "Proxy-Connection: Keep-Alive\r\n";

      if(!checkheaders(data, "User-Agent:") && data->set.useragent)
        useragent = conn->allocptr.uagent;

      if(CURLE_OK == result) {
        /* Send the connect request to the proxy */
        /* BLOCKING */
        result =
          add_bufferf(req_buffer,
                      "CONNECT %s:%d HTTP/1.0\r\n"
                      "%s"  /* Host: */
                      "%s"  /* Proxy-Authorization */
                      "%s"  /* User-Agent */
                      "%s", /* Proxy-Connection */
                      hostname, remote_port,
                      host,
                      conn->allocptr.proxyuserpwd?
                      conn->allocptr.proxyuserpwd:"",
                      useragent,
                      proxyconn);

        if(CURLE_OK == result)
          result = add_custom_headers(conn, req_buffer);

        if(host && *host)
          free(host);

        if(CURLE_OK == result)
          /* CRLF terminate the request */
          result = add_bufferf(req_buffer, "\r\n");

        if(CURLE_OK == result)
          /* Now send off the request */
          result = add_buffer_send(req_buffer, conn,
                                   &data->info.request_size, 0, sockindex);
      }
      if(result)
        failf(data, "Failed sending CONNECT to proxy");
    }
    free(host_port);
    if(result)
      return result;

    ptr=data->state.buffer;
    line_start = ptr;

    nread=0;
    perline=0;
    keepon=TRUE;

    while((nread<BUFSIZE) && (keepon && !error)) {

      /* if timeout is requested, find out how much remaining time we have */
      long check = timeout - /* timeout time */
        Curl_tvdiff(Curl_tvnow(), conn->now)/1000; /* spent time */
      if(check <=0 ) {
        failf(data, "Proxy CONNECT aborted due to timeout");
        error = SELECT_TIMEOUT; /* already too little time */
        break;
      }

      /* timeout each second and check the timeout */
      switch (Curl_select(tunnelsocket, CURL_SOCKET_BAD, 1000)) {
      case -1: /* select() error, stop reading */
        error = SELECT_ERROR;
        failf(data, "Proxy CONNECT aborted due to select() error");
        break;
      case 0: /* timeout */
        break;
      default:
        res = Curl_read(conn, tunnelsocket, ptr, BUFSIZE-nread, &gotbytes);
        if(res< 0)
          /* EWOULDBLOCK */
          continue; /* go loop yourself */
        else if(res)
          keepon = FALSE;
        else if(gotbytes <= 0) {
          keepon = FALSE;
          error = SELECT_ERROR;
          failf(data, "Proxy CONNECT aborted");
        }
        else {
          /*
           * We got a whole chunk of data, which can be anything from one byte
           * to a set of lines and possibly just a piece of the last line.
           */
          int i;

          nread += gotbytes;

          if(keepon > TRUE) {
            /* This means we are currently ignoring a response-body, so we
               simply count down our counter and make sure to break out of the
               loop when we're done! */
            cl -= gotbytes;
            if(cl<=0) {
              keepon = FALSE;
              break;
            }
          }
          else
          for(i = 0; i < gotbytes; ptr++, i++) {
            perline++; /* amount of bytes in this line so far */
            if(*ptr=='\n') {
              char letter;
              int writetype;

              /* output debug if that is requested */
              if(data->set.verbose)
                Curl_debug(data, CURLINFO_HEADER_IN,
                           line_start, (size_t)perline, conn);

              /* send the header to the callback */
              writetype = CLIENTWRITE_HEADER;
              if(data->set.include_header)
                writetype |= CLIENTWRITE_BODY;

              result = Curl_client_write(conn, writetype, line_start, perline);
              if(result)
                return result;

              /* Newlines are CRLF, so the CR is ignored as the line isn't
                 really terminated until the LF comes. Treat a following CR
                 as end-of-headers as well.*/

              if(('\r' == line_start[0]) ||
                 ('\n' == line_start[0])) {
                /* end of response-headers from the proxy */
                if(cl && (407 == k->httpcode) && !data->state.authproblem) {
                  /* If we get a 407 response code with content length when we
                   * have no auth problem, we must ignore the whole
                   * response-body */
                  keepon = 2;
                  infof(data, "Ignore %" FORMAT_OFF_T
                        " bytes of response-body\n", cl);
                  cl -= (gotbytes - i);/* remove the remaining chunk of what
                                          we already read */
                  if(cl<=0)
                    /* if the whole thing was already read, we are done! */
                    keepon=FALSE;
                }
                else
                  keepon = FALSE;
                break; /* breaks out of for-loop, not switch() */
              }

              /* keep a backup of the position we are about to blank */
              letter = line_start[perline];
              line_start[perline]=0; /* zero terminate the buffer */
              if((checkprefix("WWW-Authenticate:", line_start) &&
                  (401 == k->httpcode)) ||
                 (checkprefix("Proxy-authenticate:", line_start) &&
                  (407 == k->httpcode))) {
                result = Curl_http_input_auth(conn, k->httpcode, line_start);
                if(result)
                  return result;
              }
              else if(checkprefix("Content-Length:", line_start)) {
                cl = curlx_strtoofft(line_start + strlen("Content-Length:"),
                                     NULL, 10);
              }
              else if(Curl_compareheader(line_start,
                                         "Connection:", "close"))
                closeConnection = TRUE;
              else if(2 == sscanf(line_start, "HTTP/1.%d %d",
                                  &subversion,
                                  &k->httpcode)) {
                /* store the HTTP code from the proxy */
                data->info.httpproxycode = k->httpcode;
              }
              /* put back the letter we blanked out before */
              line_start[perline]= letter;

              perline=0; /* line starts over here */
              line_start = ptr+1; /* this skips the zero byte we wrote */
            }
          }
        }
        break;
      } /* switch */
    } /* while there's buffer left and loop is requested */

    if(error)
      return CURLE_RECV_ERROR;

    if(data->info.httpproxycode != 200)
      /* Deal with the possibly already received authenticate
         headers. 'newurl' is set to a new URL if we must loop. */
      Curl_http_auth_act(conn);

    if (closeConnection && data->reqdata.newurl) {
      /* Connection closed by server. Don't use it anymore */
      sclose(conn->sock[sockindex]);
      conn->sock[sockindex] = CURL_SOCKET_BAD;
      break;
    }
  } while(data->reqdata.newurl);

  if(200 != k->httpcode) {
    failf(data, "Received HTTP code %d from proxy after CONNECT",
          k->httpcode);

    if (closeConnection && data->reqdata.newurl)
      conn->bits.proxy_connect_closed = TRUE;

    return CURLE_RECV_ERROR;
  }

  /* If a proxy-authorization header was used for the proxy, then we should
     make sure that it isn't accidentally used for the document request
     after we've connected. So let's free and clear it here. */
  Curl_safefree(conn->allocptr.proxyuserpwd);
  conn->allocptr.proxyuserpwd = NULL;

  data->state.authproxy.done = TRUE;

  infof (data, "Proxy replied OK to CONNECT request\n");
  return CURLE_OK;
}

/*
 * Curl_http_connect() performs HTTP stuff to do at connect-time, called from
 * the generic Curl_connect().
 */
CURLcode Curl_http_connect(struct connectdata *conn, bool *done)
{
  struct SessionHandle *data;
  CURLcode result;

  data=conn->data;

  /* If we are not using a proxy and we want a secure connection, perform SSL
   * initialization & connection now.  If using a proxy with https, then we
   * must tell the proxy to CONNECT to the host we want to talk to.  Only
   * after the connect has occurred, can we start talking SSL
   */

  if(conn->bits.tunnel_proxy && conn->bits.httpproxy) {

    /* either SSL over proxy, or explicitly asked for */
    result = Curl_proxyCONNECT(conn, FIRSTSOCKET,
                               conn->host.name,
                               conn->remote_port);
    if(CURLE_OK != result)
      return result;
  }

  if(!data->state.this_is_a_follow) {
    /* this is not a followed location, get the original host name */
    if (data->state.first_host)
      /* Free to avoid leaking memory on multiple requests*/
      free(data->state.first_host);

    data->state.first_host = strdup(conn->host.name);
    if(!data->state.first_host)
      return CURLE_OUT_OF_MEMORY;
  }

  if(conn->protocol & PROT_HTTPS) {
    /* perform SSL initialization */
    if(data->state.used_interface == Curl_if_multi) {
      result = Curl_https_connecting(conn, done);
      if(result)
        return result;
    }
    else {
      /* BLOCKING */
      result = Curl_ssl_connect(conn, FIRSTSOCKET);
      if(result)
        return result;
      *done = TRUE;
    }
  }
  else {
    *done = TRUE;
  }

  return CURLE_OK;
}

CURLcode Curl_https_connecting(struct connectdata *conn, bool *done)
{
  CURLcode result;
  curlassert(conn->protocol & PROT_HTTPS);

  /* perform SSL initialization for this socket */
  result = Curl_ssl_connect_nonblocking(conn, FIRSTSOCKET, done);
  if(result)
    return result;

  return CURLE_OK;
}

#ifdef USE_SSLEAY
/* This function is OpenSSL-specific. It should be made to query the generic
   SSL layer instead. */
int Curl_https_getsock(struct connectdata *conn,
                       curl_socket_t *socks,
                       int numsocks)
{
  if (conn->protocol & PROT_HTTPS) {
    struct ssl_connect_data *connssl = &conn->ssl[FIRSTSOCKET];

    if(!numsocks)
      return GETSOCK_BLANK;

    if (connssl->connecting_state == ssl_connect_2_writing) {
      /* write mode */
      socks[0] = conn->sock[FIRSTSOCKET];
      return GETSOCK_WRITESOCK(0);
    }
    else if (connssl->connecting_state == ssl_connect_2_reading) {
      /* read mode */
      socks[0] = conn->sock[FIRSTSOCKET];
      return GETSOCK_READSOCK(0);
    }
  }
  return CURLE_OK;
}
#else
#ifdef USE_GNUTLS
int Curl_https_getsock(struct connectdata *conn,
                       curl_socket_t *socks,
                       int numsocks)
{
  (void)conn;
  (void)socks;
  (void)numsocks;
  return GETSOCK_BLANK;
}
#endif
#endif

/*
 * Curl_http_done() gets called from Curl_done() after a single HTTP request
 * has been performed.
 */

CURLcode Curl_http_done(struct connectdata *conn,
                        CURLcode status, bool premature)
{
  struct SessionHandle *data = conn->data;
  struct HTTP *http =data->reqdata.proto.http;
  struct Curl_transfer_keeper *k = &data->reqdata.keep;
  (void)premature; /* not used */

  /* set the proper values (possibly modified on POST) */
  conn->fread = data->set.fread; /* restore */
  conn->fread_in = data->set.in; /* restore */

  if (http == NULL)
    return CURLE_OK;

  if(http->send_buffer) {
    send_buffer *buff = http->send_buffer;

    free(buff->buffer);
    free(buff);
    http->send_buffer = NULL; /* clear the pointer */
  }

  if(HTTPREQ_POST_FORM == data->set.httpreq) {
    k->bytecount = http->readbytecount + http->writebytecount;

    Curl_formclean(&http->sendit); /* Now free that whole lot */
    if(http->form.fp) {
      /* a file being uploaded was left opened, close it! */
      fclose(http->form.fp);
      http->form.fp = NULL;
    }
  }
  else if(HTTPREQ_PUT == data->set.httpreq)
    k->bytecount = http->readbytecount + http->writebytecount;

  if (status != CURLE_OK)
    return (status);

  if(!conn->bits.retry &&
     ((http->readbytecount +
       conn->headerbytecount -
       conn->deductheadercount)) <= 0) {
    /* If this connection isn't simply closed to be retried, AND nothing was
       read from the HTTP server (that counts), this can't be right so we
       return an error here */
    failf(data, "Empty reply from server");
    return CURLE_GOT_NOTHING;
  }

  return CURLE_OK;
}

/* check and possibly add an Expect: header */
static CURLcode expect100(struct SessionHandle *data,
                          send_buffer *req_buffer)
{
  CURLcode result = CURLE_OK;
  data->state.expect100header = FALSE; /* default to false unless it is set
                                          to TRUE below */
  if((data->set.httpversion != CURL_HTTP_VERSION_1_0) &&
     !checkheaders(data, "Expect:")) {
    /* if not doing HTTP 1.0 or disabled explicitly, we add a Expect:
       100-continue to the headers which actually speeds up post
       operations (as there is one packet coming back from the web
       server) */
    result = add_bufferf(req_buffer,
                         "Expect: 100-continue\r\n");
    if(result == CURLE_OK)
      data->state.expect100header = TRUE;
  }
  return result;
}

static CURLcode add_custom_headers(struct connectdata *conn,
                                   send_buffer *req_buffer)
{
  CURLcode result = CURLE_OK;
  char *ptr;
  struct curl_slist *headers=conn->data->set.headers;

  while(headers) {
    ptr = strchr(headers->data, ':');
    if(ptr) {
      /* we require a colon for this to be a true header */

      ptr++; /* pass the colon */
      while(*ptr && ISSPACE(*ptr))
        ptr++;

      if(*ptr) {
        /* only send this if the contents was non-blank */

        if(conn->allocptr.host &&
           /* a Host: header was sent already, don't pass on any custom Host:
              header as that will produce *two* in the same request! */
           curl_strnequal("Host:", headers->data, 5))
          ;
        else if(conn->data->set.httpreq == HTTPREQ_POST_FORM &&
                /* this header (extended by formdata.c) is sent later */
                curl_strnequal("Content-Type:", headers->data,
                               strlen("Content-Type:")))
          ;
        else {
          result = add_bufferf(req_buffer, "%s\r\n", headers->data);
          if(result)
            return result;
        }
      }
    }
    headers = headers->next;
  }
  return result;
}

/*
 * Curl_http() gets called from the generic Curl_do() function when a HTTP
 * request is to be performed. This creates and sends a properly constructed
 * HTTP request.
 */
CURLcode Curl_http(struct connectdata *conn, bool *done)
{
  struct SessionHandle *data=conn->data;
  char *buf = data->state.buffer; /* this is a short cut to the buffer */
  CURLcode result=CURLE_OK;
  struct HTTP *http;
  char *ppath = data->reqdata.path;
  char *host = conn->host.name;
  const char *te = ""; /* transfer-encoding */
  char *ptr;
  char *request;
  Curl_HttpReq httpreq = data->set.httpreq;
  char *addcookies = NULL;
  curl_off_t included_body = 0;

  /* Always consider the DO phase done after this function call, even if there
     may be parts of the request that is not yet sent, since we can deal with
     the rest of the request in the PERFORM phase. */
  *done = TRUE;

  if(!data->reqdata.proto.http) {
    /* Only allocate this struct if we don't already have it! */

    http = (struct HTTP *)malloc(sizeof(struct HTTP));
    if(!http)
      return CURLE_OUT_OF_MEMORY;
    memset(http, 0, sizeof(struct HTTP));
    data->reqdata.proto.http = http;
  }
  else
    http = data->reqdata.proto.http;

  /* We default to persistent connections */
  conn->bits.close = FALSE;

  if ( (conn->protocol&(PROT_HTTP|PROT_FTP)) &&
       data->set.upload) {
    httpreq = HTTPREQ_PUT;
  }

  /* Now set the 'request' pointer to the proper request string */
  if(data->set.customrequest)
    request = data->set.customrequest;
  else {
    if(conn->bits.no_body)
      request = (char *)"HEAD";
    else {
      curlassert((httpreq > HTTPREQ_NONE) && (httpreq < HTTPREQ_LAST));
      switch(httpreq) {
      case HTTPREQ_POST:
      case HTTPREQ_POST_FORM:
        request = (char *)"POST";
        break;
      case HTTPREQ_PUT:
        request = (char *)"PUT";
        break;
      default: /* this should never happen */
      case HTTPREQ_GET:
        request = (char *)"GET";
        break;
      case HTTPREQ_HEAD:
        request = (char *)"HEAD";
        break;
      }
    }
  }

  /* The User-Agent string might have been allocated in url.c already, because
     it might have been used in the proxy connect, but if we have got a header
     with the user-agent string specified, we erase the previously made string
     here. */
  if(checkheaders(data, "User-Agent:") && conn->allocptr.uagent) {
    free(conn->allocptr.uagent);
    conn->allocptr.uagent=NULL;
  }

  /* setup the authentication headers */
  result = Curl_http_output_auth(conn, request, ppath, FALSE);
  if(result)
    return result;

  if((data->state.authhost.multi || data->state.authproxy.multi) &&
     (httpreq != HTTPREQ_GET) &&
     (httpreq != HTTPREQ_HEAD)) {
    /* Auth is required and we are not authenticated yet. Make a PUT or POST
       with content-length zero as a "probe". */
    conn->bits.authneg = TRUE;
  }
  else
    conn->bits.authneg = FALSE;

  Curl_safefree(conn->allocptr.ref);
  if(data->change.referer && !checkheaders(data, "Referer:"))
    conn->allocptr.ref = aprintf("Referer: %s\r\n", data->change.referer);
  else
    conn->allocptr.ref = NULL;

  if(data->set.cookie && !checkheaders(data, "Cookie:"))
    addcookies = data->set.cookie;

  if(!checkheaders(data, "Accept-Encoding:") &&
     data->set.encoding) {
    Curl_safefree(conn->allocptr.accept_encoding);
    conn->allocptr.accept_encoding =
      aprintf("Accept-Encoding: %s\r\n", data->set.encoding);
    if(!conn->allocptr.accept_encoding)
      return CURLE_OUT_OF_MEMORY;
  }

  ptr = checkheaders(data, "Transfer-Encoding:");
  if(ptr) {
    /* Some kind of TE is requested, check if 'chunked' is chosen */
    conn->bits.upload_chunky =
      Curl_compareheader(ptr, "Transfer-Encoding:", "chunked");
  }
  else {
    if (httpreq == HTTPREQ_GET)
      conn->bits.upload_chunky = FALSE;
    if(conn->bits.upload_chunky)
      te = "Transfer-Encoding: chunked\r\n";
  }

  Curl_safefree(conn->allocptr.host);

  ptr = checkheaders(data, "Host:");
  if(ptr && (!data->state.this_is_a_follow ||
             curl_strequal(data->state.first_host, conn->host.name))) {
#if !defined(CURL_DISABLE_COOKIES)
    /* If we have a given custom Host: header, we extract the host name in
       order to possibly use it for cookie reasons later on. We only allow the
       custom Host: header if this is NOT a redirect, as setting Host: in the
       redirected request is being out on thin ice. Except if the host name
       is the same as the first one! */
    char *start = ptr+strlen("Host:");
    while(*start && ISSPACE(*start ))
      start++;
    ptr = start; /* start host-scanning here */

    /* scan through the string to find the end (space or colon) */
    while(*ptr && !ISSPACE(*ptr) && !(':'==*ptr))
      ptr++;

    if(ptr != start) {
      size_t len=ptr-start;
      Curl_safefree(conn->allocptr.cookiehost);
      conn->allocptr.cookiehost = malloc(len+1);
      if(!conn->allocptr.cookiehost)
        return CURLE_OUT_OF_MEMORY;
      memcpy(conn->allocptr.cookiehost, start, len);
      conn->allocptr.cookiehost[len]=0;
    }
#endif

    conn->allocptr.host = NULL;
  }
  else {
    /* When building Host: headers, we must put the host name within
       [brackets] if the host name is a plain IPv6-address. RFC2732-style. */

    if(((conn->protocol&PROT_HTTPS) && (conn->remote_port == PORT_HTTPS)) ||
       (!(conn->protocol&PROT_HTTPS) && (conn->remote_port == PORT_HTTP)) )
      /* If (HTTPS on port 443) OR (non-HTTPS on port 80) then don't include
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

  if (conn->bits.httpproxy && !conn->bits.tunnel_proxy)  {
    /* Using a proxy but does not tunnel through it */

    /* The path sent to the proxy is in fact the entire URL. But if the remote
       host is a IDN-name, we must make sure that the request we produce only
       uses the encoded host name! */
    if(conn->host.dispname != conn->host.name) {
      char *url = data->change.url;
      ptr = strstr(url, conn->host.dispname);
      if(ptr) {
        /* This is where the display name starts in the URL, now replace this
           part with the encoded name. TODO: This method of replacing the host
           name is rather crude as I believe there's a slight risk that the
           user has entered a user name or password that contain the host name
           string. */
        size_t currlen = strlen(conn->host.dispname);
        size_t newlen = strlen(conn->host.name);
        size_t urllen = strlen(url);

        char *newurl;

        newurl = malloc(urllen + newlen - currlen + 1);
        if(newurl) {
          /* copy the part before the host name */
          memcpy(newurl, url, ptr - url);
          /* append the new host name instead of the old */
          memcpy(newurl + (ptr - url), conn->host.name, newlen);
          /* append the piece after the host name */
          memcpy(newurl + newlen + (ptr - url),
                 ptr + currlen, /* copy the trailing zero byte too */
                 urllen - (ptr-url) - currlen + 1);
          if(data->change.url_alloc)
            free(data->change.url);
          data->change.url = newurl;
          data->change.url_alloc = TRUE;
        }
        else
          return CURLE_OUT_OF_MEMORY;
      }
    }
    ppath = data->change.url;
  }
  if(HTTPREQ_POST_FORM == httpreq) {
    /* we must build the whole darned post sequence first, so that we have
       a size of the whole shebang before we start to send it */
     result = Curl_getFormData(&http->sendit, data->set.httppost,
                               checkheaders(data, "Content-Type:"),
                               &http->postsize);
     if(CURLE_OK != result) {
       /* Curl_getFormData() doesn't use failf() */
       failf(data, "failed creating formpost data");
       return result;
     }
  }


  http->p_pragma =
    (!checkheaders(data, "Pragma:") &&
     (conn->bits.httpproxy && !conn->bits.tunnel_proxy) )?
    "Pragma: no-cache\r\n":NULL;

  if(!checkheaders(data, "Accept:"))
    http->p_accept = "Accept: */*\r\n";

  if(( (HTTPREQ_POST == httpreq) ||
       (HTTPREQ_POST_FORM == httpreq) ||
       (HTTPREQ_PUT == httpreq) ) &&
     data->reqdata.resume_from) {
    /**********************************************************************
     * Resuming upload in HTTP means that we PUT or POST and that we have
     * got a resume_from value set. The resume value has already created
     * a Range: header that will be passed along. We need to "fast forward"
     * the file the given number of bytes and decrease the assume upload
     * file size before we continue this venture in the dark lands of HTTP.
     *********************************************************************/

    if(data->reqdata.resume_from < 0 ) {
      /*
       * This is meant to get the size of the present remote-file by itself.
       * We don't support this now. Bail out!
       */
       data->reqdata.resume_from = 0;
    }

    if(data->reqdata.resume_from) {
      /* do we still game? */
      curl_off_t passed=0;

      /* Now, let's read off the proper amount of bytes from the
         input. If we knew it was a proper file we could've just
         fseek()ed but we only have a stream here */
      do {
        size_t readthisamountnow = (size_t)(data->reqdata.resume_from - passed);
        size_t actuallyread;

        if(readthisamountnow > BUFSIZE)
          readthisamountnow = BUFSIZE;

        actuallyread =
          data->set.fread(data->state.buffer, 1, (size_t)readthisamountnow,
                          data->set.in);

        passed += actuallyread;
        if(actuallyread != readthisamountnow) {
          failf(data, "Could only read %" FORMAT_OFF_T
                " bytes from the input",
                passed);
          return CURLE_READ_ERROR;
        }
      } while(passed != data->reqdata.resume_from); /* loop until done */

      /* now, decrease the size of the read */
      if(data->set.infilesize>0) {
        data->set.infilesize -= data->reqdata.resume_from;

        if(data->set.infilesize <= 0) {
          failf(data, "File already completely uploaded");
          return CURLE_PARTIAL_FILE;
        }
      }
      /* we've passed, proceed as normal */
    }
  }
  if(data->reqdata.use_range) {
    /*
     * A range is selected. We use different headers whether we're downloading
     * or uploading and we always let customized headers override our internal
     * ones if any such are specified.
     */
    if((httpreq == HTTPREQ_GET) &&
       !checkheaders(data, "Range:")) {
      /* if a line like this was already allocated, free the previous one */
      if(conn->allocptr.rangeline)
        free(conn->allocptr.rangeline);
      conn->allocptr.rangeline = aprintf("Range: bytes=%s\r\n", data->reqdata.range);
    }
    else if((httpreq != HTTPREQ_GET) &&
            !checkheaders(data, "Content-Range:")) {

      if(data->reqdata.resume_from) {
        /* This is because "resume" was selected */
        curl_off_t total_expected_size=
          data->reqdata.resume_from + data->set.infilesize;
        conn->allocptr.rangeline =
            aprintf("Content-Range: bytes %s%" FORMAT_OFF_T
                    "/%" FORMAT_OFF_T "\r\n",
                    data->reqdata.range, total_expected_size-1,
                    total_expected_size);
      }
      else {
        /* Range was selected and then we just pass the incoming range and
           append total size */
        conn->allocptr.rangeline =
            aprintf("Content-Range: bytes %s/%" FORMAT_OFF_T "\r\n",
                    data->reqdata.range, data->set.infilesize);
      }
    }
  }

  {
    /* Use 1.1 unless the use specificly asked for 1.0 */
    const char *httpstring=
      data->set.httpversion==CURL_HTTP_VERSION_1_0?"1.0":"1.1";

    send_buffer *req_buffer;
    curl_off_t postsize; /* off_t type to be able to hold a large file size */

    /* initialize a dynamic send-buffer */
    req_buffer = add_buffer_init();

    if(!req_buffer)
      return CURLE_OUT_OF_MEMORY;

    /* add the main request stuff */
    result =
      add_bufferf(req_buffer,
                  "%s " /* GET/HEAD/POST/PUT */
                  "%s HTTP/%s\r\n" /* path + HTTP version */
                  "%s" /* proxyuserpwd */
                  "%s" /* userpwd */
                  "%s" /* range */
                  "%s" /* user agent */
                  "%s" /* host */
                  "%s" /* pragma */
                  "%s" /* accept */
                  "%s" /* accept-encoding */
                  "%s" /* referer */
                  "%s" /* Proxy-Connection */
                  "%s",/* transfer-encoding */

                request,
                ppath,
                httpstring,
                conn->allocptr.proxyuserpwd?
                conn->allocptr.proxyuserpwd:"",
                conn->allocptr.userpwd?conn->allocptr.userpwd:"",
                (data->reqdata.use_range && conn->allocptr.rangeline)?
                conn->allocptr.rangeline:"",
                (data->set.useragent && *data->set.useragent && conn->allocptr.uagent)?
                conn->allocptr.uagent:"",
                (conn->allocptr.host?conn->allocptr.host:""), /* Host: host */
                http->p_pragma?http->p_pragma:"",
                http->p_accept?http->p_accept:"",
                (data->set.encoding && *data->set.encoding && conn->allocptr.accept_encoding)?
                conn->allocptr.accept_encoding:"",
                (data->change.referer && conn->allocptr.ref)?conn->allocptr.ref:"" /* Referer: <data> */,
                (conn->bits.httpproxy &&
                 !conn->bits.tunnel_proxy &&
                 !checkheaders(data, "Proxy-Connection:"))?
                  "Proxy-Connection: Keep-Alive\r\n":"",
                te
                );

    if(result)
      return result;

#if !defined(CURL_DISABLE_COOKIES)
    if(data->cookies || addcookies) {
      struct Cookie *co=NULL; /* no cookies from start */
      int count=0;

      if(data->cookies) {
        Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
        co = Curl_cookie_getlist(data->cookies,
                                 conn->allocptr.cookiehost?
                                 conn->allocptr.cookiehost:host, data->reqdata.path,
                                 (bool)(conn->protocol&PROT_HTTPS?TRUE:FALSE));
        Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
      }
      if(co) {
        struct Cookie *store=co;
        /* now loop through all cookies that matched */
        while(co) {
          if(co->value) {
            if(0 == count) {
              result = add_bufferf(req_buffer, "Cookie: ");
              if(result)
                break;
            }
            result = add_bufferf(req_buffer,
                                 "%s%s=%s", count?"; ":"",
                                 co->name, co->value);
            if(result)
              break;
            count++;
          }
          co = co->next; /* next cookie please */
        }
        Curl_cookie_freelist(store); /* free the cookie list */
      }
      if(addcookies && (CURLE_OK == result)) {
        if(!count)
          result = add_bufferf(req_buffer, "Cookie: ");
        if(CURLE_OK == result) {
          result = add_bufferf(req_buffer, "%s%s",
                               count?"; ":"",
                               addcookies);
          count++;
        }
      }
      if(count && (CURLE_OK == result))
        result = add_buffer(req_buffer, "\r\n", 2);

      if(result)
        return result;
    }
#endif

    if(data->set.timecondition) {
      struct tm *tm;

      /* Phil Karn (Fri, 13 Apr 2001) pointed out that the If-Modified-Since
       * header family should have their times set in GMT as RFC2616 defines:
       * "All HTTP date/time stamps MUST be represented in Greenwich Mean Time
       * (GMT), without exception. For the purposes of HTTP, GMT is exactly
       * equal to UTC (Coordinated Universal Time)." (see page 20 of RFC2616).
       */

#ifdef HAVE_GMTIME_R
      /* thread-safe version */
      struct tm keeptime;
      tm = (struct tm *)gmtime_r(&data->set.timevalue, &keeptime);
#else
      tm = gmtime(&data->set.timevalue);
#endif

      /* format: "Tue, 15 Nov 1994 12:45:26 GMT" */
      snprintf(buf, BUFSIZE-1,
               "%s, %02d %s %4d %02d:%02d:%02d GMT",
               Curl_wkday[tm->tm_wday?tm->tm_wday-1:6],
               tm->tm_mday,
               Curl_month[tm->tm_mon],
               tm->tm_year + 1900,
               tm->tm_hour,
               tm->tm_min,
               tm->tm_sec);

      switch(data->set.timecondition) {
      case CURL_TIMECOND_IFMODSINCE:
      default:
        result = add_bufferf(req_buffer,
                             "If-Modified-Since: %s\r\n", buf);
        break;
      case CURL_TIMECOND_IFUNMODSINCE:
        result = add_bufferf(req_buffer,
                             "If-Unmodified-Since: %s\r\n", buf);
        break;
      case CURL_TIMECOND_LASTMOD:
        result = add_bufferf(req_buffer,
                             "Last-Modified: %s\r\n", buf);
        break;
      }
      if(result)
        return result;
    }

    result = add_custom_headers(conn, req_buffer);
    if(result)
      return result;

    http->postdata = NULL;  /* nothing to post at this point */
    Curl_pgrsSetUploadSize(data, 0); /* upload size is 0 atm */

    /* If 'authdone' is FALSE, we must not set the write socket index to the
       Curl_transfer() call below, as we're not ready to actually upload any
       data yet. */

    switch(httpreq) {

    case HTTPREQ_POST_FORM:
      if(!http->sendit || conn->bits.authneg) {
        /* nothing to post! */
        result = add_bufferf(req_buffer, "Content-Length: 0\r\n\r\n");
        if(result)
          return result;

        result = add_buffer_send(req_buffer, conn,
                                 &data->info.request_size, 0, FIRSTSOCKET);
        if(result)
          failf(data, "Failed sending POST request");
        else
          /* setup variables for the upcoming transfer */
          result = Curl_setup_transfer(conn, FIRSTSOCKET, -1, TRUE,
                                       &http->readbytecount,
                                       -1, NULL);
        break;
      }

      if(Curl_FormInit(&http->form, http->sendit)) {
        failf(data, "Internal HTTP POST error!");
        return CURLE_HTTP_POST_ERROR;
      }

      /* set the read function to read from the generated form data */
      conn->fread = (curl_read_callback)Curl_FormReader;
      conn->fread_in = &http->form;

      http->sending = HTTPSEND_BODY;

      if(!conn->bits.upload_chunky) {
        /* only add Content-Length if not uploading chunked */
        result = add_bufferf(req_buffer,
                             "Content-Length: %" FORMAT_OFF_T "\r\n",
                             http->postsize);
        if(result)
          return result;
      }

      result = expect100(data, req_buffer);
      if(result)
        return result;

      {

        /* Get Content-Type: line from Curl_formpostheader.
        */
        char *contentType;
        size_t linelength=0;
        contentType = Curl_formpostheader((void *)&http->form,
                                          &linelength);
        if(!contentType) {
          failf(data, "Could not get Content-Type header line!");
          return CURLE_HTTP_POST_ERROR;
        }

        result = add_buffer(req_buffer, contentType, linelength);
        if(result)
          return result;
      }

      /* make the request end in a true CRLF */
      result = add_buffer(req_buffer, "\r\n", 2);
      if(result)
        return result;

      /* set upload size to the progress meter */
      Curl_pgrsSetUploadSize(data, http->postsize);

      /* fire away the whole request to the server */
      result = add_buffer_send(req_buffer, conn,
                               &data->info.request_size, 0, FIRSTSOCKET);
      if(result)
        failf(data, "Failed sending POST request");
      else
        /* setup variables for the upcoming transfer */
        result = Curl_setup_transfer(conn, FIRSTSOCKET, -1, TRUE,
                                     &http->readbytecount,
                                     FIRSTSOCKET,
                                     &http->writebytecount);

      if(result) {
        Curl_formclean(&http->sendit); /* free that whole lot */
        return result;
      }
#ifdef CURL_DOES_CONVERSIONS
/* time to convert the form data... */
      result = Curl_formconvert(data, http->sendit);
      if(result) {
        Curl_formclean(&http->sendit); /* free that whole lot */
        return result;
      }
#endif /* CURL_DOES_CONVERSIONS */
      break;

    case HTTPREQ_PUT: /* Let's PUT the data to the server! */

      if(conn->bits.authneg)
        postsize = 0;
      else
        postsize = data->set.infilesize;

      if((postsize != -1) && !conn->bits.upload_chunky) {
        /* only add Content-Length if not uploading chunked */
        result = add_bufferf(req_buffer,
                             "Content-Length: %" FORMAT_OFF_T "\r\n",
                             postsize );
        if(result)
          return result;
      }

      result = expect100(data, req_buffer);
      if(result)
        return result;

      result = add_buffer(req_buffer, "\r\n", 2); /* end of headers */
      if(result)
        return result;

      /* set the upload size to the progress meter */
      Curl_pgrsSetUploadSize(data, postsize);

      /* this sends the buffer and frees all the buffer resources */
      result = add_buffer_send(req_buffer, conn,
                               &data->info.request_size, 0, FIRSTSOCKET);
      if(result)
        failf(data, "Failed sending PUT request");
      else
        /* prepare for transfer */
        result = Curl_setup_transfer(conn, FIRSTSOCKET, -1, TRUE,
                                     &http->readbytecount,
                                     postsize?FIRSTSOCKET:-1,
                                     postsize?&http->writebytecount:NULL);
      if(result)
        return result;
      break;

    case HTTPREQ_POST:
      /* this is the simple POST, using x-www-form-urlencoded style */

      if(conn->bits.authneg)
        postsize = 0;
      else
        /* figure out the size of the postfields */
        postsize = (data->set.postfieldsize != -1)?
          data->set.postfieldsize:
          (data->set.postfields?(curl_off_t)strlen(data->set.postfields):0);

      if(!conn->bits.upload_chunky) {
        /* We only set Content-Length and allow a custom Content-Length if
           we don't upload data chunked, as RFC2616 forbids us to set both
           kinds of headers (Transfer-Encoding: chunked and Content-Length) */

        if(!checkheaders(data, "Content-Length:")) {
          /* we allow replacing this header, although it isn't very wise to
             actually set your own */
          result = add_bufferf(req_buffer,
                               "Content-Length: %" FORMAT_OFF_T"\r\n",
                               postsize);
          if(result)
            return result;
        }
      }

      if(!checkheaders(data, "Content-Type:")) {
        result = add_bufferf(req_buffer,
                             "Content-Type: application/x-www-form-urlencoded\r\n");
        if(result)
          return result;
      }

      if(data->set.postfields) {

        /* for really small posts we don't use Expect: headers at all, and for
           the somewhat bigger ones we allow the app to disable it */
        if(postsize > TINY_INITIAL_POST_SIZE) {
          result = expect100(data, req_buffer);
          if(result)
            return result;
        }
        else
          data->state.expect100header = FALSE;

        if(!data->state.expect100header &&
           (postsize < MAX_INITIAL_POST_SIZE))  {
          /* if we don't use expect:-100  AND
             postsize is less than MAX_INITIAL_POST_SIZE

             then append the post data to the HTTP request header. This limit
             is no magic limit but only set to prevent really huge POSTs to
             get the data duplicated with malloc() and family. */

          result = add_buffer(req_buffer, "\r\n", 2); /* end of headers! */
          if(result)
            return result;

          if(!conn->bits.upload_chunky) {
            /* We're not sending it 'chunked', append it to the request
               already now to reduce the number if send() calls */
            result = add_buffer(req_buffer, data->set.postfields,
                                (size_t)postsize);
            included_body = postsize;
          }
          else {
            /* Append the POST data chunky-style */
            result = add_bufferf(req_buffer, "%x\r\n", (int)postsize);
            if(CURLE_OK == result)
              result = add_buffer(req_buffer, data->set.postfields,
                                  (size_t)postsize);
            if(CURLE_OK == result)
              result = add_buffer(req_buffer,
                                  "\x0d\x0a\x30\x0d\x0a\x0d\x0a", 7);
                                  /* CR  LF   0  CR  LF  CR  LF */
            included_body = postsize + 7;
          }
          if(result)
            return result;
        }
        else {
          /* A huge POST coming up, do data separate from the request */
          http->postsize = postsize;
          http->postdata = data->set.postfields;

          http->sending = HTTPSEND_BODY;

          conn->fread = (curl_read_callback)readmoredata;
          conn->fread_in = (void *)conn;

          /* set the upload size to the progress meter */
          Curl_pgrsSetUploadSize(data, http->postsize);

          add_buffer(req_buffer, "\r\n", 2); /* end of headers! */
        }
      }
      else {
        add_buffer(req_buffer, "\r\n", 2); /* end of headers! */

        if(data->set.postfieldsize) {
          /* set the upload size to the progress meter */
          Curl_pgrsSetUploadSize(data, postsize?postsize:-1);

          /* set the pointer to mark that we will send the post body using
             the read callback */
          http->postdata = (char *)&http->postdata;
        }
      }
      /* issue the request */
      result = add_buffer_send(req_buffer, conn, &data->info.request_size,
                               (size_t)included_body, FIRSTSOCKET);

      if(result)
        failf(data, "Failed sending HTTP POST request");
      else
        result =
          Curl_setup_transfer(conn, FIRSTSOCKET, -1, TRUE,
                        &http->readbytecount,
                        http->postdata?FIRSTSOCKET:-1,
                        http->postdata?&http->writebytecount:NULL);
      break;

    default:
      add_buffer(req_buffer, "\r\n", 2);

      /* issue the request */
      result = add_buffer_send(req_buffer, conn,
                               &data->info.request_size, 0, FIRSTSOCKET);

      if(result)
        failf(data, "Failed sending HTTP request");
      else
        /* HTTP GET/HEAD download: */
        result = Curl_setup_transfer(conn, FIRSTSOCKET, -1, TRUE,
                               &http->readbytecount,
                               http->postdata?FIRSTSOCKET:-1,
                               http->postdata?&http->writebytecount:NULL);
    }
    if(result)
      return result;
  }

  return CURLE_OK;
}
#endif
