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

#include <limits.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_LINUX_TCP_H
#include <linux/tcp.h>
#elif defined(HAVE_NETINET_TCP_H)
#include <netinet/tcp.h>
#endif

#include "urldata.h"
#include "url.h"
#include "progress.h"
#include "content_encoding.h"
#include "strcase.h"
#include "share.h"
#include "vtls/vtls.h"
#include "curlx/warnless.h"
#include "sendf.h"
#include "hostip.h"
#include "http2.h"
#include "setopt.h"
#include "multiif.h"
#include "altsvc.h"
#include "hsts.h"
#include "tftp.h"
#include "strdup.h"
#include "escape.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

static CURLcode setopt_set_timeout_sec(timediff_t *ptimeout_ms, long secs)
{
  if(secs < 0)
    return CURLE_BAD_FUNCTION_ARGUMENT;
#if LONG_MAX > (TIMEDIFF_T_MAX/1000)
  if(secs > (TIMEDIFF_T_MAX/1000)) {
    *ptimeout_ms = TIMEDIFF_T_MAX;
    return CURLE_OK;
  }
#endif
  *ptimeout_ms = (timediff_t)secs * 1000;
  return CURLE_OK;
}

static CURLcode setopt_set_timeout_ms(timediff_t *ptimeout_ms, long ms)
{
  if(ms < 0)
    return CURLE_BAD_FUNCTION_ARGUMENT;
#if LONG_MAX > TIMEDIFF_T_MAX
  if(ms > TIMEDIFF_T_MAX) {
    *ptimeout_ms = TIMEDIFF_T_MAX;
    return CURLE_OK;
  }
#endif
  *ptimeout_ms = (timediff_t)ms;
  return CURLE_OK;
}

CURLcode Curl_setstropt(char **charp, const char *s)
{
  /* Release the previous storage at `charp' and replace by a dynamic storage
     copy of `s'. Return CURLE_OK or CURLE_OUT_OF_MEMORY. */

  Curl_safefree(*charp);

  if(s) {
    if(strlen(s) > CURL_MAX_INPUT_LENGTH)
      return CURLE_BAD_FUNCTION_ARGUMENT;

    *charp = strdup(s);
    if(!*charp)
      return CURLE_OUT_OF_MEMORY;
  }

  return CURLE_OK;
}

CURLcode Curl_setblobopt(struct curl_blob **blobp,
                         const struct curl_blob *blob)
{
  /* free the previous storage at `blobp' and replace by a dynamic storage
     copy of blob. If CURL_BLOB_COPY is set, the data is copied. */

  Curl_safefree(*blobp);

  if(blob) {
    struct curl_blob *nblob;
    if(blob->len > CURL_MAX_INPUT_LENGTH)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    nblob = (struct curl_blob *)
      malloc(sizeof(struct curl_blob) +
             ((blob->flags & CURL_BLOB_COPY) ? blob->len : 0));
    if(!nblob)
      return CURLE_OUT_OF_MEMORY;
    *nblob = *blob;
    if(blob->flags & CURL_BLOB_COPY) {
      /* put the data after the blob struct in memory */
      nblob->data = (char *)nblob + sizeof(struct curl_blob);
      memcpy(nblob->data, blob->data, blob->len);
    }

    *blobp = nblob;
    return CURLE_OK;
  }

  return CURLE_OK;
}

static CURLcode setstropt_userpwd(char *option, char **userp, char **passwdp)
{
  char *user = NULL;
  char *passwd = NULL;

  DEBUGASSERT(userp);
  DEBUGASSERT(passwdp);

  /* Parse the login details if specified. It not then we treat NULL as a hint
     to clear the existing data */
  if(option) {
    size_t len = strlen(option);
    CURLcode result;
    if(len > CURL_MAX_INPUT_LENGTH)
      return CURLE_BAD_FUNCTION_ARGUMENT;

    result = Curl_parse_login_details(option, len, &user, &passwd, NULL);
    if(result)
      return result;
  }

  free(*userp);
  *userp = user;

  free(*passwdp);
  *passwdp = passwd;

  return CURLE_OK;
}

static CURLcode setstropt_interface(char *option, char **devp,
                                    char **ifacep, char **hostp)
{
  char *dev = NULL;
  char *iface = NULL;
  char *host = NULL;
  CURLcode result;

  DEBUGASSERT(devp);
  DEBUGASSERT(ifacep);
  DEBUGASSERT(hostp);

  if(option) {
    /* Parse the interface details if set, otherwise clear them all */
    result = Curl_parse_interface(option, &dev, &iface, &host);
    if(result)
      return result;
  }
  free(*devp);
  *devp = dev;

  free(*ifacep);
  *ifacep = iface;

  free(*hostp);
  *hostp = host;

  return CURLE_OK;
}

#define C_SSLVERSION_VALUE(x) (x & 0xffff)
#define C_SSLVERSION_MAX_VALUE(x) ((unsigned long)x & 0xffff0000)

static CURLcode protocol2num(const char *str, curl_prot_t *val)
{
  /*
   * We are asked to cherry-pick protocols, so play it safe and disallow all
   * protocols to start with, and re-add the wanted ones back in.
   */
  *val = 0;

  if(!str)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if(curl_strequal(str, "all")) {
    *val = ~(curl_prot_t) 0;
    return CURLE_OK;
  }

  do {
    const char *token = str;
    size_t tlen;

    str = strchr(str, ',');
    tlen = str ? (size_t) (str - token) : strlen(token);
    if(tlen) {
      const struct Curl_handler *h = Curl_getn_scheme_handler(token, tlen);

      if(!h)
        return CURLE_UNSUPPORTED_PROTOCOL;

      *val |= h->protocol;
    }
  } while(str && str++);

  if(!*val)
    /* no protocol listed */
    return CURLE_BAD_FUNCTION_ARGUMENT;
  return CURLE_OK;
}

#if !defined(CURL_DISABLE_HTTP) || !defined(CURL_DISABLE_PROXY)
static CURLcode httpauth(struct Curl_easy *data, bool proxy,
                         unsigned long auth)
{
  if(auth != CURLAUTH_NONE) {
    int bitcheck = 0;
    bool authbits = FALSE;
    /* the DIGEST_IE bit is only used to set a special marker, for all the
       rest we need to handle it as normal DIGEST */
    bool iestyle = !!(auth & CURLAUTH_DIGEST_IE);
    if(proxy)
      data->state.authproxy.iestyle = iestyle;
    else
      data->state.authhost.iestyle = iestyle;

    if(auth & CURLAUTH_DIGEST_IE) {
      auth |= CURLAUTH_DIGEST; /* set standard digest bit */
      auth &= ~CURLAUTH_DIGEST_IE; /* unset ie digest bit */
    }

    /* switch off bits we cannot support */
#ifndef USE_NTLM
    auth &= ~CURLAUTH_NTLM;    /* no NTLM support */
#endif
#ifndef USE_SPNEGO
    auth &= ~CURLAUTH_NEGOTIATE; /* no Negotiate (SPNEGO) auth without GSS-API
                                    or SSPI */
#endif

    /* check if any auth bit lower than CURLAUTH_ONLY is still set */
    while(bitcheck < 31) {
      if(auth & (1UL << bitcheck++)) {
        authbits = TRUE;
        break;
      }
    }
    if(!authbits)
      return CURLE_NOT_BUILT_IN; /* no supported types left! */
  }
  if(proxy)
    data->set.proxyauth = auth;
  else
    data->set.httpauth = auth;
  return CURLE_OK;
}
#endif /* !CURL_DISABLE_HTTP || !CURL_DISABLE_PROXY */

#ifndef CURL_DISABLE_HTTP
static CURLcode setopt_HTTP_VERSION(struct Curl_easy *data, long arg)
{
  /*
   * This sets a requested HTTP version to be used. The value is one of
   * the listed enums in curl/curl.h.
   */
  switch(arg) {
  case CURL_HTTP_VERSION_NONE:
    /* accepted */
    break;
  case CURL_HTTP_VERSION_1_0:
  case CURL_HTTP_VERSION_1_1:
    /* accepted */
    break;
#ifdef USE_HTTP2
  case CURL_HTTP_VERSION_2_0:
  case CURL_HTTP_VERSION_2TLS:
  case CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE:
    /* accepted */
    break;
#endif
#ifdef USE_HTTP3
  case CURL_HTTP_VERSION_3:
  case CURL_HTTP_VERSION_3ONLY:
    /* accepted */
    break;
#endif
  default:
    /* not accepted */
    if(arg < CURL_HTTP_VERSION_NONE)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    return CURLE_UNSUPPORTED_PROTOCOL;
  }
  data->set.httpwant = (unsigned char)arg;
  return CURLE_OK;
}
#endif /* ! CURL_DISABLE_HTTP */

#ifdef USE_SSL
CURLcode Curl_setopt_SSLVERSION(struct Curl_easy *data, CURLoption option,
                                long arg)
{
  /*
   * Set explicit SSL version to try to connect with, as some SSL
   * implementations are lame.
   */
  {
    long version, version_max;
    struct ssl_primary_config *primary = &data->set.ssl.primary;
#ifndef CURL_DISABLE_PROXY
    if(option != CURLOPT_SSLVERSION)
      primary = &data->set.proxy_ssl.primary;
#else
    if(option) {}
#endif
    version = C_SSLVERSION_VALUE(arg);
    version_max = (long)C_SSLVERSION_MAX_VALUE(arg);

    if(version < CURL_SSLVERSION_DEFAULT ||
       version == CURL_SSLVERSION_SSLv2 ||
       version == CURL_SSLVERSION_SSLv3 ||
       version >= CURL_SSLVERSION_LAST ||
       version_max < CURL_SSLVERSION_MAX_NONE ||
       version_max >= CURL_SSLVERSION_MAX_LAST)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    if(version == CURL_SSLVERSION_DEFAULT)
      version = CURL_SSLVERSION_TLSv1_2;

    primary->version = (unsigned char)version;
    primary->version_max = (unsigned int)version_max;
  }
  return CURLE_OK;
}
#endif /* ! USE_SSL */

#ifndef CURL_DISABLE_RTSP
static CURLcode setopt_RTSP_REQUEST(struct Curl_easy *data, long arg)
{
  /*
   * Set the RTSP request method (OPTIONS, SETUP, PLAY, etc...)
   * Would this be better if the RTSPREQ_* were just moved into here?
   */
  Curl_RtspReq rtspreq = RTSPREQ_NONE;
  switch(arg) {
  case CURL_RTSPREQ_OPTIONS:
    rtspreq = RTSPREQ_OPTIONS;
    break;

  case CURL_RTSPREQ_DESCRIBE:
    rtspreq = RTSPREQ_DESCRIBE;
    break;

  case CURL_RTSPREQ_ANNOUNCE:
    rtspreq = RTSPREQ_ANNOUNCE;
    break;

  case CURL_RTSPREQ_SETUP:
    rtspreq = RTSPREQ_SETUP;
    break;

  case CURL_RTSPREQ_PLAY:
    rtspreq = RTSPREQ_PLAY;
    break;

  case CURL_RTSPREQ_PAUSE:
    rtspreq = RTSPREQ_PAUSE;
    break;

  case CURL_RTSPREQ_TEARDOWN:
    rtspreq = RTSPREQ_TEARDOWN;
    break;

  case CURL_RTSPREQ_GET_PARAMETER:
    rtspreq = RTSPREQ_GET_PARAMETER;
    break;

  case CURL_RTSPREQ_SET_PARAMETER:
    rtspreq = RTSPREQ_SET_PARAMETER;
    break;

  case CURL_RTSPREQ_RECORD:
    rtspreq = RTSPREQ_RECORD;
    break;

  case CURL_RTSPREQ_RECEIVE:
    rtspreq = RTSPREQ_RECEIVE;
    break;
  default:
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  data->set.rtspreq = rtspreq;
  return CURLE_OK;
}
#endif /* ! CURL_DISABLE_RTSP */

#ifdef USE_SSL
static void set_ssl_options(struct ssl_config_data *ssl,
                            struct ssl_primary_config *config,
                            long arg)
{
  config->ssl_options = (unsigned char)(arg & 0xff);
  ssl->enable_beast = !!(arg & CURLSSLOPT_ALLOW_BEAST);
  ssl->no_revoke = !!(arg & CURLSSLOPT_NO_REVOKE);
  ssl->no_partialchain = !!(arg & CURLSSLOPT_NO_PARTIALCHAIN);
  ssl->revoke_best_effort = !!(arg & CURLSSLOPT_REVOKE_BEST_EFFORT);
  ssl->native_ca_store = !!(arg & CURLSSLOPT_NATIVE_CA);
  ssl->auto_client_cert = !!(arg & CURLSSLOPT_AUTO_CLIENT_CERT);
  ssl->earlydata = !!(arg & CURLSSLOPT_EARLYDATA);
}
#endif

static CURLcode setopt_bool(struct Curl_easy *data, CURLoption option,
                            long arg, bool *set)
{
  bool enabled = !!arg;
  int ok = 1;
  struct UserDefined *s = &data->set;
  switch(option) {
  case CURLOPT_FORBID_REUSE:
    /*
     * When this transfer is done, it must not be left to be reused by a
     * subsequent transfer but shall be closed immediately.
     */
    s->reuse_forbid = enabled;
    break;
  case CURLOPT_FRESH_CONNECT:
    /*
     * This transfer shall not use a previously cached connection but
     * should be made with a fresh new connect!
     */
    s->reuse_fresh = enabled;
    break;
  case CURLOPT_VERBOSE:
    /*
     * Verbose means infof() calls that give a lot of information about
     * the connection and transfer procedures as well as internal choices.
     */
    s->verbose = enabled;
    break;
  case CURLOPT_HEADER:
    /*
     * Set to include the header in the general data output stream.
     */
    s->include_header = enabled;
    break;
  case CURLOPT_NOPROGRESS:
    /*
     * Shut off the internal supported progress meter
     */
    data->progress.hide = enabled;
    break;
  case CURLOPT_NOBODY:
    /*
     * Do not include the body part in the output data stream.
     */
    s->opt_no_body = enabled;
#ifndef CURL_DISABLE_HTTP
    if(s->opt_no_body)
      /* in HTTP lingo, no body means using the HEAD request... */
      s->method = HTTPREQ_HEAD;
    else if(s->method == HTTPREQ_HEAD)
      s->method = HTTPREQ_GET;
#endif
    break;
  case CURLOPT_FAILONERROR:
    /*
     * Do not output the >=400 error code HTML-page, but instead only
     * return error.
     */
    s->http_fail_on_error = enabled;
    break;
  case CURLOPT_KEEP_SENDING_ON_ERROR:
    s->http_keep_sending_on_error = enabled;
    break;
  case CURLOPT_UPLOAD:
  case CURLOPT_PUT:
    /*
     * We want to sent data to the remote host. If this is HTTP, that equals
     * using the PUT request.
     */
    if(enabled) {
      /* If this is HTTP, PUT is what's needed to "upload" */
      s->method = HTTPREQ_PUT;
      s->opt_no_body = FALSE; /* this is implied */
    }
    else
      /* In HTTP, the opposite of upload is GET (unless NOBODY is true as
         then this can be changed to HEAD later on) */
      s->method = HTTPREQ_GET;
    break;
  case CURLOPT_FILETIME:
    /*
     * Try to get the file time of the remote document. The time will
     * later (possibly) become available using curl_easy_getinfo().
     */
    s->get_filetime = enabled;
    break;
#ifndef CURL_DISABLE_HTTP
  case CURLOPT_HTTP09_ALLOWED:
    s->http09_allowed = enabled;
    break;
#if !defined(CURL_DISABLE_COOKIES)
  case CURLOPT_COOKIESESSION:
    /*
     * Set this option to TRUE to start a new "cookie session". It will
     * prevent the forthcoming read-cookies-from-file actions to accept
     * cookies that are marked as being session cookies, as they belong to a
     * previous session.
     */
    s->cookiesession = enabled;
    break;
#endif
  case CURLOPT_AUTOREFERER:
    /*
     * Switch on automatic referer that gets set if curl follows locations.
     */
    s->http_auto_referer = enabled;
    break;

  case CURLOPT_TRANSFER_ENCODING:
    s->http_transfer_encoding = enabled;
    break;
  case CURLOPT_UNRESTRICTED_AUTH:
    /*
     * Send authentication (user+password) when following locations, even when
     * hostname changed.
     */
    s->allow_auth_to_other_hosts = enabled;
    break;

  case CURLOPT_HTTP_TRANSFER_DECODING:
    /*
     * disable libcurl transfer encoding is used
     */
    s->http_te_skip = !enabled; /* reversed */
    break;

  case CURLOPT_HTTP_CONTENT_DECODING:
    /*
     * raw data passed to the application when content encoding is used
     */
    s->http_ce_skip = !enabled; /* reversed */
    break;

  case CURLOPT_HTTPGET:
    /*
     * Set to force us do HTTP GET
     */
    if(enabled) {
      s->method = HTTPREQ_GET;
      s->opt_no_body = FALSE; /* this is implied */
    }
    break;
  case CURLOPT_POST:
    /* Does this option serve a purpose anymore? Yes it does, when
       CURLOPT_POSTFIELDS is not used and the POST data is read off the
       callback! */
    if(enabled) {
      s->method = HTTPREQ_POST;
      s->opt_no_body = FALSE; /* this is implied */
    }
    else
      s->method = HTTPREQ_GET;
    break;
#endif /* ! CURL_DISABLE_HTTP */
#ifndef CURL_DISABLE_PROXY
  case CURLOPT_HTTPPROXYTUNNEL:
    /*
     * Tunnel operations through the proxy instead of normal proxy use
     */
    s->tunnel_thru_httpproxy = enabled;
    break;
  case CURLOPT_HAPROXYPROTOCOL:
    /*
     * Set to send the HAProxy Proxy Protocol header
     */
    s->haproxyprotocol = enabled;
    break;
  case CURLOPT_PROXY_SSL_VERIFYPEER:
    /*
     * Enable peer SSL verifying for proxy.
     */
    s->proxy_ssl.primary.verifypeer = enabled;

    /* Update the current connection proxy_ssl_config. */
    Curl_ssl_conn_config_update(data, TRUE);
    break;
  case CURLOPT_PROXY_SSL_VERIFYHOST:
    /*
     * Enable verification of the hostname in the peer certificate for proxy
     */
    s->proxy_ssl.primary.verifyhost = enabled;
    ok = 2;
    /* Update the current connection proxy_ssl_config. */
    Curl_ssl_conn_config_update(data, TRUE);
    break;
  case CURLOPT_PROXY_TRANSFER_MODE:
    /*
     * set transfer mode (;type=<a|i>) when doing FTP via an HTTP proxy
     */
    s->proxy_transfer_mode = enabled;
    break;
#endif /* ! CURL_DISABLE_PROXY */
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  case CURLOPT_SOCKS5_GSSAPI_NEC:
    /*
     * Set flag for NEC SOCK5 support
     */
    s->socks5_gssapi_nec = enabled;
    break;
#endif
#ifdef CURL_LIST_ONLY_PROTOCOL
  case CURLOPT_DIRLISTONLY:
    /*
     * An option that changes the command to one that asks for a list only, no
     * file info details. Used for FTP, POP3 and SFTP.
     */
    s->list_only = enabled;
    break;
#endif
  case CURLOPT_APPEND:
    /*
     * We want to upload and append to an existing file. Used for FTP and
     * SFTP.
     */
    s->remote_append = enabled;
    break;
#ifndef CURL_DISABLE_FTP
  case CURLOPT_FTP_USE_EPRT:
    s->ftp_use_eprt = enabled;
    break;

  case CURLOPT_FTP_USE_EPSV:
    s->ftp_use_epsv = enabled;
    break;

  case CURLOPT_FTP_USE_PRET:
    s->ftp_use_pret = enabled;
    break;
  case CURLOPT_FTP_SKIP_PASV_IP:
    /*
     * Enable or disable FTP_SKIP_PASV_IP, which will disable/enable the
     * bypass of the IP address in PASV responses.
     */
    s->ftp_skip_ip = enabled;
    break;
  case CURLOPT_WILDCARDMATCH:
    s->wildcard_enabled = enabled;
    break;
#endif
  case CURLOPT_CRLF:
    /*
     * Kludgy option to enable CRLF conversions. Subject for removal.
     */
    s->crlf = enabled;
    break;

#ifndef CURL_DISABLE_TFTP
  case CURLOPT_TFTP_NO_OPTIONS:
    /*
     * Option that prevents libcurl from sending TFTP option requests to the
     * server.
     */
    s->tftp_no_options = enabled;
    break;
#endif /* ! CURL_DISABLE_TFTP */
  case CURLOPT_TRANSFERTEXT:
    /*
     * This option was previously named 'FTPASCII'. Renamed to work with
     * more protocols than merely FTP.
     *
     * Transfer using ASCII (instead of BINARY).
     */
    s->prefer_ascii = enabled;
    break;
  case CURLOPT_SSL_VERIFYPEER:
    /*
     * Enable peer SSL verifying.
     */
    s->ssl.primary.verifypeer = enabled;

    /* Update the current connection ssl_config. */
    Curl_ssl_conn_config_update(data, FALSE);
    break;
#ifndef CURL_DISABLE_DOH
  case CURLOPT_DOH_SSL_VERIFYPEER:
    /*
     * Enable peer SSL verifying for DoH.
     */
    s->doh_verifypeer = enabled;
    break;
  case CURLOPT_DOH_SSL_VERIFYHOST:
    /*
     * Enable verification of the hostname in the peer certificate for DoH
     */
    s->doh_verifyhost = enabled;
    ok = 2;
    break;
  case CURLOPT_DOH_SSL_VERIFYSTATUS:
    /*
     * Enable certificate status verifying for DoH.
     */
    if(!Curl_ssl_cert_status_request())
      return CURLE_NOT_BUILT_IN;

    s->doh_verifystatus = enabled;
    ok = 2;
    break;
#endif /* ! CURL_DISABLE_DOH */
  case CURLOPT_SSL_VERIFYHOST:
    /*
     * Enable verification of the hostname in the peer certificate
     */

    /* Obviously people are not reading documentation and too many thought
       this argument took a boolean when it was not and misused it.
       Treat 1 and 2 the same */
    s->ssl.primary.verifyhost = enabled;
    ok = 2;

    /* Update the current connection ssl_config. */
    Curl_ssl_conn_config_update(data, FALSE);
    break;
  case CURLOPT_SSL_VERIFYSTATUS:
    /*
     * Enable certificate status verifying.
     */
    if(!Curl_ssl_cert_status_request())
      return CURLE_NOT_BUILT_IN;

    s->ssl.primary.verifystatus = enabled;

    /* Update the current connection ssl_config. */
    Curl_ssl_conn_config_update(data, FALSE);
    break;
  case CURLOPT_CERTINFO:
#ifdef USE_SSL
    if(Curl_ssl_supports(data, SSLSUPP_CERTINFO))
      s->ssl.certinfo = enabled;
    else
#endif
      return CURLE_NOT_BUILT_IN;
    break;
  case CURLOPT_NOSIGNAL:
    /*
     * The application asks not to set any signal() or alarm() handlers,
     * even when using a timeout.
     */
    s->no_signal = enabled;
    break;
  case CURLOPT_TCP_NODELAY:
    /*
     * Enable or disable TCP_NODELAY, which will disable/enable the Nagle
     * algorithm
     */
    s->tcp_nodelay = enabled;
    break;

  case CURLOPT_IGNORE_CONTENT_LENGTH:
    s->ignorecl = enabled;
    break;
  case CURLOPT_SSL_SESSIONID_CACHE:
    s->ssl.primary.cache_session = enabled;
#ifndef CURL_DISABLE_PROXY
    s->proxy_ssl.primary.cache_session =
      s->ssl.primary.cache_session;
#endif
    break;
#ifdef USE_SSH
  case CURLOPT_SSH_COMPRESSION:
    s->ssh_compression = enabled;
    break;
#endif /* ! USE_SSH */
#ifndef CURL_DISABLE_SMTP
  case CURLOPT_MAIL_RCPT_ALLOWFAILS:
    /* allow RCPT TO command to fail for some recipients */
    s->mail_rcpt_allowfails = enabled;
    break;
#endif /* !CURL_DISABLE_SMTP */
  case CURLOPT_SASL_IR:
    /* Enable/disable SASL initial response */
    s->sasl_ir = enabled;
    break;
  case CURLOPT_TCP_KEEPALIVE:
    s->tcp_keepalive = enabled;
    break;
  case CURLOPT_TCP_FASTOPEN:
#if defined(CONNECT_DATA_IDEMPOTENT) || defined(MSG_FASTOPEN) ||        \
  defined(TCP_FASTOPEN_CONNECT)
    s->tcp_fastopen = enabled;
    break;
#else
    return CURLE_NOT_BUILT_IN;
#endif
  case CURLOPT_SSL_ENABLE_ALPN:
    s->ssl_enable_alpn = enabled;
    break;
  case CURLOPT_PATH_AS_IS:
    s->path_as_is = enabled;
    break;
  case CURLOPT_PIPEWAIT:
    s->pipewait = enabled;
    break;
  case CURLOPT_SUPPRESS_CONNECT_HEADERS:
    s->suppress_connect_headers = enabled;
    break;
#ifndef CURL_DISABLE_SHUFFLE_DNS
  case CURLOPT_DNS_SHUFFLE_ADDRESSES:
    s->dns_shuffle_addresses = enabled;
    break;
#endif
  case CURLOPT_DISALLOW_USERNAME_IN_URL:
    s->disallow_username_in_url = enabled;
    break;
  case CURLOPT_QUICK_EXIT:
    s->quick_exit = enabled;
    break;
  default:
    return CURLE_OK;
  }
  if((arg > ok) || (arg < 0))
    /* reserve other values for future use */
    infof(data, "boolean setopt(%d) got unsupported argument %ld,"
          " treated as %d", option, arg, enabled);

  *set = TRUE;
  return CURLE_OK;
}

static CURLcode value_range(long *value, long below_error, long min, long max)
{
  if(*value < below_error)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  else if(*value < min)
    *value = min;
  else if(*value > max)
    *value = max;
  return CURLE_OK;
}

static CURLcode setopt_long(struct Curl_easy *data, CURLoption option,
                            long arg)
{
  unsigned long uarg = (unsigned long)arg;
  bool set = FALSE;
  CURLcode result = setopt_bool(data, option, arg, &set);
  struct UserDefined *s = &data->set;
  if(set || result)
    return result;

  switch(option) {
  case CURLOPT_DNS_CACHE_TIMEOUT:
    return setopt_set_timeout_sec(&s->dns_cache_timeout_ms, arg);

  case CURLOPT_CA_CACHE_TIMEOUT:
    if(Curl_ssl_supports(data, SSLSUPP_CA_CACHE)) {
      result = value_range(&arg, -1, -1, INT_MAX);
      if(result)
        return result;

      s->general_ssl.ca_cache_timeout = (int)arg;
    }
    else
      return CURLE_NOT_BUILT_IN;
    break;
  case CURLOPT_MAXCONNECTS:
    result = value_range(&arg, 1, 1, UINT_MAX);
    if(result)
      return result;
    s->maxconnects = (unsigned int)arg;
    break;
  case CURLOPT_SERVER_RESPONSE_TIMEOUT:
    return setopt_set_timeout_sec(&s->server_response_timeout, arg);

  case CURLOPT_SERVER_RESPONSE_TIMEOUT_MS:
    return setopt_set_timeout_ms(&s->server_response_timeout, arg);

#ifndef CURL_DISABLE_TFTP
  case CURLOPT_TFTP_BLKSIZE:
    result = value_range(&arg, 0, TFTP_BLKSIZE_MIN, TFTP_BLKSIZE_MAX);
    if(result)
      return result;
    s->tftp_blksize = (unsigned short)arg;
    break;
#endif
#ifndef CURL_DISABLE_NETRC
  case CURLOPT_NETRC:
    if((arg < CURL_NETRC_IGNORED) || (arg >= CURL_NETRC_LAST))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->use_netrc = (unsigned char)arg;
    break;
#endif
  case CURLOPT_TIMECONDITION:
    if((arg < CURL_TIMECOND_NONE) || (arg >= CURL_TIMECOND_LAST))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->timecondition = (unsigned char)arg;
    break;
  case CURLOPT_TIMEVALUE:
    s->timevalue = (time_t)arg;
    break;
  case CURLOPT_SSLVERSION:
#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXY_SSLVERSION:
#endif
    return Curl_setopt_SSLVERSION(data, option, arg);

  case CURLOPT_POSTFIELDSIZE:
    if(arg < -1)
      return CURLE_BAD_FUNCTION_ARGUMENT;

    if(s->postfieldsize < arg &&
       s->postfields == s->str[STRING_COPYPOSTFIELDS]) {
      /* Previous CURLOPT_COPYPOSTFIELDS is no longer valid. */
      Curl_safefree(s->str[STRING_COPYPOSTFIELDS]);
      s->postfields = NULL;
    }

    s->postfieldsize = arg;
    break;
#ifndef CURL_DISABLE_HTTP
  case CURLOPT_FOLLOWLOCATION:
    if(uarg > 3)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->http_follow_mode = (unsigned char)uarg;
    break;

  case CURLOPT_MAXREDIRS:
    result = value_range(&arg, -1, -1, 0x7fff);
    if(result)
      return result;
    s->maxredirs = (short)arg;
    break;

  case CURLOPT_POSTREDIR:
    if(arg < CURL_REDIR_GET_ALL)
      /* no return error on too high numbers since the bitmask could be
         extended in a future */
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->keep_post = arg & CURL_REDIR_POST_ALL;
    break;

  case CURLOPT_HEADEROPT:
    s->sep_headers = !!(arg & CURLHEADER_SEPARATE);
    break;
  case CURLOPT_HTTPAUTH:
    return httpauth(data, FALSE, uarg);

  case CURLOPT_HTTP_VERSION:
    return setopt_HTTP_VERSION(data, arg);

  case CURLOPT_EXPECT_100_TIMEOUT_MS:
    result = value_range(&arg, 0, 0, 0xffff);
    if(result)
      return result;
    s->expect_100_timeout = (unsigned short)arg;
    break;

#endif /* ! CURL_DISABLE_HTTP */

#ifndef CURL_DISABLE_MIME
  case CURLOPT_MIME_OPTIONS:
    s->mime_formescape = !!(arg & CURLMIMEOPT_FORMESCAPE);
    break;
#endif
#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXYPORT:
    if((arg < 0) || (arg > 65535))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->proxyport = (unsigned short)arg;
    break;

  case CURLOPT_PROXYAUTH:
    return httpauth(data, TRUE, uarg);

  case CURLOPT_PROXYTYPE:
    if((arg < CURLPROXY_HTTP) || (arg > CURLPROXY_SOCKS5_HOSTNAME))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->proxytype = (unsigned char)arg;
    break;

  case CURLOPT_SOCKS5_AUTH:
    if(uarg & ~(CURLAUTH_BASIC | CURLAUTH_GSSAPI))
      return CURLE_NOT_BUILT_IN;
    s->socks5auth = (unsigned char)uarg;
    break;
#endif /* ! CURL_DISABLE_PROXY */

#ifndef CURL_DISABLE_FTP
  case CURLOPT_FTP_FILEMETHOD:
    if((arg < CURLFTPMETHOD_DEFAULT) || (arg >= CURLFTPMETHOD_LAST))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->ftp_filemethod = (unsigned char)arg;
    break;
  case CURLOPT_FTP_SSL_CCC:
    if((arg < CURLFTPSSL_CCC_NONE) || (arg >= CURLFTPSSL_CCC_LAST))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->ftp_ccc = (unsigned char)arg;
    break;

  case CURLOPT_FTPSSLAUTH:
    if((arg < CURLFTPAUTH_DEFAULT) || (arg >= CURLFTPAUTH_LAST))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->ftpsslauth = (unsigned char)arg;
    break;
  case CURLOPT_ACCEPTTIMEOUT_MS:
    return setopt_set_timeout_ms(&s->accepttimeout, arg);
#endif /* ! CURL_DISABLE_FTP */
#if !defined(CURL_DISABLE_FTP) || defined(USE_SSH)
  case CURLOPT_FTP_CREATE_MISSING_DIRS:
    if((arg < CURLFTP_CREATE_DIR_NONE) || (arg > CURLFTP_CREATE_DIR_RETRY))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->ftp_create_missing_dirs = (unsigned char)arg;
    break;
#endif /* ! CURL_DISABLE_FTP || USE_SSH */
  case CURLOPT_INFILESIZE:
    if(arg < -1)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->filesize = arg;
    break;
  case CURLOPT_LOW_SPEED_LIMIT:
    if(arg < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->low_speed_limit = arg;
    break;
  case CURLOPT_LOW_SPEED_TIME:
    if(arg < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->low_speed_time = arg;
    break;
  case CURLOPT_PORT:
    if((arg < 0) || (arg > 65535))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->use_port = (unsigned short)arg;
    break;
  case CURLOPT_TIMEOUT:
    return setopt_set_timeout_sec(&s->timeout, arg);

  case CURLOPT_TIMEOUT_MS:
    return setopt_set_timeout_ms(&s->timeout, arg);

  case CURLOPT_CONNECTTIMEOUT:
    return setopt_set_timeout_sec(&s->connecttimeout, arg);

  case CURLOPT_CONNECTTIMEOUT_MS:
    return setopt_set_timeout_ms(&s->connecttimeout, arg);

  case CURLOPT_RESUME_FROM:
    if(arg < -1)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->set_resume_from = arg;
    break;

#ifndef CURL_DISABLE_BINDLOCAL
  case CURLOPT_LOCALPORT:
    if((arg < 0) || (arg > 65535))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->localport = curlx_sltous(arg);
    break;
  case CURLOPT_LOCALPORTRANGE:
    if((arg < 0) || (arg > 65535))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->localportrange = curlx_sltous(arg);
    break;
#endif

#ifdef HAVE_GSSAPI
  case CURLOPT_GSSAPI_DELEGATION:
    s->gssapi_delegation = (unsigned char)uarg&
      (CURLGSSAPI_DELEGATION_POLICY_FLAG|CURLGSSAPI_DELEGATION_FLAG);
    break;
#endif

  case CURLOPT_SSL_FALSESTART:
    return CURLE_NOT_BUILT_IN;
  case CURLOPT_BUFFERSIZE:
    result = value_range(&arg, 0, READBUFFER_MIN, READBUFFER_MAX);
    if(result)
      return result;
    s->buffer_size = (unsigned int)arg;
    break;

  case CURLOPT_UPLOAD_BUFFERSIZE:
    result = value_range(&arg, 0, UPLOADBUFFER_MIN, UPLOADBUFFER_MAX);
    if(result)
      return result;
    s->upload_buffer_size = (unsigned int)arg;
    break;

  case CURLOPT_MAXFILESIZE:
    if(arg < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->max_filesize = arg;
    break;

#ifdef USE_SSL
  case CURLOPT_USE_SSL:
    if((arg < CURLUSESSL_NONE) || (arg >= CURLUSESSL_LAST))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->use_ssl = (unsigned char)arg;
    break;
  case CURLOPT_SSL_OPTIONS:
    set_ssl_options(&s->ssl, &s->ssl.primary, arg);
    break;

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXY_SSL_OPTIONS:
    set_ssl_options(&s->proxy_ssl, &s->proxy_ssl.primary, arg);
    break;
#endif

#endif /* USE_SSL */
  case CURLOPT_IPRESOLVE:
    if((arg < CURL_IPRESOLVE_WHATEVER) || (arg > CURL_IPRESOLVE_V6))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->ipver = (unsigned char) arg;
    break;

  case CURLOPT_CONNECT_ONLY:
    if(arg < 0 || arg > 2)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->connect_only = !!arg;
    s->connect_only_ws = (arg == 2);
    break;


#ifdef USE_SSH
  case CURLOPT_SSH_AUTH_TYPES:
    s->ssh_auth_types = (int)arg;
    break;
#endif

#if !defined(CURL_DISABLE_FTP) || defined(USE_SSH)
  case CURLOPT_NEW_FILE_PERMS:
    if((arg < 0) || (arg > 0777))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->new_file_perms = (unsigned int)arg;
    break;
#endif
#ifdef USE_SSH
  case CURLOPT_NEW_DIRECTORY_PERMS:
    if((arg < 0) || (arg > 0777))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->new_directory_perms = (unsigned int)arg;
    break;
#endif
#ifdef USE_IPV6
  case CURLOPT_ADDRESS_SCOPE:
#if SIZEOF_LONG > 4
    if(uarg > UINT_MAX)
      return CURLE_BAD_FUNCTION_ARGUMENT;
#endif
    s->scope_id = (unsigned int)uarg;
    break;
#endif
  case CURLOPT_PROTOCOLS:
    s->allowed_protocols = (curl_prot_t)arg;
    break;

  case CURLOPT_REDIR_PROTOCOLS:
    s->redir_protocols = (curl_prot_t)arg;
    break;

#ifndef CURL_DISABLE_RTSP
  case CURLOPT_RTSP_REQUEST:
    return setopt_RTSP_REQUEST(data, arg);
  case CURLOPT_RTSP_CLIENT_CSEQ:
    data->state.rtsp_next_client_CSeq = arg;
    break;

  case CURLOPT_RTSP_SERVER_CSEQ:
    data->state.rtsp_next_server_CSeq = arg;
    break;

#endif /* ! CURL_DISABLE_RTSP */

  case CURLOPT_TCP_KEEPIDLE:
    result = value_range(&arg, 0, 0, INT_MAX);
    if(result)
      return result;
    s->tcp_keepidle = (int)arg;
    break;
  case CURLOPT_TCP_KEEPINTVL:
    result = value_range(&arg, 0, 0, INT_MAX);
    if(result)
      return result;
    s->tcp_keepintvl = (int)arg;
    break;
  case CURLOPT_TCP_KEEPCNT:
    result = value_range(&arg, 0, 0, INT_MAX);
    if(result)
      return result;
    s->tcp_keepcnt = (int)arg;
    break;
  case CURLOPT_SSL_ENABLE_NPN:
    break;
  case CURLOPT_STREAM_WEIGHT:
#if defined(USE_HTTP2) || defined(USE_HTTP3)
    if((arg >= 1) && (arg <= 256))
      s->priority.weight = (int)arg;
    break;
#else
    return CURLE_NOT_BUILT_IN;
#endif
  case CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS:
    return setopt_set_timeout_ms(&s->happy_eyeballs_timeout, arg);

  case CURLOPT_UPKEEP_INTERVAL_MS:
    if(arg < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->upkeep_interval_ms = arg;
    break;
  case CURLOPT_MAXAGE_CONN:
    return setopt_set_timeout_sec(&s->conn_max_idle_ms, arg);

  case CURLOPT_MAXLIFETIME_CONN:
    return setopt_set_timeout_sec(&s->conn_max_age_ms, arg);

#ifndef CURL_DISABLE_HSTS
  case CURLOPT_HSTS_CTRL:
    if(arg & CURLHSTS_ENABLE) {
      if(!data->hsts) {
        data->hsts = Curl_hsts_init();
        if(!data->hsts)
          return CURLE_OUT_OF_MEMORY;
      }
    }
    else
      Curl_hsts_cleanup(&data->hsts);
    break;
#endif /* ! CURL_DISABLE_HSTS */
#ifndef CURL_DISABLE_ALTSVC
  case CURLOPT_ALTSVC_CTRL:
    if(!arg) {
      DEBUGF(infof(data, "bad CURLOPT_ALTSVC_CTRL input"));
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if(!data->asi) {
      data->asi = Curl_altsvc_init();
      if(!data->asi)
        return CURLE_OUT_OF_MEMORY;
    }
    return Curl_altsvc_ctrl(data->asi, arg);
#endif /* ! CURL_DISABLE_ALTSVC */
#ifndef CURL_DISABLE_WEBSOCKETS
  case CURLOPT_WS_OPTIONS:
    s->ws_raw_mode = (bool)(arg & CURLWS_RAW_MODE);
    s->ws_no_auto_pong = (bool)(arg & CURLWS_NOAUTOPONG);
    break;
#endif
  case CURLOPT_DNS_USE_GLOBAL_CACHE:
    /* deprecated */
    break;
  case CURLOPT_SSLENGINE_DEFAULT:
    Curl_safefree(s->str[STRING_SSL_ENGINE]);
    return Curl_ssl_set_engine_default(data);
  case CURLOPT_UPLOAD_FLAGS:
    s->upload_flags = (unsigned char)arg;
    break;
  default:
    return CURLE_UNKNOWN_OPTION;
  }
  return CURLE_OK;
}

static CURLcode setopt_slist(struct Curl_easy *data, CURLoption option,
                             struct curl_slist *slist)
{
  CURLcode result = CURLE_OK;
  struct UserDefined *s = &data->set;
  switch(option) {
#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXYHEADER:
    /*
     * Set a list with proxy headers to use (or replace internals with)
     *
     * Since CURLOPT_HTTPHEADER was the only way to set HTTP headers for a
     * long time we remain doing it this way until CURLOPT_PROXYHEADER is
     * used. As soon as this option has been used, if set to anything but
     * NULL, custom headers for proxies are only picked from this list.
     *
     * Set this option to NULL to restore the previous behavior.
     */
    s->proxyheaders = slist;
    break;
#endif
#ifndef CURL_DISABLE_HTTP
  case CURLOPT_HTTP200ALIASES:
    /*
     * Set a list of aliases for HTTP 200 in response header
     */
    s->http200aliases = slist;
    break;
#endif
#if !defined(CURL_DISABLE_FTP) || defined(USE_SSH)
  case CURLOPT_POSTQUOTE:
    /*
     * List of RAW FTP commands to use after a transfer
     */
    s->postquote = slist;
    break;
  case CURLOPT_PREQUOTE:
    /*
     * List of RAW FTP commands to use prior to RETR (Wesley Laxton)
     */
    s->prequote = slist;
    break;
  case CURLOPT_QUOTE:
    /*
     * List of RAW FTP commands to use before a transfer
     */
    s->quote = slist;
    break;
#endif
  case CURLOPT_RESOLVE:
    /*
     * List of HOST:PORT:[addresses] strings to populate the DNS cache with
     * Entries added this way will remain in the cache until explicitly
     * removed or the handle is cleaned up.
     *
     * Prefix the HOST with plus sign (+) to have the entry expire just like
     * automatically added entries.
     *
     * Prefix the HOST with dash (-) to _remove_ the entry from the cache.
     *
     * This API can remove any entry from the DNS cache, but only entries
     * that are not actually in use right now will be pruned immediately.
     */
    s->resolve = slist;
    data->state.resolve = s->resolve;
    break;
#if !defined(CURL_DISABLE_HTTP) || !defined(CURL_DISABLE_MIME)
  case CURLOPT_HTTPHEADER:
    /*
     * Set a list with HTTP headers to use (or replace internals with)
     */
    s->headers = slist;
    break;
#endif
#ifndef CURL_DISABLE_TELNET
  case CURLOPT_TELNETOPTIONS:
    /*
     * Set a linked list of telnet options
     */
    s->telnet_options = slist;
    break;
#endif
#ifndef CURL_DISABLE_SMTP
  case CURLOPT_MAIL_RCPT:
    /* Set the list of mail recipients */
    s->mail_rcpt = slist;
    break;
#endif
  case CURLOPT_CONNECT_TO:
    s->connect_to = slist;
    break;
  default:
    return CURLE_UNKNOWN_OPTION;
  }
  return result;
}

/* assorted pointer type arguments */
static CURLcode setopt_pointers(struct Curl_easy *data, CURLoption option,
                                va_list param)
{
  CURLcode result = CURLE_OK;
  struct UserDefined *s = &data->set;
  switch(option) {
#ifndef CURL_DISABLE_HTTP
#ifndef CURL_DISABLE_FORM_API
  case CURLOPT_HTTPPOST:
    /*
     * Set to make us do HTTP POST. Legacy API-style.
     */
    s->httppost = va_arg(param, struct curl_httppost *);
    s->method = HTTPREQ_POST_FORM;
    s->opt_no_body = FALSE; /* this is implied */
    Curl_mime_cleanpart(data->state.formp);
    Curl_safefree(data->state.formp);
    data->state.mimepost = NULL;
    break;
#endif /* ! CURL_DISABLE_FORM_API */
#endif /* ! CURL_DISABLE_HTTP */
#if !defined(CURL_DISABLE_HTTP) || !defined(CURL_DISABLE_SMTP) ||       \
    !defined(CURL_DISABLE_IMAP)
# ifndef CURL_DISABLE_MIME
  case CURLOPT_MIMEPOST:
    /*
     * Set to make us do MIME POST
     */
    result = Curl_mime_set_subparts(&s->mimepost,
                                    va_arg(param, curl_mime *),
                                    FALSE);
    if(!result) {
      s->method = HTTPREQ_POST_MIME;
      s->opt_no_body = FALSE; /* this is implied */
#ifndef CURL_DISABLE_FORM_API
      Curl_mime_cleanpart(data->state.formp);
      Curl_safefree(data->state.formp);
      data->state.mimepost = NULL;
#endif
    }
    break;
#endif /* ! CURL_DISABLE_MIME */
#endif /* ! disabled HTTP, SMTP or IMAP */
  case CURLOPT_STDERR:
    /*
     * Set to a FILE * that should receive all error writes. This
     * defaults to stderr for normal operations.
     */
    s->err = va_arg(param, FILE *);
    if(!s->err)
      s->err = stderr;
    break;
  case CURLOPT_SHARE:
  {
    struct Curl_share *set = va_arg(param, struct Curl_share *);

    /* disconnect from old share, if any */
    if(data->share) {
      Curl_share_lock(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE);

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
      if(data->share->cookies == data->cookies)
        data->cookies = NULL;
#endif

#ifndef CURL_DISABLE_HSTS
      if(data->share->hsts == data->hsts)
        data->hsts = NULL;
#endif
#ifdef USE_LIBPSL
      if(data->psl == &data->share->psl)
        data->psl = data->multi ? &data->multi->psl : NULL;
#endif
      if(data->share->specifier & (1 << CURL_LOCK_DATA_DNS)) {
        Curl_resolv_unlink(data, &data->state.dns[0]);
        Curl_resolv_unlink(data, &data->state.dns[1]);
      }

      data->share->dirty--;

      Curl_share_unlock(data, CURL_LOCK_DATA_SHARE);
      data->share = NULL;
    }

    if(GOOD_SHARE_HANDLE(set))
      /* use new share if it set */
      data->share = set;
    if(data->share) {

      Curl_share_lock(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE);

      data->share->dirty++;

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
      if(data->share->cookies) {
        /* use shared cookie list, first free own one if any */
        Curl_cookie_cleanup(data->cookies);
        /* enable cookies since we now use a share that uses cookies! */
        data->cookies = data->share->cookies;
      }
#endif   /* CURL_DISABLE_HTTP */
#ifndef CURL_DISABLE_HSTS
      if(data->share->hsts) {
        /* first free the private one if any */
        Curl_hsts_cleanup(&data->hsts);
        data->hsts = data->share->hsts;
      }
#endif
#ifdef USE_LIBPSL
      if(data->share->specifier & (1 << CURL_LOCK_DATA_PSL))
        data->psl = &data->share->psl;
#endif

      Curl_share_unlock(data, CURL_LOCK_DATA_SHARE);
    }
    /* check for host cache not needed,
     * it will be done by curl_easy_perform */
  }
  break;

#ifdef USE_HTTP2
  case CURLOPT_STREAM_DEPENDS:
  case CURLOPT_STREAM_DEPENDS_E: {
    struct Curl_easy *dep = va_arg(param, struct Curl_easy *);
    if(!dep || GOOD_EASY_HANDLE(dep))
      return Curl_data_priority_add_child(dep, data,
                                          option == CURLOPT_STREAM_DEPENDS_E);
    break;
  }
#endif

  default:
    return CURLE_UNKNOWN_OPTION;
  }
  return result;
}

#ifndef CURL_DISABLE_COOKIES
static CURLcode cookielist(struct Curl_easy *data,
                           const char *ptr)
{
  if(!ptr)
    return CURLE_OK;

  if(curl_strequal(ptr, "ALL")) {
    /* clear all cookies */
    Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
    Curl_cookie_clearall(data->cookies);
    Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
  }
  else if(curl_strequal(ptr, "SESS")) {
    /* clear session cookies */
    Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
    Curl_cookie_clearsess(data->cookies);
    Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
  }
  else if(curl_strequal(ptr, "FLUSH")) {
    /* flush cookies to file, takes care of the locking */
    Curl_flush_cookies(data, FALSE);
  }
  else if(curl_strequal(ptr, "RELOAD")) {
    /* reload cookies from file */
    Curl_cookie_loadfiles(data);
  }
  else {
    if(!data->cookies) {
      /* if cookie engine was not running, activate it */
      data->cookies = Curl_cookie_init(data, NULL, NULL, TRUE);
      if(!data->cookies)
        return CURLE_OUT_OF_MEMORY;
    }

    /* general protection against mistakes and abuse */
    if(strlen(ptr) > CURL_MAX_INPUT_LENGTH)
      return CURLE_BAD_FUNCTION_ARGUMENT;

    Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
    if(checkprefix("Set-Cookie:", ptr))
      /* HTTP Header format line */
      Curl_cookie_add(data, data->cookies, TRUE, FALSE, ptr + 11, NULL,
                      NULL, TRUE);
    else
      /* Netscape format line */
      Curl_cookie_add(data, data->cookies, FALSE, FALSE, ptr, NULL,
                      NULL, TRUE);
    Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
  }
  return CURLE_OK;
}

static CURLcode cookiefile(struct Curl_easy *data,
                           const char *ptr)
{
  /*
   * Set cookie file to read and parse. Can be used multiple times.
   */
  if(ptr) {
    struct curl_slist *cl;
    /* general protection against mistakes and abuse */
    if(strlen(ptr) > CURL_MAX_INPUT_LENGTH)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    /* append the cookie filename to the list of filenames, and deal with
       them later */
    cl = curl_slist_append(data->state.cookielist, ptr);
    if(!cl) {
      curl_slist_free_all(data->state.cookielist);
      data->state.cookielist = NULL;
      return CURLE_OUT_OF_MEMORY;
    }
    data->state.cookielist = cl; /* store the list for later use */
  }
  else {
    /* clear the list of cookie files */
    curl_slist_free_all(data->state.cookielist);
    data->state.cookielist = NULL;

    if(!data->share || !data->share->cookies) {
      /* throw away all existing cookies if this is not a shared cookie
         container */
      Curl_cookie_clearall(data->cookies);
      Curl_cookie_cleanup(data->cookies);
    }
    /* disable the cookie engine */
    data->cookies = NULL;
  }
  return CURLE_OK;
}
#endif

static CURLcode setopt_cptr(struct Curl_easy *data, CURLoption option,
                            char *ptr)
{
  CURLcode result = CURLE_OK;
  struct UserDefined *s = &data->set;
  switch(option) {
  case CURLOPT_SSL_CIPHER_LIST:
    if(Curl_ssl_supports(data, SSLSUPP_CIPHER_LIST))
      /* set a list of cipher we want to use in the SSL connection */
      return Curl_setstropt(&s->str[STRING_SSL_CIPHER_LIST], ptr);
    else
      return CURLE_NOT_BUILT_IN;
#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXY_SSL_CIPHER_LIST:
    if(Curl_ssl_supports(data, SSLSUPP_CIPHER_LIST)) {
      /* set a list of cipher we want to use in the SSL connection for proxy */
      return Curl_setstropt(&s->str[STRING_SSL_CIPHER_LIST_PROXY],
                            ptr);
    }
    else
      return CURLE_NOT_BUILT_IN;
#endif
  case CURLOPT_TLS13_CIPHERS:
    if(Curl_ssl_supports(data, SSLSUPP_TLS13_CIPHERSUITES)) {
      /* set preferred list of TLS 1.3 cipher suites */
      return Curl_setstropt(&s->str[STRING_SSL_CIPHER13_LIST], ptr);
    }
    else
      return CURLE_NOT_BUILT_IN;
#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXY_TLS13_CIPHERS:
    if(Curl_ssl_supports(data, SSLSUPP_TLS13_CIPHERSUITES))
      /* set preferred list of TLS 1.3 cipher suites for proxy */
      return Curl_setstropt(&s->str[STRING_SSL_CIPHER13_LIST_PROXY],
                            ptr);
    else
      return CURLE_NOT_BUILT_IN;
#endif
  case CURLOPT_RANDOM_FILE:
    break;
  case CURLOPT_EGDSOCKET:
    break;
  case CURLOPT_REQUEST_TARGET:
    return Curl_setstropt(&s->str[STRING_TARGET], ptr);
#ifndef CURL_DISABLE_NETRC
  case CURLOPT_NETRC_FILE:
    /*
     * Use this file instead of the $HOME/.netrc file
     */
    return Curl_setstropt(&s->str[STRING_NETRC_FILE], ptr);
#endif

#if !defined(CURL_DISABLE_HTTP) || !defined(CURL_DISABLE_MQTT)
  case CURLOPT_COPYPOSTFIELDS:
    /*
     * A string with POST data. Makes curl HTTP POST. Even if it is NULL.
     * If needed, CURLOPT_POSTFIELDSIZE must have been set prior to
     *  CURLOPT_COPYPOSTFIELDS and not altered later.
     */
    if(!ptr || s->postfieldsize == -1)
      result = Curl_setstropt(&s->str[STRING_COPYPOSTFIELDS], ptr);
    else {
      if(s->postfieldsize < 0)
        return CURLE_BAD_FUNCTION_ARGUMENT;
#if SIZEOF_CURL_OFF_T > SIZEOF_SIZE_T
      /*
       *  Check that requested length does not overflow the size_t type.
       */
      else if(s->postfieldsize > SIZE_MAX)
        return CURLE_OUT_OF_MEMORY;
#endif
      else {
        /* Allocate even when size == 0. This satisfies the need of possible
           later address compare to detect the COPYPOSTFIELDS mode, and to
           mark that postfields is used rather than read function or form
           data.
        */
        char *p = Curl_memdup0(ptr, (size_t)s->postfieldsize);
        if(!p)
          return CURLE_OUT_OF_MEMORY;
        else {
          free(s->str[STRING_COPYPOSTFIELDS]);
          s->str[STRING_COPYPOSTFIELDS] = p;
        }
      }
    }

    s->postfields = s->str[STRING_COPYPOSTFIELDS];
    s->method = HTTPREQ_POST;
    break;

  case CURLOPT_POSTFIELDS:
    /*
     * Like above, but use static data instead of copying it.
     */
    s->postfields = ptr;
    /* Release old copied data. */
    Curl_safefree(s->str[STRING_COPYPOSTFIELDS]);
    s->method = HTTPREQ_POST;
    break;
#endif /* ! CURL_DISABLE_HTTP || ! CURL_DISABLE_MQTT */

#ifndef CURL_DISABLE_HTTP
  case CURLOPT_ACCEPT_ENCODING:
    /*
     * String to use at the value of Accept-Encoding header.
     *
     * If the encoding is set to "" we use an Accept-Encoding header that
     * encompasses all the encodings we support.
     * If the encoding is set to NULL we do not send an Accept-Encoding header
     * and ignore an received Content-Encoding header.
     *
     */
    if(ptr && !*ptr) {
      char all[256];
      Curl_all_content_encodings(all, sizeof(all));
      return Curl_setstropt(&s->str[STRING_ENCODING], all);
    }
    return Curl_setstropt(&s->str[STRING_ENCODING], ptr);

#ifndef CURL_DISABLE_AWS
  case CURLOPT_AWS_SIGV4:
    /*
     * String that is merged to some authentication
     * parameters are used by the algorithm.
     */
    result = Curl_setstropt(&s->str[STRING_AWS_SIGV4], ptr);
    /*
     * Basic been set by default it need to be unset here
     */
    if(s->str[STRING_AWS_SIGV4])
      s->httpauth = CURLAUTH_AWS_SIGV4;
    break;
#endif
  case CURLOPT_REFERER:
    /*
     * String to set in the HTTP Referer: field.
     */
    if(data->state.referer_alloc) {
      Curl_safefree(data->state.referer);
      data->state.referer_alloc = FALSE;
    }
    result = Curl_setstropt(&s->str[STRING_SET_REFERER], ptr);
    data->state.referer = s->str[STRING_SET_REFERER];
    break;

  case CURLOPT_USERAGENT:
    /*
     * String to use in the HTTP User-Agent field
     */
    return Curl_setstropt(&s->str[STRING_USERAGENT], ptr);

#ifndef CURL_DISABLE_COOKIES
  case CURLOPT_COOKIE:
    /*
     * Cookie string to send to the remote server in the request.
     */
    return Curl_setstropt(&s->str[STRING_COOKIE], ptr);

  case CURLOPT_COOKIEFILE:
    return cookiefile(data, ptr);

  case CURLOPT_COOKIEJAR:
    /*
     * Set cookie filename to dump all cookies to when we are done.
     */
    result = Curl_setstropt(&s->str[STRING_COOKIEJAR], ptr);
    if(!result) {
      /*
       * Activate the cookie parser. This may or may not already
       * have been made.
       */
      struct CookieInfo *newcookies =
        Curl_cookie_init(data, NULL, data->cookies, s->cookiesession);
      if(!newcookies)
        result = CURLE_OUT_OF_MEMORY;
      data->cookies = newcookies;
    }
    break;

  case CURLOPT_COOKIELIST:
    return cookielist(data, ptr);
#endif /* !CURL_DISABLE_COOKIES */

#endif /* ! CURL_DISABLE_HTTP */

  case CURLOPT_CUSTOMREQUEST:
    /*
     * Set a custom string to use as request
     */
    return Curl_setstropt(&s->str[STRING_CUSTOMREQUEST], ptr);

    /* we do not set
       s->method = HTTPREQ_CUSTOM;
       here, we continue as if we were using the already set type
       and this just changes the actual request keyword */

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXY:
    /*
     * Set proxy server:port to use as proxy.
     *
     * If the proxy is set to "" (and CURLOPT_SOCKS_PROXY is set to "" or NULL)
     * we explicitly say that we do not want to use a proxy
     * (even though there might be environment variables saying so).
     *
     * Setting it to NULL, means no proxy but allows the environment variables
     * to decide for us (if CURLOPT_SOCKS_PROXY setting it to NULL).
     */
    return Curl_setstropt(&s->str[STRING_PROXY], ptr);

  case CURLOPT_PRE_PROXY:
    /*
     * Set proxy server:port to use as SOCKS proxy.
     *
     * If the proxy is set to "" or NULL we explicitly say that we do not want
     * to use the socks proxy.
     */
    return Curl_setstropt(&s->str[STRING_PRE_PROXY], ptr);
#endif   /* CURL_DISABLE_PROXY */

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_SOCKS5_GSSAPI_SERVICE:
  case CURLOPT_PROXY_SERVICE_NAME:
    /*
     * Set proxy authentication service name for Kerberos 5 and SPNEGO
     */
    return Curl_setstropt(&s->str[STRING_PROXY_SERVICE_NAME], ptr);
#endif
  case CURLOPT_SERVICE_NAME:
    /*
     * Set authentication service name for DIGEST-MD5, Kerberos 5 and SPNEGO
     */
    return Curl_setstropt(&s->str[STRING_SERVICE_NAME], ptr);

  case CURLOPT_HEADERDATA:
    /*
     * Custom pointer to pass the header write callback function
     */
    s->writeheader = ptr;
    break;
  case CURLOPT_READDATA:
    /*
     * FILE pointer to read the file to be uploaded from. Or possibly used as
     * argument to the read callback.
     */
    s->in_set = ptr;
    break;
  case CURLOPT_WRITEDATA:
    /*
     * FILE pointer to write to. Or possibly used as argument to the write
     * callback.
     */
    s->out = ptr;
    break;
  case CURLOPT_DEBUGDATA:
    /*
     * Set to a void * that should receive all error writes. This
     * defaults to CURLOPT_STDERR for normal operations.
     */
    s->debugdata = ptr;
    break;
  case CURLOPT_PROGRESSDATA:
    /*
     * Custom client data to pass to the progress callback
     */
    s->progress_client = ptr;
    break;
  case CURLOPT_SEEKDATA:
    /*
     * Seek control callback. Might be NULL.
     */
    s->seek_client = ptr;
    break;
  case CURLOPT_IOCTLDATA:
    /*
     * I/O control data pointer. Might be NULL.
     */
    s->ioctl_client = ptr;
    break;
  case CURLOPT_SSL_CTX_DATA:
    /*
     * Set an SSL_CTX callback parameter pointer
     */
#ifdef USE_SSL
    if(Curl_ssl_supports(data, SSLSUPP_SSL_CTX)) {
      s->ssl.fsslctxp = ptr;
      break;
    }
    else
#endif
      return CURLE_NOT_BUILT_IN;
  case CURLOPT_SOCKOPTDATA:
    /*
     * socket callback data pointer. Might be NULL.
     */
    s->sockopt_client = ptr;
    break;
  case CURLOPT_OPENSOCKETDATA:
    /*
     * socket callback data pointer. Might be NULL.
     */
    s->opensocket_client = ptr;
    break;
  case CURLOPT_RESOLVER_START_DATA:
    /*
     * resolver start callback data pointer. Might be NULL.
     */
    s->resolver_start_client = ptr;
    break;
  case CURLOPT_CLOSESOCKETDATA:
    /*
     * socket callback data pointer. Might be NULL.
     */
    s->closesocket_client = ptr;
    break;
  case CURLOPT_TRAILERDATA:
#ifndef CURL_DISABLE_HTTP
    s->trailer_data = ptr;
#endif
    break;
  case CURLOPT_PREREQDATA:
    s->prereq_userp = ptr;
    break;

  case CURLOPT_ERRORBUFFER:
    /*
     * Error buffer provided by the caller to get the human readable error
     * string in.
     */
    s->errorbuffer = ptr;
    break;

#ifndef CURL_DISABLE_FTP
  case CURLOPT_FTPPORT:
    /*
     * Use FTP PORT, this also specifies which IP address to use
     */
    result = Curl_setstropt(&s->str[STRING_FTPPORT], ptr);
    s->ftp_use_port = !!(s->str[STRING_FTPPORT]);
    break;

  case CURLOPT_FTP_ACCOUNT:
    return Curl_setstropt(&s->str[STRING_FTP_ACCOUNT], ptr);

  case CURLOPT_FTP_ALTERNATIVE_TO_USER:
    return Curl_setstropt(&s->str[STRING_FTP_ALTERNATIVE_TO_USER], ptr);

#ifdef HAVE_GSSAPI
  case CURLOPT_KRBLEVEL:
    /*
     * A string that defines the kerberos security level.
     */
    result = Curl_setstropt(&s->str[STRING_KRB_LEVEL], ptr);
    s->krb = !!(s->str[STRING_KRB_LEVEL]);
    break;
#endif
#endif
  case CURLOPT_URL:
    /*
     * The URL to fetch.
     */
    if(data->state.url_alloc) {
      Curl_safefree(data->state.url);
      data->state.url_alloc = FALSE;
    }
    result = Curl_setstropt(&s->str[STRING_SET_URL], ptr);
    data->state.url = s->str[STRING_SET_URL];
    break;

  case CURLOPT_USERPWD:
    /*
     * user:password to use in the operation
     */
    return setstropt_userpwd(ptr, &s->str[STRING_USERNAME],
                             &s->str[STRING_PASSWORD]);

  case CURLOPT_USERNAME:
    /*
     * authentication username to use in the operation
     */
    return Curl_setstropt(&s->str[STRING_USERNAME], ptr);

  case CURLOPT_PASSWORD:
    /*
     * authentication password to use in the operation
     */
    return Curl_setstropt(&s->str[STRING_PASSWORD], ptr);

  case CURLOPT_LOGIN_OPTIONS:
    /*
     * authentication options to use in the operation
     */
    return Curl_setstropt(&s->str[STRING_OPTIONS], ptr);

  case CURLOPT_XOAUTH2_BEARER:
    /*
     * OAuth 2.0 bearer token to use in the operation
     */
    return Curl_setstropt(&s->str[STRING_BEARER], ptr);

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXYUSERPWD: {
    /*
     * user:password needed to use the proxy
     */
    char *u = NULL;
    char *p = NULL;
    result = setstropt_userpwd(ptr, &u, &p);

    /* URL decode the components */
    if(!result && u) {
      Curl_safefree(s->str[STRING_PROXYUSERNAME]);
      result = Curl_urldecode(u, 0, &s->str[STRING_PROXYUSERNAME], NULL,
                              REJECT_ZERO);
    }
    if(!result && p) {
      Curl_safefree(s->str[STRING_PROXYPASSWORD]);
      result = Curl_urldecode(p, 0, &s->str[STRING_PROXYPASSWORD], NULL,
                              REJECT_ZERO);
    }
    free(u);
    free(p);
  }
    break;
  case CURLOPT_PROXYUSERNAME:
    /*
     * authentication username to use in the operation
     */
    return Curl_setstropt(&s->str[STRING_PROXYUSERNAME], ptr);

  case CURLOPT_PROXYPASSWORD:
    /*
     * authentication password to use in the operation
     */
    return Curl_setstropt(&s->str[STRING_PROXYPASSWORD], ptr);

  case CURLOPT_NOPROXY:
    /*
     * proxy exception list
     */
    return Curl_setstropt(&s->str[STRING_NOPROXY], ptr);
#endif /* ! CURL_DISABLE_PROXY */

  case CURLOPT_RANGE:
    /*
     * What range of the file you want to transfer
     */
    return Curl_setstropt(&s->str[STRING_SET_RANGE], ptr);

  case CURLOPT_CURLU:
    /*
     * pass CURLU to set URL
     */
    if(data->state.url_alloc) {
      Curl_safefree(data->state.url);
      data->state.url_alloc = FALSE;
    }
    else
      data->state.url = NULL;
    Curl_safefree(s->str[STRING_SET_URL]);
    s->uh = (CURLU *)ptr;
    break;
  case CURLOPT_SSLCERT:
    /*
     * String that holds filename of the SSL certificate to use
     */
    return Curl_setstropt(&s->str[STRING_CERT], ptr);

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXY_SSLCERT:
    /*
     * String that holds filename of the SSL certificate to use for proxy
     */
    return Curl_setstropt(&s->str[STRING_CERT_PROXY], ptr);

#endif
  case CURLOPT_SSLCERTTYPE:
    /*
     * String that holds file type of the SSL certificate to use
     */
    return Curl_setstropt(&s->str[STRING_CERT_TYPE], ptr);

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXY_SSLCERTTYPE:
    /*
     * String that holds file type of the SSL certificate to use for proxy
     */
    return Curl_setstropt(&s->str[STRING_CERT_TYPE_PROXY], ptr);

#endif
  case CURLOPT_SSLKEY:
    /*
     * String that holds filename of the SSL key to use
     */
    return Curl_setstropt(&s->str[STRING_KEY], ptr);

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXY_SSLKEY:
    /*
     * String that holds filename of the SSL key to use for proxy
     */
    return Curl_setstropt(&s->str[STRING_KEY_PROXY], ptr);

#endif
  case CURLOPT_SSLKEYTYPE:
    /*
     * String that holds file type of the SSL key to use
     */
    return Curl_setstropt(&s->str[STRING_KEY_TYPE], ptr);

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXY_SSLKEYTYPE:
    /*
     * String that holds file type of the SSL key to use for proxy
     */
    return Curl_setstropt(&s->str[STRING_KEY_TYPE_PROXY], ptr);

#endif
  case CURLOPT_KEYPASSWD:
    /*
     * String that holds the SSL or SSH private key password.
     */
    return Curl_setstropt(&s->str[STRING_KEY_PASSWD], ptr);

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXY_KEYPASSWD:
    /*
     * String that holds the SSL private key password for proxy.
     */
    return Curl_setstropt(&s->str[STRING_KEY_PASSWD_PROXY], ptr);

#endif
  case CURLOPT_SSLENGINE:
    /*
     * String that holds the SSL crypto engine.
     */
    if(ptr && ptr[0]) {
      result = Curl_setstropt(&s->str[STRING_SSL_ENGINE], ptr);
      if(!result) {
        result = Curl_ssl_set_engine(data, ptr);
      }
    }
    break;

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_HAPROXY_CLIENT_IP:
    /*
     * Set the client IP to send through HAProxy PROXY protocol
     */
    result = Curl_setstropt(&s->str[STRING_HAPROXY_CLIENT_IP], ptr);
    /* enable the HAProxy protocol */
    s->haproxyprotocol = TRUE;
    break;

#endif
  case CURLOPT_INTERFACE:
    /*
     * Set what interface or address/hostname to bind the socket to when
     * performing an operation and thus what from-IP your connection will use.
     */
    return setstropt_interface(ptr,
                               &s->str[STRING_DEVICE],
                               &s->str[STRING_INTERFACE],
                               &s->str[STRING_BINDHOST]);

  case CURLOPT_PINNEDPUBLICKEY:
    /*
     * Set pinned public key for SSL connection.
     * Specify filename of the public key in DER format.
     */
#ifdef USE_SSL
    if(Curl_ssl_supports(data, SSLSUPP_PINNEDPUBKEY))
      return Curl_setstropt(&s->str[STRING_SSL_PINNEDPUBLICKEY], ptr);
#endif
    return CURLE_NOT_BUILT_IN;

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXY_PINNEDPUBLICKEY:
    /*
     * Set pinned public key for SSL connection.
     * Specify filename of the public key in DER format.
     */
#ifdef USE_SSL
    if(Curl_ssl_supports(data, SSLSUPP_PINNEDPUBKEY))
      return Curl_setstropt(&s->str[STRING_SSL_PINNEDPUBLICKEY_PROXY],
                            ptr);
#endif
    return CURLE_NOT_BUILT_IN;
#endif
  case CURLOPT_CAINFO:
    /*
     * Set CA info for SSL connection. Specify filename of the CA certificate
     */
    return Curl_setstropt(&s->str[STRING_SSL_CAFILE], ptr);

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXY_CAINFO:
    /*
     * Set CA info SSL connection for proxy. Specify filename of the
     * CA certificate
     */
    return Curl_setstropt(&s->str[STRING_SSL_CAFILE_PROXY], ptr);

#endif
  case CURLOPT_CAPATH:
    /*
     * Set CA path info for SSL connection. Specify directory name of the CA
     * certificates which have been prepared using openssl c_rehash utility.
     */
#ifdef USE_SSL
    if(Curl_ssl_supports(data, SSLSUPP_CA_PATH))
      /* This does not work on Windows. */
      return Curl_setstropt(&s->str[STRING_SSL_CAPATH], ptr);
#endif
    return CURLE_NOT_BUILT_IN;
#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXY_CAPATH:
    /*
     * Set CA path info for SSL connection proxy. Specify directory name of the
     * CA certificates which have been prepared using openssl c_rehash utility.
     */
#ifdef USE_SSL
    if(Curl_ssl_supports(data, SSLSUPP_CA_PATH))
      /* This does not work on Windows. */
      return Curl_setstropt(&s->str[STRING_SSL_CAPATH_PROXY], ptr);
#endif
    return CURLE_NOT_BUILT_IN;
#endif
  case CURLOPT_CRLFILE:
    /*
     * Set CRL file info for SSL connection. Specify filename of the CRL
     * to check certificates revocation
     */
    return Curl_setstropt(&s->str[STRING_SSL_CRLFILE], ptr);

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXY_CRLFILE:
    /*
     * Set CRL file info for SSL connection for proxy. Specify filename of the
     * CRL to check certificates revocation
     */
    return Curl_setstropt(&s->str[STRING_SSL_CRLFILE_PROXY], ptr);

#endif
  case CURLOPT_ISSUERCERT:
    /*
     * Set Issuer certificate file
     * to check certificates issuer
     */
    return Curl_setstropt(&s->str[STRING_SSL_ISSUERCERT], ptr);

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXY_ISSUERCERT:
    /*
     * Set Issuer certificate file
     * to check certificates issuer
     */
    return Curl_setstropt(&s->str[STRING_SSL_ISSUERCERT_PROXY], ptr);

#endif
  case CURLOPT_PRIVATE:
    /*
     * Set private data pointer.
     */
    s->private_data = ptr;
    break;

#ifdef USE_SSL
  case CURLOPT_SSL_EC_CURVES:
    /*
     * Set accepted curves in SSL connection setup.
     * Specify colon-delimited list of curve algorithm names.
     */
    return Curl_setstropt(&s->str[STRING_SSL_EC_CURVES], ptr);

  case CURLOPT_SSL_SIGNATURE_ALGORITHMS:
    /*
     * Set accepted signature algorithms.
     * Specify colon-delimited list of signature scheme names.
     */
    if(Curl_ssl_supports(data, SSLSUPP_SIGNATURE_ALGORITHMS))
      return Curl_setstropt(&s->str[STRING_SSL_SIGNATURE_ALGORITHMS],
                            ptr);
    return CURLE_NOT_BUILT_IN;
#endif
#ifdef USE_SSH
  case CURLOPT_SSH_PUBLIC_KEYFILE:
    /*
     * Use this file instead of the $HOME/.ssh/id_dsa.pub file
     */
    return Curl_setstropt(&s->str[STRING_SSH_PUBLIC_KEY], ptr);

  case CURLOPT_SSH_PRIVATE_KEYFILE:
    /*
     * Use this file instead of the $HOME/.ssh/id_dsa file
     */
    return Curl_setstropt(&s->str[STRING_SSH_PRIVATE_KEY], ptr);

#if defined(USE_LIBSSH2) || defined(USE_LIBSSH)
  case CURLOPT_SSH_HOST_PUBLIC_KEY_MD5:
    /*
     * Option to allow for the MD5 of the host public key to be checked
     * for validation purposes.
     */
    return Curl_setstropt(&s->str[STRING_SSH_HOST_PUBLIC_KEY_MD5], ptr);

  case CURLOPT_SSH_KNOWNHOSTS:
    /*
     * Store the filename to read known hosts from.
     */
    return Curl_setstropt(&s->str[STRING_SSH_KNOWNHOSTS], ptr);
#endif
  case CURLOPT_SSH_KEYDATA:
    /*
     * Custom client data to pass to the SSH keyfunc callback
     */
    s->ssh_keyfunc_userp = ptr;
    break;
#ifdef USE_LIBSSH2
  case CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256:
    /*
     * Option to allow for the SHA256 of the host public key to be checked
     * for validation purposes.
     */
    return Curl_setstropt(&s->str[STRING_SSH_HOST_PUBLIC_KEY_SHA256],
                          ptr);

  case CURLOPT_SSH_HOSTKEYDATA:
    /*
     * Custom client data to pass to the SSH keyfunc callback
     */
    s->ssh_hostkeyfunc_userp = ptr;
    break;
#endif /* USE_LIBSSH2 */
#endif /* USE_SSH */
  case CURLOPT_PROTOCOLS_STR:
    if(ptr)
      return protocol2num(ptr, &s->allowed_protocols);
    /* make a NULL argument reset to default */
    s->allowed_protocols = (curl_prot_t) CURLPROTO_ALL;
    break;

  case CURLOPT_REDIR_PROTOCOLS_STR:
    if(ptr)
      return protocol2num(ptr, &s->redir_protocols);
    /* make a NULL argument reset to default */
    s->redir_protocols = (curl_prot_t) CURLPROTO_REDIR;
    break;

  case CURLOPT_DEFAULT_PROTOCOL:
    /* Set the protocol to use when the URL does not include any protocol */
    return Curl_setstropt(&s->str[STRING_DEFAULT_PROTOCOL], ptr);

#ifndef CURL_DISABLE_SMTP
  case CURLOPT_MAIL_FROM:
    /* Set the SMTP mail originator */
    return Curl_setstropt(&s->str[STRING_MAIL_FROM], ptr);

  case CURLOPT_MAIL_AUTH:
    /* Set the SMTP auth originator */
    return Curl_setstropt(&s->str[STRING_MAIL_AUTH], ptr);
#endif
  case CURLOPT_SASL_AUTHZID:
    /* Authorization identity (identity to act as) */
    return Curl_setstropt(&s->str[STRING_SASL_AUTHZID], ptr);

#ifndef CURL_DISABLE_RTSP
  case CURLOPT_RTSP_SESSION_ID:
    /*
     * Set the RTSP Session ID manually. Useful if the application is
     * resuming a previously established RTSP session
     */
    return Curl_setstropt(&s->str[STRING_RTSP_SESSION_ID], ptr);

  case CURLOPT_RTSP_STREAM_URI:
    /*
     * Set the Stream URI for the RTSP request. Unless the request is
     * for generic server options, the application will need to set this.
     */
    return Curl_setstropt(&s->str[STRING_RTSP_STREAM_URI], ptr);

  case CURLOPT_RTSP_TRANSPORT:
    /*
     * The content of the Transport: header for the RTSP request
     */
    return Curl_setstropt(&s->str[STRING_RTSP_TRANSPORT], ptr);

  case CURLOPT_INTERLEAVEDATA:
    s->rtp_out = ptr;
    break;
#endif /* ! CURL_DISABLE_RTSP */
#ifndef CURL_DISABLE_FTP
  case CURLOPT_CHUNK_DATA:
    s->wildcardptr = ptr;
    break;
  case CURLOPT_FNMATCH_DATA:
    s->fnmatch_data = ptr;
    break;
#endif
#ifdef USE_TLS_SRP
  case CURLOPT_TLSAUTH_USERNAME:
    return Curl_setstropt(&s->str[STRING_TLSAUTH_USERNAME], ptr);

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXY_TLSAUTH_USERNAME:
    return Curl_setstropt(&s->str[STRING_TLSAUTH_USERNAME_PROXY], ptr);

#endif
  case CURLOPT_TLSAUTH_PASSWORD:
    return Curl_setstropt(&s->str[STRING_TLSAUTH_PASSWORD], ptr);

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXY_TLSAUTH_PASSWORD:
    return Curl_setstropt(&s->str[STRING_TLSAUTH_PASSWORD_PROXY], ptr);
#endif
  case CURLOPT_TLSAUTH_TYPE:
    if(ptr && !curl_strequal(ptr, "SRP"))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    break;
#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXY_TLSAUTH_TYPE:
    if(ptr && !curl_strequal(ptr, "SRP"))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    break;
#endif
#endif
#ifdef CURLRES_ARES
  case CURLOPT_DNS_SERVERS:
    result = Curl_setstropt(&s->str[STRING_DNS_SERVERS], ptr);
    if(result)
      return result;
    return Curl_async_ares_set_dns_servers(data);

  case CURLOPT_DNS_INTERFACE:
    result = Curl_setstropt(&s->str[STRING_DNS_INTERFACE], ptr);
    if(result)
      return result;
    return Curl_async_ares_set_dns_interface(data);

  case CURLOPT_DNS_LOCAL_IP4:
    result = Curl_setstropt(&s->str[STRING_DNS_LOCAL_IP4], ptr);
    if(result)
      return result;
    return Curl_async_ares_set_dns_local_ip4(data);

  case CURLOPT_DNS_LOCAL_IP6:
    result = Curl_setstropt(&s->str[STRING_DNS_LOCAL_IP6], ptr);
    if(result)
      return result;
    return Curl_async_ares_set_dns_local_ip6(data);

#endif
#ifdef USE_UNIX_SOCKETS
  case CURLOPT_UNIX_SOCKET_PATH:
    s->abstract_unix_socket = FALSE;
    return Curl_setstropt(&s->str[STRING_UNIX_SOCKET_PATH], ptr);

  case CURLOPT_ABSTRACT_UNIX_SOCKET:
    s->abstract_unix_socket = TRUE;
    return Curl_setstropt(&s->str[STRING_UNIX_SOCKET_PATH], ptr);

#endif

#ifndef CURL_DISABLE_DOH
  case CURLOPT_DOH_URL:
    result = Curl_setstropt(&s->str[STRING_DOH], ptr);
    s->doh = !!(s->str[STRING_DOH]);
    break;
#endif
#ifndef CURL_DISABLE_HSTS
  case CURLOPT_HSTSREADDATA:
    s->hsts_read_userp = ptr;
    break;
  case CURLOPT_HSTSWRITEDATA:
    s->hsts_write_userp = ptr;
    break;
  case CURLOPT_HSTS: {
    struct curl_slist *h;
    if(!data->hsts) {
      data->hsts = Curl_hsts_init();
      if(!data->hsts)
        return CURLE_OUT_OF_MEMORY;
    }
    if(ptr) {
      result = Curl_setstropt(&s->str[STRING_HSTS], ptr);
      if(result)
        return result;
      /* this needs to build a list of filenames to read from, so that it can
         read them later, as we might get a shared HSTS handle to load them
         into */
      h = curl_slist_append(data->state.hstslist, ptr);
      if(!h) {
        curl_slist_free_all(data->state.hstslist);
        data->state.hstslist = NULL;
        return CURLE_OUT_OF_MEMORY;
      }
      data->state.hstslist = h; /* store the list for later use */
    }
    else {
      /* clear the list of HSTS files */
      curl_slist_free_all(data->state.hstslist);
      data->state.hstslist = NULL;
      if(!data->share || !data->share->hsts)
        /* throw away the HSTS cache unless shared */
        Curl_hsts_cleanup(&data->hsts);
    }
    break;
  }
#endif /* ! CURL_DISABLE_HSTS */
#ifndef CURL_DISABLE_ALTSVC
  case CURLOPT_ALTSVC:
    if(!data->asi) {
      data->asi = Curl_altsvc_init();
      if(!data->asi)
        return CURLE_OUT_OF_MEMORY;
    }
    result = Curl_setstropt(&s->str[STRING_ALTSVC], ptr);
    if(result)
      return result;
    if(ptr)
      (void)Curl_altsvc_load(data->asi, ptr);
    break;
#endif /* ! CURL_DISABLE_ALTSVC */
#ifdef USE_ECH
  case CURLOPT_ECH: {
    size_t plen = 0;

    if(!ptr) {
      s->tls_ech = CURLECH_DISABLE;
      return CURLE_OK;
    }
    plen = strlen(ptr);
    if(plen > CURL_MAX_INPUT_LENGTH) {
      s->tls_ech = CURLECH_DISABLE;
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    /* set tls_ech flag value, preserving CLA_CFG bit */
    if(!strcmp(ptr, "false"))
      s->tls_ech = CURLECH_DISABLE |
        (s->tls_ech & CURLECH_CLA_CFG);
    else if(!strcmp(ptr, "grease"))
      s->tls_ech = CURLECH_GREASE |
        (s->tls_ech & CURLECH_CLA_CFG);
    else if(!strcmp(ptr, "true"))
      s->tls_ech = CURLECH_ENABLE |
        (s->tls_ech & CURLECH_CLA_CFG);
    else if(!strcmp(ptr, "hard"))
      s->tls_ech = CURLECH_HARD |
        (s->tls_ech & CURLECH_CLA_CFG);
    else if(plen > 5 && !strncmp(ptr, "ecl:", 4)) {
      result = Curl_setstropt(&s->str[STRING_ECH_CONFIG], ptr + 4);
      if(result)
        return result;
      s->tls_ech |= CURLECH_CLA_CFG;
    }
    else if(plen > 4 && !strncmp(ptr, "pn:", 3)) {
      result = Curl_setstropt(&s->str[STRING_ECH_PUBLIC], ptr + 3);
      if(result)
        return result;
    }
    break;
  }
#endif
  default:
    return CURLE_UNKNOWN_OPTION;
  }
  return result;
}

static CURLcode setopt_func(struct Curl_easy *data, CURLoption option,
                            va_list param)
{
  struct UserDefined *s = &data->set;
  switch(option) {
  case CURLOPT_PROGRESSFUNCTION:
    /*
     * Progress callback function
     */
    s->fprogress = va_arg(param, curl_progress_callback);
    if(s->fprogress)
      data->progress.callback = TRUE; /* no longer internal */
    else
      data->progress.callback = FALSE; /* NULL enforces internal */
    break;

  case CURLOPT_XFERINFOFUNCTION:
    /*
     * Transfer info callback function
     */
    s->fxferinfo = va_arg(param, curl_xferinfo_callback);
    if(s->fxferinfo)
      data->progress.callback = TRUE; /* no longer internal */
    else
      data->progress.callback = FALSE; /* NULL enforces internal */

    break;
  case CURLOPT_DEBUGFUNCTION:
    /*
     * stderr write callback.
     */
    s->fdebug = va_arg(param, curl_debug_callback);
    /*
     * if the callback provided is NULL, it will use the default callback
     */
    break;
  case CURLOPT_HEADERFUNCTION:
    /*
     * Set header write callback
     */
    s->fwrite_header = va_arg(param, curl_write_callback);
    break;
  case CURLOPT_WRITEFUNCTION:
    /*
     * Set data write callback
     */
    s->fwrite_func = va_arg(param, curl_write_callback);
    if(!s->fwrite_func)
#if defined(__clang__) && __clang_major__ >= 16
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-function-type-strict"
#endif
      /* When set to NULL, reset to our internal default function */
      s->fwrite_func = (curl_write_callback)fwrite;
#if defined(__clang__) && __clang_major__ >= 16
#pragma clang diagnostic pop
#endif
    break;
  case CURLOPT_READFUNCTION:
    /*
     * Read data callback
     */
    s->fread_func_set = va_arg(param, curl_read_callback);
    if(!s->fread_func_set) {
      s->is_fread_set = 0;
#if defined(__clang__) && __clang_major__ >= 16
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-function-type-strict"
#endif
      /* When set to NULL, reset to our internal default function */
      s->fread_func_set = (curl_read_callback)fread;
#if defined(__clang__) && __clang_major__ >= 16
#pragma clang diagnostic pop
#endif
    }
    else
      s->is_fread_set = 1;
    break;
  case CURLOPT_SEEKFUNCTION:
    /*
     * Seek callback. Might be NULL.
     */
    s->seek_func = va_arg(param, curl_seek_callback);
    break;
  case CURLOPT_IOCTLFUNCTION:
    /*
     * I/O control callback. Might be NULL.
     */
    s->ioctl_func = va_arg(param, curl_ioctl_callback);
    break;
  case CURLOPT_SSL_CTX_FUNCTION:
    /*
     * Set an SSL_CTX callback
     */
#ifdef USE_SSL
    if(Curl_ssl_supports(data, SSLSUPP_SSL_CTX)) {
      s->ssl.fsslctx = va_arg(param, curl_ssl_ctx_callback);
      break;
    }
    else
#endif
      return CURLE_NOT_BUILT_IN;

  case CURLOPT_SOCKOPTFUNCTION:
    /*
     * socket callback function: called after socket() but before connect()
     */
    s->fsockopt = va_arg(param, curl_sockopt_callback);
    break;

  case CURLOPT_OPENSOCKETFUNCTION:
    /*
     * open/create socket callback function: called instead of socket(),
     * before connect()
     */
    s->fopensocket = va_arg(param, curl_opensocket_callback);
    break;

  case CURLOPT_CLOSESOCKETFUNCTION:
    /*
     * close socket callback function: called instead of close()
     * when shutting down a connection
     */
    s->fclosesocket = va_arg(param, curl_closesocket_callback);
    break;

  case CURLOPT_RESOLVER_START_FUNCTION:
    /*
     * resolver start callback function: called before a new resolver request
     * is started
     */
    s->resolver_start = va_arg(param, curl_resolver_start_callback);
    break;

#ifdef USE_SSH
#ifdef USE_LIBSSH2
  case CURLOPT_SSH_HOSTKEYFUNCTION:
    /* the callback to check the hostkey without the knownhost file */
    s->ssh_hostkeyfunc = va_arg(param, curl_sshhostkeycallback);
    break;
#endif

  case CURLOPT_SSH_KEYFUNCTION:
    /* setting to NULL is fine since the ssh.c functions themselves will
       then revert to use the internal default */
    s->ssh_keyfunc = va_arg(param, curl_sshkeycallback);
    break;

#endif /* USE_SSH */

#ifndef CURL_DISABLE_RTSP
  case CURLOPT_INTERLEAVEFUNCTION:
    /* Set the user defined RTP write function */
    s->fwrite_rtp = va_arg(param, curl_write_callback);
    break;
#endif
#ifndef CURL_DISABLE_FTP
  case CURLOPT_CHUNK_BGN_FUNCTION:
    s->chunk_bgn = va_arg(param, curl_chunk_bgn_callback);
    break;
  case CURLOPT_CHUNK_END_FUNCTION:
    s->chunk_end = va_arg(param, curl_chunk_end_callback);
    break;
  case CURLOPT_FNMATCH_FUNCTION:
    s->fnmatch = va_arg(param, curl_fnmatch_callback);
    break;
#endif
#ifndef CURL_DISABLE_HTTP
  case CURLOPT_TRAILERFUNCTION:
    s->trailer_callback = va_arg(param, curl_trailer_callback);
    break;
#endif
#ifndef CURL_DISABLE_HSTS
  case CURLOPT_HSTSREADFUNCTION:
    s->hsts_read = va_arg(param, curl_hstsread_callback);
    break;
  case CURLOPT_HSTSWRITEFUNCTION:
    s->hsts_write = va_arg(param, curl_hstswrite_callback);
    break;
#endif
  case CURLOPT_PREREQFUNCTION:
    s->fprereq = va_arg(param, curl_prereq_callback);
    break;
  default:
    return CURLE_UNKNOWN_OPTION;
  }
  return CURLE_OK;
}

static CURLcode setopt_offt(struct Curl_easy *data, CURLoption option,
                            curl_off_t offt)
{
  struct UserDefined *s = &data->set;
  switch(option) {
  case CURLOPT_TIMEVALUE_LARGE:
    /*
     * This is the value to compare with the remote document with the
     * method set with CURLOPT_TIMECONDITION
     */
    s->timevalue = (time_t)offt;
    break;

    /* MQTT "borrows" some of the HTTP options */
  case CURLOPT_POSTFIELDSIZE_LARGE:
    /*
     * The size of the POSTFIELD data to prevent libcurl to do strlen() to
     * figure it out. Enables binary posts.
     */
    if(offt < -1)
      return CURLE_BAD_FUNCTION_ARGUMENT;

    if(s->postfieldsize < offt &&
       s->postfields == s->str[STRING_COPYPOSTFIELDS]) {
      /* Previous CURLOPT_COPYPOSTFIELDS is no longer valid. */
      Curl_safefree(s->str[STRING_COPYPOSTFIELDS]);
      s->postfields = NULL;
    }
    s->postfieldsize = offt;
    break;
  case CURLOPT_INFILESIZE_LARGE:
    /*
     * If known, this should inform curl about the file size of the
     * to-be-uploaded file.
     */
    if(offt < -1)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->filesize = offt;
    break;
  case CURLOPT_MAX_SEND_SPEED_LARGE:
    /*
     * When transfer uploads are faster then CURLOPT_MAX_SEND_SPEED_LARGE
     * bytes per second the transfer is throttled..
     */
    if(offt < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->max_send_speed = offt;
    break;
  case CURLOPT_MAX_RECV_SPEED_LARGE:
    /*
     * When receiving data faster than CURLOPT_MAX_RECV_SPEED_LARGE bytes per
     * second the transfer is throttled..
     */
    if(offt < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->max_recv_speed = offt;
    break;
  case CURLOPT_RESUME_FROM_LARGE:
    /*
     * Resume transfer at the given file position
     */
    if(offt < -1)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->set_resume_from = offt;
    break;
  case CURLOPT_MAXFILESIZE_LARGE:
    /*
     * Set the maximum size of a file to download.
     */
    if(offt < 0)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s->max_filesize = offt;
    break;

  default:
    return CURLE_UNKNOWN_OPTION;
  }
  return CURLE_OK;
}

static CURLcode setopt_blob(struct Curl_easy *data, CURLoption option,
                            struct curl_blob *blob)
{
  struct UserDefined *s = &data->set;
  switch(option) {
  case CURLOPT_SSLCERT_BLOB:
    /*
     * Blob that holds file content of the SSL certificate to use
     */
    return Curl_setblobopt(&s->blobs[BLOB_CERT], blob);
#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXY_SSLCERT_BLOB:
    /*
     * Blob that holds file content of the SSL certificate to use for proxy
     */
    return Curl_setblobopt(&s->blobs[BLOB_CERT_PROXY], blob);
  case CURLOPT_PROXY_SSLKEY_BLOB:
    /*
     * Blob that holds file content of the SSL key to use for proxy
     */
    return Curl_setblobopt(&s->blobs[BLOB_KEY_PROXY], blob);
  case CURLOPT_PROXY_CAINFO_BLOB:
    /*
     * Blob that holds CA info for SSL connection proxy.
     * Specify entire PEM of the CA certificate
     */
#ifdef USE_SSL
    if(Curl_ssl_supports(data, SSLSUPP_CAINFO_BLOB))
      return Curl_setblobopt(&s->blobs[BLOB_CAINFO_PROXY], blob);
#endif
    return CURLE_NOT_BUILT_IN;
  case CURLOPT_PROXY_ISSUERCERT_BLOB:
    /*
     * Blob that holds Issuer certificate to check certificates issuer
     */
    return Curl_setblobopt(&s->blobs[BLOB_SSL_ISSUERCERT_PROXY],
                           blob);
#endif
  case CURLOPT_SSLKEY_BLOB:
    /*
     * Blob that holds file content of the SSL key to use
     */
    return Curl_setblobopt(&s->blobs[BLOB_KEY], blob);
  case CURLOPT_CAINFO_BLOB:
    /*
     * Blob that holds CA info for SSL connection.
     * Specify entire PEM of the CA certificate
     */
#ifdef USE_SSL
    if(Curl_ssl_supports(data, SSLSUPP_CAINFO_BLOB))
      return Curl_setblobopt(&s->blobs[BLOB_CAINFO], blob);
#endif
    return CURLE_NOT_BUILT_IN;
  case CURLOPT_ISSUERCERT_BLOB:
    /*
     * Blob that holds Issuer certificate to check certificates issuer
     */
    return Curl_setblobopt(&s->blobs[BLOB_SSL_ISSUERCERT], blob);

  default:
    return CURLE_UNKNOWN_OPTION;
  }
  /* unreachable */
}

/*
 * Do not make Curl_vsetopt() static: it is called from
 * packages/OS400/ccsidcurl.c.
 */
CURLcode Curl_vsetopt(struct Curl_easy *data, CURLoption option, va_list param)
{
  if(option < CURLOPTTYPE_OBJECTPOINT)
    return setopt_long(data, option, va_arg(param, long));
  else if(option < CURLOPTTYPE_FUNCTIONPOINT) {
    /* unfortunately, different pointer types cannot be identified any other
       way than being listed explicitly */
    switch(option) {
    case CURLOPT_HTTPHEADER:
    case CURLOPT_QUOTE:
    case CURLOPT_POSTQUOTE:
    case CURLOPT_TELNETOPTIONS:
    case CURLOPT_PREQUOTE:
    case CURLOPT_HTTP200ALIASES:
    case CURLOPT_MAIL_RCPT:
    case CURLOPT_RESOLVE:
    case CURLOPT_PROXYHEADER:
    case CURLOPT_CONNECT_TO:
      return setopt_slist(data, option, va_arg(param, struct curl_slist *));
    case CURLOPT_HTTPPOST:         /* curl_httppost * */
    case CURLOPT_MIMEPOST:         /* curl_mime * */
    case CURLOPT_STDERR:           /* FILE * */
    case CURLOPT_SHARE:            /* CURLSH * */
    case CURLOPT_STREAM_DEPENDS:   /* CURL * */
    case CURLOPT_STREAM_DEPENDS_E: /* CURL * */
      return setopt_pointers(data, option, param);
    default:
      break;
    }
    /* the char pointer options */
    return setopt_cptr(data, option, va_arg(param, char *));
  }
  else if(option < CURLOPTTYPE_OFF_T)
    return setopt_func(data, option, param);
  else if(option < CURLOPTTYPE_BLOB)
    return setopt_offt(data, option, va_arg(param, curl_off_t));
  return setopt_blob(data, option, va_arg(param, struct curl_blob *));
}

/*
 * curl_easy_setopt() is the external interface for setting options on an
 * easy handle.
 *
 * NOTE: This is one of few API functions that are allowed to be called from
 * within a callback.
 */

#undef curl_easy_setopt
CURLcode curl_easy_setopt(CURL *d, CURLoption tag, ...)
{
  va_list arg;
  CURLcode result;
  struct Curl_easy *data = d;

  if(!data)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  va_start(arg, tag);

  result = Curl_vsetopt(data, tag, arg);

  va_end(arg);
  if(result == CURLE_BAD_FUNCTION_ARGUMENT)
    failf(data, "setopt 0x%x got bad argument", tag);
  return result;
}
