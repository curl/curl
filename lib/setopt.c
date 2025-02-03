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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"

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
#include "warnless.h"
#include "sendf.h"
#include "http2.h"
#include "setopt.h"
#include "multiif.h"
#include "altsvc.h"
#include "hsts.h"
#include "tftp.h"
#include "strdup.h"
#include "escape.h"

/* The last 3 #include files should be in this order */
#include "fetch_printf.h"
#include "fetch_memory.h"
#include "memdebug.h"

FETCHcode Curl_setstropt(char **charp, const char *s)
{
  /* Release the previous storage at `charp' and replace by a dynamic storage
     copy of `s'. Return FETCHE_OK or FETCHE_OUT_OF_MEMORY. */

  Curl_safefree(*charp);

  if (s)
  {
    if (strlen(s) > FETCH_MAX_INPUT_LENGTH)
      return FETCHE_BAD_FUNCTION_ARGUMENT;

    *charp = strdup(s);
    if (!*charp)
      return FETCHE_OUT_OF_MEMORY;
  }

  return FETCHE_OK;
}

FETCHcode Curl_setblobopt(struct fetch_blob **blobp,
                          const struct fetch_blob *blob)
{
  /* free the previous storage at `blobp' and replace by a dynamic storage
     copy of blob. If FETCH_BLOB_COPY is set, the data is copied. */

  Curl_safefree(*blobp);

  if (blob)
  {
    struct fetch_blob *nblob;
    if (blob->len > FETCH_MAX_INPUT_LENGTH)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    nblob = (struct fetch_blob *)
        malloc(sizeof(struct fetch_blob) +
               ((blob->flags & FETCH_BLOB_COPY) ? blob->len : 0));
    if (!nblob)
      return FETCHE_OUT_OF_MEMORY;
    *nblob = *blob;
    if (blob->flags & FETCH_BLOB_COPY)
    {
      /* put the data after the blob struct in memory */
      nblob->data = (char *)nblob + sizeof(struct fetch_blob);
      memcpy(nblob->data, blob->data, blob->len);
    }

    *blobp = nblob;
    return FETCHE_OK;
  }

  return FETCHE_OK;
}

static FETCHcode setstropt_userpwd(char *option, char **userp, char **passwdp)
{
  char *user = NULL;
  char *passwd = NULL;

  DEBUGASSERT(userp);
  DEBUGASSERT(passwdp);

  /* Parse the login details if specified. It not then we treat NULL as a hint
     to clear the existing data */
  if (option)
  {
    size_t len = strlen(option);
    FETCHcode result;
    if (len > FETCH_MAX_INPUT_LENGTH)
      return FETCHE_BAD_FUNCTION_ARGUMENT;

    result = Curl_parse_login_details(option, len, &user, &passwd, NULL);
    if (result)
      return result;
  }

  free(*userp);
  *userp = user;

  free(*passwdp);
  *passwdp = passwd;

  return FETCHE_OK;
}

static FETCHcode setstropt_interface(char *option, char **devp,
                                     char **ifacep, char **hostp)
{
  char *dev = NULL;
  char *iface = NULL;
  char *host = NULL;
  FETCHcode result;

  DEBUGASSERT(devp);
  DEBUGASSERT(ifacep);
  DEBUGASSERT(hostp);

  if (option)
  {
    /* Parse the interface details if set, otherwise clear them all */
    result = Curl_parse_interface(option, &dev, &iface, &host);
    if (result)
      return result;
  }
  free(*devp);
  *devp = dev;

  free(*ifacep);
  *ifacep = iface;

  free(*hostp);
  *hostp = host;

  return FETCHE_OK;
}

#define C_SSLVERSION_VALUE(x) (x & 0xffff)
#define C_SSLVERSION_MAX_VALUE(x) ((unsigned long)x & 0xffff0000)

static FETCHcode protocol2num(const char *str, fetch_prot_t *val)
{
  /*
   * We are asked to cherry-pick protocols, so play it safe and disallow all
   * protocols to start with, and re-add the wanted ones back in.
   */
  *val = 0;

  if (!str)
    return FETCHE_BAD_FUNCTION_ARGUMENT;

  if (fetch_strequal(str, "all"))
  {
    *val = ~(fetch_prot_t)0;
    return FETCHE_OK;
  }

  do
  {
    const char *token = str;
    size_t tlen;

    str = strchr(str, ',');
    tlen = str ? (size_t)(str - token) : strlen(token);
    if (tlen)
    {
      const struct Curl_handler *h = Curl_getn_scheme_handler(token, tlen);

      if (!h)
        return FETCHE_UNSUPPORTED_PROTOCOL;

      *val |= h->protocol;
    }
  } while (str && str++);

  if (!*val)
    /* no protocol listed */
    return FETCHE_BAD_FUNCTION_ARGUMENT;
  return FETCHE_OK;
}

static FETCHcode httpauth(struct Curl_easy *data, bool proxy,
                          unsigned long auth)
{
  if (auth != FETCHAUTH_NONE)
  {
    int bitcheck = 0;
    bool authbits = FALSE;
    /* the DIGEST_IE bit is only used to set a special marker, for all the
       rest we need to handle it as normal DIGEST */
    bool iestyle = !!(auth & FETCHAUTH_DIGEST_IE);
    if (proxy)
      data->state.authproxy.iestyle = iestyle;
    else
      data->state.authhost.iestyle = iestyle;

    if (auth & FETCHAUTH_DIGEST_IE)
    {
      auth |= FETCHAUTH_DIGEST;     /* set standard digest bit */
      auth &= ~FETCHAUTH_DIGEST_IE; /* unset ie digest bit */
    }

    /* switch off bits we cannot support */
#ifndef USE_NTLM
    auth &= ~FETCHAUTH_NTLM; /* no NTLM support */
#endif
#ifndef USE_SPNEGO
    auth &= ~FETCHAUTH_NEGOTIATE; /* no Negotiate (SPNEGO) auth without GSS-API
                                    or SSPI */
#endif

    /* check if any auth bit lower than FETCHAUTH_ONLY is still set */
    while (bitcheck < 31)
    {
      if (auth & (1UL << bitcheck++))
      {
        authbits = TRUE;
        break;
      }
    }
    if (!authbits)
      return FETCHE_NOT_BUILT_IN; /* no supported types left! */
  }
  if (proxy)
    data->set.proxyauth = auth;
  else
    data->set.httpauth = auth;
  return FETCHE_OK;
}

static FETCHcode setopt_long(struct Curl_easy *data, FETCHoption option,
                             long arg)
{
  bool enabled = (0 != arg);
  unsigned long uarg = (unsigned long)arg;
  switch (option)
  {
  case FETCHOPT_DNS_CACHE_TIMEOUT:
    if (arg < -1)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    else if (arg > INT_MAX)
      arg = INT_MAX;

    data->set.dns_cache_timeout = (int)arg;
    break;
  case FETCHOPT_CA_CACHE_TIMEOUT:
    if (Curl_ssl_supports(data, SSLSUPP_CA_CACHE))
    {
      if (arg < -1)
        return FETCHE_BAD_FUNCTION_ARGUMENT;
      else if (arg > INT_MAX)
        arg = INT_MAX;

      data->set.general_ssl.ca_cache_timeout = (int)arg;
    }
    else
      return FETCHE_NOT_BUILT_IN;
    break;
  case FETCHOPT_MAXCONNECTS:
    /*
     * Set the absolute number of maximum simultaneous alive connection that
     * libfetch is allowed to have.
     */
    if (uarg > UINT_MAX)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.maxconnects = (unsigned int)uarg;
    break;
  case FETCHOPT_FORBID_REUSE:
    /*
     * When this transfer is done, it must not be left to be reused by a
     * subsequent transfer but shall be closed immediately.
     */
    data->set.reuse_forbid = enabled;
    break;
  case FETCHOPT_FRESH_CONNECT:
    /*
     * This transfer shall not use a previously cached connection but
     * should be made with a fresh new connect!
     */
    data->set.reuse_fresh = enabled;
    break;
  case FETCHOPT_VERBOSE:
    /*
     * Verbose means infof() calls that give a lot of information about
     * the connection and transfer procedures as well as internal choices.
     */
    data->set.verbose = enabled;
    break;
  case FETCHOPT_HEADER:
    /*
     * Set to include the header in the general data output stream.
     */
    data->set.include_header = enabled;
    break;
  case FETCHOPT_NOPROGRESS:
    /*
     * Shut off the internal supported progress meter
     */
    data->set.hide_progress = enabled;
    if (data->set.hide_progress)
      data->progress.flags |= PGRS_HIDE;
    else
      data->progress.flags &= ~PGRS_HIDE;
    break;
  case FETCHOPT_NOBODY:
    /*
     * Do not include the body part in the output data stream.
     */
    data->set.opt_no_body = enabled;
#ifndef FETCH_DISABLE_HTTP
    if (data->set.opt_no_body)
      /* in HTTP lingo, no body means using the HEAD request... */
      data->set.method = HTTPREQ_HEAD;
    else if (data->set.method == HTTPREQ_HEAD)
      data->set.method = HTTPREQ_GET;
#endif
    break;
  case FETCHOPT_FAILONERROR:
    /*
     * Do not output the >=400 error code HTML-page, but instead only
     * return error.
     */
    data->set.http_fail_on_error = enabled;
    break;
  case FETCHOPT_KEEP_SENDING_ON_ERROR:
    data->set.http_keep_sending_on_error = enabled;
    break;
  case FETCHOPT_UPLOAD:
  case FETCHOPT_PUT:
    /*
     * We want to sent data to the remote host. If this is HTTP, that equals
     * using the PUT request.
     */
    if (arg)
    {
      /* If this is HTTP, PUT is what's needed to "upload" */
      data->set.method = HTTPREQ_PUT;
      data->set.opt_no_body = FALSE; /* this is implied */
    }
    else
      /* In HTTP, the opposite of upload is GET (unless NOBODY is true as
         then this can be changed to HEAD later on) */
      data->set.method = HTTPREQ_GET;
    break;
  case FETCHOPT_FILETIME:
    /*
     * Try to get the file time of the remote document. The time will
     * later (possibly) become available using fetch_easy_getinfo().
     */
    data->set.get_filetime = enabled;
    break;
  case FETCHOPT_SERVER_RESPONSE_TIMEOUT:
    /*
     * Option that specifies how quickly a server response must be obtained
     * before it is considered failure. For pingpong protocols.
     */
    if ((arg >= 0) && (arg <= (INT_MAX / 1000)))
      data->set.server_response_timeout = (unsigned int)arg * 1000;
    else
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    break;
  case FETCHOPT_SERVER_RESPONSE_TIMEOUT_MS:
    /*
     * Option that specifies how quickly a server response must be obtained
     * before it is considered failure. For pingpong protocols.
     */
    if ((arg >= 0) && (arg <= INT_MAX))
      data->set.server_response_timeout = (unsigned int)arg;
    else
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    break;
#ifndef FETCH_DISABLE_TFTP
  case FETCHOPT_TFTP_NO_OPTIONS:
    /*
     * Option that prevents libfetch from sending TFTP option requests to the
     * server.
     */
    data->set.tftp_no_options = enabled;
    break;
  case FETCHOPT_TFTP_BLKSIZE:
    /*
     * TFTP option that specifies the block size to use for data transmission.
     */
    if (arg < TFTP_BLKSIZE_MIN)
      arg = 512;
    else if (arg > TFTP_BLKSIZE_MAX)
      arg = TFTP_BLKSIZE_MAX;
    data->set.tftp_blksize = arg;
    break;
#endif
#ifndef FETCH_DISABLE_NETRC
  case FETCHOPT_NETRC:
    /*
     * Parse the $HOME/.netrc file
     */
    if ((arg < FETCH_NETRC_IGNORED) || (arg >= FETCH_NETRC_LAST))
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.use_netrc = (unsigned char)arg;
    break;
#endif
  case FETCHOPT_TRANSFERTEXT:
    /*
     * This option was previously named 'FTPASCII'. Renamed to work with
     * more protocols than merely FTP.
     *
     * Transfer using ASCII (instead of BINARY).
     */
    data->set.prefer_ascii = enabled;
    break;
  case FETCHOPT_TIMECONDITION:
    /*
     * Set HTTP time condition. This must be one of the defines in the
     * fetch/fetch.h header file.
     */
    if ((arg < FETCH_TIMECOND_NONE) || (arg >= FETCH_TIMECOND_LAST))
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.timecondition = (unsigned char)(fetch_TimeCond)arg;
    break;
  case FETCHOPT_TIMEVALUE:
    /*
     * This is the value to compare with the remote document with the
     * method set with FETCHOPT_TIMECONDITION
     */
    data->set.timevalue = (time_t)arg;
    break;
  case FETCHOPT_SSLVERSION:
#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXY_SSLVERSION:
#endif
    /*
     * Set explicit SSL version to try to connect with, as some SSL
     * implementations are lame.
     */
#ifdef USE_SSL
  {
    long version, version_max;
    struct ssl_primary_config *primary = &data->set.ssl.primary;
#ifndef FETCH_DISABLE_PROXY
    if (option != FETCHOPT_SSLVERSION)
      primary = &data->set.proxy_ssl.primary;
#endif
    version = C_SSLVERSION_VALUE(arg);
    version_max = (long)C_SSLVERSION_MAX_VALUE(arg);

    if (version < FETCH_SSLVERSION_DEFAULT ||
        version == FETCH_SSLVERSION_SSLv2 ||
        version == FETCH_SSLVERSION_SSLv3 ||
        version >= FETCH_SSLVERSION_LAST ||
        version_max < FETCH_SSLVERSION_MAX_NONE ||
        version_max >= FETCH_SSLVERSION_MAX_LAST)
      return FETCHE_BAD_FUNCTION_ARGUMENT;

    primary->version = (unsigned char)version;
    primary->version_max = (unsigned int)version_max;
  }
#else
    return FETCHE_NOT_BUILT_IN;
#endif
  break;
  case FETCHOPT_POSTFIELDSIZE:
    /*
     * The size of the POSTFIELD data to prevent libfetch to do strlen() to
     * figure it out. Enables binary posts.
     */
    if (arg < -1)
      return FETCHE_BAD_FUNCTION_ARGUMENT;

    if (data->set.postfieldsize < arg &&
        data->set.postfields == data->set.str[STRING_COPYPOSTFIELDS])
    {
      /* Previous FETCHOPT_COPYPOSTFIELDS is no longer valid. */
      Curl_safefree(data->set.str[STRING_COPYPOSTFIELDS]);
      data->set.postfields = NULL;
    }

    data->set.postfieldsize = arg;
    break;
#ifndef FETCH_DISABLE_HTTP
#if !defined(FETCH_DISABLE_COOKIES)
  case FETCHOPT_COOKIESESSION:
    /*
     * Set this option to TRUE to start a new "cookie session". It will
     * prevent the forthcoming read-cookies-from-file actions to accept
     * cookies that are marked as being session cookies, as they belong to a
     * previous session.
     */
    data->set.cookiesession = enabled;
    break;
#endif
  case FETCHOPT_AUTOREFERER:
    /*
     * Switch on automatic referer that gets set if fetch follows locations.
     */
    data->set.http_auto_referer = enabled;
    break;

  case FETCHOPT_TRANSFER_ENCODING:
    data->set.http_transfer_encoding = enabled;
    break;

  case FETCHOPT_FOLLOWLOCATION:
    /*
     * Follow Location: header hints on an HTTP-server.
     */
    data->set.http_follow_location = enabled;
    break;

  case FETCHOPT_UNRESTRICTED_AUTH:
    /*
     * Send authentication (user+password) when following locations, even when
     * hostname changed.
     */
    data->set.allow_auth_to_other_hosts = enabled;
    break;

  case FETCHOPT_MAXREDIRS:
    /*
     * The maximum amount of hops you allow fetch to follow Location:
     * headers. This should mostly be used to detect never-ending loops.
     */
    if (arg < -1)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.maxredirs = arg;
    break;

  case FETCHOPT_POSTREDIR:
    /*
     * Set the behavior of POST when redirecting
     * FETCH_REDIR_GET_ALL - POST is changed to GET after 301 and 302
     * FETCH_REDIR_POST_301 - POST is kept as POST after 301
     * FETCH_REDIR_POST_302 - POST is kept as POST after 302
     * FETCH_REDIR_POST_303 - POST is kept as POST after 303
     * FETCH_REDIR_POST_ALL - POST is kept as POST after 301, 302 and 303
     * other - POST is kept as POST after 301 and 302
     */
    if (arg < FETCH_REDIR_GET_ALL)
      /* no return error on too high numbers since the bitmask could be
         extended in a future */
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.keep_post = arg & FETCH_REDIR_POST_ALL;
    break;

  case FETCHOPT_POST:
    /* Does this option serve a purpose anymore? Yes it does, when
       FETCHOPT_POSTFIELDS is not used and the POST data is read off the
       callback! */
    if (arg)
    {
      data->set.method = HTTPREQ_POST;
      data->set.opt_no_body = FALSE; /* this is implied */
    }
    else
      data->set.method = HTTPREQ_GET;
    break;
  case FETCHOPT_HEADEROPT:
    /*
     * Set header option.
     */
    data->set.sep_headers = !!(arg & FETCHHEADER_SEPARATE);
    break;
  case FETCHOPT_HTTPAUTH:
    return httpauth(data, FALSE, uarg);

  case FETCHOPT_HTTPGET:
    /*
     * Set to force us do HTTP GET
     */
    if (enabled)
    {
      data->set.method = HTTPREQ_GET;
      data->set.opt_no_body = FALSE; /* this is implied */
    }
    break;

  case FETCHOPT_HTTP_VERSION:
    /*
     * This sets a requested HTTP version to be used. The value is one of
     * the listed enums in fetch/fetch.h.
     */
    switch (arg)
    {
    case FETCH_HTTP_VERSION_NONE:
#ifdef USE_HTTP2
      /* TODO: this seems an undesirable quirk to force a behaviour on
       * lower implementations that they should recognize independently? */
      arg = FETCH_HTTP_VERSION_2TLS;
#endif
      /* accepted */
      break;
    case FETCH_HTTP_VERSION_1_0:
    case FETCH_HTTP_VERSION_1_1:
      /* accepted */
      break;
#ifdef USE_HTTP2
    case FETCH_HTTP_VERSION_2_0:
    case FETCH_HTTP_VERSION_2TLS:
    case FETCH_HTTP_VERSION_2_PRIOR_KNOWLEDGE:
      /* accepted */
      break;
#endif
#ifdef USE_HTTP3
    case FETCH_HTTP_VERSION_3:
    case FETCH_HTTP_VERSION_3ONLY:
      /* accepted */
      break;
#endif
    default:
      /* not accepted */
      if (arg < FETCH_HTTP_VERSION_NONE)
        return FETCHE_BAD_FUNCTION_ARGUMENT;
      return FETCHE_UNSUPPORTED_PROTOCOL;
    }
    data->set.httpwant = (unsigned char)arg;
    break;

  case FETCHOPT_EXPECT_100_TIMEOUT_MS:
    /*
     * Time to wait for a response to an HTTP request containing an
     * Expect: 100-continue header before sending the data anyway.
     */
    if (arg < 0)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.expect_100_timeout = arg;
    break;

  case FETCHOPT_HTTP09_ALLOWED:
    data->set.http09_allowed = enabled;
    break;
#endif /* ! FETCH_DISABLE_HTTP */

#ifndef FETCH_DISABLE_MIME
  case FETCHOPT_MIME_OPTIONS:
    data->set.mime_formescape = !!(arg & FETCHMIMEOPT_FORMESCAPE);
    break;
#endif
#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_HTTPPROXYTUNNEL:
    /*
     * Tunnel operations through the proxy instead of normal proxy use
     */
    data->set.tunnel_thru_httpproxy = enabled;
    break;

  case FETCHOPT_PROXYPORT:
    /*
     * Explicitly set HTTP proxy port number.
     */
    if ((arg < 0) || (arg > 65535))
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.proxyport = (unsigned short)arg;
    break;

  case FETCHOPT_PROXYAUTH:
    return httpauth(data, TRUE, uarg);

  case FETCHOPT_PROXYTYPE:
    /*
     * Set proxy type.
     */
    if ((arg < FETCHPROXY_HTTP) || (arg > FETCHPROXY_SOCKS5_HOSTNAME))
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.proxytype = (unsigned char)(fetch_proxytype)arg;
    break;

  case FETCHOPT_PROXY_TRANSFER_MODE:
    /*
     * set transfer mode (;type=<a|i>) when doing FTP via an HTTP proxy
     */
    if (uarg > 1)
      /* reserve other values for future use */
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.proxy_transfer_mode = (bool)uarg;
    break;
  case FETCHOPT_SOCKS5_AUTH:
    if (data->set.socks5auth & ~(FETCHAUTH_BASIC | FETCHAUTH_GSSAPI))
      return FETCHE_NOT_BUILT_IN;
    data->set.socks5auth = (unsigned char)uarg;
    break;
  case FETCHOPT_HAPROXYPROTOCOL:
    /*
     * Set to send the HAProxy Proxy Protocol header
     */
    data->set.haproxyprotocol = enabled;
    break;
  case FETCHOPT_PROXY_SSL_VERIFYPEER:
    /*
     * Enable peer SSL verifying for proxy.
     */
    data->set.proxy_ssl.primary.verifypeer = enabled;

    /* Update the current connection proxy_ssl_config. */
    Curl_ssl_conn_config_update(data, TRUE);
    break;
  case FETCHOPT_PROXY_SSL_VERIFYHOST:
    /*
     * Enable verification of the hostname in the peer certificate for proxy
     */
    data->set.proxy_ssl.primary.verifyhost = enabled;

    /* Update the current connection proxy_ssl_config. */
    Curl_ssl_conn_config_update(data, TRUE);
    break;
#endif /* ! FETCH_DISABLE_PROXY */

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  case FETCHOPT_SOCKS5_GSSAPI_NEC:
    /*
     * Set flag for NEC SOCK5 support
     */
    data->set.socks5_gssapi_nec = enabled;
    break;
#endif
#ifdef FETCH_LIST_ONLY_PROTOCOL
  case FETCHOPT_DIRLISTONLY:
    /*
     * An option that changes the command to one that asks for a list only, no
     * file info details. Used for FTP, POP3 and SFTP.
     */
    data->set.list_only = enabled;
    break;
#endif
  case FETCHOPT_APPEND:
    /*
     * We want to upload and append to an existing file. Used for FTP and
     * SFTP.
     */
    data->set.remote_append = enabled;
    break;

#ifndef FETCH_DISABLE_FTP
  case FETCHOPT_FTP_FILEMETHOD:
    /*
     * How do access files over FTP.
     */
    if ((arg < FETCHFTPMETHOD_DEFAULT) || (arg >= FETCHFTPMETHOD_LAST))
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.ftp_filemethod = (unsigned char)arg;
    break;
  case FETCHOPT_FTP_USE_EPRT:
    data->set.ftp_use_eprt = enabled;
    break;

  case FETCHOPT_FTP_USE_EPSV:
    data->set.ftp_use_epsv = enabled;
    break;

  case FETCHOPT_FTP_USE_PRET:
    data->set.ftp_use_pret = enabled;
    break;

  case FETCHOPT_FTP_SSL_CCC:
    if ((arg < FETCHFTPSSL_CCC_NONE) || (arg >= FETCHFTPSSL_CCC_LAST))
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.ftp_ccc = (unsigned char)arg;
    break;

  case FETCHOPT_FTP_SKIP_PASV_IP:
    /*
     * Enable or disable FTP_SKIP_PASV_IP, which will disable/enable the
     * bypass of the IP address in PASV responses.
     */
    data->set.ftp_skip_ip = enabled;
    break;

  case FETCHOPT_FTPSSLAUTH:
    /*
     * Set a specific auth for FTP-SSL transfers.
     */
    if ((arg < FETCHFTPAUTH_DEFAULT) || (arg >= FETCHFTPAUTH_LAST))
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.ftpsslauth = (unsigned char)(fetch_ftpauth)arg;
    break;
  case FETCHOPT_ACCEPTTIMEOUT_MS:
    /*
     * The maximum time for fetch to wait for FTP server connect
     */
    if (uarg > UINT_MAX)
      uarg = UINT_MAX;
    data->set.accepttimeout = (unsigned int)uarg;
    break;
  case FETCHOPT_WILDCARDMATCH:
    data->set.wildcard_enabled = enabled;
    break;
#endif /* ! FETCH_DISABLE_FTP */
#if !defined(FETCH_DISABLE_FTP) || defined(USE_SSH)
  case FETCHOPT_FTP_CREATE_MISSING_DIRS:
    /*
     * An FTP/SFTP option that modifies an upload to create missing
     * directories on the server.
     */
    /* reserve other values for future use */
    if ((arg < FETCHFTP_CREATE_DIR_NONE) || (arg > FETCHFTP_CREATE_DIR_RETRY))
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.ftp_create_missing_dirs = (unsigned char)arg;
    break;
#endif /* ! FETCH_DISABLE_FTP || USE_SSH */
  case FETCHOPT_INFILESIZE:
    /*
     * If known, this should inform fetch about the file size of the
     * to-be-uploaded file.
     */
    if (arg < -1)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.filesize = arg;
    break;
  case FETCHOPT_LOW_SPEED_LIMIT:
    /*
     * The low speed limit that if transfers are below this for
     * FETCHOPT_LOW_SPEED_TIME, the transfer is aborted.
     */
    if (arg < 0)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.low_speed_limit = arg;
    break;
  case FETCHOPT_LOW_SPEED_TIME:
    /*
     * The low speed time that if transfers are below the set
     * FETCHOPT_LOW_SPEED_LIMIT during this time, the transfer is aborted.
     */
    if (arg < 0)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.low_speed_time = arg;
    break;
  case FETCHOPT_PORT:
    /*
     * The port number to use when getting the URL. 0 disables it.
     */
    if ((arg < 0) || (arg > 65535))
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.use_port = (unsigned short)arg;
    break;
  case FETCHOPT_TIMEOUT:
    /*
     * The maximum time you allow fetch to use for a single transfer
     * operation.
     */
    if ((arg >= 0) && (arg <= (INT_MAX / 1000)))
      data->set.timeout = (unsigned int)arg * 1000;
    else
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    break;

  case FETCHOPT_TIMEOUT_MS:
    if (uarg > UINT_MAX)
      uarg = UINT_MAX;
    data->set.timeout = (unsigned int)uarg;
    break;

  case FETCHOPT_CONNECTTIMEOUT:
    /*
     * The maximum time you allow fetch to use to connect.
     */
    if ((arg >= 0) && (arg <= (INT_MAX / 1000)))
      data->set.connecttimeout = (unsigned int)arg * 1000;
    else
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    break;

  case FETCHOPT_CONNECTTIMEOUT_MS:
    if (uarg > UINT_MAX)
      uarg = UINT_MAX;
    data->set.connecttimeout = (unsigned int)uarg;
    break;

  case FETCHOPT_RESUME_FROM:
    /*
     * Resume transfer at the given file position
     */
    if (arg < -1)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.set_resume_from = arg;
    break;

  case FETCHOPT_CRLF:
    /*
     * Kludgy option to enable CRLF conversions. Subject for removal.
     */
    data->set.crlf = enabled;
    break;

#ifndef FETCH_DISABLE_BINDLOCAL
  case FETCHOPT_LOCALPORT:
    /*
     * Set what local port to bind the socket to when performing an operation.
     */
    if ((arg < 0) || (arg > 65535))
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.localport = fetchx_sltous(arg);
    break;
  case FETCHOPT_LOCALPORTRANGE:
    /*
     * Set number of local ports to try, starting with FETCHOPT_LOCALPORT.
     */
    if ((arg < 0) || (arg > 65535))
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.localportrange = fetchx_sltous(arg);
    break;
#endif

#ifdef HAVE_GSSAPI
  case FETCHOPT_GSSAPI_DELEGATION:
    /*
     * GSS-API credential delegation bitmask
     */
    data->set.gssapi_delegation = (unsigned char)uarg &
                                  (FETCHGSSAPI_DELEGATION_POLICY_FLAG | FETCHGSSAPI_DELEGATION_FLAG);
    break;
#endif
  case FETCHOPT_SSL_VERIFYPEER:
    /*
     * Enable peer SSL verifying.
     */
    data->set.ssl.primary.verifypeer = enabled;

    /* Update the current connection ssl_config. */
    Curl_ssl_conn_config_update(data, FALSE);
    break;
#ifndef FETCH_DISABLE_DOH
  case FETCHOPT_DOH_SSL_VERIFYPEER:
    /*
     * Enable peer SSL verifying for DoH.
     */
    data->set.doh_verifypeer = enabled;
    break;
  case FETCHOPT_DOH_SSL_VERIFYHOST:
    /*
     * Enable verification of the hostname in the peer certificate for DoH
     */
    data->set.doh_verifyhost = enabled;
    break;
  case FETCHOPT_DOH_SSL_VERIFYSTATUS:
    /*
     * Enable certificate status verifying for DoH.
     */
    if (!Curl_ssl_cert_status_request())
      return FETCHE_NOT_BUILT_IN;

    data->set.doh_verifystatus = enabled;
    break;
#endif /* ! FETCH_DISABLE_DOH */
  case FETCHOPT_SSL_VERIFYHOST:
    /*
     * Enable verification of the hostname in the peer certificate
     */

    /* Obviously people are not reading documentation and too many thought
       this argument took a boolean when it was not and misused it.
       Treat 1 and 2 the same */
    data->set.ssl.primary.verifyhost = enabled;

    /* Update the current connection ssl_config. */
    Curl_ssl_conn_config_update(data, FALSE);
    break;
  case FETCHOPT_SSL_VERIFYSTATUS:
    /*
     * Enable certificate status verifying.
     */
    if (!Curl_ssl_cert_status_request())
      return FETCHE_NOT_BUILT_IN;

    data->set.ssl.primary.verifystatus = enabled;

    /* Update the current connection ssl_config. */
    Curl_ssl_conn_config_update(data, FALSE);
    break;
  case FETCHOPT_SSL_FALSESTART:
    /*
     * Enable TLS false start.
     */
    if (!Curl_ssl_false_start())
      return FETCHE_NOT_BUILT_IN;

    data->set.ssl.falsestart = enabled;
    break;
  case FETCHOPT_CERTINFO:
#ifdef USE_SSL
    if (Curl_ssl_supports(data, SSLSUPP_CERTINFO))
      data->set.ssl.certinfo = enabled;
    else
#endif
      return FETCHE_NOT_BUILT_IN;
    break;
  case FETCHOPT_BUFFERSIZE:
    /*
     * The application kindly asks for a differently sized receive buffer.
     * If it seems reasonable, we will use it.
     */
    if (arg > READBUFFER_MAX)
      arg = READBUFFER_MAX;
    else if (arg < 1)
      arg = READBUFFER_SIZE;
    else if (arg < READBUFFER_MIN)
      arg = READBUFFER_MIN;

    data->set.buffer_size = (unsigned int)arg;
    break;

  case FETCHOPT_UPLOAD_BUFFERSIZE:
    /*
     * The application kindly asks for a differently sized upload buffer.
     * Cap it to sensible.
     */
    if (arg > UPLOADBUFFER_MAX)
      arg = UPLOADBUFFER_MAX;
    else if (arg < UPLOADBUFFER_MIN)
      arg = UPLOADBUFFER_MIN;

    data->set.upload_buffer_size = (unsigned int)arg;
    break;

  case FETCHOPT_NOSIGNAL:
    /*
     * The application asks not to set any signal() or alarm() handlers,
     * even when using a timeout.
     */
    data->set.no_signal = enabled;
    break;
  case FETCHOPT_MAXFILESIZE:
    /*
     * Set the maximum size of a file to download.
     */
    if (arg < 0)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.max_filesize = arg;
    break;

#ifdef USE_SSL
  case FETCHOPT_USE_SSL:
    /*
     * Make transfers attempt to use SSL/TLS.
     */
    if ((arg < FETCHUSESSL_NONE) || (arg >= FETCHUSESSL_LAST))
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.use_ssl = (unsigned char)arg;
    break;
  case FETCHOPT_SSL_OPTIONS:
    data->set.ssl.primary.ssl_options = (unsigned char)(arg & 0xff);
    data->set.ssl.enable_beast = !!(arg & FETCHSSLOPT_ALLOW_BEAST);
    data->set.ssl.no_revoke = !!(arg & FETCHSSLOPT_NO_REVOKE);
    data->set.ssl.no_partialchain = !!(arg & FETCHSSLOPT_NO_PARTIALCHAIN);
    data->set.ssl.revoke_best_effort = !!(arg & FETCHSSLOPT_REVOKE_BEST_EFFORT);
    data->set.ssl.native_ca_store = !!(arg & FETCHSSLOPT_NATIVE_CA);
    data->set.ssl.auto_client_cert = !!(arg & FETCHSSLOPT_AUTO_CLIENT_CERT);
    data->set.ssl.earlydata = !!(arg & FETCHSSLOPT_EARLYDATA);
    /* If a setting is added here it should also be added in dohprobe()
       which sets its own FETCHOPT_SSL_OPTIONS based on these settings. */
    break;

#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXY_SSL_OPTIONS:
    data->set.proxy_ssl.primary.ssl_options = (unsigned char)(arg & 0xff);
    data->set.proxy_ssl.enable_beast = !!(arg & FETCHSSLOPT_ALLOW_BEAST);
    data->set.proxy_ssl.no_revoke = !!(arg & FETCHSSLOPT_NO_REVOKE);
    data->set.proxy_ssl.no_partialchain = !!(arg & FETCHSSLOPT_NO_PARTIALCHAIN);
    data->set.proxy_ssl.revoke_best_effort =
        !!(arg & FETCHSSLOPT_REVOKE_BEST_EFFORT);
    data->set.proxy_ssl.native_ca_store = !!(arg & FETCHSSLOPT_NATIVE_CA);
    data->set.proxy_ssl.auto_client_cert =
        !!(arg & FETCHSSLOPT_AUTO_CLIENT_CERT);
    break;
#endif

#endif /* USE_SSL */
  case FETCHOPT_IPRESOLVE:
    if ((arg < FETCH_IPRESOLVE_WHATEVER) || (arg > FETCH_IPRESOLVE_V6))
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.ipver = (unsigned char)arg;
    break;
  case FETCHOPT_TCP_NODELAY:
    /*
     * Enable or disable TCP_NODELAY, which will disable/enable the Nagle
     * algorithm
     */
    data->set.tcp_nodelay = enabled;
    break;

  case FETCHOPT_IGNORE_CONTENT_LENGTH:
    data->set.ignorecl = enabled;
    break;

  case FETCHOPT_CONNECT_ONLY:
    /*
     * No data transfer.
     * (1) - only do connection
     * (2) - do first get request but get no content
     */
    if (arg > 2)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.connect_only = !!arg;
    data->set.connect_only_ws = (arg == 2);
    break;

  case FETCHOPT_SSL_SESSIONID_CACHE:
    data->set.ssl.primary.cache_session = enabled;
#ifndef FETCH_DISABLE_PROXY
    data->set.proxy_ssl.primary.cache_session =
        data->set.ssl.primary.cache_session;
#endif
    break;

#ifdef USE_SSH
    /* we only include SSH options if explicitly built to support SSH */
  case FETCHOPT_SSH_AUTH_TYPES:
    data->set.ssh_auth_types = (int)arg;
    break;
  case FETCHOPT_SSH_COMPRESSION:
    data->set.ssh_compression = enabled;
    break;
#endif

  case FETCHOPT_HTTP_TRANSFER_DECODING:
    /*
     * disable libfetch transfer encoding is used
     */
#ifndef USE_HYPER
    data->set.http_te_skip = !enabled; /* reversed */
    break;
#else
    return FETCHE_NOT_BUILT_IN; /* hyper does not support */
#endif

  case FETCHOPT_HTTP_CONTENT_DECODING:
    /*
     * raw data passed to the application when content encoding is used
     */
    data->set.http_ce_skip = !enabled; /* reversed */
    break;

#if !defined(FETCH_DISABLE_FTP) || defined(USE_SSH)
  case FETCHOPT_NEW_FILE_PERMS:
    /*
     * Uses these permissions instead of 0644
     */
    if ((arg < 0) || (arg > 0777))
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.new_file_perms = (unsigned int)arg;
    break;
#endif
#ifdef USE_SSH
  case FETCHOPT_NEW_DIRECTORY_PERMS:
    /*
     * Uses these permissions instead of 0755
     */
    if ((arg < 0) || (arg > 0777))
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.new_directory_perms = (unsigned int)arg;
    break;
#endif
#ifdef USE_IPV6
  case FETCHOPT_ADDRESS_SCOPE:
    /*
     * Use this scope id when using IPv6
     * We always get longs when passed plain numericals so we should check
     * that the value fits into an unsigned 32-bit integer.
     */
#if SIZEOF_LONG > 4
    if (uarg > UINT_MAX)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
#endif
    data->set.scope_id = (unsigned int)uarg;
    break;
#endif
  case FETCHOPT_PROTOCOLS:
    /* set the bitmask for the protocols that are allowed to be used for the
       transfer, which thus helps the app which takes URLs from users or other
       external inputs and want to restrict what protocol(s) to deal with.
       Defaults to FETCHPROTO_ALL. */
    data->set.allowed_protocols = (fetch_prot_t)arg;
    break;

  case FETCHOPT_REDIR_PROTOCOLS:
    /* set the bitmask for the protocols that libfetch is allowed to follow to,
       as a subset of the FETCHOPT_PROTOCOLS ones. That means the protocol
       needs to be set in both bitmasks to be allowed to get redirected to. */
    data->set.redir_protocols = (fetch_prot_t)arg;
    break;

#ifndef FETCH_DISABLE_SMTP
  case FETCHOPT_MAIL_RCPT_ALLOWFAILS:
    /* allow RCPT TO command to fail for some recipients */
    data->set.mail_rcpt_allowfails = enabled;
    break;
#endif /* !FETCH_DISABLE_SMTP */
  case FETCHOPT_SASL_IR:
    /* Enable/disable SASL initial response */
    data->set.sasl_ir = enabled;
    break;
#ifndef FETCH_DISABLE_RTSP
  case FETCHOPT_RTSP_REQUEST:
  {
    /*
     * Set the RTSP request method (OPTIONS, SETUP, PLAY, etc...)
     * Would this be better if the RTSPREQ_* were just moved into here?
     */
    Curl_RtspReq rtspreq = RTSPREQ_NONE;
    switch (arg)
    {
    case FETCH_RTSPREQ_OPTIONS:
      rtspreq = RTSPREQ_OPTIONS;
      break;

    case FETCH_RTSPREQ_DESCRIBE:
      rtspreq = RTSPREQ_DESCRIBE;
      break;

    case FETCH_RTSPREQ_ANNOUNCE:
      rtspreq = RTSPREQ_ANNOUNCE;
      break;

    case FETCH_RTSPREQ_SETUP:
      rtspreq = RTSPREQ_SETUP;
      break;

    case FETCH_RTSPREQ_PLAY:
      rtspreq = RTSPREQ_PLAY;
      break;

    case FETCH_RTSPREQ_PAUSE:
      rtspreq = RTSPREQ_PAUSE;
      break;

    case FETCH_RTSPREQ_TEARDOWN:
      rtspreq = RTSPREQ_TEARDOWN;
      break;

    case FETCH_RTSPREQ_GET_PARAMETER:
      rtspreq = RTSPREQ_GET_PARAMETER;
      break;

    case FETCH_RTSPREQ_SET_PARAMETER:
      rtspreq = RTSPREQ_SET_PARAMETER;
      break;

    case FETCH_RTSPREQ_RECORD:
      rtspreq = RTSPREQ_RECORD;
      break;

    case FETCH_RTSPREQ_RECEIVE:
      rtspreq = RTSPREQ_RECEIVE;
      break;
    default:
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    }

    data->set.rtspreq = rtspreq;
    break;
  }
  case FETCHOPT_RTSP_CLIENT_CSEQ:
    /*
     * Set the CSEQ number to issue for the next RTSP request. Useful if the
     * application is resuming a previously broken connection. The CSEQ
     * will increment from this new number henceforth.
     */
    data->state.rtsp_next_client_CSeq = arg;
    break;

  case FETCHOPT_RTSP_SERVER_CSEQ:
    /* Same as the above, but for server-initiated requests */
    data->state.rtsp_next_server_CSeq = arg;
    break;

#endif /* ! FETCH_DISABLE_RTSP */

  case FETCHOPT_TCP_KEEPALIVE:
    data->set.tcp_keepalive = enabled;
    break;
  case FETCHOPT_TCP_KEEPIDLE:
    if (arg < 0)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    else if (arg > INT_MAX)
      arg = INT_MAX;
    data->set.tcp_keepidle = (int)arg;
    break;
  case FETCHOPT_TCP_KEEPINTVL:
    if (arg < 0)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    else if (arg > INT_MAX)
      arg = INT_MAX;
    data->set.tcp_keepintvl = (int)arg;
    break;
  case FETCHOPT_TCP_KEEPCNT:
    if (arg < 0)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    else if (arg > INT_MAX)
      arg = INT_MAX;
    data->set.tcp_keepcnt = (int)arg;
    break;
  case FETCHOPT_TCP_FASTOPEN:
#if defined(CONNECT_DATA_IDEMPOTENT) || defined(MSG_FASTOPEN) || \
    defined(TCP_FASTOPEN_CONNECT)
    data->set.tcp_fastopen = enabled;
#else
    return FETCHE_NOT_BUILT_IN;
#endif
    break;
  case FETCHOPT_SSL_ENABLE_NPN:
    break;
  case FETCHOPT_SSL_ENABLE_ALPN:
    data->set.ssl_enable_alpn = enabled;
    break;
  case FETCHOPT_PATH_AS_IS:
    data->set.path_as_is = enabled;
    break;
  case FETCHOPT_PIPEWAIT:
    data->set.pipewait = enabled;
    break;
  case FETCHOPT_STREAM_WEIGHT:
#if defined(USE_HTTP2) || defined(USE_HTTP3)
    if ((arg >= 1) && (arg <= 256))
      data->set.priority.weight = (int)arg;
    break;
#else
    return FETCHE_NOT_BUILT_IN;
#endif
  case FETCHOPT_SUPPRESS_CONNECT_HEADERS:
    data->set.suppress_connect_headers = enabled;
    break;
  case FETCHOPT_HAPPY_EYEBALLS_TIMEOUT_MS:
    if (uarg > UINT_MAX)
      uarg = UINT_MAX;
    data->set.happy_eyeballs_timeout = (unsigned int)uarg;
    break;
#ifndef FETCH_DISABLE_SHUFFLE_DNS
  case FETCHOPT_DNS_SHUFFLE_ADDRESSES:
    data->set.dns_shuffle_addresses = enabled;
    break;
#endif
  case FETCHOPT_DISALLOW_USERNAME_IN_URL:
    data->set.disallow_username_in_url = enabled;
    break;

  case FETCHOPT_UPKEEP_INTERVAL_MS:
    if (arg < 0)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.upkeep_interval_ms = arg;
    break;
  case FETCHOPT_MAXAGE_CONN:
    if (arg < 0)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.maxage_conn = arg;
    break;
  case FETCHOPT_MAXLIFETIME_CONN:
    if (arg < 0)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.maxlifetime_conn = arg;
    break;
#ifndef FETCH_DISABLE_HSTS
  case FETCHOPT_HSTS_CTRL:
    if (arg & FETCHHSTS_ENABLE)
    {
      if (!data->hsts)
      {
        data->hsts = Curl_hsts_init();
        if (!data->hsts)
          return FETCHE_OUT_OF_MEMORY;
      }
    }
    else
      Curl_hsts_cleanup(&data->hsts);
    break;
#endif /* ! FETCH_DISABLE_HSTS */
#ifndef FETCH_DISABLE_ALTSVC
  case FETCHOPT_ALTSVC_CTRL:
    if (!arg)
    {
      DEBUGF(infof(data, "bad FETCHOPT_ALTSVC_CTRL input"));
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    }
    if (!data->asi)
    {
      data->asi = Curl_altsvc_init();
      if (!data->asi)
        return FETCHE_OUT_OF_MEMORY;
    }
    return Curl_altsvc_ctrl(data->asi, arg);
#endif /* ! FETCH_DISABLE_ALTSVC */
#ifndef FETCH_DISABLE_WEBSOCKETS
  case FETCHOPT_WS_OPTIONS:
    data->set.ws_raw_mode = (bool)(arg & FETCHWS_RAW_MODE);
    break;
#endif
  case FETCHOPT_QUICK_EXIT:
    data->set.quick_exit = enabled;
    break;
  case FETCHOPT_DNS_USE_GLOBAL_CACHE:
    /* deprecated */
    break;
  case FETCHOPT_SSLENGINE_DEFAULT:
    /*
     * flag to set engine as default.
     */
    Curl_safefree(data->set.str[STRING_SSL_ENGINE]);
    return Curl_ssl_set_engine_default(data);

  default:
    /* unknown option */
    return FETCHE_UNKNOWN_OPTION;
  }
  return FETCHE_OK;
}

static FETCHcode setopt_slist(struct Curl_easy *data, FETCHoption option,
                              struct fetch_slist *slist)
{
  FETCHcode result = FETCHE_OK;
  switch (option)
  {
#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXYHEADER:
    /*
     * Set a list with proxy headers to use (or replace internals with)
     *
     * Since FETCHOPT_HTTPHEADER was the only way to set HTTP headers for a
     * long time we remain doing it this way until FETCHOPT_PROXYHEADER is
     * used. As soon as this option has been used, if set to anything but
     * NULL, custom headers for proxies are only picked from this list.
     *
     * Set this option to NULL to restore the previous behavior.
     */
    data->set.proxyheaders = slist;
    break;
#endif
#ifndef FETCH_DISABLE_HTTP
  case FETCHOPT_HTTP200ALIASES:
    /*
     * Set a list of aliases for HTTP 200 in response header
     */
    data->set.http200aliases = slist;
    break;
#endif
#if !defined(FETCH_DISABLE_FTP) || defined(USE_SSH)
  case FETCHOPT_POSTQUOTE:
    /*
     * List of RAW FTP commands to use after a transfer
     */
    data->set.postquote = slist;
    break;
  case FETCHOPT_PREQUOTE:
    /*
     * List of RAW FTP commands to use prior to RETR (Wesley Laxton)
     */
    data->set.prequote = slist;
    break;
  case FETCHOPT_QUOTE:
    /*
     * List of RAW FTP commands to use before a transfer
     */
    data->set.quote = slist;
    break;
#endif
  case FETCHOPT_RESOLVE:
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
    data->set.resolve = slist;
    data->state.resolve = data->set.resolve;
    break;
#if !defined(FETCH_DISABLE_HTTP) || !defined(FETCH_DISABLE_MIME)
  case FETCHOPT_HTTPHEADER:
    /*
     * Set a list with HTTP headers to use (or replace internals with)
     */
    data->set.headers = slist;
    break;
#endif
#ifndef FETCH_DISABLE_TELNET
  case FETCHOPT_TELNETOPTIONS:
    /*
     * Set a linked list of telnet options
     */
    data->set.telnet_options = slist;
    break;
#endif
#ifndef FETCH_DISABLE_SMTP
  case FETCHOPT_MAIL_RCPT:
    /* Set the list of mail recipients */
    data->set.mail_rcpt = slist;
    break;
#endif
  case FETCHOPT_CONNECT_TO:
    data->set.connect_to = slist;
    break;
  default:
    return FETCHE_UNKNOWN_OPTION;
  }
  return result;
}

/* assorted pointer type arguments */
static FETCHcode setopt_pointers(struct Curl_easy *data, FETCHoption option,
                                 va_list param)
{
  FETCHcode result = FETCHE_OK;
  switch (option)
  {
#ifndef FETCH_DISABLE_HTTP
#ifndef FETCH_DISABLE_FORM_API
  case FETCHOPT_HTTPPOST:
    /*
     * Set to make us do HTTP POST. Legacy API-style.
     */
    data->set.httppost = va_arg(param, struct fetch_httppost *);
    data->set.method = HTTPREQ_POST_FORM;
    data->set.opt_no_body = FALSE; /* this is implied */
    Curl_mime_cleanpart(data->state.formp);
    Curl_safefree(data->state.formp);
    data->state.mimepost = NULL;
    break;
#endif /* ! FETCH_DISABLE_FORM_API */
#endif /* ! FETCH_DISABLE_HTTP */
#if !defined(FETCH_DISABLE_HTTP) || !defined(FETCH_DISABLE_SMTP) || \
    !defined(FETCH_DISABLE_IMAP)
#ifndef FETCH_DISABLE_MIME
  case FETCHOPT_MIMEPOST:
    /*
     * Set to make us do MIME POST
     */
    result = Curl_mime_set_subparts(&data->set.mimepost,
                                    va_arg(param, fetch_mime *),
                                    FALSE);
    if (!result)
    {
      data->set.method = HTTPREQ_POST_MIME;
      data->set.opt_no_body = FALSE; /* this is implied */
#ifndef FETCH_DISABLE_FORM_API
      Curl_mime_cleanpart(data->state.formp);
      Curl_safefree(data->state.formp);
      data->state.mimepost = NULL;
#endif
    }
    break;
#endif /* ! FETCH_DISABLE_MIME */
#endif /* ! disabled HTTP, SMTP or IMAP */
  case FETCHOPT_STDERR:
    /*
     * Set to a FILE * that should receive all error writes. This
     * defaults to stderr for normal operations.
     */
    data->set.err = va_arg(param, FILE *);
    if (!data->set.err)
      data->set.err = stderr;
    break;
  case FETCHOPT_SHARE:
  {
    struct Curl_share *set = va_arg(param, struct Curl_share *);

    /* disconnect from old share, if any */
    if (data->share)
    {
      Curl_share_lock(data, FETCH_LOCK_DATA_SHARE, FETCH_LOCK_ACCESS_SINGLE);

      if (data->dns.hostcachetype == HCACHE_SHARED)
      {
        data->dns.hostcache = NULL;
        data->dns.hostcachetype = HCACHE_NONE;
      }

#if !defined(FETCH_DISABLE_HTTP) && !defined(FETCH_DISABLE_COOKIES)
      if (data->share->cookies == data->cookies)
        data->cookies = NULL;
#endif

#ifndef FETCH_DISABLE_HSTS
      if (data->share->hsts == data->hsts)
        data->hsts = NULL;
#endif
#ifdef USE_SSL
      if (data->share->ssl_scache == data->state.ssl_scache)
        data->state.ssl_scache = data->multi ? data->multi->ssl_scache : NULL;
#endif
#ifdef USE_LIBPSL
      if (data->psl == &data->share->psl)
        data->psl = data->multi ? &data->multi->psl : NULL;
#endif

      data->share->dirty--;

      Curl_share_unlock(data, FETCH_LOCK_DATA_SHARE);
      data->share = NULL;
    }

    if (GOOD_SHARE_HANDLE(set))
      /* use new share if it set */
      data->share = set;
    if (data->share)
    {

      Curl_share_lock(data, FETCH_LOCK_DATA_SHARE, FETCH_LOCK_ACCESS_SINGLE);

      data->share->dirty++;

      if (data->share->specifier & (1 << FETCH_LOCK_DATA_DNS))
      {
        /* use shared host cache */
        data->dns.hostcache = &data->share->hostcache;
        data->dns.hostcachetype = HCACHE_SHARED;
      }
#if !defined(FETCH_DISABLE_HTTP) && !defined(FETCH_DISABLE_COOKIES)
      if (data->share->cookies)
      {
        /* use shared cookie list, first free own one if any */
        Curl_cookie_cleanup(data->cookies);
        /* enable cookies since we now use a share that uses cookies! */
        data->cookies = data->share->cookies;
      }
#endif /* FETCH_DISABLE_HTTP */
#ifndef FETCH_DISABLE_HSTS
      if (data->share->hsts)
      {
        /* first free the private one if any */
        Curl_hsts_cleanup(&data->hsts);
        data->hsts = data->share->hsts;
      }
#endif
#ifdef USE_SSL
      if (data->share->ssl_scache)
        data->state.ssl_scache = data->share->ssl_scache;
#endif
#ifdef USE_LIBPSL
      if (data->share->specifier & (1 << FETCH_LOCK_DATA_PSL))
        data->psl = &data->share->psl;
#endif

      Curl_share_unlock(data, FETCH_LOCK_DATA_SHARE);
    }
    /* check for host cache not needed,
     * it will be done by fetch_easy_perform */
  }
  break;

#ifdef USE_HTTP2
  case FETCHOPT_STREAM_DEPENDS:
  case FETCHOPT_STREAM_DEPENDS_E:
  {
    struct Curl_easy *dep = va_arg(param, struct Curl_easy *);
    if (!dep || GOOD_EASY_HANDLE(dep))
      return Curl_data_priority_add_child(dep, data,
                                          option == FETCHOPT_STREAM_DEPENDS_E);
    break;
  }
#endif

  default:
    return FETCHE_UNKNOWN_OPTION;
  }
  return result;
}

static FETCHcode setopt_cptr(struct Curl_easy *data, FETCHoption option,
                             char *ptr)
{
  FETCHcode result = FETCHE_OK;
  switch (option)
  {
  case FETCHOPT_SSL_CIPHER_LIST:
    if (Curl_ssl_supports(data, SSLSUPP_CIPHER_LIST))
      /* set a list of cipher we want to use in the SSL connection */
      return Curl_setstropt(&data->set.str[STRING_SSL_CIPHER_LIST], ptr);
    return FETCHE_NOT_BUILT_IN;
    break;
#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXY_SSL_CIPHER_LIST:
    if (Curl_ssl_supports(data, SSLSUPP_CIPHER_LIST))
    {
      /* set a list of cipher we want to use in the SSL connection for proxy */
      return Curl_setstropt(&data->set.str[STRING_SSL_CIPHER_LIST_PROXY],
                            ptr);
    }
    else
      return FETCHE_NOT_BUILT_IN;
    break;
#endif
  case FETCHOPT_TLS13_CIPHERS:
    if (Curl_ssl_supports(data, SSLSUPP_TLS13_CIPHERSUITES))
    {
      /* set preferred list of TLS 1.3 cipher suites */
      return Curl_setstropt(&data->set.str[STRING_SSL_CIPHER13_LIST], ptr);
    }
    else
      return FETCHE_NOT_BUILT_IN;
    break;
#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXY_TLS13_CIPHERS:
    if (Curl_ssl_supports(data, SSLSUPP_TLS13_CIPHERSUITES))
      /* set preferred list of TLS 1.3 cipher suites for proxy */
      return Curl_setstropt(&data->set.str[STRING_SSL_CIPHER13_LIST_PROXY],
                            ptr);
    else
      return FETCHE_NOT_BUILT_IN;
    break;
#endif
  case FETCHOPT_RANDOM_FILE:
    break;
  case FETCHOPT_EGDSOCKET:
    break;
  case FETCHOPT_REQUEST_TARGET:
    return Curl_setstropt(&data->set.str[STRING_TARGET], ptr);
#ifndef FETCH_DISABLE_NETRC
  case FETCHOPT_NETRC_FILE:
    /*
     * Use this file instead of the $HOME/.netrc file
     */
    return Curl_setstropt(&data->set.str[STRING_NETRC_FILE], ptr);
#endif

#if !defined(FETCH_DISABLE_HTTP) || !defined(FETCH_DISABLE_MQTT)
  case FETCHOPT_COPYPOSTFIELDS:
    /*
     * A string with POST data. Makes fetch HTTP POST. Even if it is NULL.
     * If needed, FETCHOPT_POSTFIELDSIZE must have been set prior to
     *  FETCHOPT_COPYPOSTFIELDS and not altered later.
     */
    if (!ptr || data->set.postfieldsize == -1)
      result = Curl_setstropt(&data->set.str[STRING_COPYPOSTFIELDS], ptr);
    else
    {
      if (data->set.postfieldsize < 0)
        return FETCHE_BAD_FUNCTION_ARGUMENT;
#if SIZEOF_FETCH_OFF_T > SIZEOF_SIZE_T
      /*
       *  Check that requested length does not overflow the size_t type.
       */
      else if (data->set.postfieldsize > SIZE_T_MAX)
        return FETCHE_OUT_OF_MEMORY;
#endif
      else
      {
        /* Allocate even when size == 0. This satisfies the need of possible
           later address compare to detect the COPYPOSTFIELDS mode, and to
           mark that postfields is used rather than read function or form
           data.
        */
        char *p = Curl_memdup0(ptr, (size_t)data->set.postfieldsize);
        if (!p)
          return FETCHE_OUT_OF_MEMORY;
        else
        {
          free(data->set.str[STRING_COPYPOSTFIELDS]);
          data->set.str[STRING_COPYPOSTFIELDS] = p;
        }
      }
    }

    data->set.postfields = data->set.str[STRING_COPYPOSTFIELDS];
    data->set.method = HTTPREQ_POST;
    break;

  case FETCHOPT_POSTFIELDS:
    /*
     * Like above, but use static data instead of copying it.
     */
    data->set.postfields = ptr;
    /* Release old copied data. */
    Curl_safefree(data->set.str[STRING_COPYPOSTFIELDS]);
    data->set.method = HTTPREQ_POST;
    break;
#endif /* ! FETCH_DISABLE_HTTP || ! FETCH_DISABLE_MQTT */

#ifndef FETCH_DISABLE_HTTP
  case FETCHOPT_ACCEPT_ENCODING:
    /*
     * String to use at the value of Accept-Encoding header.
     *
     * If the encoding is set to "" we use an Accept-Encoding header that
     * encompasses all the encodings we support.
     * If the encoding is set to NULL we do not send an Accept-Encoding header
     * and ignore an received Content-Encoding header.
     *
     */
    if (ptr && !*ptr)
    {
      char all[256];
      Curl_all_content_encodings(all, sizeof(all));
      return Curl_setstropt(&data->set.str[STRING_ENCODING], all);
    }
    return Curl_setstropt(&data->set.str[STRING_ENCODING], ptr);

#if !defined(FETCH_DISABLE_AWS)
  case FETCHOPT_AWS_SIGV4:
    /*
     * String that is merged to some authentication
     * parameters are used by the algorithm.
     */
    result = Curl_setstropt(&data->set.str[STRING_AWS_SIGV4], ptr);
    /*
     * Basic been set by default it need to be unset here
     */
    if (data->set.str[STRING_AWS_SIGV4])
      data->set.httpauth = FETCHAUTH_AWS_SIGV4;
    break;
#endif
  case FETCHOPT_REFERER:
    /*
     * String to set in the HTTP Referer: field.
     */
    if (data->state.referer_alloc)
    {
      Curl_safefree(data->state.referer);
      data->state.referer_alloc = FALSE;
    }
    result = Curl_setstropt(&data->set.str[STRING_SET_REFERER], ptr);
    data->state.referer = data->set.str[STRING_SET_REFERER];
    break;

  case FETCHOPT_USERAGENT:
    /*
     * String to use in the HTTP User-Agent field
     */
    return Curl_setstropt(&data->set.str[STRING_USERAGENT], ptr);

#if !defined(FETCH_DISABLE_COOKIES)
  case FETCHOPT_COOKIE:
    /*
     * Cookie string to send to the remote server in the request.
     */
    return Curl_setstropt(&data->set.str[STRING_COOKIE], ptr);

  case FETCHOPT_COOKIEFILE:
    /*
     * Set cookie file to read and parse. Can be used multiple times.
     */
    if (ptr)
    {
      struct fetch_slist *cl;
      /* general protection against mistakes and abuse */
      if (strlen(ptr) > FETCH_MAX_INPUT_LENGTH)
        return FETCHE_BAD_FUNCTION_ARGUMENT;
      /* append the cookie filename to the list of filenames, and deal with
         them later */
      cl = fetch_slist_append(data->state.cookielist, ptr);
      if (!cl)
      {
        fetch_slist_free_all(data->state.cookielist);
        data->state.cookielist = NULL;
        return FETCHE_OUT_OF_MEMORY;
      }
      data->state.cookielist = cl; /* store the list for later use */
    }
    else
    {
      /* clear the list of cookie files */
      fetch_slist_free_all(data->state.cookielist);
      data->state.cookielist = NULL;

      if (!data->share || !data->share->cookies)
      {
        /* throw away all existing cookies if this is not a shared cookie
           container */
        Curl_cookie_clearall(data->cookies);
        Curl_cookie_cleanup(data->cookies);
      }
      /* disable the cookie engine */
      data->cookies = NULL;
    }
    break;

  case FETCHOPT_COOKIEJAR:
    /*
     * Set cookie filename to dump all cookies to when we are done.
     */
    result = Curl_setstropt(&data->set.str[STRING_COOKIEJAR], ptr);
    if (!result)
    {
      /*
       * Activate the cookie parser. This may or may not already
       * have been made.
       */
      struct CookieInfo *newcookies =
          Curl_cookie_init(data, NULL, data->cookies, data->set.cookiesession);
      if (!newcookies)
        result = FETCHE_OUT_OF_MEMORY;
      data->cookies = newcookies;
    }
    break;

  case FETCHOPT_COOKIELIST:
    if (!ptr)
      break;

    if (strcasecompare(ptr, "ALL"))
    {
      /* clear all cookies */
      Curl_share_lock(data, FETCH_LOCK_DATA_COOKIE, FETCH_LOCK_ACCESS_SINGLE);
      Curl_cookie_clearall(data->cookies);
      Curl_share_unlock(data, FETCH_LOCK_DATA_COOKIE);
    }
    else if (strcasecompare(ptr, "SESS"))
    {
      /* clear session cookies */
      Curl_share_lock(data, FETCH_LOCK_DATA_COOKIE, FETCH_LOCK_ACCESS_SINGLE);
      Curl_cookie_clearsess(data->cookies);
      Curl_share_unlock(data, FETCH_LOCK_DATA_COOKIE);
    }
    else if (strcasecompare(ptr, "FLUSH"))
    {
      /* flush cookies to file, takes care of the locking */
      Curl_flush_cookies(data, FALSE);
    }
    else if (strcasecompare(ptr, "RELOAD"))
    {
      /* reload cookies from file */
      Curl_cookie_loadfiles(data);
      break;
    }
    else
    {
      if (!data->cookies)
      {
        /* if cookie engine was not running, activate it */
        data->cookies = Curl_cookie_init(data, NULL, NULL, TRUE);
        if (!data->cookies)
          return FETCHE_OUT_OF_MEMORY;
      }

      /* general protection against mistakes and abuse */
      if (strlen(ptr) > FETCH_MAX_INPUT_LENGTH)
        return FETCHE_BAD_FUNCTION_ARGUMENT;

      Curl_share_lock(data, FETCH_LOCK_DATA_COOKIE, FETCH_LOCK_ACCESS_SINGLE);
      if (checkprefix("Set-Cookie:", ptr))
        /* HTTP Header format line */
        Curl_cookie_add(data, data->cookies, TRUE, FALSE, ptr + 11, NULL,
                        NULL, TRUE);
      else
        /* Netscape format line */
        Curl_cookie_add(data, data->cookies, FALSE, FALSE, ptr, NULL,
                        NULL, TRUE);
      Curl_share_unlock(data, FETCH_LOCK_DATA_COOKIE);
    }
    break;
#endif /* !FETCH_DISABLE_COOKIES */

#endif /* ! FETCH_DISABLE_HTTP */

  case FETCHOPT_CUSTOMREQUEST:
    /*
     * Set a custom string to use as request
     */
    return Curl_setstropt(&data->set.str[STRING_CUSTOMREQUEST], ptr);

    /* we do not set
       data->set.method = HTTPREQ_CUSTOM;
       here, we continue as if we were using the already set type
       and this just changes the actual request keyword */

#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXY:
    /*
     * Set proxy server:port to use as proxy.
     *
     * If the proxy is set to "" (and FETCHOPT_SOCKS_PROXY is set to "" or NULL)
     * we explicitly say that we do not want to use a proxy
     * (even though there might be environment variables saying so).
     *
     * Setting it to NULL, means no proxy but allows the environment variables
     * to decide for us (if FETCHOPT_SOCKS_PROXY setting it to NULL).
     */
    return Curl_setstropt(&data->set.str[STRING_PROXY], ptr);
    break;

  case FETCHOPT_PRE_PROXY:
    /*
     * Set proxy server:port to use as SOCKS proxy.
     *
     * If the proxy is set to "" or NULL we explicitly say that we do not want
     * to use the socks proxy.
     */
    return Curl_setstropt(&data->set.str[STRING_PRE_PROXY], ptr);
#endif /* FETCH_DISABLE_PROXY */

#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_SOCKS5_GSSAPI_SERVICE:
  case FETCHOPT_PROXY_SERVICE_NAME:
    /*
     * Set proxy authentication service name for Kerberos 5 and SPNEGO
     */
    return Curl_setstropt(&data->set.str[STRING_PROXY_SERVICE_NAME], ptr);
#endif
  case FETCHOPT_SERVICE_NAME:
    /*
     * Set authentication service name for DIGEST-MD5, Kerberos 5 and SPNEGO
     */
    return Curl_setstropt(&data->set.str[STRING_SERVICE_NAME], ptr);
    break;

  case FETCHOPT_HEADERDATA:
    /*
     * Custom pointer to pass the header write callback function
     */
    data->set.writeheader = (void *)ptr;
    break;
  case FETCHOPT_READDATA:
    /*
     * FILE pointer to read the file to be uploaded from. Or possibly used as
     * argument to the read callback.
     */
    data->set.in_set = (void *)ptr;
    break;
  case FETCHOPT_WRITEDATA:
    /*
     * FILE pointer to write to. Or possibly used as argument to the write
     * callback.
     */
    data->set.out = (void *)ptr;
    break;
  case FETCHOPT_DEBUGDATA:
    /*
     * Set to a void * that should receive all error writes. This
     * defaults to FETCHOPT_STDERR for normal operations.
     */
    data->set.debugdata = (void *)ptr;
    break;
  case FETCHOPT_PROGRESSDATA:
    /*
     * Custom client data to pass to the progress callback
     */
    data->set.progress_client = (void *)ptr;
    break;
  case FETCHOPT_SEEKDATA:
    /*
     * Seek control callback. Might be NULL.
     */
    data->set.seek_client = (void *)ptr;
    break;
  case FETCHOPT_IOCTLDATA:
    /*
     * I/O control data pointer. Might be NULL.
     */
    data->set.ioctl_client = (void *)ptr;
    break;
  case FETCHOPT_SSL_CTX_DATA:
    /*
     * Set a SSL_CTX callback parameter pointer
     */
#ifdef USE_SSL
    if (Curl_ssl_supports(data, SSLSUPP_SSL_CTX))
      data->set.ssl.fsslctxp = (void *)ptr;
    else
#endif
      return FETCHE_NOT_BUILT_IN;
    break;
  case FETCHOPT_SOCKOPTDATA:
    /*
     * socket callback data pointer. Might be NULL.
     */
    data->set.sockopt_client = (void *)ptr;
    break;
  case FETCHOPT_OPENSOCKETDATA:
    /*
     * socket callback data pointer. Might be NULL.
     */
    data->set.opensocket_client = (void *)ptr;
    break;
  case FETCHOPT_RESOLVER_START_DATA:
    /*
     * resolver start callback data pointer. Might be NULL.
     */
    data->set.resolver_start_client = (void *)ptr;
    break;
  case FETCHOPT_CLOSESOCKETDATA:
    /*
     * socket callback data pointer. Might be NULL.
     */
    data->set.closesocket_client = (void *)ptr;
    break;
  case FETCHOPT_TRAILERDATA:
#ifndef FETCH_DISABLE_HTTP
    data->set.trailer_data = (void *)ptr;
#endif
    break;
  case FETCHOPT_PREREQDATA:
    data->set.prereq_userp = (void *)ptr;
    break;

  case FETCHOPT_ERRORBUFFER:
    /*
     * Error buffer provided by the caller to get the human readable error
     * string in.
     */
    data->set.errorbuffer = ptr;
    break;

#ifndef FETCH_DISABLE_FTP
  case FETCHOPT_FTPPORT:
    /*
     * Use FTP PORT, this also specifies which IP address to use
     */
    result = Curl_setstropt(&data->set.str[STRING_FTPPORT], ptr);
    data->set.ftp_use_port = !!(data->set.str[STRING_FTPPORT]);
    break;

  case FETCHOPT_FTP_ACCOUNT:
    return Curl_setstropt(&data->set.str[STRING_FTP_ACCOUNT], ptr);

  case FETCHOPT_FTP_ALTERNATIVE_TO_USER:
    return Curl_setstropt(&data->set.str[STRING_FTP_ALTERNATIVE_TO_USER], ptr);

#ifdef HAVE_GSSAPI
  case FETCHOPT_KRBLEVEL:
    /*
     * A string that defines the kerberos security level.
     */
    result = Curl_setstropt(&data->set.str[STRING_KRB_LEVEL], ptr);
    data->set.krb = !!(data->set.str[STRING_KRB_LEVEL]);
    break;
#endif
#endif
  case FETCHOPT_URL:
    /*
     * The URL to fetch.
     */
    if (data->state.url_alloc)
    {
      Curl_safefree(data->state.url);
      data->state.url_alloc = FALSE;
    }
    result = Curl_setstropt(&data->set.str[STRING_SET_URL], ptr);
    data->state.url = data->set.str[STRING_SET_URL];
    break;

  case FETCHOPT_USERPWD:
    /*
     * user:password to use in the operation
     */
    return setstropt_userpwd(ptr, &data->set.str[STRING_USERNAME],
                             &data->set.str[STRING_PASSWORD]);

  case FETCHOPT_USERNAME:
    /*
     * authentication username to use in the operation
     */
    return Curl_setstropt(&data->set.str[STRING_USERNAME], ptr);

  case FETCHOPT_PASSWORD:
    /*
     * authentication password to use in the operation
     */
    return Curl_setstropt(&data->set.str[STRING_PASSWORD], ptr);

  case FETCHOPT_LOGIN_OPTIONS:
    /*
     * authentication options to use in the operation
     */
    return Curl_setstropt(&data->set.str[STRING_OPTIONS], ptr);

  case FETCHOPT_XOAUTH2_BEARER:
    /*
     * OAuth 2.0 bearer token to use in the operation
     */
    return Curl_setstropt(&data->set.str[STRING_BEARER], ptr);

#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXYUSERPWD:
  {
    /*
     * user:password needed to use the proxy
     */
    char *u = NULL;
    char *p = NULL;
    result = setstropt_userpwd(ptr, &u, &p);

    /* URL decode the components */
    if (!result && u)
      result = Curl_urldecode(u, 0, &data->set.str[STRING_PROXYUSERNAME], NULL,
                              REJECT_ZERO);
    if (!result && p)
      result = Curl_urldecode(p, 0, &data->set.str[STRING_PROXYPASSWORD], NULL,
                              REJECT_ZERO);
    free(u);
    free(p);
  }
  break;
  case FETCHOPT_PROXYUSERNAME:
    /*
     * authentication username to use in the operation
     */
    return Curl_setstropt(&data->set.str[STRING_PROXYUSERNAME], ptr);

  case FETCHOPT_PROXYPASSWORD:
    /*
     * authentication password to use in the operation
     */
    return Curl_setstropt(&data->set.str[STRING_PROXYPASSWORD], ptr);

  case FETCHOPT_NOPROXY:
    /*
     * proxy exception list
     */
    return Curl_setstropt(&data->set.str[STRING_NOPROXY], ptr);
#endif /* ! FETCH_DISABLE_PROXY */

  case FETCHOPT_RANGE:
    /*
     * What range of the file you want to transfer
     */
    return Curl_setstropt(&data->set.str[STRING_SET_RANGE], ptr);

  case FETCHOPT_FETCHU:
    /*
     * pass FETCHU to set URL
     */
    if (data->state.url_alloc)
    {
      Curl_safefree(data->state.url);
      data->state.url_alloc = FALSE;
    }
    else
      data->state.url = NULL;
    Curl_safefree(data->set.str[STRING_SET_URL]);
    data->set.uh = (FETCHU *)ptr;
    break;
  case FETCHOPT_SSLCERT:
    /*
     * String that holds filename of the SSL certificate to use
     */
    return Curl_setstropt(&data->set.str[STRING_CERT], ptr);

#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXY_SSLCERT:
    /*
     * String that holds filename of the SSL certificate to use for proxy
     */
    return Curl_setstropt(&data->set.str[STRING_CERT_PROXY], ptr);

#endif
  case FETCHOPT_SSLCERTTYPE:
    /*
     * String that holds file type of the SSL certificate to use
     */
    return Curl_setstropt(&data->set.str[STRING_CERT_TYPE], ptr);

#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXY_SSLCERTTYPE:
    /*
     * String that holds file type of the SSL certificate to use for proxy
     */
    return Curl_setstropt(&data->set.str[STRING_CERT_TYPE_PROXY], ptr);
#endif
  case FETCHOPT_SSLKEY:
    /*
     * String that holds filename of the SSL key to use
     */
    return Curl_setstropt(&data->set.str[STRING_KEY], ptr);

#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXY_SSLKEY:
    /*
     * String that holds filename of the SSL key to use for proxy
     */
    return Curl_setstropt(&data->set.str[STRING_KEY_PROXY], ptr);

#endif
  case FETCHOPT_SSLKEYTYPE:
    /*
     * String that holds file type of the SSL key to use
     */
    return Curl_setstropt(&data->set.str[STRING_KEY_TYPE], ptr);
    break;
#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXY_SSLKEYTYPE:
    /*
     * String that holds file type of the SSL key to use for proxy
     */
    return Curl_setstropt(&data->set.str[STRING_KEY_TYPE_PROXY], ptr);

#endif
  case FETCHOPT_KEYPASSWD:
    /*
     * String that holds the SSL or SSH private key password.
     */
    return Curl_setstropt(&data->set.str[STRING_KEY_PASSWD], ptr);

#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXY_KEYPASSWD:
    /*
     * String that holds the SSL private key password for proxy.
     */
    return Curl_setstropt(&data->set.str[STRING_KEY_PASSWD_PROXY], ptr);
#endif
  case FETCHOPT_SSLENGINE:
    /*
     * String that holds the SSL crypto engine.
     */
    if (ptr && ptr[0])
    {
      result = Curl_setstropt(&data->set.str[STRING_SSL_ENGINE], ptr);
      if (!result)
      {
        result = Curl_ssl_set_engine(data, ptr);
      }
    }
    break;

#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_HAPROXY_CLIENT_IP:
    /*
     * Set the client IP to send through HAProxy PROXY protocol
     */
    result = Curl_setstropt(&data->set.str[STRING_HAPROXY_CLIENT_IP], ptr);
    /* enable the HAProxy protocol */
    data->set.haproxyprotocol = TRUE;
    break;
#endif
  case FETCHOPT_INTERFACE:
    /*
     * Set what interface or address/hostname to bind the socket to when
     * performing an operation and thus what from-IP your connection will use.
     */
    return setstropt_interface(ptr,
                               &data->set.str[STRING_DEVICE],
                               &data->set.str[STRING_INTERFACE],
                               &data->set.str[STRING_BINDHOST]);

  case FETCHOPT_PINNEDPUBLICKEY:
    /*
     * Set pinned public key for SSL connection.
     * Specify filename of the public key in DER format.
     */
#ifdef USE_SSL
    if (Curl_ssl_supports(data, SSLSUPP_PINNEDPUBKEY))
      return Curl_setstropt(&data->set.str[STRING_SSL_PINNEDPUBLICKEY], ptr);
#endif
    return FETCHE_NOT_BUILT_IN;

#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXY_PINNEDPUBLICKEY:
    /*
     * Set pinned public key for SSL connection.
     * Specify filename of the public key in DER format.
     */
#ifdef USE_SSL
    if (Curl_ssl_supports(data, SSLSUPP_PINNEDPUBKEY))
      return Curl_setstropt(&data->set.str[STRING_SSL_PINNEDPUBLICKEY_PROXY],
                            ptr);
#endif
    return FETCHE_NOT_BUILT_IN;
#endif
  case FETCHOPT_CAINFO:
    /*
     * Set CA info for SSL connection. Specify filename of the CA certificate
     */
    return Curl_setstropt(&data->set.str[STRING_SSL_CAFILE], ptr);

#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXY_CAINFO:
    /*
     * Set CA info SSL connection for proxy. Specify filename of the
     * CA certificate
     */
    return Curl_setstropt(&data->set.str[STRING_SSL_CAFILE_PROXY], ptr);
#endif

  case FETCHOPT_CAPATH:
    /*
     * Set CA path info for SSL connection. Specify directory name of the CA
     * certificates which have been prepared using openssl c_rehash utility.
     */
#ifdef USE_SSL
    if (Curl_ssl_supports(data, SSLSUPP_CA_PATH))
      /* This does not work on Windows. */
      return Curl_setstropt(&data->set.str[STRING_SSL_CAPATH], ptr);
#endif
    return FETCHE_NOT_BUILT_IN;
#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXY_CAPATH:
    /*
     * Set CA path info for SSL connection proxy. Specify directory name of the
     * CA certificates which have been prepared using openssl c_rehash utility.
     */
#ifdef USE_SSL
    if (Curl_ssl_supports(data, SSLSUPP_CA_PATH))
      /* This does not work on Windows. */
      return Curl_setstropt(&data->set.str[STRING_SSL_CAPATH_PROXY], ptr);
#endif
    return FETCHE_NOT_BUILT_IN;
#endif
  case FETCHOPT_CRLFILE:
    /*
     * Set CRL file info for SSL connection. Specify filename of the CRL
     * to check certificates revocation
     */
    return Curl_setstropt(&data->set.str[STRING_SSL_CRLFILE], ptr);

#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXY_CRLFILE:
    /*
     * Set CRL file info for SSL connection for proxy. Specify filename of the
     * CRL to check certificates revocation
     */
    return Curl_setstropt(&data->set.str[STRING_SSL_CRLFILE_PROXY], ptr);
#endif
  case FETCHOPT_ISSUERCERT:
    /*
     * Set Issuer certificate file
     * to check certificates issuer
     */
    return Curl_setstropt(&data->set.str[STRING_SSL_ISSUERCERT], ptr);

#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXY_ISSUERCERT:
    /*
     * Set Issuer certificate file
     * to check certificates issuer
     */
    return Curl_setstropt(&data->set.str[STRING_SSL_ISSUERCERT_PROXY], ptr);

#endif

  case FETCHOPT_PRIVATE:
    /*
     * Set private data pointer.
     */
    data->set.private_data = (void *)ptr;
    break;

#ifdef USE_SSL
  case FETCHOPT_SSL_EC_CURVES:
    /*
     * Set accepted curves in SSL connection setup.
     * Specify colon-delimited list of curve algorithm names.
     */
    return Curl_setstropt(&data->set.str[STRING_SSL_EC_CURVES], ptr);
#endif
#ifdef USE_SSH
  case FETCHOPT_SSH_PUBLIC_KEYFILE:
    /*
     * Use this file instead of the $HOME/.ssh/id_dsa.pub file
     */
    return Curl_setstropt(&data->set.str[STRING_SSH_PUBLIC_KEY], ptr);

  case FETCHOPT_SSH_PRIVATE_KEYFILE:
    /*
     * Use this file instead of the $HOME/.ssh/id_dsa file
     */
    return Curl_setstropt(&data->set.str[STRING_SSH_PRIVATE_KEY], ptr);

  case FETCHOPT_SSH_HOST_PUBLIC_KEY_MD5:
    /*
     * Option to allow for the MD5 of the host public key to be checked
     * for validation purposes.
     */
    return Curl_setstropt(&data->set.str[STRING_SSH_HOST_PUBLIC_KEY_MD5], ptr);

  case FETCHOPT_SSH_KNOWNHOSTS:
    /*
     * Store the filename to read known hosts from.
     */
    return Curl_setstropt(&data->set.str[STRING_SSH_KNOWNHOSTS], ptr);

  case FETCHOPT_SSH_KEYDATA:
    /*
     * Custom client data to pass to the SSH keyfunc callback
     */
    data->set.ssh_keyfunc_userp = (void *)ptr;
    break;
#ifdef USE_LIBSSH2
  case FETCHOPT_SSH_HOST_PUBLIC_KEY_SHA256:
    /*
     * Option to allow for the SHA256 of the host public key to be checked
     * for validation purposes.
     */
    return Curl_setstropt(&data->set.str[STRING_SSH_HOST_PUBLIC_KEY_SHA256],
                          ptr);

  case FETCHOPT_SSH_HOSTKEYDATA:
    /*
     * Custom client data to pass to the SSH keyfunc callback
     */
    data->set.ssh_hostkeyfunc_userp = (void *)ptr;
    break;
#endif /* USE_LIBSSH2 */
#endif /* USE_SSH */
  case FETCHOPT_PROTOCOLS_STR:
    if (ptr)
      return protocol2num(ptr, &data->set.allowed_protocols);
    /* make a NULL argument reset to default */
    data->set.allowed_protocols = (fetch_prot_t)FETCHPROTO_ALL;
    break;

  case FETCHOPT_REDIR_PROTOCOLS_STR:
    if (ptr)
      return protocol2num(ptr, &data->set.redir_protocols);
    /* make a NULL argument reset to default */
    data->set.redir_protocols = (fetch_prot_t)FETCHPROTO_REDIR;
    break;

  case FETCHOPT_DEFAULT_PROTOCOL:
    /* Set the protocol to use when the URL does not include any protocol */
    return Curl_setstropt(&data->set.str[STRING_DEFAULT_PROTOCOL], ptr);

#ifndef FETCH_DISABLE_SMTP
  case FETCHOPT_MAIL_FROM:
    /* Set the SMTP mail originator */
    return Curl_setstropt(&data->set.str[STRING_MAIL_FROM], ptr);

  case FETCHOPT_MAIL_AUTH:
    /* Set the SMTP auth originator */
    return Curl_setstropt(&data->set.str[STRING_MAIL_AUTH], ptr);
#endif

  case FETCHOPT_SASL_AUTHZID:
    /* Authorization identity (identity to act as) */
    return Curl_setstropt(&data->set.str[STRING_SASL_AUTHZID], ptr);

#ifndef FETCH_DISABLE_RTSP
  case FETCHOPT_RTSP_SESSION_ID:
    /*
     * Set the RTSP Session ID manually. Useful if the application is
     * resuming a previously established RTSP session
     */
    return Curl_setstropt(&data->set.str[STRING_RTSP_SESSION_ID], ptr);

  case FETCHOPT_RTSP_STREAM_URI:
    /*
     * Set the Stream URI for the RTSP request. Unless the request is
     * for generic server options, the application will need to set this.
     */
    return Curl_setstropt(&data->set.str[STRING_RTSP_STREAM_URI], ptr);
    break;

  case FETCHOPT_RTSP_TRANSPORT:
    /*
     * The content of the Transport: header for the RTSP request
     */
    return Curl_setstropt(&data->set.str[STRING_RTSP_TRANSPORT], ptr);

  case FETCHOPT_INTERLEAVEDATA:
    data->set.rtp_out = (void *)ptr;
    break;
#endif /* ! FETCH_DISABLE_RTSP */
#ifndef FETCH_DISABLE_FTP
  case FETCHOPT_CHUNK_DATA:
    data->set.wildcardptr = (void *)ptr;
    break;
  case FETCHOPT_FNMATCH_DATA:
    data->set.fnmatch_data = (void *)ptr;
    break;
#endif
#ifdef USE_TLS_SRP
  case FETCHOPT_TLSAUTH_USERNAME:
    return Curl_setstropt(&data->set.str[STRING_TLSAUTH_USERNAME], ptr);

#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXY_TLSAUTH_USERNAME:
    return Curl_setstropt(&data->set.str[STRING_TLSAUTH_USERNAME_PROXY], ptr);

#endif
  case FETCHOPT_TLSAUTH_PASSWORD:
    return Curl_setstropt(&data->set.str[STRING_TLSAUTH_PASSWORD], ptr);

#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXY_TLSAUTH_PASSWORD:
    return Curl_setstropt(&data->set.str[STRING_TLSAUTH_PASSWORD_PROXY], ptr);
#endif
  case FETCHOPT_TLSAUTH_TYPE:
    if (ptr && !strcasecompare(ptr, "SRP"))
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    break;
#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXY_TLSAUTH_TYPE:
    if (ptr && !strcasecompare(ptr, "SRP"))
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    break;
#endif
#endif
#ifdef USE_ARES
  case FETCHOPT_DNS_SERVERS:
    result = Curl_setstropt(&data->set.str[STRING_DNS_SERVERS], ptr);
    if (result)
      return result;
    return Curl_set_dns_servers(data, data->set.str[STRING_DNS_SERVERS]);

  case FETCHOPT_DNS_INTERFACE:
    result = Curl_setstropt(&data->set.str[STRING_DNS_INTERFACE], ptr);
    if (result)
      return result;
    return Curl_set_dns_interface(data, data->set.str[STRING_DNS_INTERFACE]);

  case FETCHOPT_DNS_LOCAL_IP4:
    result = Curl_setstropt(&data->set.str[STRING_DNS_LOCAL_IP4], ptr);
    if (result)
      return result;
    return Curl_set_dns_local_ip4(data, data->set.str[STRING_DNS_LOCAL_IP4]);

  case FETCHOPT_DNS_LOCAL_IP6:
    result = Curl_setstropt(&data->set.str[STRING_DNS_LOCAL_IP6], ptr);
    if (result)
      return result;
    return Curl_set_dns_local_ip6(data, data->set.str[STRING_DNS_LOCAL_IP6]);

#endif
#ifdef USE_UNIX_SOCKETS
  case FETCHOPT_UNIX_SOCKET_PATH:
    data->set.abstract_unix_socket = FALSE;
    return Curl_setstropt(&data->set.str[STRING_UNIX_SOCKET_PATH], ptr);

  case FETCHOPT_ABSTRACT_UNIX_SOCKET:
    data->set.abstract_unix_socket = TRUE;
    return Curl_setstropt(&data->set.str[STRING_UNIX_SOCKET_PATH], ptr);

#endif

#ifndef FETCH_DISABLE_DOH
  case FETCHOPT_DOH_URL:
    result = Curl_setstropt(&data->set.str[STRING_DOH], ptr);
    data->set.doh = !!(data->set.str[STRING_DOH]);
    break;
#endif
#ifndef FETCH_DISABLE_HSTS
  case FETCHOPT_HSTSREADDATA:
    data->set.hsts_read_userp = (void *)ptr;
    break;
  case FETCHOPT_HSTSWRITEDATA:
    data->set.hsts_write_userp = (void *)ptr;
    break;
  case FETCHOPT_HSTS:
  {
    struct fetch_slist *h;
    if (!data->hsts)
    {
      data->hsts = Curl_hsts_init();
      if (!data->hsts)
        return FETCHE_OUT_OF_MEMORY;
    }
    if (ptr)
    {
      result = Curl_setstropt(&data->set.str[STRING_HSTS], ptr);
      if (result)
        return result;
      /* this needs to build a list of filenames to read from, so that it can
         read them later, as we might get a shared HSTS handle to load them
         into */
      h = fetch_slist_append(data->state.hstslist, ptr);
      if (!h)
      {
        fetch_slist_free_all(data->state.hstslist);
        data->state.hstslist = NULL;
        return FETCHE_OUT_OF_MEMORY;
      }
      data->state.hstslist = h; /* store the list for later use */
    }
    else
    {
      /* clear the list of HSTS files */
      fetch_slist_free_all(data->state.hstslist);
      data->state.hstslist = NULL;
      if (!data->share || !data->share->hsts)
        /* throw away the HSTS cache unless shared */
        Curl_hsts_cleanup(&data->hsts);
    }
    break;
  }
#endif /* ! FETCH_DISABLE_HSTS */
#ifndef FETCH_DISABLE_ALTSVC
  case FETCHOPT_ALTSVC:
    if (!data->asi)
    {
      data->asi = Curl_altsvc_init();
      if (!data->asi)
        return FETCHE_OUT_OF_MEMORY;
    }
    result = Curl_setstropt(&data->set.str[STRING_ALTSVC], ptr);
    if (result)
      return result;
    if (ptr)
      (void)Curl_altsvc_load(data->asi, ptr);
    break;
#endif /* ! FETCH_DISABLE_ALTSVC */
#ifdef USE_ECH
  case FETCHOPT_ECH:
  {
    size_t plen = 0;

    if (!ptr)
    {
      data->set.tls_ech = FETCHECH_DISABLE;
      return FETCHE_OK;
    }
    plen = strlen(ptr);
    if (plen > FETCH_MAX_INPUT_LENGTH)
    {
      data->set.tls_ech = FETCHECH_DISABLE;
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    }
    /* set tls_ech flag value, preserving CLA_CFG bit */
    if (!strcmp(ptr, "false"))
      data->set.tls_ech = FETCHECH_DISABLE |
                          (data->set.tls_ech & FETCHECH_CLA_CFG);
    else if (!strcmp(ptr, "grease"))
      data->set.tls_ech = FETCHECH_GREASE |
                          (data->set.tls_ech & FETCHECH_CLA_CFG);
    else if (!strcmp(ptr, "true"))
      data->set.tls_ech = FETCHECH_ENABLE |
                          (data->set.tls_ech & FETCHECH_CLA_CFG);
    else if (!strcmp(ptr, "hard"))
      data->set.tls_ech = FETCHECH_HARD |
                          (data->set.tls_ech & FETCHECH_CLA_CFG);
    else if (plen > 5 && !strncmp(ptr, "ecl:", 4))
    {
      result = Curl_setstropt(&data->set.str[STRING_ECH_CONFIG], ptr + 4);
      if (result)
        return result;
      data->set.tls_ech |= FETCHECH_CLA_CFG;
    }
    else if (plen > 4 && !strncmp(ptr, "pn:", 3))
    {
      result = Curl_setstropt(&data->set.str[STRING_ECH_PUBLIC], ptr + 3);
      if (result)
        return result;
    }
    break;
  }
#endif
  default:
    return FETCHE_UNKNOWN_OPTION;
  }
  return result;
}

static FETCHcode setopt_func(struct Curl_easy *data, FETCHoption option,
                             va_list param)
{
  switch (option)
  {
  case FETCHOPT_PROGRESSFUNCTION:
    /*
     * Progress callback function
     */
    data->set.fprogress = va_arg(param, fetch_progress_callback);
    if (data->set.fprogress)
      data->progress.callback = TRUE; /* no longer internal */
    else
      data->progress.callback = FALSE; /* NULL enforces internal */
    break;

  case FETCHOPT_XFERINFOFUNCTION:
    /*
     * Transfer info callback function
     */
    data->set.fxferinfo = va_arg(param, fetch_xferinfo_callback);
    if (data->set.fxferinfo)
      data->progress.callback = TRUE; /* no longer internal */
    else
      data->progress.callback = FALSE; /* NULL enforces internal */

    break;
  case FETCHOPT_DEBUGFUNCTION:
    /*
     * stderr write callback.
     */
    data->set.fdebug = va_arg(param, fetch_debug_callback);
    /*
     * if the callback provided is NULL, it will use the default callback
     */
    break;
  case FETCHOPT_HEADERFUNCTION:
    /*
     * Set header write callback
     */
    data->set.fwrite_header = va_arg(param, fetch_write_callback);
    break;
  case FETCHOPT_WRITEFUNCTION:
    /*
     * Set data write callback
     */
    data->set.fwrite_func = va_arg(param, fetch_write_callback);
    if (!data->set.fwrite_func)
      /* When set to NULL, reset to our internal default function */
      data->set.fwrite_func = (fetch_write_callback)fwrite;
    break;
  case FETCHOPT_READFUNCTION:
    /*
     * Read data callback
     */
    data->set.fread_func_set = va_arg(param, fetch_read_callback);
    if (!data->set.fread_func_set)
    {
      data->set.is_fread_set = 0;
      /* When set to NULL, reset to our internal default function */
      data->set.fread_func_set = (fetch_read_callback)fread;
    }
    else
      data->set.is_fread_set = 1;
    break;
  case FETCHOPT_SEEKFUNCTION:
    /*
     * Seek callback. Might be NULL.
     */
    data->set.seek_func = va_arg(param, fetch_seek_callback);
    break;
  case FETCHOPT_IOCTLFUNCTION:
    /*
     * I/O control callback. Might be NULL.
     */
    data->set.ioctl_func = va_arg(param, fetch_ioctl_callback);
    break;
  case FETCHOPT_SSL_CTX_FUNCTION:
    /*
     * Set a SSL_CTX callback
     */
#ifdef USE_SSL
    if (Curl_ssl_supports(data, SSLSUPP_SSL_CTX))
      data->set.ssl.fsslctx = va_arg(param, fetch_ssl_ctx_callback);
    else
#endif
      return FETCHE_NOT_BUILT_IN;
    break;

  case FETCHOPT_SOCKOPTFUNCTION:
    /*
     * socket callback function: called after socket() but before connect()
     */
    data->set.fsockopt = va_arg(param, fetch_sockopt_callback);
    break;

  case FETCHOPT_OPENSOCKETFUNCTION:
    /*
     * open/create socket callback function: called instead of socket(),
     * before connect()
     */
    data->set.fopensocket = va_arg(param, fetch_opensocket_callback);
    break;

  case FETCHOPT_CLOSESOCKETFUNCTION:
    /*
     * close socket callback function: called instead of close()
     * when shutting down a connection
     */
    data->set.fclosesocket = va_arg(param, fetch_closesocket_callback);
    break;

  case FETCHOPT_RESOLVER_START_FUNCTION:
    /*
     * resolver start callback function: called before a new resolver request
     * is started
     */
    data->set.resolver_start = va_arg(param, fetch_resolver_start_callback);
    break;

#ifdef USE_SSH
#ifdef USE_LIBSSH2
  case FETCHOPT_SSH_HOSTKEYFUNCTION:
    /* the callback to check the hostkey without the knownhost file */
    data->set.ssh_hostkeyfunc = va_arg(param, fetch_sshhostkeycallback);
    break;
#endif

  case FETCHOPT_SSH_KEYFUNCTION:
    /* setting to NULL is fine since the ssh.c functions themselves will
       then revert to use the internal default */
    data->set.ssh_keyfunc = va_arg(param, fetch_sshkeycallback);
    break;

#endif /* USE_SSH */

#ifndef FETCH_DISABLE_RTSP
  case FETCHOPT_INTERLEAVEFUNCTION:
    /* Set the user defined RTP write function */
    data->set.fwrite_rtp = va_arg(param, fetch_write_callback);
    break;
#endif
#ifndef FETCH_DISABLE_FTP
  case FETCHOPT_CHUNK_BGN_FUNCTION:
    data->set.chunk_bgn = va_arg(param, fetch_chunk_bgn_callback);
    break;
  case FETCHOPT_CHUNK_END_FUNCTION:
    data->set.chunk_end = va_arg(param, fetch_chunk_end_callback);
    break;
  case FETCHOPT_FNMATCH_FUNCTION:
    data->set.fnmatch = va_arg(param, fetch_fnmatch_callback);
    break;
#endif
#ifndef FETCH_DISABLE_HTTP
  case FETCHOPT_TRAILERFUNCTION:
    data->set.trailer_callback = va_arg(param, fetch_trailer_callback);
    break;
#endif
#ifndef FETCH_DISABLE_HSTS
  case FETCHOPT_HSTSREADFUNCTION:
    data->set.hsts_read = va_arg(param, fetch_hstsread_callback);
    break;
  case FETCHOPT_HSTSWRITEFUNCTION:
    data->set.hsts_write = va_arg(param, fetch_hstswrite_callback);
    break;
#endif
  case FETCHOPT_PREREQFUNCTION:
    data->set.fprereq = va_arg(param, fetch_prereq_callback);
    break;
  default:
    return FETCHE_UNKNOWN_OPTION;
  }
  return FETCHE_OK;
}

static FETCHcode setopt_offt(struct Curl_easy *data, FETCHoption option,
                             fetch_off_t offt)
{
  switch (option)
  {
  case FETCHOPT_TIMEVALUE_LARGE:
    /*
     * This is the value to compare with the remote document with the
     * method set with FETCHOPT_TIMECONDITION
     */
    data->set.timevalue = (time_t)offt;
    break;

    /* MQTT "borrows" some of the HTTP options */
  case FETCHOPT_POSTFIELDSIZE_LARGE:
    /*
     * The size of the POSTFIELD data to prevent libfetch to do strlen() to
     * figure it out. Enables binary posts.
     */
    if (offt < -1)
      return FETCHE_BAD_FUNCTION_ARGUMENT;

    if (data->set.postfieldsize < offt &&
        data->set.postfields == data->set.str[STRING_COPYPOSTFIELDS])
    {
      /* Previous FETCHOPT_COPYPOSTFIELDS is no longer valid. */
      Curl_safefree(data->set.str[STRING_COPYPOSTFIELDS]);
      data->set.postfields = NULL;
    }
    data->set.postfieldsize = offt;
    break;
  case FETCHOPT_INFILESIZE_LARGE:
    /*
     * If known, this should inform fetch about the file size of the
     * to-be-uploaded file.
     */
    if (offt < -1)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.filesize = offt;
    break;
  case FETCHOPT_MAX_SEND_SPEED_LARGE:
    /*
     * When transfer uploads are faster then FETCHOPT_MAX_SEND_SPEED_LARGE
     * bytes per second the transfer is throttled..
     */
    if (offt < 0)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.max_send_speed = offt;
    break;
  case FETCHOPT_MAX_RECV_SPEED_LARGE:
    /*
     * When receiving data faster than FETCHOPT_MAX_RECV_SPEED_LARGE bytes per
     * second the transfer is throttled..
     */
    if (offt < 0)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.max_recv_speed = offt;
    break;
  case FETCHOPT_RESUME_FROM_LARGE:
    /*
     * Resume transfer at the given file position
     */
    if (offt < -1)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.set_resume_from = offt;
    break;
  case FETCHOPT_MAXFILESIZE_LARGE:
    /*
     * Set the maximum size of a file to download.
     */
    if (offt < 0)
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    data->set.max_filesize = offt;
    break;

  default:
    return FETCHE_UNKNOWN_OPTION;
  }
  return FETCHE_OK;
}

static FETCHcode setopt_blob(struct Curl_easy *data, FETCHoption option,
                             struct fetch_blob *blob)
{
  switch (option)
  {
  case FETCHOPT_SSLCERT_BLOB:
    /*
     * Blob that holds file content of the SSL certificate to use
     */
    return Curl_setblobopt(&data->set.blobs[BLOB_CERT], blob);
#ifndef FETCH_DISABLE_PROXY
  case FETCHOPT_PROXY_SSLCERT_BLOB:
    /*
     * Blob that holds file content of the SSL certificate to use for proxy
     */
    return Curl_setblobopt(&data->set.blobs[BLOB_CERT_PROXY], blob);
  case FETCHOPT_PROXY_SSLKEY_BLOB:
    /*
     * Blob that holds file content of the SSL key to use for proxy
     */
    return Curl_setblobopt(&data->set.blobs[BLOB_KEY_PROXY], blob);
  case FETCHOPT_PROXY_CAINFO_BLOB:
    /*
     * Blob that holds CA info for SSL connection proxy.
     * Specify entire PEM of the CA certificate
     */
#ifdef USE_SSL
    if (Curl_ssl_supports(data, SSLSUPP_CAINFO_BLOB))
      return Curl_setblobopt(&data->set.blobs[BLOB_CAINFO_PROXY], blob);
#endif
    return FETCHE_NOT_BUILT_IN;
  case FETCHOPT_PROXY_ISSUERCERT_BLOB:
    /*
     * Blob that holds Issuer certificate to check certificates issuer
     */
    return Curl_setblobopt(&data->set.blobs[BLOB_SSL_ISSUERCERT_PROXY],
                           blob);
#endif
  case FETCHOPT_SSLKEY_BLOB:
    /*
     * Blob that holds file content of the SSL key to use
     */
    return Curl_setblobopt(&data->set.blobs[BLOB_KEY], blob);
  case FETCHOPT_CAINFO_BLOB:
    /*
     * Blob that holds CA info for SSL connection.
     * Specify entire PEM of the CA certificate
     */
#ifdef USE_SSL
    if (Curl_ssl_supports(data, SSLSUPP_CAINFO_BLOB))
      return Curl_setblobopt(&data->set.blobs[BLOB_CAINFO], blob);
#endif
    return FETCHE_NOT_BUILT_IN;
  case FETCHOPT_ISSUERCERT_BLOB:
    /*
     * Blob that holds Issuer certificate to check certificates issuer
     */
    return Curl_setblobopt(&data->set.blobs[BLOB_SSL_ISSUERCERT], blob);

  default:
    return FETCHE_UNKNOWN_OPTION;
  }
  /* unreachable */
}

/*
 * Do not make Curl_vsetopt() static: it is called from
 * packages/OS400/ccsidfetch.c.
 */
FETCHcode Curl_vsetopt(struct Curl_easy *data, FETCHoption option, va_list param)
{
  if (option < FETCHOPTTYPE_OBJECTPOINT)
    return setopt_long(data, option, va_arg(param, long));
  else if (option < FETCHOPTTYPE_FUNCTIONPOINT)
  {
    /* unfortunately, different pointer types cannot be identified any other
       way than being listed explicitly */
    switch (option)
    {
    case FETCHOPT_HTTPHEADER:
    case FETCHOPT_QUOTE:
    case FETCHOPT_POSTQUOTE:
    case FETCHOPT_TELNETOPTIONS:
    case FETCHOPT_PREQUOTE:
    case FETCHOPT_HTTP200ALIASES:
    case FETCHOPT_MAIL_RCPT:
    case FETCHOPT_RESOLVE:
    case FETCHOPT_PROXYHEADER:
    case FETCHOPT_CONNECT_TO:
      return setopt_slist(data, option, va_arg(param, struct fetch_slist *));
    case FETCHOPT_HTTPPOST:         /* fetch_httppost * */
    case FETCHOPT_MIMEPOST:         /* fetch_mime * */
    case FETCHOPT_STDERR:           /* FILE * */
    case FETCHOPT_SHARE:            /* FETCHSH * */
    case FETCHOPT_STREAM_DEPENDS:   /* FETCH * */
    case FETCHOPT_STREAM_DEPENDS_E: /* FETCH * */
      return setopt_pointers(data, option, param);
    default:
      break;
    }
    /* the char pointer options */
    return setopt_cptr(data, option, va_arg(param, char *));
  }
  else if (option < FETCHOPTTYPE_OFF_T)
    return setopt_func(data, option, param);
  else if (option < FETCHOPTTYPE_BLOB)
    return setopt_offt(data, option, va_arg(param, fetch_off_t));
  return setopt_blob(data, option, va_arg(param, struct fetch_blob *));
}

/*
 * fetch_easy_setopt() is the external interface for setting options on an
 * easy handle.
 *
 * NOTE: This is one of few API functions that are allowed to be called from
 * within a callback.
 */

#undef fetch_easy_setopt
FETCHcode fetch_easy_setopt(FETCH *d, FETCHoption tag, ...)
{
  va_list arg;
  FETCHcode result;
  struct Curl_easy *data = d;

  if (!data)
    return FETCHE_BAD_FUNCTION_ARGUMENT;

  va_start(arg, tag);

  result = Curl_vsetopt(data, tag, arg);

  va_end(arg);
#ifdef DEBUGBUILD
  if (result == FETCHE_BAD_FUNCTION_ARGUMENT)
    infof(data, "setopt arg 0x%x returned FETCHE_BAD_FUNCTION_ARGUMENT", tag);
#endif
  return result;
}
