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
#include "tool_setup.h"

#include "tool_cfgable.h"
#include "tool_setopt.h"
#include "tool_findfile.h"
#include "tool_msgs.h"
#include "tool_libinfo.h"
#include "tool_cb_soc.h"
#include "tool_operate.h"
#include "config2setopts.h"
#include "tool_ipfs.h"
#include "tool_cb_wrt.h"
#include "tool_cb_rea.h"
#include "tool_cb_see.h"
#include "tool_cb_dbg.h"
#include "tool_helpers.h"

#define BUFFER_SIZE 102400L

#ifdef IP_TOS
static int get_address_family(curl_socket_t sockfd)
{
  struct sockaddr addr;
  curl_socklen_t addrlen = sizeof(addr);
  memset(&addr, 0, sizeof(addr));
  if(getsockname(sockfd, (struct sockaddr *)&addr, &addrlen) == 0)
    return addr.sa_family;
  return AF_UNSPEC;
}
#endif

#ifndef SOL_IP
#  define SOL_IP IPPROTO_IP
#endif

#if defined(IP_TOS) || defined(IPV6_TCLASS) || defined(SO_PRIORITY)
static int sockopt_callback(void *clientp, curl_socket_t curlfd,
                            curlsocktype purpose)
{
  struct OperationConfig *config = (struct OperationConfig *)clientp;
  if(purpose != CURLSOCKTYPE_IPCXN)
    return CURL_SOCKOPT_OK;
  (void)config;
  (void)curlfd;
#if defined(IP_TOS) || defined(IPV6_TCLASS)
  if(config->ip_tos > 0) {
    int tos = (int)config->ip_tos;
    int result = 0;
    switch(get_address_family(curlfd)) {
    case AF_INET:
#ifdef IP_TOS
      result = setsockopt(curlfd, SOL_IP, IP_TOS, (void *)&tos, sizeof(tos));
#endif
      break;
#if defined(IPV6_TCLASS) && defined(AF_INET6)
    case AF_INET6:
      result = setsockopt(curlfd, IPPROTO_IPV6, IPV6_TCLASS,
                          (void *)&tos, sizeof(tos));
      break;
#endif
    }
    if(result < 0) {
      int error = errno;
      warnf("Setting type of service to %d failed with errno %d: %s",
            tos, error, strerror(error));
    }
  }
#endif
#ifdef SO_PRIORITY
  if(config->vlan_priority > 0) {
    int priority = (int)config->vlan_priority;
    if(setsockopt(curlfd, SOL_SOCKET, SO_PRIORITY,
                  (void *)&priority, sizeof(priority)) != 0) {
      int error = errno;
      warnf("VLAN priority %d failed with errno %d: %s",
            priority, error, strerror(error));
    }
  }
#endif
  return CURL_SOCKOPT_OK;
}
#endif /* IP_TOD || IPV6_TCLASS || SO_PRIORITY */

/* return current SSL backend name, chop off multissl */
static char *ssl_backend(void)
{
  static char ssl_ver[80] = "no ssl";
  static bool already = FALSE;
  if(!already) { /* if there is no existing version */
    const char *v = curl_version_info(CURLVERSION_NOW)->ssl_version;
    if(v)
      msnprintf(ssl_ver, sizeof(ssl_ver), "%.*s", (int) strcspn(v, " "), v);
    already = TRUE;
  }
  return ssl_ver;
}

/*
 * Possibly rewrite the URL for IPFS and return the protocol token for the
 * scheme used in the given URL.
 */
static CURLcode url_proto_and_rewrite(char **url,
                                      struct OperationConfig *config,
                                      const char **scheme)
{
  CURLcode result = CURLE_OK;
  CURLU *uh = curl_url();
  const char *proto = NULL;
  *scheme = NULL;

  DEBUGASSERT(url && *url);
  if(uh) {
    char *schemep = NULL;
    if(!curl_url_set(uh, CURLUPART_URL, *url,
                     CURLU_GUESS_SCHEME | CURLU_NON_SUPPORT_SCHEME) &&
       !curl_url_get(uh, CURLUPART_SCHEME, &schemep,
                     CURLU_DEFAULT_SCHEME)) {
#ifdef CURL_DISABLE_IPFS
      (void)config;
#else
      if(curl_strequal(schemep, proto_ipfs) ||
         curl_strequal(schemep, proto_ipns)) {
        result = ipfs_url_rewrite(uh, schemep, url, config);
        /* short-circuit proto_token, we know it is ipfs or ipns */
        if(curl_strequal(schemep, proto_ipfs))
          proto = proto_ipfs;
        else if(curl_strequal(schemep, proto_ipns))
          proto = proto_ipns;
        if(result)
          config->synthetic_error = TRUE;
      }
      else
#endif /* !CURL_DISABLE_IPFS */
        proto = proto_token(schemep);

      curl_free(schemep);
    }
    curl_url_cleanup(uh);
  }
  else
    result = CURLE_OUT_OF_MEMORY;

  *scheme = proto ? proto : "?"; /* Never match if not found. */
  return result;
}

static CURLcode ssh_setopts(struct OperationConfig *config, CURL *curl)
{
  CURLcode result;

  /* SSH and SSL private key uses same command-line option */
  /* new in libcurl 7.16.1 */
  my_setopt_str(curl, CURLOPT_SSH_PRIVATE_KEYFILE, config->key);
  /* new in libcurl 7.16.1 */
  my_setopt_str(curl, CURLOPT_SSH_PUBLIC_KEYFILE, config->pubkey);

  /* new in libcurl 7.17.1: SSH host key md5 checking allows us
     to fail if we are not talking to who we think we should */
  my_setopt_str(curl, CURLOPT_SSH_HOST_PUBLIC_KEY_MD5,
                config->hostpubmd5);

  /* new in libcurl 7.80.0: SSH host key sha256 checking allows us
     to fail if we are not talking to who we think we should */
  my_setopt_str(curl, CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256,
                config->hostpubsha256);

  /* new in libcurl 7.56.0 */
  if(config->ssh_compression)
    my_setopt_long(curl, CURLOPT_SSH_COMPRESSION, 1);

  if(!config->insecure_ok) {
    char *known = global->knownhosts;

    if(!known)
      known = findfile(".ssh/known_hosts", FALSE);
    if(known) {
      /* new in curl 7.19.6 */
      result = my_setopt_str(curl, CURLOPT_SSH_KNOWNHOSTS, known);
      if(result) {
        global->knownhosts = NULL;
        curl_free(known);
        return result;
      }
      /* store it in global to avoid repeated checks */
      global->knownhosts = known;
    }
    else if(!config->hostpubmd5 && !config->hostpubsha256) {
      errorf("Couldn't find a known_hosts file");
      return CURLE_FAILED_INIT;
    }
    else
      warnf("Couldn't find a known_hosts file");
  }
  return CURLE_OK; /* ignore if SHA256 did not work */
}

#ifdef CURL_CA_EMBED
#ifndef CURL_DECLARED_CURL_CA_EMBED
#define CURL_DECLARED_CURL_CA_EMBED
extern const unsigned char curl_ca_embed[];
#endif
#endif

static long tlsversion(unsigned char mintls,
                       unsigned char maxtls)
{
  long tlsver = 0;
  if(!mintls) { /* minimum is at default */
    /* minimum is set to default, which we want to be 1.2 */
    if(maxtls && (maxtls < 3))
      /* max is set lower than 1.2 and minimum is default, change minimum to
         the same as max */
      mintls = maxtls;
  }
  switch(mintls) {
  case 1:
    tlsver = CURL_SSLVERSION_TLSv1_0;
    break;
  case 2:
    tlsver = CURL_SSLVERSION_TLSv1_1;
    break;
  case 0: /* let default minimum be 1.2 */
  case 3:
    tlsver = CURL_SSLVERSION_TLSv1_2;
    break;
  case 4:
  default: /* just in case */
    tlsver = CURL_SSLVERSION_TLSv1_3;
    break;
  }
  switch(maxtls) {
  case 0: /* not set, leave it */
    break;
  case 1:
    tlsver |= CURL_SSLVERSION_MAX_TLSv1_0;
    break;
  case 2:
    tlsver |= CURL_SSLVERSION_MAX_TLSv1_1;
    break;
  case 3:
    tlsver |= CURL_SSLVERSION_MAX_TLSv1_2;
    break;
  case 4:
  default: /* just in case */
    tlsver |= CURL_SSLVERSION_MAX_TLSv1_3;
    break;
  }
  return tlsver;
}

/* only called if libcurl supports TLS */
static CURLcode ssl_setopts(struct OperationConfig *config, CURL *curl)
{
  CURLcode result = CURLE_OK;

  if(config->cacert)
    my_setopt_str(curl, CURLOPT_CAINFO, config->cacert);
  if(config->proxy_cacert)
    my_setopt_str(curl, CURLOPT_PROXY_CAINFO, config->proxy_cacert);

  if(config->capath) {
    result = my_setopt_str(curl, CURLOPT_CAPATH, config->capath);
    if(result)
      return result;
  }
  /* For the time being if --proxy-capath is not set then we use the
     --capath value for it, if any. See #1257 */
  if(config->proxy_capath || config->capath) {
    result = my_setopt_str(curl, CURLOPT_PROXY_CAPATH,
                           (config->proxy_capath ? config->proxy_capath :
                            config->capath));
    if((result == CURLE_NOT_BUILT_IN) ||
       (result == CURLE_UNKNOWN_OPTION)) {
      if(config->proxy_capath) {
        warnf("ignoring %s, not supported by libcurl with %s",
              config->proxy_capath ? "--proxy-capath" : "--capath",
              ssl_backend());
      }
    }
    else if(result)
      return result;
  }

#ifdef CURL_CA_EMBED
  if(!config->cacert && !config->capath) {
    struct curl_blob blob;
    blob.data = CURL_UNCONST(curl_ca_embed);
    blob.len = strlen((const char *)curl_ca_embed);
    blob.flags = CURL_BLOB_NOCOPY;
    notef("Using embedded CA bundle (%zu bytes)", blob.len);
    result = curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &blob);
    if(result == CURLE_NOT_BUILT_IN) {
      warnf("ignoring %s, not supported by libcurl with %s",
            "embedded CA bundle", ssl_backend());
    }
  }
  if(!config->proxy_cacert && !config->proxy_capath) {
    struct curl_blob blob;
    blob.data = CURL_UNCONST(curl_ca_embed);
    blob.len = strlen((const char *)curl_ca_embed);
    blob.flags = CURL_BLOB_NOCOPY;
    notef("Using embedded CA bundle, for proxies (%zu bytes)", blob.len);
    result = curl_easy_setopt(curl, CURLOPT_PROXY_CAINFO_BLOB, &blob);
    if(result == CURLE_NOT_BUILT_IN) {
      warnf("ignoring %s, not supported by libcurl with %s",
            "embedded CA bundle", ssl_backend());
    }
  }
#endif

  if(config->crlfile)
    my_setopt_str(curl, CURLOPT_CRLFILE, config->crlfile);
  if(config->proxy_crlfile)
    my_setopt_str(curl, CURLOPT_PROXY_CRLFILE, config->proxy_crlfile);
  else if(config->crlfile) /* CURLOPT_PROXY_CRLFILE default is crlfile */
    my_setopt_str(curl, CURLOPT_PROXY_CRLFILE, config->crlfile);

  if(config->pinnedpubkey) {
    result = my_setopt_str(curl, CURLOPT_PINNEDPUBLICKEY,
                           config->pinnedpubkey);
    if(result == CURLE_NOT_BUILT_IN)
      warnf("ignoring %s, not supported by libcurl with %s",
            "--pinnedpubkey", ssl_backend());
  }
  if(config->proxy_pinnedpubkey) {
    result = my_setopt_str(curl, CURLOPT_PROXY_PINNEDPUBLICKEY,
                           config->proxy_pinnedpubkey);
    if(result == CURLE_NOT_BUILT_IN)
      warnf("ignoring %s, not supported by libcurl with %s",
            "--proxy-pinnedpubkey", ssl_backend());
  }

  if(config->ssl_ec_curves)
    my_setopt_str(curl, CURLOPT_SSL_EC_CURVES, config->ssl_ec_curves);

  if(config->ssl_signature_algorithms)
    my_setopt_str(curl, CURLOPT_SSL_SIGNATURE_ALGORITHMS,
                  config->ssl_signature_algorithms);

  if(config->writeout)
    my_setopt_long(curl, CURLOPT_CERTINFO, 1);

  my_setopt_str(curl, CURLOPT_SSLCERT, config->cert);
  my_setopt_str(curl, CURLOPT_PROXY_SSLCERT, config->proxy_cert);
  my_setopt_str(curl, CURLOPT_SSLCERTTYPE, config->cert_type);
  my_setopt_str(curl, CURLOPT_PROXY_SSLCERTTYPE,
                config->proxy_cert_type);
  my_setopt_str(curl, CURLOPT_SSLKEY, config->key);
  my_setopt_str(curl, CURLOPT_PROXY_SSLKEY, config->proxy_key);
  my_setopt_str(curl, CURLOPT_SSLKEYTYPE, config->key_type);
  my_setopt_str(curl, CURLOPT_PROXY_SSLKEYTYPE,
                config->proxy_key_type);

  /* libcurl default is strict verifyhost -> 1L, verifypeer -> 1L */
  if(config->insecure_ok) {
    my_setopt_long(curl, CURLOPT_SSL_VERIFYPEER, 0);
    my_setopt_long(curl, CURLOPT_SSL_VERIFYHOST, 0);
  }

  if(config->doh_insecure_ok) {
    my_setopt_long(curl, CURLOPT_DOH_SSL_VERIFYPEER, 0);
    my_setopt_long(curl, CURLOPT_DOH_SSL_VERIFYHOST, 0);
  }

  if(config->proxy_insecure_ok) {
    my_setopt_long(curl, CURLOPT_PROXY_SSL_VERIFYPEER, 0);
    my_setopt_long(curl, CURLOPT_PROXY_SSL_VERIFYHOST, 0);
  }

  if(config->verifystatus)
    my_setopt_long(curl, CURLOPT_SSL_VERIFYSTATUS, 1);

  if(config->doh_verifystatus)
    my_setopt_long(curl, CURLOPT_DOH_SSL_VERIFYSTATUS, 1);

  my_setopt_SSLVERSION(curl, CURLOPT_SSLVERSION,
                       tlsversion(config->ssl_version,
                                  config->ssl_version_max));
  if(config->proxy)
    my_setopt_SSLVERSION(curl, CURLOPT_PROXY_SSLVERSION,
                         config->proxy_ssl_version);

  {
    long mask =
      (config->ssl_allow_beast ? CURLSSLOPT_ALLOW_BEAST : 0) |
      (config->ssl_allow_earlydata ? CURLSSLOPT_EARLYDATA : 0) |
      (config->ssl_no_revoke ? CURLSSLOPT_NO_REVOKE : 0) |
      (config->ssl_revoke_best_effort ? CURLSSLOPT_REVOKE_BEST_EFFORT : 0) |
      (config->native_ca_store ? CURLSSLOPT_NATIVE_CA : 0) |
      (config->ssl_auto_client_cert ? CURLSSLOPT_AUTO_CLIENT_CERT : 0);

    if(mask)
      my_setopt_bitmask(curl, CURLOPT_SSL_OPTIONS, mask);
  }

  {
    long mask =
      (config->proxy_ssl_allow_beast ? CURLSSLOPT_ALLOW_BEAST : 0) |
      (config->proxy_ssl_auto_client_cert ?
       CURLSSLOPT_AUTO_CLIENT_CERT : 0) |
      (config->proxy_native_ca_store ? CURLSSLOPT_NATIVE_CA : 0);

    if(mask)
      my_setopt_bitmask(curl, CURLOPT_PROXY_SSL_OPTIONS, mask);
  }

  if(config->cipher_list) {
    result = my_setopt_str(curl, CURLOPT_SSL_CIPHER_LIST,
                           config->cipher_list);
    if(result == CURLE_NOT_BUILT_IN)
      warnf("ignoring %s, not supported by libcurl with %s",
            "--ciphers", ssl_backend());
  }
  if(config->proxy_cipher_list) {
    result = my_setopt_str(curl, CURLOPT_PROXY_SSL_CIPHER_LIST,
                           config->proxy_cipher_list);
    if(result == CURLE_NOT_BUILT_IN)
      warnf("ignoring %s, not supported by libcurl with %s",
            "--proxy-ciphers", ssl_backend());
  }
  if(config->cipher13_list) {
    result = my_setopt_str(curl, CURLOPT_TLS13_CIPHERS,
                           config->cipher13_list);
    if(result == CURLE_NOT_BUILT_IN)
      warnf("ignoring %s, not supported by libcurl with %s",
            "--tls13-ciphers", ssl_backend());
  }
  if(config->proxy_cipher13_list) {
    result = my_setopt_str(curl, CURLOPT_PROXY_TLS13_CIPHERS,
                           config->proxy_cipher13_list);
    if(result == CURLE_NOT_BUILT_IN)
      warnf("ignoring %s, not supported by libcurl with %s",
            "--proxy-tls13-ciphers", ssl_backend());
  }

  /* curl 7.16.0 */
  if(config->disable_sessionid)
    /* disable it */
    my_setopt_long(curl, CURLOPT_SSL_SESSIONID_CACHE, 0);

  if(feature_ech) {
    /* only if enabled in libcurl */
    if(config->ech) /* only if set (optional) */
      my_setopt_str(curl, CURLOPT_ECH, config->ech);
    if(config->ech_public) /* only if set (optional) */
      my_setopt_str(curl, CURLOPT_ECH, config->ech_public);
    if(config->ech_config) /* only if set (optional) */
      my_setopt_str(curl, CURLOPT_ECH, config->ech_config);
  }

  /* new in curl 7.9.3 */
  if(config->engine) {
    result = my_setopt_str(curl, CURLOPT_SSLENGINE, config->engine);
    if(result)
      return result;
  }

  /* new in curl 7.15.5 */
  if(config->ftp_ssl_reqd)
    my_setopt_enum(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

  /* new in curl 7.11.0 */
  else if(config->ftp_ssl)
    my_setopt_enum(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);

  /* new in curl 7.16.0 */
  else if(config->ftp_ssl_control)
    my_setopt_enum(curl, CURLOPT_USE_SSL, CURLUSESSL_CONTROL);

  if(config->noalpn)
    my_setopt_long(curl, CURLOPT_SSL_ENABLE_ALPN, 0);

  return CURLE_OK;
}

/* only called for HTTP transfers */
static CURLcode http_setopts(struct OperationConfig *config,
                             CURL *curl)
{
  long postRedir = 0;

  my_setopt_long(curl, CURLOPT_FOLLOWLOCATION, config->followlocation);
  my_setopt_long(curl, CURLOPT_UNRESTRICTED_AUTH,
                 config->unrestricted_auth);
  my_setopt_str(curl, CURLOPT_AWS_SIGV4, config->aws_sigv4);
  my_setopt_long(curl, CURLOPT_AUTOREFERER, config->autoreferer);

  /* new in libcurl 7.36.0 */
  if(config->proxyheaders) {
    my_setopt_slist(curl, CURLOPT_PROXYHEADER, config->proxyheaders);
    my_setopt_long(curl, CURLOPT_HEADEROPT, CURLHEADER_SEPARATE);
  }

  /* new in libcurl 7.5 */
  my_setopt_long(curl, CURLOPT_MAXREDIRS, config->maxredirs);

  if(config->httpversion)
    my_setopt_enum(curl, CURLOPT_HTTP_VERSION, config->httpversion);

  /* curl 7.19.1 (the 301 version existed in 7.18.2),
     303 was added in 7.26.0 */
  if(config->post301)
    postRedir |= CURL_REDIR_POST_301;
  if(config->post302)
    postRedir |= CURL_REDIR_POST_302;
  if(config->post303)
    postRedir |= CURL_REDIR_POST_303;
  my_setopt_long(curl, CURLOPT_POSTREDIR, postRedir);

  /* new in libcurl 7.21.6 */
  if(config->encoding)
    my_setopt_str(curl, CURLOPT_ACCEPT_ENCODING, "");

  /* new in libcurl 7.21.6 */
  if(config->tr_encoding)
    my_setopt_long(curl, CURLOPT_TRANSFER_ENCODING, 1);
  /* new in libcurl 7.64.0 */
  my_setopt_long(curl, CURLOPT_HTTP09_ALLOWED, config->http09_allowed);

  if(config->altsvc)
    my_setopt_str(curl, CURLOPT_ALTSVC, config->altsvc);

  if(config->hsts)
    my_setopt_str(curl, CURLOPT_HSTS, config->hsts);

  /* new in 7.47.0 */
  if(config->expect100timeout_ms > 0)
    my_setopt_long(curl, CURLOPT_EXPECT_100_TIMEOUT_MS,
                   config->expect100timeout_ms);

  return CURLE_OK;
}

static CURLcode cookie_setopts(struct OperationConfig *config, CURL *curl)
{
  CURLcode result = CURLE_OK;
  if(config->cookies) {
    struct dynbuf cookies;
    struct curl_slist *cl;

    /* The maximum size needs to match MAX_NAME in cookie.h */
#define MAX_COOKIE_LINE 8200
    curlx_dyn_init(&cookies, MAX_COOKIE_LINE);
    for(cl = config->cookies; cl; cl = cl->next) {
      if(cl == config->cookies)
        result = curlx_dyn_add(&cookies, cl->data);
      else
        result = curlx_dyn_addf(&cookies, ";%s", cl->data);

      if(result) {
        warnf("skipped provided cookie, the cookie header "
              "would go over %u bytes", MAX_COOKIE_LINE);
        return result;
      }
    }

    my_setopt_str(curl, CURLOPT_COOKIE, curlx_dyn_ptr(&cookies));
    curlx_dyn_free(&cookies);
  }

  if(config->cookiefiles) {
    struct curl_slist *cfl;

    for(cfl = config->cookiefiles; cfl; cfl = cfl->next)
      my_setopt_str(curl, CURLOPT_COOKIEFILE, cfl->data);
  }

  /* new in libcurl 7.9 */
  if(config->cookiejar)
    my_setopt_str(curl, CURLOPT_COOKIEJAR, config->cookiejar);

  /* new in libcurl 7.9.7 */
  my_setopt_long(curl, CURLOPT_COOKIESESSION, config->cookiesession);

  return result;
}

static CURLcode tcp_setopts(struct OperationConfig *config,
                            CURL *curl)
{
  if(!config->tcp_nodelay)
    my_setopt_long(curl, CURLOPT_TCP_NODELAY, 0);

  if(config->tcp_fastopen)
    my_setopt_long(curl, CURLOPT_TCP_FASTOPEN, 1);

  if(config->mptcp)
    my_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, tool_socket_open_mptcp_cb);

  /* curl 7.17.1 */
  if(!config->nokeepalive) {
    my_setopt_long(curl, CURLOPT_TCP_KEEPALIVE, 1);
    if(config->alivetime) {
      my_setopt_long(curl, CURLOPT_TCP_KEEPIDLE, config->alivetime);
      my_setopt_long(curl, CURLOPT_TCP_KEEPINTVL, config->alivetime);
    }
    if(config->alivecnt)
      my_setopt_long(curl, CURLOPT_TCP_KEEPCNT, config->alivecnt);
  }
  else
    my_setopt_long(curl, CURLOPT_TCP_KEEPALIVE, 0);
  return CURLE_OK;
}

static CURLcode ftp_setopts(struct OperationConfig *config, CURL *curl)
{
  my_setopt_str(curl, CURLOPT_FTPPORT, config->ftpport);

  /* new in libcurl 7.9.2: */
  if(config->disable_epsv)
    /* disable it */
    my_setopt_long(curl, CURLOPT_FTP_USE_EPSV, 0);

  /* new in libcurl 7.10.5 */
  if(config->disable_eprt)
    /* disable it */
    my_setopt_long(curl, CURLOPT_FTP_USE_EPRT, 0);

  /* new in curl 7.16.1 */
  if(config->ftp_ssl_ccc)
    my_setopt_enum(curl, CURLOPT_FTP_SSL_CCC, config->ftp_ssl_ccc_mode);

  my_setopt_str(curl, CURLOPT_FTP_ACCOUNT, config->ftp_account);

  /* curl 7.14.2 */
  my_setopt_long(curl, CURLOPT_FTP_SKIP_PASV_IP, config->ftp_skip_ip);

  /* curl 7.15.1 */
  my_setopt_long(curl, CURLOPT_FTP_FILEMETHOD, config->ftp_filemethod);

    /* curl 7.15.5 */
  my_setopt_str(curl, CURLOPT_FTP_ALTERNATIVE_TO_USER,
                config->ftp_alternative_to_user);

  /* curl 7.20.x */
  if(config->ftp_pret)
    my_setopt_long(curl, CURLOPT_FTP_USE_PRET, 1);

  return CURLE_OK;
}

static void gen_trace_setopts(struct OperationConfig *config, CURL *curl)
{
  if(global->tracetype != TRACE_NONE) {
    my_setopt(curl, CURLOPT_DEBUGFUNCTION, tool_debug_cb);
    my_setopt(curl, CURLOPT_DEBUGDATA, config);
    my_setopt_long(curl, CURLOPT_VERBOSE, 1L);
  }
}

static void gen_cb_setopts(struct OperationConfig *config,
                           struct per_transfer *per,
                           CURL *curl)
{
  (void)config; /* when --libcurl is disabled */

  /* where to store */
  my_setopt(curl, CURLOPT_WRITEDATA, per);
  my_setopt(curl, CURLOPT_INTERLEAVEDATA, per);

  /* what call to write */
  my_setopt(curl, CURLOPT_WRITEFUNCTION, tool_write_cb);

  /* what to read */
  my_setopt(curl, CURLOPT_READDATA, per);
  my_setopt(curl, CURLOPT_READFUNCTION, tool_read_cb);

  /* in 7.18.0, the CURLOPT_SEEKFUNCTION/DATA pair is taking over what
     CURLOPT_IOCTLFUNCTION/DATA pair previously provided for seeking */
  my_setopt(curl, CURLOPT_SEEKDATA, per);
  my_setopt(curl, CURLOPT_SEEKFUNCTION, tool_seek_cb);

  if((global->progressmode == CURL_PROGRESS_BAR) &&
     !global->noprogress && !global->silent) {
    /* we want the alternative style, then we have to implement it
       ourselves! */
    my_setopt(curl, CURLOPT_XFERINFOFUNCTION, tool_progress_cb);
    my_setopt(curl, CURLOPT_XFERINFODATA, per);
  }
  else if(per->uploadfile && !strcmp(per->uploadfile, ".")) {
    /* when reading from stdin in non-blocking mode, we use the progress
       function to unpause a busy read */
    my_setopt_long(curl, CURLOPT_NOPROGRESS, 0);
    my_setopt(curl, CURLOPT_XFERINFOFUNCTION, tool_readbusy_cb);
    my_setopt(curl, CURLOPT_XFERINFODATA, per);
  }

  my_setopt(curl, CURLOPT_HEADERFUNCTION, tool_header_cb);
  my_setopt(curl, CURLOPT_HEADERDATA, per);
}

static CURLcode proxy_setopts(struct OperationConfig *config, CURL *curl)
{
  if(config->proxy) {
    CURLcode result = my_setopt_str(curl, CURLOPT_PROXY, config->proxy);

    if(result) {
      errorf("proxy support is disabled in this libcurl");
      config->synthetic_error = TRUE;
      return CURLE_NOT_BUILT_IN;
    }
  }

  /* new in libcurl 7.5 */
  if(config->proxy)
    my_setopt_enum(curl, CURLOPT_PROXYTYPE, config->proxyver);

  my_setopt_str(curl, CURLOPT_PROXYUSERPWD, config->proxyuserpwd);

  /* new in libcurl 7.3 */
  my_setopt_long(curl, CURLOPT_HTTPPROXYTUNNEL, config->proxytunnel);

  /* new in libcurl 7.52.0 */
  if(config->preproxy)
    my_setopt_str(curl, CURLOPT_PRE_PROXY, config->preproxy);

  /* new in libcurl 7.10.6 */
  if(config->proxyanyauth)
    my_setopt_bitmask(curl, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
  else if(config->proxynegotiate)
    my_setopt_bitmask(curl, CURLOPT_PROXYAUTH, CURLAUTH_GSSNEGOTIATE);
  else if(config->proxyntlm)
    my_setopt_bitmask(curl, CURLOPT_PROXYAUTH, CURLAUTH_NTLM);
  else if(config->proxydigest)
    my_setopt_bitmask(curl, CURLOPT_PROXYAUTH, CURLAUTH_DIGEST);
  else if(config->proxybasic)
    my_setopt_bitmask(curl, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);

  /* new in libcurl 7.19.4 */
  my_setopt_str(curl, CURLOPT_NOPROXY, config->noproxy);

  my_setopt_long(curl, CURLOPT_SUPPRESS_CONNECT_HEADERS,
                 config->suppress_connect_headers);

  /* new in curl 7.43.0 */
  if(config->proxy_service_name)
    my_setopt_str(curl, CURLOPT_PROXY_SERVICE_NAME,
                  config->proxy_service_name);

  /* new in 7.60.0 */
  if(config->haproxy_protocol)
    my_setopt_long(curl, CURLOPT_HAPROXYPROTOCOL, 1);

  /* new in 8.2.0 */
  if(config->haproxy_clientip)
    my_setopt_str(curl, CURLOPT_HAPROXY_CLIENT_IP, config->haproxy_clientip);

  return CURLE_OK;
}

static void tls_srp_setopts(struct OperationConfig *config, CURL *curl)
{
  if(config->tls_username)
    my_setopt_str(curl, CURLOPT_TLSAUTH_USERNAME, config->tls_username);
  if(config->tls_password)
    my_setopt_str(curl, CURLOPT_TLSAUTH_PASSWORD, config->tls_password);
  if(config->tls_authtype)
    my_setopt_str(curl, CURLOPT_TLSAUTH_TYPE, config->tls_authtype);
  if(config->proxy_tls_username)
    my_setopt_str(curl, CURLOPT_PROXY_TLSAUTH_USERNAME,
                  config->proxy_tls_username);
  if(config->proxy_tls_password)
    my_setopt_str(curl, CURLOPT_PROXY_TLSAUTH_PASSWORD,
                  config->proxy_tls_password);
  if(config->proxy_tls_authtype)
    my_setopt_str(curl, CURLOPT_PROXY_TLSAUTH_TYPE,
                  config->proxy_tls_authtype);
}

CURLcode config2setopts(struct OperationConfig *config,
                        struct per_transfer *per,
                        CURL *curl,
                        CURLSH *share)
{
  const char *use_proto;
  CURLcode result = url_proto_and_rewrite(&per->url, config, &use_proto);

  /* Avoid having this setopt added to the --libcurl source output. */
  if(!result)
    result = curl_easy_setopt(curl, CURLOPT_SHARE, share);
  if(result)
    return result;

#ifndef DEBUGBUILD
  /* On most modern OSes, exiting works thoroughly,
     we will clean everything up via exit(), so do not bother with
     slow cleanups. Crappy ones might need to skip this.
     Note: avoid having this setopt added to the --libcurl source
     output. */
  result = curl_easy_setopt(curl, CURLOPT_QUICK_EXIT, 1L);
  if(result)
    return result;
#endif

  gen_trace_setopts(config, curl);

  {
#ifdef DEBUGBUILD
    char *env = getenv("CURL_BUFFERSIZE");
    if(env) {
      curl_off_t num;
      const char *p = env;
      if(!curlx_str_number(&p, &num, LONG_MAX))
        my_setopt_long(curl, CURLOPT_BUFFERSIZE, (long)num);
    }
    else
#endif
      if(config->recvpersecond && (config->recvpersecond < BUFFER_SIZE))
        /* use a smaller sized buffer for better sleeps */
        my_setopt_long(curl, CURLOPT_BUFFERSIZE, (long)config->recvpersecond);
      else
        my_setopt_long(curl, CURLOPT_BUFFERSIZE, BUFFER_SIZE);
  }

  my_setopt_str(curl, CURLOPT_URL, per->url);
  my_setopt_long(curl, CURLOPT_NOPROGRESS,
                 global->noprogress || global->silent);
  /* call after the line above. It may override CURLOPT_NOPROGRESS */
  gen_cb_setopts(config, per, curl);

  my_setopt_long(curl, CURLOPT_NOBODY, config->no_body);
  my_setopt_str(curl, CURLOPT_XOAUTH2_BEARER, config->oauth_bearer);

  result = proxy_setopts(config, curl);
  if(result)
    return result;

  my_setopt_long(curl, CURLOPT_FAILONERROR, config->failonerror);
  my_setopt_str(curl, CURLOPT_REQUEST_TARGET, config->request_target);
  my_setopt_long(curl, CURLOPT_UPLOAD, !!per->uploadfile);
  my_setopt_long(curl, CURLOPT_DIRLISTONLY, config->dirlistonly);
  my_setopt_long(curl, CURLOPT_APPEND, config->ftp_append);

  if(config->netrc_opt)
    my_setopt_enum(curl, CURLOPT_NETRC, CURL_NETRC_OPTIONAL);
  else if(config->netrc || config->netrc_file)
    my_setopt_enum(curl, CURLOPT_NETRC, CURL_NETRC_REQUIRED);
  else
    my_setopt_enum(curl, CURLOPT_NETRC, CURL_NETRC_IGNORED);

  my_setopt_str(curl, CURLOPT_NETRC_FILE, config->netrc_file);
  my_setopt_long(curl, CURLOPT_TRANSFERTEXT, config->use_ascii);
  my_setopt_str(curl, CURLOPT_LOGIN_OPTIONS, config->login_options);
  my_setopt_str(curl, CURLOPT_USERPWD, config->userpwd);
  my_setopt_str(curl, CURLOPT_RANGE, config->range);
  my_setopt(curl, CURLOPT_ERRORBUFFER, per->errorbuffer);
  my_setopt_long(curl, CURLOPT_TIMEOUT_MS, config->timeout_ms);

  switch(config->httpreq) {
  case TOOL_HTTPREQ_SIMPLEPOST:
    if(config->resume_from) {
      errorf("cannot mix --continue-at with --data");
      result = CURLE_FAILED_INIT;
    }
    else {
      my_setopt_str(curl, CURLOPT_POSTFIELDS,
                    curlx_dyn_ptr(&config->postdata));
      my_setopt_offt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                     curlx_dyn_len(&config->postdata));
    }
    break;
  case TOOL_HTTPREQ_MIMEPOST:
    /* free previous remainders */
    curl_mime_free(config->mimepost);
    config->mimepost = NULL;
    if(config->resume_from) {
      errorf("cannot mix --continue-at with --form");
      result = CURLE_FAILED_INIT;
    }
    else {
      result = tool2curlmime(curl, config->mimeroot, &config->mimepost);
      if(!result)
        my_setopt_mimepost(curl, CURLOPT_MIMEPOST, config->mimepost);
    }
    break;
  default:
    break;
  }
  if(result)
    return result;

  if(config->mime_options)
    my_setopt_long(curl, CURLOPT_MIME_OPTIONS, config->mime_options);

  if(config->authtype)
    my_setopt_bitmask(curl, CURLOPT_HTTPAUTH, config->authtype);

  my_setopt_slist(curl, CURLOPT_HTTPHEADER, config->headers);

  if(proto_http || proto_rtsp) {
    my_setopt_str(curl, CURLOPT_REFERER, config->referer);
    my_setopt_str(curl, CURLOPT_USERAGENT, config->useragent);
  }

  if(use_proto == proto_http || use_proto == proto_https) {
    result = http_setopts(config, curl);
    if(!result)
      result = cookie_setopts(config, curl);
    if(result)
      return result;
  }

  if(use_proto == proto_ftp || use_proto == proto_ftps) {
    result = ftp_setopts(config, curl);
    if(result)
      return result;
  }

  my_setopt_long(curl, CURLOPT_LOW_SPEED_LIMIT, config->low_speed_limit);
  my_setopt_long(curl, CURLOPT_LOW_SPEED_TIME, config->low_speed_time);
  my_setopt_offt(curl, CURLOPT_MAX_SEND_SPEED_LARGE, config->sendpersecond);
  my_setopt_offt(curl, CURLOPT_MAX_RECV_SPEED_LARGE, config->recvpersecond);

  if(config->use_resume)
    my_setopt_offt(curl, CURLOPT_RESUME_FROM_LARGE, config->resume_from);
  else
    my_setopt_offt(curl, CURLOPT_RESUME_FROM_LARGE, 0);

  my_setopt_str(curl, CURLOPT_KEYPASSWD, config->key_passwd);
  my_setopt_str(curl, CURLOPT_PROXY_KEYPASSWD, config->proxy_key_passwd);

  if(use_proto == proto_scp || use_proto == proto_sftp) {
    result = ssh_setopts(config, curl);
    if(result)
      return result;
  }

  if(feature_ssl) {
    result = ssl_setopts(config, curl);
    if(result)
      return result;
  }

  if(config->path_as_is)
    my_setopt_long(curl, CURLOPT_PATH_AS_IS, 1);

  if(config->no_body || config->remote_time) {
    /* no body or use remote time */
    my_setopt_long(curl, CURLOPT_FILETIME, 1);
  }

  my_setopt_long(curl, CURLOPT_CRLF, config->crlf);
  my_setopt_slist(curl, CURLOPT_QUOTE, config->quote);
  my_setopt_slist(curl, CURLOPT_POSTQUOTE, config->postquote);
  my_setopt_slist(curl, CURLOPT_PREQUOTE, config->prequote);

  my_setopt_enum(curl, CURLOPT_TIMECONDITION, config->timecond);
  my_setopt_offt(curl, CURLOPT_TIMEVALUE_LARGE, config->condtime);
  my_setopt_str(curl, CURLOPT_CUSTOMREQUEST, config->customrequest);
  customrequest_helper(config->httpreq, config->customrequest);
  my_setopt(curl, CURLOPT_STDERR, tool_stderr);
  my_setopt_str(curl, CURLOPT_INTERFACE, config->iface);
  my_setopt_str(curl, CURLOPT_KRBLEVEL, config->krblevel);
  progressbarinit(&per->progressbar, config);
  my_setopt_str(curl, CURLOPT_DNS_SERVERS, config->dns_servers);
  my_setopt_str(curl, CURLOPT_DNS_INTERFACE, config->dns_interface);
  my_setopt_str(curl, CURLOPT_DNS_LOCAL_IP4, config->dns_ipv4_addr);
  my_setopt_str(curl, CURLOPT_DNS_LOCAL_IP6, config->dns_ipv6_addr);
  my_setopt_slist(curl, CURLOPT_TELNETOPTIONS, config->telnet_options);
  my_setopt_long(curl, CURLOPT_CONNECTTIMEOUT_MS, config->connecttimeout_ms);
  my_setopt_str(curl, CURLOPT_DOH_URL, config->doh_url);
  my_setopt_long(curl, CURLOPT_FTP_CREATE_MISSING_DIRS,
                 (config->ftp_create_dirs ?
                  CURLFTP_CREATE_DIR_RETRY : CURLFTP_CREATE_DIR_NONE));
  my_setopt_offt(curl, CURLOPT_MAXFILESIZE_LARGE,
                 config->max_filesize);
  my_setopt_long(curl, CURLOPT_IPRESOLVE, config->ip_version);
  if(config->socks5_gssapi_nec)
    my_setopt_long(curl, CURLOPT_SOCKS5_GSSAPI_NEC, 1);
  if(config->socks5_auth)
    my_setopt_bitmask(curl, CURLOPT_SOCKS5_AUTH, config->socks5_auth);
  my_setopt_str(curl, CURLOPT_SERVICE_NAME, config->service_name);
  my_setopt_long(curl, CURLOPT_IGNORE_CONTENT_LENGTH, config->ignorecl);

  if(config->localport) {
    my_setopt_long(curl, CURLOPT_LOCALPORT, config->localport);
    my_setopt_long(curl, CURLOPT_LOCALPORTRANGE, config->localportrange);
  }

  if(config->raw) {
    my_setopt_long(curl, CURLOPT_HTTP_CONTENT_DECODING, 0);
    my_setopt_long(curl, CURLOPT_HTTP_TRANSFER_DECODING, 0);
  }

  result = tcp_setopts(config, curl);
  if(result)
    return result;

  if(config->tftp_blksize && proto_tftp)
    my_setopt_long(curl, CURLOPT_TFTP_BLKSIZE, config->tftp_blksize);

  my_setopt_str(curl, CURLOPT_MAIL_FROM, config->mail_from);
  my_setopt_slist(curl, CURLOPT_MAIL_RCPT, config->mail_rcpt);
  my_setopt_long(curl, CURLOPT_MAIL_RCPT_ALLOWFAILS,
                 config->mail_rcpt_allowfails);
  if(config->create_file_mode)
    my_setopt_long(curl, CURLOPT_NEW_FILE_PERMS, config->create_file_mode);

  if(config->proto_present)
    my_setopt_str(curl, CURLOPT_PROTOCOLS_STR, config->proto_str);
  if(config->proto_redir_present)
    my_setopt_str(curl, CURLOPT_REDIR_PROTOCOLS_STR, config->proto_redir_str);

  my_setopt_slist(curl, CURLOPT_RESOLVE, config->resolve);
  my_setopt_slist(curl, CURLOPT_CONNECT_TO, config->connect_to);

  if(feature_tls_srp)
    tls_srp_setopts(config, curl);

  if(config->gssapi_delegation)
    my_setopt_long(curl, CURLOPT_GSSAPI_DELEGATION, config->gssapi_delegation);

  my_setopt_str(curl, CURLOPT_MAIL_AUTH, config->mail_auth);
  my_setopt_str(curl, CURLOPT_SASL_AUTHZID, config->sasl_authzid);
  my_setopt_long(curl, CURLOPT_SASL_IR, config->sasl_ir);

  if(config->unix_socket_path) {
    if(config->abstract_unix_socket) {
      my_setopt_str(curl, CURLOPT_ABSTRACT_UNIX_SOCKET,
                    config->unix_socket_path);
    }
    else {
      my_setopt_str(curl, CURLOPT_UNIX_SOCKET_PATH,
                    config->unix_socket_path);
    }
  }

  my_setopt_str(curl, CURLOPT_DEFAULT_PROTOCOL, config->proto_default);
  my_setopt_long(curl, CURLOPT_TFTP_NO_OPTIONS,
                 config->tftp_no_options && proto_tftp);

  if(config->happy_eyeballs_timeout_ms != CURL_HET_DEFAULT)
    my_setopt_long(curl, CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS,
                   config->happy_eyeballs_timeout_ms);

  my_setopt_long(curl, CURLOPT_DISALLOW_USERNAME_IN_URL,
                 config->disallow_username_in_url);

  if(config->ip_tos > 0 || config->vlan_priority > 0) {
#if defined(IP_TOS) || defined(IPV6_TCLASS) || defined(SO_PRIORITY)
    my_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_callback);
    my_setopt(curl, CURLOPT_SOCKOPTDATA, config);
#else
    if(config->ip_tos > 0) {
      errorf("Type of service is not supported in this build.");
      result = CURLE_NOT_BUILT_IN;
    }
    if(config->vlan_priority > 0) {
      errorf("VLAN priority is not supported in this build.");
      result = CURLE_NOT_BUILT_IN;
    }
#endif
  }
  my_setopt_long(curl, CURLOPT_UPLOAD_FLAGS, config->upload_flags);
  return result;
}
