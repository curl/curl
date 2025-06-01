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

#include "nwf.h"
#include "curl/curl.h"

#ifdef USE_NWF

#include "apple.h"
#include "urldata.h"
#include "cfilters.h"
#include "vtls.h"
#include "vtls_int.h"
#include "sendf.h"
#include "connect.h"
#include "strerror.h"
#include "select.h"
#include "../socketpair.h"
#include "../http_proxy.h"
#include "multiif.h"
#include "curl_printf.h"
#include <Network/Network.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <unistd.h>


#include "../curl_memory.h"
/* The last #include file should be: */
#include "../memdebug.h"

#define DEFAULT_RECEIVE_SIZE 4096

#if defined(__GNUC__) && defined(__APPLE__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#ifdef USE_ECH
#define ECH_ENABLED(__data__) \
    (__data__->set.tls_ech && \
     !(__data__->set.tls_ech & CURLECH_DISABLE)\
    )
#endif /* USE_ECH */

struct nwf_data {
    dispatch_data_t data;
    struct Curl_llist_node storage;
};

struct nwf_ssl_backend_data {
  nw_connection_t connection;
  dispatch_queue_t queue;
  bool done_connecting;
  bool done_receiving;
  dispatch_data_t recv_data;
  CURLcode error;
  nw_connection_state_t state;
  int signal_pipe[2];
  bool write_outstanding;
  bool read_outstanding;
  nw_endpoint_t remote_endpoint, local_endpoint;
  struct Curl_sockaddr_ex remote_addr;
  unsigned char alpn;
};

static dispatch_queue_t nwf_queue;

static CURLcode
nwf_code_from_error(nw_error_t error, CURLcode def)
{
  nw_error_domain_t domain;
  CURLcode result;

  result = CURLE_OK;
  if(error == nil) {
    return result;
  }

  domain = nw_error_get_error_domain(error);
  switch(domain) {
    case nw_error_domain_posix:
      result = def;
      break;
    case nw_error_domain_dns:
      result = CURLE_COULDNT_RESOLVE_HOST;
      break;
    case nw_error_domain_tls:
      result = CURLE_SSL_CONNECT_ERROR;
      break;
    case nw_error_domain_invalid:
    default:
      result = CURLE_COULDNT_CONNECT;
      break;
  }
  return result;
}

static size_t
nwf_copy_from_data(char *buf, size_t len, dispatch_data_t data)
{
  dispatch_data_applier_t applier;
  __block size_t copied = 0;

  applier = ^bool(dispatch_data_t region UNUSED_PARAM, size_t offset,
                  const void *buffer, size_t buffer_size) {
    size_t to_copy = CURLMIN(len - copied, buffer_size);
    memcpy(buf + offset, buffer, to_copy);
    copied += to_copy;
    return copied < len;
  };
  dispatch_data_apply(data, applier);

  return copied;
}

static CURLcode
nwf_set_ssl_version_min_max(struct Curl_easy *data,
                            sec_protocol_options_t options,
                            struct ssl_primary_config *conn_config)
{
  tls_protocol_version_t ver_min;
  tls_protocol_version_t ver_max;

  switch(conn_config->version) {
    case CURL_SSLVERSION_DEFAULT:
      ver_min = sec_protocol_options_get_default_min_tls_protocol_version();
      break;
    case CURL_SSLVERSION_TLSv1:
    case CURL_SSLVERSION_TLSv1_0:
      ver_min = tls_protocol_version_TLSv10;
      break;
    case CURL_SSLVERSION_TLSv1_1:
      ver_min = tls_protocol_version_TLSv11;
      break;
    case CURL_SSLVERSION_TLSv1_2:
      ver_min = tls_protocol_version_TLSv12;
      break;
    case CURL_SSLVERSION_TLSv1_3:
      ver_min = tls_protocol_version_TLSv13;
      break;
    default:
      failf(data, "SSL: unsupported minimum TLS version value");
      return CURLE_SSL_CONNECT_ERROR;
  }

  switch(conn_config->version_max) {
    case CURL_SSLVERSION_MAX_DEFAULT:
      ver_max = sec_protocol_options_get_default_max_tls_protocol_version();
      break;
    case CURL_SSLVERSION_MAX_NONE:
    case CURL_SSLVERSION_MAX_TLSv1_3:
      ver_max = tls_protocol_version_TLSv13;
      break;
    case CURL_SSLVERSION_MAX_TLSv1_2:
      ver_max = tls_protocol_version_TLSv12;
      break;
    case CURL_SSLVERSION_MAX_TLSv1_1:
      ver_max = tls_protocol_version_TLSv11;
      break;
    case CURL_SSLVERSION_MAX_TLSv1_0:
    case CURL_SSLVERSION_TLSv1:
      ver_max = tls_protocol_version_TLSv10;
      break;
    default:
      failf(data, "SSL: unsupported maximum TLS version value");
      return CURLE_SSL_CONNECT_ERROR;
  }

  sec_protocol_options_set_min_tls_protocol_version(options, ver_min);
  sec_protocol_options_set_max_tls_protocol_version(options, ver_max);

  return CURLE_OK;
}

static int nwf_init(void)
{
  dispatch_queue_attr_t attr;

  attr = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL,
                                                 QOS_CLASS_USER_INITIATED, 0);
  nwf_queue = dispatch_queue_create("se.curl.curl", attr);
  return 1;
}

static void nwf_cleanup(void)
{
  dispatch_release(nwf_queue);
}

static size_t nwf_version(char *buffer, size_t size)
{
  CFStringRef path;
  CFURLRef url;
  CFStringRef string;
  CFBundleRef bundle;
  char version[15];
  size_t len = -1;
  CFStringEncoding encoding;

  path = CFSTR("/System/Library/Frameworks/Network.framework");
  url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                      path, kCFURLPOSIXPathStyle, true);
  bundle = CFBundleCreate(kCFAllocatorDefault, url);
  CFRelease(url);

  if(!bundle) {
    return len;
  }

  string = CFBundleGetValueForInfoDictionaryKey(bundle,
                                                kCFBundleVersionKey);
  if(!string) {
    goto out;
  }

  encoding = kCFStringEncodingUTF8;
  if(!CFStringGetCString(string, version, sizeof(version), encoding)) {
    goto out;
  }

  len = msnprintf(buffer, size, "Network/%s", version);
out:
  CFRelease(bundle);
  return len;
}

static void nwf_drain_wakeup(struct nwf_ssl_backend_data *backend)
{
  char buf[64];
  ssize_t nread;
  while(1) {
    /* the reading socket is non-blocking, try to read
       data from it until it receives an error (except EINTR).
       In normal cases it will get EAGAIN or EWOULDBLOCK
       when there is no more data, breaking the loop. */
    nread = wakeup_read(backend->signal_pipe[0], buf, sizeof(buf));
    if(nread <= 0) {
      if(nread < 0 && SOCKEINTR == SOCKERRNO)
        continue;
      break;
    }
  }
}

static void nwf_signal(struct nwf_ssl_backend_data *backend)
{
    char buf[1] = {0};
    wakeup_write(backend->signal_pipe[1], buf, sizeof(buf));
}

static nw_endpoint_t nwf_make_host_endpoint(const char *host, int port)
{
  char portstr[20];
  char hoststr[256];
  size_t len = strlen(host);

  /* NWF doesn't like trailing dots in hostnames */
  if(len > 0 && host[len - 1] == '.') {
    len--;
  }

  msnprintf(portstr, sizeof(portstr), "%i", port);
  msnprintf(hoststr, sizeof(hoststr), "%.*s", (int)len, host);

  return nw_endpoint_create_host(hoststr, portstr);
}

static CURLcode nwf_connect_start(struct Curl_cfilter *cf,
                                  struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct nwf_ssl_backend_data *backend =
    (struct nwf_ssl_backend_data *)connssl->backend;
  struct ssl_primary_config *conn_config;
  nw_endpoint_t endpoint;
  nw_parameters_t parameters;
  nw_parameters_configure_protocol_block_t configure_tls;
  nw_parameters_configure_protocol_block_t configure_tcp;
  nw_connection_state_changed_handler_t conn_handler;
#ifdef USE_ECH
  bool ech_on;
#endif
  struct Curl_dns_entry *dns = Curl_dnscache_get(data,
    connssl->peer.hostname, connssl->peer.port,
    data->set.ipver);

  backend->signal_pipe[0] = backend->signal_pipe[1] = CURL_SOCKET_BAD;
  if(wakeup_create(backend->signal_pipe, true) < 0) {
    return CURLE_SSL_CONNECT_ERROR;
  }
  data->conn->sockfd = backend->signal_pipe[0];

  backend->error = CURLE_OK;
  backend->queue = nwf_queue;

  if(dns && dns->timestamp == 0 && dns->addr && dns->addr->ai_addr) {
    struct sockaddr_storage addr;
    memcpy(&addr, dns->addr->ai_addr,
      CURLMIN(sizeof(addr), (size_t)dns->addr->ai_addrlen));
    addr.ss_len = (uint8_t)dns->addr->ai_addrlen;
    endpoint = nw_endpoint_create_address((struct sockaddr*)&addr);
  }
  else {
    endpoint = nwf_make_host_endpoint(connssl->peer.hostname,
      connssl->peer.port);
  }

  Curl_resolv_unlink(data, &dns);

  conn_config = Curl_ssl_cf_get_primary_config(cf);
  configure_tls = ^(nw_protocol_options_t tls_opts) {
    sec_protocol_options_t opts;
    sec_protocol_verify_t verify_block;
    size_t i;
    bool verify = conn_config->verifypeer;

    opts = nw_tls_copy_sec_protocol_options(tls_opts);
    sec_protocol_options_set_peer_authentication_required(opts, verify);
    nwf_set_ssl_version_min_max(data, opts, conn_config);

#ifdef USE_ECH
    ech_on = ECH_ENABLED(data);
    sec_protocol_options_set_enable_encrypted_client_hello(opts, ech_on);
#endif /* USE_ECH */

    if(connssl->peer.sni) {
      sec_protocol_options_set_tls_server_name(opts, connssl->peer.sni);
    }

    if(connssl->alpn) {
      struct alpn_proto_buf proto;
      const char *entry;

      for(i = 0; i < connssl->alpn->count; ++i) {
        entry = connssl->alpn->entries[i];
        sec_protocol_options_add_tls_application_protocol(opts, entry);
      }

      Curl_alpn_to_proto_str(&proto, connssl->alpn);
      infof(data, VTLS_INFOF_ALPN_OFFER_1STR, proto.data);
    }

    verify_block = ^(
      sec_protocol_metadata_t metadata,
      sec_trust_t trust,
      void(^completion)(bool)
    ) {
      SecTrustRef trust_ref;
      CURLcode result;
      CFErrorRef error;
      CFStringRef error_desc;
      const char *desc;
      CFIndex code;
      CFStringEncoding encoding;
      bool proceed = FALSE;
      const char *alpn;

      trust_ref = sec_trust_copy_ref(trust);
      result = apple_collect_cert_trust(cf, data, trust_ref);
      if(result) {
        failf(data, "collect_cert returned error %u", result);
      }

      error = NULL;
      if(conn_config->verifypeer) {
        result = apple_setup_trust(cf, data, trust_ref);
        if(result != CURLE_OK) {
          backend->error = result;
        }
        else {
          proceed = SecTrustEvaluateWithError(trust_ref, &error);
          if(!proceed) {
            backend->error = CURLE_PEER_FAILED_VERIFICATION;
          }
        }
      }
      else {
        proceed = TRUE;
      }

      if(error) {
        error_desc = CFErrorCopyDescription(error);
        if(error_desc) {
          encoding = CFStringGetSystemEncoding();
          desc = CFStringGetCStringPtr(error_desc, encoding);
          failf(data, "SecTrustEvaluate() returned error %s", desc);
        }
        else {
          code = CFErrorGetCode(error);
          failf(data, "SecTrustEvaluate() returned error %lu", code);
        }
      }


#ifdef APPLE_PINNEDPUBKEY
      if(proceed && data->set.str[STRING_SSL_PINNEDPUBLICKEY]) {
        result = apple_pin_peer_pubkey(data, trust_ref,
          data->set.str[STRING_SSL_PINNEDPUBLICKEY]);
        if(result) {
          failf(data, "SSL: public key does not match pinned public key");
          backend->error = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
          proceed = false;
        }
      }
#endif /* APPLE_PINNEDPUBKEY */

      alpn = sec_protocol_metadata_get_negotiated_protocol(metadata);
      if(alpn && !strcmp(alpn, ALPN_H2)) {
        backend->alpn = CURL_HTTP_VERSION_2;
      }
      else if(alpn && !strcmp(alpn, ALPN_HTTP_1_1)) {
        backend->alpn = CURL_HTTP_VERSION_1_1;
      }

      CFRelease(trust_ref);

      completion(proceed);
    };
    sec_protocol_options_set_verify_block(opts, verify_block, backend->queue);

    if(data->set.ssl.fsslctx) {
      Curl_set_in_callback(data, TRUE);
      backend->error = (*data->set.ssl.fsslctx)(
        data, opts, data->set.ssl.fsslctxp
      );
      Curl_set_in_callback(data, FALSE);
    }
  };

  configure_tcp = NW_PARAMETERS_DEFAULT_CONFIGURATION;
  parameters = nw_parameters_create_secure_tcp(configure_tls, configure_tcp);

  if(data->set.ipver != CURL_IPRESOLVE_WHATEVER) {
    nw_protocol_stack_t protocol_stack =
      nw_parameters_copy_default_protocol_stack(parameters);
    nw_protocol_options_t ip_options =
      nw_protocol_stack_copy_internet_protocol(protocol_stack);
    if(data->set.ipver == CURL_IPRESOLVE_V4) {
      nw_ip_options_set_version(ip_options, nw_ip_version_4);
    }
    else if(data->set.ipver == CURL_IPRESOLVE_V6) {
      nw_ip_options_set_version(ip_options, nw_ip_version_6);
    }
    nw_release(ip_options);
    nw_release(protocol_stack);
  }

  if(__builtin_available(macOS 11, iOS 14, tvOS 14, watchOS 7, *)) {
    if(cf->conn->bits.socksproxy || cf->conn->bits.httpproxy ||
       data->set.doh) {
      nw_privacy_context_t priv = nw_privacy_context_create("curl");

      if(data->set.doh) {
        nw_endpoint_t ep = nw_endpoint_create_url(data->set.str[STRING_DOH]);
        nw_resolver_config_t res = nw_resolver_config_create_https(ep);
        nw_privacy_context_require_encrypted_name_resolution(priv, true, res);
      }

      if(__builtin_available(macOS 14, iOS 17, tvOS 17, watchOS 10, *)) {
        if(cf->conn->bits.tunnel_proxy && cf->conn->bits.httpproxy) {
          nw_protocol_options_t opts = NULL;
          nw_proxy_config_t proxy;

          nw_endpoint_t ep = nwf_make_host_endpoint(
            cf->conn->http_proxy.host.name, cf->conn->http_proxy.port);

          if(IS_HTTPS_PROXY(cf->conn->http_proxy.proxytype)) {
            opts = nw_tls_create_options();
          }

          proxy = nw_proxy_config_create_http_connect(ep, opts);

          if(cf->conn->bits.proxy_user_passwd) {
            nw_proxy_config_set_username_and_password(proxy,
              data->state.aptr.proxyuser,
              data->state.aptr.proxypasswd);
          }

          nw_privacy_context_add_proxy(priv, proxy);
        }

        if(cf->conn->bits.socksproxy) {
          nw_proxy_config_t proxy;

          nw_endpoint_t ep = nwf_make_host_endpoint(
            cf->conn->socks_proxy.host.name, cf->conn->socks_proxy.port);

          proxy = nw_proxy_config_create_socksv5(ep);
          nw_privacy_context_add_proxy(priv, proxy);
        }
      }

      nw_parameters_set_privacy_context(parameters, priv);
    }
  }

  backend->connection = nw_connection_create(endpoint, parameters);
  nw_connection_set_queue(backend->connection, backend->queue);

  conn_handler = ^(nw_connection_state_t state, nw_error_t error) {
    if(error && !backend->error) {
      backend->error = nwf_code_from_error(error, CURLE_RECV_ERROR);
    }
    backend->state = state;

    switch(state) {
      case nw_connection_state_preparing:
        connssl->state = ssl_connection_negotiating;
        connssl->connecting_state = ssl_connect_2;
        break;

      case nw_connection_state_ready:
      case nw_connection_state_waiting:
      case nw_connection_state_invalid:
      case nw_connection_state_failed:
      default:
        backend->done_connecting = true;
        connssl->connecting_state = ssl_connect_done;
        connssl->state = ssl_connection_complete;
        nwf_signal(backend);
        break;
    }
  };
  nw_connection_set_state_changed_handler(backend->connection, conn_handler);
  nw_connection_start(backend->connection);

  return backend->error;
}

static void nwf_try_receive(struct nwf_ssl_backend_data *backend, uint32_t len)
{
  nw_connection_receive_completion_t completion = ^(dispatch_data_t content,
                 nw_content_context_t context UNUSED_PARAM,
                 bool is_complete,
                 nw_error_t error) {
    if(error) {
      backend->error = nwf_code_from_error(error, CURLE_RECV_ERROR);
    }
    else if(!content) {
      backend->done_receiving = true;
    }
    else {
      dispatch_retain(content);
      backend->recv_data = content;
      if(is_complete)
        backend->done_receiving = true;
    }
    backend->read_outstanding = false;
    nwf_signal(backend);
  };

  if(!backend->done_receiving
    && !backend->recv_data
    && !backend->read_outstanding) {
    backend->read_outstanding = true;
    nw_connection_receive(backend->connection, 1, len, completion);
  }
}

static CURLcode nwf_connect(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            bool *done)
{
  CURLcode result = CURLE_OK;
  struct ssl_connect_data *connssl = cf->ctx;
  struct nwf_ssl_backend_data *backend =
    (struct nwf_ssl_backend_data *)connssl->backend;

  if(!backend->connection) {
    result = nwf_connect_start(cf, data);
    if(result)
      return result;
  }

  if(backend->done_connecting) {
    nw_path_t path = nw_connection_copy_current_path(backend->connection);
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

    nw_connection_access_establishment_report(backend->connection,
      backend->queue, ^(nw_establishment_report_t report) {
        backend->remote_endpoint =
          nw_establishment_report_copy_proxy_endpoint(report);
        dispatch_semaphore_signal(semaphore);
      });

    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    dispatch_release(semaphore);

    if(path) {
      backend->local_endpoint = nw_path_copy_effective_local_endpoint(path);
      if(!backend->remote_endpoint)
        backend->remote_endpoint =
          nw_path_copy_effective_remote_endpoint(path);

      if(backend->remote_endpoint) {
        const struct sockaddr *addr =
          nw_endpoint_get_address(backend->remote_endpoint);
        if(addr) {
          backend->remote_addr.addrlen = addr->sa_len;
          backend->remote_addr.socktype = SOCK_STREAM;
          backend->remote_addr.protocol = IPPROTO_TCP;
          backend->remote_addr.family = addr->sa_family;
          memcpy(&backend->remote_addr.curl_sa_addr, addr, CURLMIN(
            sizeof(addr->sa_len),
            sizeof(struct Curl_sockaddr_storage)));
        }
      }

      nw_release(path);
    }

    if(backend->alpn) {
      cf->conn->alpn = backend->alpn;
    }
    else {
      infof(data, VTLS_INFOF_NO_ALPN);
    }

    *done = true;

    nwf_try_receive(backend, DEFAULT_RECEIVE_SIZE);
  }

  return backend->error;
}

static ssize_t nwf_send(struct Curl_cfilter *cf,
                        struct Curl_easy *data UNUSED_PARAM,
                        const void *buf, size_t len, CURLcode *code)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct nwf_ssl_backend_data *backend =
    (struct nwf_ssl_backend_data *)connssl->backend;
  dispatch_data_t dispatch_data;
  nw_connection_send_completion_t completion;

  nwf_drain_wakeup(backend);
  *code = CURLE_OK;

  dispatch_sync(backend->queue, ^{
    *code = backend->error;
    if(*code == CURLE_OK && backend->write_outstanding) {
      *code = CURLE_AGAIN;
    }
  });

  if(*code != CURLE_OK) {
    return -1;
  }

  dispatch_data = dispatch_data_create(buf, len, backend->queue,
                                       DISPATCH_DATA_DESTRUCTOR_DEFAULT);

  backend->write_outstanding = true;

  completion = ^(nw_error_t error) {
    if(error) {
      backend->error = nwf_code_from_error(error, CURLE_SEND_ERROR);
    }
    backend->write_outstanding = false;
    nwf_signal(backend);
  };
  nw_connection_send(backend->connection, dispatch_data,
                     NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, completion);

  *code = CURLE_OK;
  return len;
}

static CURLcode nwf_random(struct Curl_easy *data UNUSED_PARAM,
                           unsigned char *entropy, size_t length)
{
  arc4random_buf(entropy, length);
  return CURLE_OK;
}

static CURLcode nwf_sha256sum(const unsigned char *tmp, /* input */
                              size_t tmplen,
                              unsigned char *sha256sum, /* output */
                              size_t sha256len)
{
  (void)sha256len;
  assert(sha256len >= CURL_SHA256_DIGEST_LENGTH);
  (void)CC_SHA256(tmp, (CC_LONG)tmplen, sha256sum);
  return CURLE_OK;
}

static ssize_t nwf_recv(struct Curl_cfilter *cf,
                        struct Curl_easy *data UNUSED_PARAM,
                        char *buf,
                        size_t len,
                        CURLcode *err)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct nwf_ssl_backend_data *backend =
    (struct nwf_ssl_backend_data *)connssl->backend;
  dispatch_block_t block;
  __block size_t size;
  *err = CURLE_OK;

  nwf_drain_wakeup(backend);

  block = ^{
    if(backend->recv_data) {
      size_t got_size = dispatch_data_get_size(backend->recv_data);

      size = CURLMIN(got_size, len);
      size = nwf_copy_from_data(buf, len, backend->recv_data);
      if(got_size > size) {
        dispatch_data_t orig_data = backend->recv_data;
        backend->recv_data = dispatch_data_create_subrange(orig_data,
                                                           size,
                                                           got_size - size);
        dispatch_release(orig_data);
      }
      else {
        dispatch_release(backend->recv_data);
        backend->recv_data = NULL;
      }
    }
    else {
      size = -1;
      if(backend->error) {
        *err = backend->error;
      }
      else {
        if(backend->done_receiving) {
          size = 0;
        }
        else {
          *err = CURLE_AGAIN;
        }
      }
    }

    nwf_try_receive(backend, CURLMAX(
      (uint32_t)CURLMIN(len, (size_t)UINT32_MAX),
      DEFAULT_RECEIVE_SIZE));
  };
  dispatch_sync(backend->queue, block);

  return *err != CURLE_OK ? -1 : size;
}

static CURLcode nwf_shutdown(struct Curl_cfilter *cf,
                             struct Curl_easy *data UNUSED_PARAM,
                             bool send_shutdown UNUSED_PARAM, bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct nwf_ssl_backend_data *backend =
    (struct nwf_ssl_backend_data *)connssl->backend;
  dispatch_semaphore_t semaphore;
  nw_connection_state_changed_handler_t handler;
  CURLcode result;

  nwf_drain_wakeup(backend);

  result = CURLE_OK;

  if(backend->connection) {
    semaphore = dispatch_semaphore_create(0);
    handler = ^(nw_connection_state_t state, nw_error_t error) {
      if(error) {
        backend->error = nwf_code_from_error(error, CURLE_RECV_ERROR);
      }
      backend->state = state;
      switch(state) {
        case nw_connection_state_cancelled:
          *done = true;
          dispatch_semaphore_signal(semaphore);
          break;

        case nw_connection_state_invalid:
        case nw_connection_state_failed:
          backend->error = CURLE_RECV_ERROR;
          *done = true;
          dispatch_semaphore_signal(semaphore);
          break;

        default:
          break;
      }
    };
    nw_connection_set_state_changed_handler(backend->connection, handler);
    nw_connection_cancel(backend->connection);
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    dispatch_release(semaphore);
    result = backend->error;
  }

  return result;
}

static void *nwf_get_internals(struct ssl_connect_data *connssl,
                               CURLINFO info UNUSED_PARAM)
{
  struct nwf_ssl_backend_data *backend =
    (struct nwf_ssl_backend_data *)connssl->backend;
  return backend->connection;
}

static void nwf_close(struct Curl_cfilter *cf,
                      struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct nwf_ssl_backend_data *backend =
    (struct nwf_ssl_backend_data *)connssl->backend;
  if(backend->connection) {
    nw_release(backend->connection);
    backend->connection = NULL;
  }
  if(backend->recv_data) {
    dispatch_release(backend->recv_data);
    backend->recv_data = NULL;
  }
  if(backend->remote_endpoint) {
    nw_release(backend->remote_endpoint);
    backend->remote_endpoint = NULL;
  }
  if(backend->local_endpoint) {
    nw_release(backend->local_endpoint);
    backend->local_endpoint = NULL;
  }

  if(backend->signal_pipe[0] == cf->conn->sock[cf->sockindex])
    cf->conn->sock[cf->sockindex] = CURL_SOCKET_BAD;
  if(cf->sockindex == FIRSTSOCKET)
    cf->conn->remote_addr = NULL;

  Curl_multi_will_close(data, backend->signal_pipe[0]);
  wakeup_close(backend->signal_pipe[0]);
  wakeup_close(backend->signal_pipe[1]);
  backend->signal_pipe[0] = backend->signal_pipe[1] = CURL_SOCKET_BAD;

  cf->connected = FALSE;
}

static bool nwf_data_pending(struct Curl_cfilter *cf,
                             const struct Curl_easy *data UNUSED_PARAM)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct nwf_ssl_backend_data *backend =
    (struct nwf_ssl_backend_data *)connssl->backend;
  __block bool pending = FALSE;

  dispatch_sync(backend->queue, ^{
    pending = backend->recv_data != NULL || backend->done_receiving;
  });

  return pending;
}

static void nwf_update_data(struct Curl_cfilter *cf,
                            struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct nwf_ssl_backend_data *backend =
    (struct nwf_ssl_backend_data *)connssl->backend;

  /* Update the IP info held in the transfer, if we have that. */
  if(cf->connected && (cf->sockindex == FIRSTSOCKET) && backend->connection) {
    if(backend->local_endpoint) {
      const struct sockaddr *addr =
        nw_endpoint_get_address(backend->local_endpoint);
      if(addr) {
        Curl_addr2string(addr, addr->sa_len, data->info.primary.local_ip,
          &data->info.primary.local_port);
      }
    }
    if(backend->remote_endpoint) {
      const struct sockaddr *addr =
        nw_endpoint_get_address(backend->remote_endpoint);
      if(addr) {
      #ifdef USE_IPV6
        cf->conn->bits.ipv6 = (addr->sa_family == AF_INET6);
      #endif
        Curl_addr2string(addr, addr->sa_len, data->info.primary.remote_ip,
          &data->info.primary.remote_port);
      }
    }

    /* not sure if this is redundant... */
    data->info.conn_remote_port = data->info.primary.remote_port;
  }
}

static void nwf_active(struct Curl_cfilter *cf,
                       struct Curl_easy *data UNUSED_PARAM)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct nwf_ssl_backend_data *backend =
    (struct nwf_ssl_backend_data *)connssl->backend;

  /* use this socket from now on */
  cf->conn->sock[cf->sockindex] = backend->signal_pipe[0];
  if(backend->remote_endpoint)
    cf->conn->remote_addr = &backend->remote_addr;
}

static CURLcode nwf_cntrl(struct Curl_cfilter *cf,
                          struct Curl_easy *data,
                          int event, int arg1, void *arg2)
{
  (void)arg1;
  (void)arg2;
  switch(event) {
  case CF_CTRL_CONN_INFO_UPDATE:
    nwf_active(cf, data);
    nwf_update_data(cf, data);
    break;
  case CF_CTRL_DATA_SETUP:
    nwf_update_data(cf, data);
    break;
  }
  return CURLE_OK;
}

static bool nwf_is_alive(struct Curl_cfilter *cf,
                         struct Curl_easy *data UNUSED_PARAM,
                         bool *input_pending)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct nwf_ssl_backend_data *backend =
    (struct nwf_ssl_backend_data *)connssl->backend;
  __block bool ret = FALSE;

  dispatch_sync(backend->queue, ^{
    *input_pending = backend->recv_data != NULL;
    ret = backend->state == nw_connection_state_ready
      || backend->state == nw_connection_state_waiting
      || backend->state == nw_connection_state_preparing;
  });

  return ret;
}

const struct Curl_ssl Curl_ssl_nwf = {
  { CURLSSLBACKEND_NETWORKFRAMEWORK, "network-framework" }, /* info */

  SSLSUPP_CERTINFO |
#ifdef APPLE_PINNEDPUBKEY
  SSLSUPP_PINNEDPUBKEY |
#endif /* APPLE_PINNEDPUBKEY */
  SSLSUPP_SSL_CTX |
  SSLSUPP_HTTPS_PROXY |
  SSLSUPP_TLS13_CIPHERSUITES |
  SSLSUPP_CAINFO_BLOB |
#ifdef USE_ECH
  SSLSUPP_ECH |
#endif
  SSLSUPP_NO_UNDERLYING |
  SSLSUPP_CIPHER_LIST,     /* supports */

  sizeof(struct nwf_ssl_backend_data),

  nwf_init,                /* init */
  nwf_cleanup,             /* cleanup */
  nwf_version,             /* version */
  nwf_shutdown,            /* shut_down */
  nwf_data_pending,        /* data_pending */
  nwf_random,              /* random */
  NULL,                    /* cert_status_request */
  nwf_connect,             /* connect */
  Curl_ssl_adjust_pollset, /* adjust_pollset */
  nwf_get_internals,       /* get_internals */
  nwf_close,               /* close */
  NULL,                    /* close_all */
  NULL,                    /* set_engine */
  NULL,                    /* set_engine_default */
  NULL,                    /* engines_list */
  NULL,                    /* false_start */
  nwf_sha256sum,           /* sha256sum */
  nwf_recv,                /* recv_plain */
  nwf_send,                /* send_plain */
  NULL,                    /* get_channel_binding */
  nwf_cntrl,               /* cntrl */
  nwf_is_alive,            /* is_alive */
};

#endif /* USE_NWF */
