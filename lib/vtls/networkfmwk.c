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
 ***************************************************************************/

#include "networkfmwk.h"
#include "curl/curl.h"

#ifdef USE_NETWORKFMWK

#include "urldata.h"
#include "cfilters.h"
#include "vtls.h"
#include "vtls_int.h"
#include "sendf.h"
#include "connect.h"
#include "strerror.h"
#include "select.h"
#include "multiif.h"
#include "curl_printf.h"
#include "security.h"
#include <Network/Network.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>

/* The last #include file should be: */
#include "curl_memory.h"
#include "memdebug.h"

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

struct network_data {
    dispatch_data_t data;
    struct Curl_llist_node storage;
};

struct network_ssl_backend_data {
  nw_connection_t connection;
  dispatch_queue_t queue;
  bool done_connecting;
  bool done_receiving;
  struct Curl_llist recv_queue;
  CURLcode error;
};

static dispatch_queue_t network_queue;

static void network_data_dtor(void *user UNUSED_PARAM, void *elem)
{
  struct network_data *node = (struct network_data *)elem;
  dispatch_release(node->data);
  free(elem);
}

static CURLcode
network_code_from_error(nw_error_t error)
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
      result = CURLE_WRITE_ERROR;
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
network_copy_from_data(char *buf, size_t len, dispatch_data_t data)
{
  dispatch_data_applier_t applier;
  size_t size;

  size = dispatch_data_get_size(data);
  if(size > len)
    size = len;

  applier = ^bool(dispatch_data_t region UNUSED_PARAM, size_t offset,
                  const void *buffer, size_t buffer_size) {
    memcpy(buf + offset, buffer, buffer_size);
    return true;
  };
  dispatch_data_apply(data, applier);

  return size;
}

static CURLcode
network_set_ssl_version_min_max(struct Curl_easy *data,
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

static int network_init(void)
{
  dispatch_queue_attr_t attr;

  attr = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL,
                                                 QOS_CLASS_USER_INITIATED, 0);
  network_queue = dispatch_queue_create("se.curl.curl", attr);
  return 1;
}

static void network_cleanup(void)
{
  dispatch_release(network_queue);
}

static size_t network_version(char *buffer, size_t size)
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

static CURLcode network_connect_start(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      bool *done)
{
  char port[20];
  struct ssl_connect_data *connssl = cf->ctx;
  struct network_ssl_backend_data *backend =
    (struct network_ssl_backend_data *)connssl->backend;
  struct ssl_primary_config *conn_config;
  nw_endpoint_t endpoint;
  nw_parameters_t parameters;
  nw_parameters_configure_protocol_block_t configure_tls;
  nw_parameters_configure_protocol_block_t configure_tcp;
  dispatch_semaphore_t semaphore;
  nw_connection_state_changed_handler_t handler;
  nw_connection_state_changed_handler_t conn_handler;
#ifdef USE_ECH
  bool ech_on;
#endif

  backend->error = CURLE_OK;
  backend->queue = network_queue;
  Curl_llist_init(&backend->recv_queue, network_data_dtor);

  msnprintf(port, sizeof(port), "%i", connssl->peer.port);
  endpoint = nw_endpoint_create_host(connssl->peer.hostname, port);

  conn_config = Curl_ssl_cf_get_primary_config(cf);
  configure_tls = ^(nw_protocol_options_t tls_opts) {
    sec_protocol_options_t opts;
    sec_protocol_verify_t verify_block;
    size_t i;
    bool verify = conn_config->verifypeer;

    opts = nw_tls_copy_sec_protocol_options(tls_opts);
    sec_protocol_options_set_peer_authentication_required(opts, verify);
    network_set_ssl_version_min_max(data, opts, conn_config);

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
      CURLcode collect_result;
      CFErrorRef error;
      CFStringRef error_desc;
      const char *desc;
      CFIndex code;
      CFStringEncoding encoding;
      bool proceed;

      trust_ref = sec_trust_copy_ref(trust);
      collect_result = security_collect_cert_trust(cf, data, trust_ref);
      if(collect_result) {
        failf(data, "collect_cert returned error %u", collect_result);
      }

      error = NULL;
      if(conn_config->verifypeer) {
        proceed = SecTrustEvaluateWithError(trust_ref, &error);
      }
      else {
        proceed = true;
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

  backend->connection = nw_connection_create(endpoint, parameters);
  nw_connection_set_queue(backend->connection, backend->queue);

  handler = ^(nw_connection_state_t state UNUSED_PARAM, nw_error_t error) {
    if(error) {
      backend->error = network_code_from_error(error);
    }
  };

  semaphore = dispatch_semaphore_create(0);
  conn_handler = ^(nw_connection_state_t state, nw_error_t error) {
    handler(state, error);

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
        *done = true;
        dispatch_semaphore_signal(semaphore);
        break;
    }
  };
  nw_connection_set_state_changed_handler(backend->connection, conn_handler);
  nw_connection_start(backend->connection);
  dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
  nw_connection_set_state_changed_handler(backend->connection, handler);
  dispatch_release(semaphore);

  return backend->error;
}

static CURLcode network_connect(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                bool *done)
{
  CURLcode result = CURLE_OK;
  struct ssl_connect_data *connssl = cf->ctx;
  struct network_ssl_backend_data *backend =
    (struct network_ssl_backend_data *)connssl->backend;

  if(!backend->connection) {
    result = network_connect_start(cf, data, done);
    if(result)
      return result;
  }

  if(backend->done_connecting) {
    *done = true;
  }

  return backend->error;
}

static ssize_t network_send(struct Curl_cfilter *cf,
                            struct Curl_easy *data UNUSED_PARAM,
                            const void *buf, size_t len, CURLcode *code)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct network_ssl_backend_data *backend =
    (struct network_ssl_backend_data *)connssl->backend;
  void *copy;
  dispatch_semaphore_t semaphore;
  dispatch_data_t dispatch_data;
  __block ssize_t bytes_written = -1;
  nw_connection_send_completion_t completion;

  copy = malloc(len);
  memcpy(copy, buf, len);
  dispatch_data = dispatch_data_create(copy, len, backend->queue,
                                       DISPATCH_DATA_DESTRUCTOR_FREE);

  semaphore = dispatch_semaphore_create(0);

  completion = ^(nw_error_t error) {
    if(error) {
      *code = network_code_from_error(error);
    }
    else {
      bytes_written = len;
      *code = CURLE_OK;
    }
    dispatch_semaphore_signal(semaphore);
  };
  nw_connection_send(backend->connection, dispatch_data,
                     NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, completion);
  dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
  dispatch_release(semaphore);

  return bytes_written;
}

static CURLcode network_random(struct Curl_easy *data UNUSED_PARAM,
                               unsigned char *entropy, size_t length)
{
  arc4random_buf(entropy, length);
  return CURLE_OK;
}

static CURLcode network_sha256sum(const unsigned char *tmp, /* input */
                                  size_t tmplen,
                                  unsigned char *sha256sum, /* output */
                                  size_t sha256len)
{
  (void)sha256len;
  assert(sha256len >= CURL_SHA256_DIGEST_LENGTH);
  (void)CC_SHA256(tmp, (CC_LONG)tmplen, sha256sum);
  return CURLE_OK;
}

static ssize_t network_recv(struct Curl_cfilter *cf,
                            struct Curl_easy *data UNUSED_PARAM,
                            char *buf,
                            size_t len,
                            CURLcode *err)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct network_ssl_backend_data *backend =
    (struct network_ssl_backend_data *)connssl->backend;
  nw_connection_receive_completion_t completion;
  dispatch_block_t block;
  __block ssize_t size;

  completion = ^(dispatch_data_t content,
                 nw_content_context_t context UNUSED_PARAM,
                 bool is_complete UNUSED_PARAM,
                 nw_error_t error) {
    if(error) {
      backend->error = network_code_from_error(error);
    }
    else if(!content) {
      backend->done_receiving = true;
      size = 0; /* EOF */
    }
    else {
      struct network_data *recv_data = malloc(sizeof(struct network_data));
      dispatch_retain(content);
      recv_data->data = content;
      Curl_llist_append(&backend->recv_queue, recv_data, &recv_data->storage);
    }
  };

  block = ^{
    struct Curl_llist_node *iter;
    struct network_data *node;
    size_t node_size;
    dispatch_data_t orig_data;

    if(!backend->done_receiving) {
      nw_connection_receive(backend->connection, 1, (uint32_t)len, completion);
    }

    iter = Curl_llist_head(&backend->recv_queue);
    if(iter) {
      node = Curl_node_elem(iter);
      node_size = dispatch_data_get_size(node->data);

      size = CURLMIN(node_size, len);
      size = network_copy_from_data(buf, len, node->data);
      if(node_size > len) {
        orig_data = node->data;
        node->data = dispatch_data_create_subrange(orig_data,
                                                    len,
                                                    node_size - len);
        dispatch_release(orig_data);
      }
      else {
        Curl_node_uremove(&node->storage, NULL);
      }
    }
    else {
      size = -1;
      if(backend->error) {
        *err = backend->error;
      }
      else {
        *err = CURLE_AGAIN;
      }
    }
  };
  dispatch_sync(backend->queue, block);

  return size;
}

static CURLcode network_shutdown(struct Curl_cfilter *cf,
                                 struct Curl_easy *data UNUSED_PARAM,
                                 bool send_shutdown UNUSED_PARAM, bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct network_ssl_backend_data *backend =
    (struct network_ssl_backend_data *)connssl->backend;
  dispatch_semaphore_t semaphore;
  nw_connection_state_changed_handler_t handler;
  CURLcode result;

  result = CURLE_OK;

  if(backend->connection) {
    semaphore = dispatch_semaphore_create(0);
    handler = ^(nw_connection_state_t state, nw_error_t error) {
      if(error) {
        backend->error = network_code_from_error(error);
      }
      switch(state) {
        case nw_connection_state_cancelled:
          *done = true;
          dispatch_semaphore_signal(semaphore);
          break;

        case nw_connection_state_invalid:
        case nw_connection_state_failed:
          backend->error = CURLE_READ_ERROR;
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

static void *network_get_internals(struct ssl_connect_data *connssl,
                                   CURLINFO info UNUSED_PARAM)
{
  struct network_ssl_backend_data *backend =
    (struct network_ssl_backend_data *)connssl->backend;
  return backend->connection;
}

static void network_close(struct Curl_cfilter *cf UNUSED_PARAM,
                          struct Curl_easy *data UNUSED_PARAM)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct network_ssl_backend_data *backend =
    (struct network_ssl_backend_data *)connssl->backend;
  if(backend->connection) {
    nw_release(backend->connection);
    backend->connection = NULL;
  }
  Curl_llist_destroy(&backend->recv_queue, NULL);
}

static bool network_data_pending(struct Curl_cfilter *cf UNUSED_PARAM,
                                 const struct Curl_easy *data UNUSED_PARAM)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct network_ssl_backend_data *backend =
    (struct network_ssl_backend_data *)connssl->backend;
  __block bool pending = FALSE;

  dispatch_sync(backend->queue, ^{
    pending = (Curl_llist_count(&backend->recv_queue) > 0);
  });

  return pending;
}

const struct Curl_ssl Curl_ssl_networkfmwk = {
  { CURLSSLBACKEND_NETWORKFRAMEWORK, "network-framework" }, /* info */

  SSLSUPP_CERTINFO |
  /* SSLSUPP_PINNEDPUBKEY | */
  SSLSUPP_SSL_CTX |
  SSLSUPP_HTTPS_PROXY |
  SSLSUPP_TLS13_CIPHERSUITES |
  SSLSUPP_CAINFO_BLOB |
#ifdef USE_ECH
  SSLSUPP_ECH |
#endif
  SSLSUPP_CIPHER_LIST,     /* supports */

  sizeof(struct network_ssl_backend_data),

  network_init,            /* init */
  network_cleanup,         /* cleanup */
  network_version,         /* version */
  network_shutdown,        /* shut_down */
  network_data_pending,    /* data_pending */
  network_random,          /* random */
  NULL,                    /* cert_status_request */
  network_connect,         /* connect */
  Curl_ssl_adjust_pollset, /* adjust_pollset */
  network_get_internals,   /* get_internals */
  network_close,           /* close */
  NULL,                    /* close_all */
  NULL,                    /* set_engine */
  NULL,                    /* set_engine_default */
  NULL,                    /* engines_list */
  NULL,                    /* false_start */
  network_sha256sum,       /* sha256sum */
  network_recv,            /* recv_plain */
  network_send,            /* send_plain */
  NULL                     /* get_channel_binding */
};

#endif /* USE_NETWORKFMWK */
