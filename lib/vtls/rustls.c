/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2020 - 2021, Jacob Hoffman-Andrews,
 * <github@hoffman-andrews.com>
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
#include "curl_setup.h"

#ifdef USE_RUSTLS

#include "curl_printf.h"

#include <errno.h>
#include <crustls.h>

#include "urldata.h"
#include "sendf.h"
#include "vtls.h"
#include "select.h"

#include "multiif.h"

struct ssl_backend_data
{
  const struct rustls_client_config *config;
  struct rustls_client_session *session;
  bool data_pending;
};

/* For a given rustls_result error code, return the best-matching CURLcode. */
static CURLcode map_error(rustls_result r)
{
  if(rustls_result_is_cert_error(r)) {
    return CURLE_PEER_FAILED_VERIFICATION;
  }
  switch(r) {
    case RUSTLS_RESULT_OK:
      return CURLE_OK;
    case RUSTLS_RESULT_NULL_PARAMETER:
      return CURLE_BAD_FUNCTION_ARGUMENT;
    default:
      return CURLE_READ_ERROR;
  }
}

static bool
cr_data_pending(const struct connectdata *conn, int sockindex)
{
  const struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *backend = connssl->backend;
  return backend->data_pending;
}

static CURLcode
cr_connect(struct Curl_easy *data UNUSED_PARAM,
                    struct connectdata *conn UNUSED_PARAM,
                    int sockindex UNUSED_PARAM)
{
  infof(data, "rustls_connect: unimplemented\n");
  return CURLE_SSL_CONNECT_ERROR;
}

/*
 * On each run:
 *  - Read a chunk of bytes from the socket into rustls' TLS input buffer.
 *  - Tell rustls to process any new packets.
 *  - Read out as many plaintext bytes from rustls as possible, until hitting
 *    error, EOF, or EAGAIN/EWOULDBLOCK, or plainbuf/plainlen is filled up.
 *
 * It's okay to call this function with plainbuf == NULL and plainlen == 0.
 * In that case, it will copy bytes from the socket into rustls' TLS input
 * buffer, and process packets, but won't consume bytes from rustls' plaintext
 * output buffer.
 */
static ssize_t
cr_recv(struct Curl_easy *data, int sockindex,
            char *plainbuf, size_t plainlen, CURLcode *err)
{
  struct connectdata *conn = data->conn;
  struct ssl_connect_data *const connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *const backend = connssl->backend;
  struct rustls_client_session *const session = backend->session;
  curl_socket_t sockfd = conn->sock[sockindex];
  /* Per https://www.bearssl.org/api1.html, max TLS record size plus max
     per-record overhead. */
  uint8_t tlsbuf[16384 + 325];
  size_t n = 0;
  ssize_t tls_bytes_read = 0;
  size_t tls_bytes_processed = 0;
  size_t plain_bytes_copied = 0;
  rustls_result rresult = 0;
  char errorbuf[255];

  tls_bytes_read = sread(sockfd, tlsbuf, sizeof(tlsbuf));
  if(tls_bytes_read == 0) {
    failf(data, "EOF in sread");
    *err = CURLE_READ_ERROR;
    return -1;
  }
  else if(tls_bytes_read < 0) {
    if(SOCKERRNO == EAGAIN || SOCKERRNO == EWOULDBLOCK) {
      infof(data, "sread: EAGAIN or EWOULDBLOCK\n");
      *err = CURLE_AGAIN;
      return -1;
    }
    failf(data, "reading from socket: %s", strerror(SOCKERRNO));
    *err = CURLE_READ_ERROR;
    return -1;
  }

  /*
  * Now pull those bytes from the buffer into ClientSession.
  */
  DEBUGASSERT(tls_bytes_read > 0);
  while(tls_bytes_processed < (size_t)tls_bytes_read) {
    rresult = rustls_client_session_read_tls(session,
      (uint8_t *)tlsbuf + tls_bytes_processed,
      tls_bytes_read - tls_bytes_processed,
      &n);
    if(rresult != RUSTLS_RESULT_OK) {
      failf(data, "error in rustls_client_session_read_tls");
      *err = CURLE_READ_ERROR;
      return -1;
    }
    else if(n == 0) {
      infof(data, "EOF from rustls_client_session_read_tls\n");
      break;
    }

    rresult = rustls_client_session_process_new_packets(session);
    if(rresult != RUSTLS_RESULT_OK) {
      rustls_error(rresult, errorbuf, sizeof(errorbuf), &n);
      failf(data, "%.*s", n, errorbuf);
      *err = map_error(rresult);
      return -1;
    }

    tls_bytes_processed += n;
    backend->data_pending = TRUE;
  }

  while(plain_bytes_copied < plainlen) {
    rresult = rustls_client_session_read(session,
      (uint8_t *)plainbuf + plain_bytes_copied,
      plainlen - plain_bytes_copied,
      &n);
    if(rresult != RUSTLS_RESULT_OK) {
      failf(data, "error in rustls_client_session_read");
      *err = CURLE_READ_ERROR;
      return -1;
    }
    else if(n == 0) {
      /* rustls returns 0 from client_session_read to mean "all currently
        available data has been read." If we bring in more ciphertext with
        read_tls, more plaintext will become available. So don't tell curl
        this is an EOF. Instead, say "come back later." */
      infof(data, "EOF from rustls_client_session_read\n");
      backend->data_pending = FALSE;
      break;
    }
    else {
      plain_bytes_copied += n;
    }
  }

  /* If we wrote out 0 plaintext bytes, it might just mean we haven't yet
     read a full TLS record. Return CURLE_AGAIN so curl doesn't treat this
     as EOF. */
  if(plain_bytes_copied == 0) {
    *err = CURLE_AGAIN;
    return -1;
  }

  return plain_bytes_copied;
}

/*
 * On each call:
 *  - Copy `plainlen` bytes into rustls' plaintext input buffer (if > 0).
 *  - Fully drain rustls' plaintext output buffer into the socket until
 *    we get either an error or EAGAIN/EWOULDBLOCK.
 *
 * It's okay to call this function with plainbuf == NULL and plainlen == 0.
 * In that case, it won't read anything into rustls' plaintext input buffer.
 * It will only drain rustls' plaintext output buffer into the socket.
 */
static ssize_t
cr_send(struct Curl_easy *data, int sockindex,
            const void *plainbuf, size_t plainlen, CURLcode *err)
{
  struct connectdata *conn = data->conn;
  struct ssl_connect_data *const connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *const backend = connssl->backend;
  struct rustls_client_session *const session = backend->session;
  curl_socket_t sockfd = conn->sock[sockindex];
  ssize_t n = 0;
  size_t plainwritten = 0;
  size_t tlslen = 0;
  size_t tlswritten = 0;
  /* Max size of a TLS message, plus some space for TLS framing overhead. */
  uint8_t tlsbuf[16384 + 325];
  rustls_result rresult;

  if(plainlen > 0) {
    rresult = rustls_client_session_write(session,
        plainbuf, plainlen, &plainwritten);
    if(rresult != RUSTLS_RESULT_OK) {
      failf(data, "error in rustls_client_session_write");
      *err = CURLE_WRITE_ERROR;
      return -1;
    }
    else if(plainwritten == 0) {
      failf(data, "EOF in rustls_client_session_write");
      *err = CURLE_WRITE_ERROR;
      return -1;
    }
  }

  while(rustls_client_session_wants_write(session)) {
    rresult = rustls_client_session_write_tls(
        session, tlsbuf, sizeof(tlsbuf), &tlslen);
    if(rresult != RUSTLS_RESULT_OK) {
      failf(data, "error in rustls_client_session_write_tls");
      *err = CURLE_WRITE_ERROR;
      return -1;
    }
    else if(tlslen == 0) {
      failf(data, "EOF in rustls_client_session_write_tls");
      *err = CURLE_WRITE_ERROR;
      return -1;
    }

    tlswritten = 0;

    while(tlswritten < tlslen) {
      n = swrite(sockfd, tlsbuf + tlswritten, tlslen - tlswritten);
      if(n < 0) {
        if(SOCKERRNO == EAGAIN || SOCKERRNO == EWOULDBLOCK) {
          /* Since recv is called from poll, there should be room to
            write at least some bytes before hitting EAGAIN. */
          infof(data, "swrite: EAGAIN after %ld bytes\n", tlswritten);
          DEBUGASSERT(tlswritten > 0);
          break;
        }
        failf(data, "error in swrite");
        *err = CURLE_WRITE_ERROR;
        return -1;
      }
      if(n == 0) {
        failf(data, "EOF in swrite");
        *err = CURLE_WRITE_ERROR;
        return -1;
      }
      tlswritten += n;
    }

    DEBUGASSERT(tlswritten <= tlslen);
  }

  return plainwritten;
}

static CURLcode
cr_connect_nonblocking(struct Curl_easy *data, struct connectdata *conn,
                                int sockindex, bool *done)
{
  struct ssl_connect_data *const connssl = &conn->ssl[sockindex];
  curl_socket_t sockfd = conn->sock[sockindex];
  struct ssl_backend_data *const backend = connssl->backend;
  struct rustls_client_session *session = backend->session;
  struct rustls_client_config_builder *config_builder = NULL;
  const char *const ssl_cafile = SSL_CONN_CONFIG(CAfile);
  CURLcode tmperr = CURLE_OK;
  int result;
  int what;
  bool wants_read;
  bool wants_write;
  curl_socket_t writefd;
  curl_socket_t readfd;
  char errorbuf[256];
  size_t errorlen;

  if(ssl_connection_none == connssl->state) {
    config_builder = rustls_client_config_builder_new();
    if(ssl_cafile) {
      result = rustls_client_config_builder_load_roots_from_file(
        config_builder, ssl_cafile);
      if(result != RUSTLS_RESULT_OK) {
        failf(data, "failed to load trusted certificates");
        rustls_client_config_free(
          rustls_client_config_builder_build(config_builder));
        return CURLE_SSL_CACERT_BADFILE;
      }
    }
    else {
      result = rustls_client_config_builder_load_native_roots(config_builder);
      if(result != RUSTLS_RESULT_OK) {
        failf(data, "failed to load trusted certificates");
        rustls_client_config_free(
          rustls_client_config_builder_build(config_builder));
        return CURLE_SSL_CACERT_BADFILE;
      }
    }

    backend->config = rustls_client_config_builder_build(config_builder);
    DEBUGASSERT(session == NULL);
    result = rustls_client_session_new(
      backend->config, conn->host.name, &session);
    if(result != RUSTLS_RESULT_OK) {
      rustls_error(result, errorbuf, sizeof(errorbuf), &errorlen);
      failf(data, "failed to create client session: %.*s", errorlen, errorbuf);
      return CURLE_COULDNT_CONNECT;
    }
    backend->session = session;
    connssl->state = ssl_connection_negotiating;
  }

  /* Read/write data until the handshake is done or the socket would block. */
  for(;;) {
    /*
    * Connection has been established according to rustls. Set send/recv
    * handlers, and update the state machine.
    * This check has to come last because is_handshaking starts out false,
    * then becomes true when we first write data, then becomes false again
    * once the handshake is done.
    */
    if(!rustls_client_session_is_handshaking(session)) {
      infof(data, "Done handshaking\n");
      /* Done with the handshake. Set up callbacks to send/receive data. */
      connssl->state = ssl_connection_complete;
      conn->recv[sockindex] = cr_recv;
      conn->send[sockindex] = cr_send;
      *done = TRUE;
      return CURLE_OK;
    }

    wants_read = rustls_client_session_wants_read(session);
    wants_write = rustls_client_session_wants_write(session);
    DEBUGASSERT(wants_read || wants_write);
    writefd = wants_write?sockfd:CURL_SOCKET_BAD;
    readfd = wants_read?sockfd:CURL_SOCKET_BAD;

    what = Curl_socket_check(readfd, CURL_SOCKET_BAD, writefd, 0);
    if(what < 0) {
      /* fatal error */
      failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
      return CURLE_SSL_CONNECT_ERROR;
    }
    if(0 == what) {
      infof(data, "Curl_socket_check: %s would block\n",
          wants_read&&wants_write ?
            "writing and reading" :
            wants_write ?
              "writing" :
              "reading");
      *done = FALSE;
      return CURLE_OK;
    }
    /* socket is readable or writable */

    if(wants_write) {
      infof(data, "ClientSession wants us to write_tls.\n");
      cr_send(data, sockindex, NULL, 0, &tmperr);
      if(tmperr == CURLE_AGAIN) {
        infof(data, "writing would block\n");
        /* fall through */
      }
      else if(tmperr != CURLE_OK) {
        return tmperr;
      }
    }

    if(wants_read) {
      infof(data, "ClientSession wants us to read_tls.\n");

      cr_recv(data, sockindex, NULL, 0, &tmperr);
      if(tmperr == CURLE_AGAIN) {
        infof(data, "reading would block\n");
        /* fall through */
      }
      else if(tmperr != CURLE_OK) {
        if(tmperr == CURLE_READ_ERROR) {
          return CURLE_SSL_CONNECT_ERROR;
        }
        else {
          return tmperr;
        }
      }
    }
  }

  /* We should never fall through the loop. We should return either because
     the handshake is done or because we can't read/write without blocking. */
  DEBUGASSERT(false);
}

/* returns a bitmap of flags for this connection's first socket indicating
   whether we want to read or write */
static int
cr_getsock(struct connectdata *conn, curl_socket_t *socks)
{
  struct ssl_connect_data *const connssl = &conn->ssl[FIRSTSOCKET];
  curl_socket_t sockfd = conn->sock[FIRSTSOCKET];
  struct ssl_backend_data *const backend = connssl->backend;
  struct rustls_client_session *session = backend->session;

  if(rustls_client_session_wants_write(session)) {
    socks[0] = sockfd;
    return GETSOCK_WRITESOCK(0);
  }
  if(rustls_client_session_wants_read(session)) {
    socks[0] = sockfd;
    return GETSOCK_READSOCK(0);
  }

  return GETSOCK_BLANK;
}

static void *
cr_get_internals(struct ssl_connect_data *connssl,
                          CURLINFO info UNUSED_PARAM)
{
  struct ssl_backend_data *backend = connssl->backend;
  return &backend->session;
}

static void
cr_close(struct Curl_easy *data, struct connectdata *conn,
                  int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *backend = connssl->backend;
  CURLcode tmperr = CURLE_OK;
  ssize_t n = 0;

  if(backend->session) {
    rustls_client_session_send_close_notify(backend->session);
    n = cr_send(data, sockindex, NULL, 0, &tmperr);
    if(n < 0) {
      failf(data, "error sending close notify: %d", tmperr);
    }

    rustls_client_session_free(backend->session);
    backend->session = NULL;
  }
  if(backend->config) {
    rustls_client_config_free(backend->config);
    backend->config = NULL;
  }
}

const struct Curl_ssl Curl_ssl_rustls = {
  { CURLSSLBACKEND_RUSTLS, "rustls" },
  SSLSUPP_TLS13_CIPHERSUITES,      /* supports */
  sizeof(struct ssl_backend_data),

  Curl_none_init,                  /* init */
  Curl_none_cleanup,               /* cleanup */
  rustls_version,                  /* version */
  Curl_none_check_cxn,             /* check_cxn */
  Curl_none_shutdown,              /* shutdown */
  cr_data_pending,                 /* data_pending */
  Curl_none_random,                /* random */
  Curl_none_cert_status_request,   /* cert_status_request */
  cr_connect,                      /* connect */
  cr_connect_nonblocking,          /* connect_nonblocking */
  cr_getsock,                      /* cr_getsock */
  cr_get_internals,                /* get_internals */
  cr_close,                        /* close_one */
  Curl_none_close_all,             /* close_all */
  Curl_none_session_free,          /* session_free */
  Curl_none_set_engine,            /* set_engine */
  Curl_none_set_engine_default,    /* set_engine_default */
  Curl_none_engines_list,          /* engines_list */
  Curl_none_false_start,           /* false_start */
  NULL                             /* sha256sum */
};

#endif /* USE_RUSTLS */
