/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/* This file is for implementing all "generic" SSL functions that all libcurl
   internals should use. It is then responsible for calling the proper
   "backend" function.

   SSL-functions in libcurl should call functions in this source file, and not
   to any specific SSL-layer.

   Curl_ssl_ - prefix for generic ones
   Curl_ossl_ - prefix for OpenSSL ones
   Curl_gtls_ - prefix for GnuTLS ones
   Curl_nss_ - prefix for NSS ones
   Curl_gskit_ - prefix for GSKit ones
   Curl_polarssl_ - prefix for PolarSSL ones
   Curl_cyassl_ - prefix for CyaSSL ones
   Curl_schannel_ - prefix for Schannel SSPI ones
   Curl_darwinssl_ - prefix for SecureTransport (Darwin) ones

   Note that this source code uses curlssl_* functions, and they are all
   defines/macros #defined by the lib-specific header files.

   "SSL/TLS Strong Encryption: An Introduction"
   https://httpd.apache.org/docs/2.0/ssl/ssl_intro.html
*/

#include "curl_setup.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include "urldata.h"

#include "vtls.h" /* generic SSL protos etc */
#include "slist.h"
#include "sendf.h"
#include "strcase.h"
#include "url.h"
#include "progress.h"
#include "share.h"
#include "multiif.h"
#include "timeval.h"
#include "curl_md5.h"
#include "warnless.h"
#include "curl_base64.h"
#include "curl_printf.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

/* convenience macro to check if this handle is using a shared SSL session */
#define SSLSESSION_SHARED(data) (data->share &&                        \
                                 (data->share->specifier &             \
                                  (1<<CURL_LOCK_DATA_SSL_SESSION)))

#define CLONE_STRING(var)                    \
  if(source->var) {                          \
    dest->var = strdup(source->var);         \
    if(!dest->var)                           \
      return FALSE;                          \
  }                                          \
  else                                       \
    dest->var = NULL;

bool
Curl_ssl_config_matches(struct ssl_primary_config* data,
                        struct ssl_primary_config* needle)
{
  if((data->version == needle->version) &&
     (data->verifypeer == needle->verifypeer) &&
     (data->verifyhost == needle->verifyhost) &&
     Curl_safe_strcasecompare(data->CApath, needle->CApath) &&
     Curl_safe_strcasecompare(data->CAfile, needle->CAfile) &&
     Curl_safe_strcasecompare(data->clientcert, needle->clientcert) &&
     Curl_safe_strcasecompare(data->cipher_list, needle->cipher_list))
    return TRUE;

  return FALSE;
}

bool
Curl_clone_primary_ssl_config(struct ssl_primary_config *source,
                              struct ssl_primary_config *dest)
{
  dest->verifyhost = source->verifyhost;
  dest->verifypeer = source->verifypeer;
  dest->version = source->version;

  CLONE_STRING(CAfile);
  CLONE_STRING(CApath);
  CLONE_STRING(cipher_list);
  CLONE_STRING(egdsocket);
  CLONE_STRING(random_file);
  CLONE_STRING(clientcert);
  return TRUE;
}

void Curl_free_primary_ssl_config(struct ssl_primary_config* sslc)
{
  Curl_safefree(sslc->CAfile);
  Curl_safefree(sslc->CApath);
  Curl_safefree(sslc->cipher_list);
  Curl_safefree(sslc->egdsocket);
  Curl_safefree(sslc->random_file);
  Curl_safefree(sslc->clientcert);
}

int Curl_ssl_backend(void)
{
  return (int)CURL_SSL_BACKEND;
}

#ifdef USE_SSL

/* "global" init done? */
static bool init_ssl=FALSE;

/**
 * Global SSL init
 *
 * @retval 0 error initializing SSL
 * @retval 1 SSL initialized successfully
 */
int Curl_ssl_init(void)
{
  /* make sure this is only done once */
  if(init_ssl)
    return 1;
  init_ssl = TRUE; /* never again */

  return curlssl_init();
}


/* Global cleanup */
void Curl_ssl_cleanup(void)
{
  if(init_ssl) {
    /* only cleanup if we did a previous init */
    curlssl_cleanup();
    init_ssl = FALSE;
  }
}

static bool ssl_prefs_check(struct Curl_easy *data)
{
  /* check for CURLOPT_SSLVERSION invalid parameter value */
  if((data->set.ssl.primary.version < 0)
     || (data->set.ssl.primary.version >= CURL_SSLVERSION_LAST)) {
    failf(data, "Unrecognized parameter value passed via CURLOPT_SSLVERSION");
    return FALSE;
  }
  return TRUE;
}

static CURLcode
ssl_connect_init_proxy(struct connectdata *conn, int sockindex)
{
  DEBUGASSERT(conn->bits.proxy_ssl_connected[sockindex]);
  if(ssl_connection_complete == conn->ssl[sockindex].state &&
     !conn->proxy_ssl[sockindex].use) {
#if defined(HTTPS_PROXY_SUPPORT)
    conn->proxy_ssl[sockindex] = conn->ssl[sockindex];
    memset(&conn->ssl[sockindex], 0, sizeof(conn->ssl[sockindex]));
#else
    return CURLE_NOT_BUILT_IN;
#endif
  }
  return CURLE_OK;
}

CURLcode
Curl_ssl_connect(struct connectdata *conn, int sockindex)
{
  CURLcode result;

  if(conn->bits.proxy_ssl_connected[sockindex]) {
    result = ssl_connect_init_proxy(conn, sockindex);
    if(result)
      return result;
  }

  if(!ssl_prefs_check(conn->data))
    return CURLE_SSL_CONNECT_ERROR;

  /* mark this is being ssl-enabled from here on. */
  conn->ssl[sockindex].use = TRUE;
  conn->ssl[sockindex].state = ssl_connection_negotiating;

  result = curlssl_connect(conn, sockindex);

  if(!result)
    Curl_pgrsTime(conn->data, TIMER_APPCONNECT); /* SSL is connected */

  return result;
}

CURLcode
Curl_ssl_connect_nonblocking(struct connectdata *conn, int sockindex,
                             bool *done)
{
  CURLcode result;
  if(conn->bits.proxy_ssl_connected[sockindex]) {
    result = ssl_connect_init_proxy(conn, sockindex);
    if(result)
      return result;
  }

  if(!ssl_prefs_check(conn->data))
    return CURLE_SSL_CONNECT_ERROR;

  /* mark this is being ssl requested from here on. */
  conn->ssl[sockindex].use = TRUE;
#ifdef curlssl_connect_nonblocking
  result = curlssl_connect_nonblocking(conn, sockindex, done);
#else
  *done = TRUE; /* fallback to BLOCKING */
  result = curlssl_connect(conn, sockindex);
#endif /* non-blocking connect support */
  if(!result && *done)
    Curl_pgrsTime(conn->data, TIMER_APPCONNECT); /* SSL is connected */
  return result;
}

/*
 * Lock shared SSL session data
 */
void Curl_ssl_sessionid_lock(struct connectdata *conn)
{
  if(SSLSESSION_SHARED(conn->data))
    Curl_share_lock(conn->data,
                    CURL_LOCK_DATA_SSL_SESSION, CURL_LOCK_ACCESS_SINGLE);
}

/*
 * Unlock shared SSL session data
 */
void Curl_ssl_sessionid_unlock(struct connectdata *conn)
{
  if(SSLSESSION_SHARED(conn->data))
    Curl_share_unlock(conn->data, CURL_LOCK_DATA_SSL_SESSION);
}

/*
 * Check if there's a session ID for the given connection in the cache, and if
 * there's one suitable, it is provided. Returns TRUE when no entry matched.
 */
bool Curl_ssl_getsessionid(struct connectdata *conn,
                           void **ssl_sessionid,
                           size_t *idsize, /* set 0 if unknown */
                           int sockindex)
{
  struct curl_ssl_session *check;
  struct Curl_easy *data = conn->data;
  size_t i;
  long *general_age;
  bool no_match = TRUE;

  const bool isProxy = CONNECT_PROXY_SSL();
  struct ssl_primary_config * const ssl_config = isProxy ?
                                                 &conn->proxy_ssl_config :
                                                 &conn->ssl_config;
  const char * const name = isProxy ? conn->http_proxy.host.name :
                                      conn->host.name;
  int port = isProxy ? (int)conn->port : conn->remote_port;
  *ssl_sessionid = NULL;

  DEBUGASSERT(data->set.general_ssl.sessionid);

  if(!data->set.general_ssl.sessionid)
    /* session ID re-use is disabled */
    return TRUE;

  /* Lock if shared */
  if(SSLSESSION_SHARED(data))
    general_age = &data->share->sessionage;
  else
    general_age = &data->state.sessionage;

  for(i = 0; i < data->set.general_ssl.max_ssl_sessions; i++) {
    check = &data->state.session[i];
    if(!check->sessionid)
      /* not session ID means blank entry */
      continue;
    if(strcasecompare(name, check->name) &&
       ((!conn->bits.conn_to_host && !check->conn_to_host) ||
        (conn->bits.conn_to_host && check->conn_to_host &&
         strcasecompare(conn->conn_to_host.name, check->conn_to_host))) &&
       ((!conn->bits.conn_to_port && check->conn_to_port == -1) ||
        (conn->bits.conn_to_port && check->conn_to_port != -1 &&
         conn->conn_to_port == check->conn_to_port)) &&
       (port == check->remote_port) &&
       strcasecompare(conn->handler->scheme, check->scheme) &&
       Curl_ssl_config_matches(ssl_config, &check->ssl_config)) {
      /* yes, we have a session ID! */
      (*general_age)++;          /* increase general age */
      check->age = *general_age; /* set this as used in this age */
      *ssl_sessionid = check->sessionid;
      if(idsize)
        *idsize = check->idsize;
      no_match = FALSE;
      break;
    }
  }

  return no_match;
}

/*
 * Kill a single session ID entry in the cache.
 */
void Curl_ssl_kill_session(struct curl_ssl_session *session)
{
  if(session->sessionid) {
    /* defensive check */

    /* free the ID the SSL-layer specific way */
    curlssl_session_free(session->sessionid);

    session->sessionid = NULL;
    session->age = 0; /* fresh */

    Curl_free_primary_ssl_config(&session->ssl_config);

    Curl_safefree(session->name);
    Curl_safefree(session->conn_to_host);
  }
}

/*
 * Delete the given session ID from the cache.
 */
void Curl_ssl_delsessionid(struct connectdata *conn, void *ssl_sessionid)
{
  size_t i;
  struct Curl_easy *data=conn->data;

  for(i = 0; i < data->set.general_ssl.max_ssl_sessions; i++) {
    struct curl_ssl_session *check = &data->state.session[i];

    if(check->sessionid == ssl_sessionid) {
      Curl_ssl_kill_session(check);
      break;
    }
  }
}

/*
 * Store session id in the session cache. The ID passed on to this function
 * must already have been extracted and allocated the proper way for the SSL
 * layer. Curl_XXXX_session_free() will be called to free/kill the session ID
 * later on.
 */
CURLcode Curl_ssl_addsessionid(struct connectdata *conn,
                               void *ssl_sessionid,
                               size_t idsize,
                               int sockindex)
{
  size_t i;
  struct Curl_easy *data=conn->data; /* the mother of all structs */
  struct curl_ssl_session *store = &data->state.session[0];
  long oldest_age=data->state.session[0].age; /* zero if unused */
  char *clone_host;
  char *clone_conn_to_host;
  int conn_to_port;
  long *general_age;
  const bool isProxy = CONNECT_PROXY_SSL();
  struct ssl_primary_config * const ssl_config = isProxy ?
                                           &conn->proxy_ssl_config :
                                           &conn->ssl_config;

  DEBUGASSERT(data->set.general_ssl.sessionid);

  clone_host = strdup(isProxy ? conn->http_proxy.host.name : conn->host.name);
  if(!clone_host)
    return CURLE_OUT_OF_MEMORY; /* bail out */

  if(conn->bits.conn_to_host) {
    clone_conn_to_host = strdup(conn->conn_to_host.name);
    if(!clone_conn_to_host) {
      free(clone_host);
      return CURLE_OUT_OF_MEMORY; /* bail out */
    }
  }
  else
    clone_conn_to_host = NULL;

  if(conn->bits.conn_to_port)
    conn_to_port = conn->conn_to_port;
  else
    conn_to_port = -1;

  /* Now we should add the session ID and the host name to the cache, (remove
     the oldest if necessary) */

  /* If using shared SSL session, lock! */
  if(SSLSESSION_SHARED(data)) {
    general_age = &data->share->sessionage;
  }
  else {
    general_age = &data->state.sessionage;
  }

  /* find an empty slot for us, or find the oldest */
  for(i = 1; (i < data->set.general_ssl.max_ssl_sessions) &&
        data->state.session[i].sessionid; i++) {
    if(data->state.session[i].age < oldest_age) {
      oldest_age = data->state.session[i].age;
      store = &data->state.session[i];
    }
  }
  if(i == data->set.general_ssl.max_ssl_sessions)
    /* cache is full, we must "kill" the oldest entry! */
    Curl_ssl_kill_session(store);
  else
    store = &data->state.session[i]; /* use this slot */

  /* now init the session struct wisely */
  store->sessionid = ssl_sessionid;
  store->idsize = idsize;
  store->age = *general_age;    /* set current age */
    /* free it if there's one already present */
  free(store->name);
  free(store->conn_to_host);
  store->name = clone_host;               /* clone host name */
  store->conn_to_host = clone_conn_to_host; /* clone connect to host name */
  store->conn_to_port = conn_to_port; /* connect to port number */
  /* port number */
  store->remote_port = isProxy ? (int)conn->port : conn->remote_port;
  store->scheme = conn->handler->scheme;

  if(!Curl_clone_primary_ssl_config(ssl_config, &store->ssl_config)) {
    store->sessionid = NULL; /* let caller free sessionid */
    free(clone_host);
    free(clone_conn_to_host);
    return CURLE_OUT_OF_MEMORY;
  }

  return CURLE_OK;
}


void Curl_ssl_close_all(struct Curl_easy *data)
{
  size_t i;
  /* kill the session ID cache if not shared */
  if(data->state.session && !SSLSESSION_SHARED(data)) {
    for(i = 0; i < data->set.general_ssl.max_ssl_sessions; i++)
      /* the single-killer function handles empty table slots */
      Curl_ssl_kill_session(&data->state.session[i]);

    /* free the cache data */
    Curl_safefree(data->state.session);
  }

  curlssl_close_all(data);
}

#if defined(USE_SSLEAY) || defined(USE_GNUTLS) || defined(USE_SCHANNEL) || \
    defined(USE_DARWINSSL) || defined(USE_NSS)
/* This function is for OpenSSL, GnuTLS, darwinssl, and schannel only. */
int Curl_ssl_getsock(struct connectdata *conn, curl_socket_t *socks,
                     int numsocks)
{
  struct ssl_connect_data *connssl = &conn->ssl[FIRSTSOCKET];

  if(!numsocks)
    return GETSOCK_BLANK;

  if(connssl->connecting_state == ssl_connect_2_writing) {
    /* write mode */
    socks[0] = conn->sock[FIRSTSOCKET];
    return GETSOCK_WRITESOCK(0);
  }
  else if(connssl->connecting_state == ssl_connect_2_reading) {
    /* read mode */
    socks[0] = conn->sock[FIRSTSOCKET];
    return GETSOCK_READSOCK(0);
  }

  return GETSOCK_BLANK;
}
#else
int Curl_ssl_getsock(struct connectdata *conn,
                          curl_socket_t *socks,
                          int numsocks)
{
  (void)conn;
  (void)socks;
  (void)numsocks;
  return GETSOCK_BLANK;
}
/* USE_SSLEAY || USE_GNUTLS || USE_SCHANNEL || USE_DARWINSSL || USE_NSS */
#endif

void Curl_ssl_close(struct connectdata *conn, int sockindex)
{
  DEBUGASSERT((sockindex <= 1) && (sockindex >= -1));
  curlssl_close(conn, sockindex);
}

CURLcode Curl_ssl_shutdown(struct connectdata *conn, int sockindex)
{
  if(curlssl_shutdown(conn, sockindex))
    return CURLE_SSL_SHUTDOWN_FAILED;

  conn->ssl[sockindex].use = FALSE; /* get back to ordinary socket usage */
  conn->ssl[sockindex].state = ssl_connection_none;

  conn->recv[sockindex] = Curl_recv_plain;
  conn->send[sockindex] = Curl_send_plain;

  return CURLE_OK;
}

/* Selects an SSL crypto engine
 */
CURLcode Curl_ssl_set_engine(struct Curl_easy *data, const char *engine)
{
  return curlssl_set_engine(data, engine);
}

/* Selects the default SSL crypto engine
 */
CURLcode Curl_ssl_set_engine_default(struct Curl_easy *data)
{
  return curlssl_set_engine_default(data);
}

/* Return list of OpenSSL crypto engine names. */
struct curl_slist *Curl_ssl_engines_list(struct Curl_easy *data)
{
  return curlssl_engines_list(data);
}

/*
 * This sets up a session ID cache to the specified size. Make sure this code
 * is agnostic to what underlying SSL technology we use.
 */
CURLcode Curl_ssl_initsessions(struct Curl_easy *data, size_t amount)
{
  struct curl_ssl_session *session;

  if(data->state.session)
    /* this is just a precaution to prevent multiple inits */
    return CURLE_OK;

  session = calloc(amount, sizeof(struct curl_ssl_session));
  if(!session)
    return CURLE_OUT_OF_MEMORY;

  /* store the info in the SSL section */
  data->set.general_ssl.max_ssl_sessions = amount;
  data->state.session = session;
  data->state.sessionage = 1; /* this is brand new */
  return CURLE_OK;
}

size_t Curl_ssl_version(char *buffer, size_t size)
{
  return curlssl_version(buffer, size);
}

/*
 * This function tries to determine connection status.
 *
 * Return codes:
 *     1 means the connection is still in place
 *     0 means the connection has been closed
 *    -1 means the connection status is unknown
 */
int Curl_ssl_check_cxn(struct connectdata *conn)
{
  return curlssl_check_cxn(conn);
}

bool Curl_ssl_data_pending(const struct connectdata *conn,
                           int connindex)
{
  return curlssl_data_pending(conn, connindex);
}

void Curl_ssl_free_certinfo(struct Curl_easy *data)
{
  int i;
  struct curl_certinfo *ci = &data->info.certs;

  if(ci->num_of_certs) {
    /* free all individual lists used */
    for(i=0; i<ci->num_of_certs; i++) {
      curl_slist_free_all(ci->certinfo[i]);
      ci->certinfo[i] = NULL;
    }

    free(ci->certinfo); /* free the actual array too */
    ci->certinfo = NULL;
    ci->num_of_certs = 0;
  }
}

CURLcode Curl_ssl_init_certinfo(struct Curl_easy *data, int num)
{
  struct curl_certinfo *ci = &data->info.certs;
  struct curl_slist **table;

  /* Free any previous certificate information structures */
  Curl_ssl_free_certinfo(data);

  /* Allocate the required certificate information structures */
  table = calloc((size_t) num, sizeof(struct curl_slist *));
  if(!table)
    return CURLE_OUT_OF_MEMORY;

  ci->num_of_certs = num;
  ci->certinfo = table;

  return CURLE_OK;
}

/*
 * 'value' is NOT a zero terminated string
 */
CURLcode Curl_ssl_push_certinfo_len(struct Curl_easy *data,
                                    int certnum,
                                    const char *label,
                                    const char *value,
                                    size_t valuelen)
{
  struct curl_certinfo *ci = &data->info.certs;
  char *output;
  struct curl_slist *nl;
  CURLcode result = CURLE_OK;
  size_t labellen = strlen(label);
  size_t outlen = labellen + 1 + valuelen + 1; /* label:value\0 */

  output = malloc(outlen);
  if(!output)
    return CURLE_OUT_OF_MEMORY;

  /* sprintf the label and colon */
  snprintf(output, outlen, "%s:", label);

  /* memcpy the value (it might not be zero terminated) */
  memcpy(&output[labellen+1], value, valuelen);

  /* zero terminate the output */
  output[labellen + 1 + valuelen] = 0;

  nl = Curl_slist_append_nodup(ci->certinfo[certnum], output);
  if(!nl) {
    free(output);
    curl_slist_free_all(ci->certinfo[certnum]);
    result = CURLE_OUT_OF_MEMORY;
  }

  ci->certinfo[certnum] = nl;
  return result;
}

/*
 * This is a convenience function for push_certinfo_len that takes a zero
 * terminated value.
 */
CURLcode Curl_ssl_push_certinfo(struct Curl_easy *data,
                                int certnum,
                                const char *label,
                                const char *value)
{
  size_t valuelen = strlen(value);

  return Curl_ssl_push_certinfo_len(data, certnum, label, value, valuelen);
}

CURLcode Curl_ssl_random(struct Curl_easy *data,
                         unsigned char *entropy,
                         size_t length)
{
  int rc = curlssl_random(data, entropy, length);
  if(rc) {
    failf(data, "PRNG seeding failed");
    return CURLE_FAILED_INIT; /* possibly weird return code */
  }
  return CURLE_OK;
}

/*
 * Public key pem to der conversion
 */

static CURLcode pubkey_pem_to_der(const char *pem,
                                  unsigned char **der, size_t *der_len)
{
  char *stripped_pem, *begin_pos, *end_pos;
  size_t pem_count, stripped_pem_count = 0, pem_len;
  CURLcode result;

  /* if no pem, exit. */
  if(!pem)
    return CURLE_BAD_CONTENT_ENCODING;

  begin_pos = strstr(pem, "-----BEGIN PUBLIC KEY-----");
  if(!begin_pos)
    return CURLE_BAD_CONTENT_ENCODING;

  pem_count = begin_pos - pem;
  /* Invalid if not at beginning AND not directly following \n */
  if(0 != pem_count && '\n' != pem[pem_count - 1])
    return CURLE_BAD_CONTENT_ENCODING;

  /* 26 is length of "-----BEGIN PUBLIC KEY-----" */
  pem_count += 26;

  /* Invalid if not directly following \n */
  end_pos = strstr(pem + pem_count, "\n-----END PUBLIC KEY-----");
  if(!end_pos)
    return CURLE_BAD_CONTENT_ENCODING;

  pem_len = end_pos - pem;

  stripped_pem = malloc(pem_len - pem_count + 1);
  if(!stripped_pem)
    return CURLE_OUT_OF_MEMORY;

  /*
   * Here we loop through the pem array one character at a time between the
   * correct indices, and place each character that is not '\n' or '\r'
   * into the stripped_pem array, which should represent the raw base64 string
   */
  while(pem_count < pem_len) {
    if('\n' != pem[pem_count] && '\r' != pem[pem_count])
      stripped_pem[stripped_pem_count++] = pem[pem_count];
    ++pem_count;
  }
  /* Place the null terminator in the correct place */
  stripped_pem[stripped_pem_count] = '\0';

  result = Curl_base64_decode(stripped_pem, der, der_len);

  Curl_safefree(stripped_pem);

  return result;
}

/*
 * Generic pinned public key check.
 */

CURLcode Curl_pin_peer_pubkey(struct Curl_easy *data,
                              const char *pinnedpubkey,
                              const unsigned char *pubkey, size_t pubkeylen)
{
  FILE *fp;
  unsigned char *buf = NULL, *pem_ptr = NULL;
  long filesize;
  size_t size, pem_len;
  CURLcode pem_read;
  CURLcode result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
#ifdef curlssl_sha256sum
  CURLcode encode;
  size_t encodedlen, pinkeylen;
  char *encoded, *pinkeycopy, *begin_pos, *end_pos;
  unsigned char *sha256sumdigest = NULL;
#endif

  /* if a path wasn't specified, don't pin */
  if(!pinnedpubkey)
    return CURLE_OK;
  if(!pubkey || !pubkeylen)
    return result;

  /* only do this if pinnedpubkey starts with "sha256//", length 8 */
  if(strncmp(pinnedpubkey, "sha256//", 8) == 0) {
#ifdef curlssl_sha256sum
    /* compute sha256sum of public key */
    sha256sumdigest = malloc(SHA256_DIGEST_LENGTH);
    if(!sha256sumdigest)
      return CURLE_OUT_OF_MEMORY;
    curlssl_sha256sum(pubkey, pubkeylen,
                      sha256sumdigest, SHA256_DIGEST_LENGTH);
    encode = Curl_base64_encode(data, (char *)sha256sumdigest,
                                SHA256_DIGEST_LENGTH, &encoded, &encodedlen);
    Curl_safefree(sha256sumdigest);

    if(encode)
      return encode;

    infof(data, "\t public key hash: sha256//%s\n", encoded);

    /* it starts with sha256//, copy so we can modify it */
    pinkeylen = strlen(pinnedpubkey) + 1;
    pinkeycopy = malloc(pinkeylen);
    if(!pinkeycopy) {
      Curl_safefree(encoded);
      return CURLE_OUT_OF_MEMORY;
    }
    memcpy(pinkeycopy, pinnedpubkey, pinkeylen);
    /* point begin_pos to the copy, and start extracting keys */
    begin_pos = pinkeycopy;
    do {
      end_pos = strstr(begin_pos, ";sha256//");
      /*
       * if there is an end_pos, null terminate,
       * otherwise it'll go to the end of the original string
       */
      if(end_pos)
        end_pos[0] = '\0';

      /* compare base64 sha256 digests, 8 is the length of "sha256//" */
      if(encodedlen == strlen(begin_pos + 8) &&
         !memcmp(encoded, begin_pos + 8, encodedlen)) {
        result = CURLE_OK;
        break;
      }

      /*
       * change back the null-terminator we changed earlier,
       * and look for next begin
       */
      if(end_pos) {
        end_pos[0] = ';';
        begin_pos = strstr(end_pos, "sha256//");
      }
    } while(end_pos && begin_pos);
    Curl_safefree(encoded);
    Curl_safefree(pinkeycopy);
#else
    /* without sha256 support, this cannot match */
    (void)data;
#endif
    return result;
  }

  fp = fopen(pinnedpubkey, "rb");
  if(!fp)
    return result;

  do {
    /* Determine the file's size */
    if(fseek(fp, 0, SEEK_END))
      break;
    filesize = ftell(fp);
    if(fseek(fp, 0, SEEK_SET))
      break;
    if(filesize < 0 || filesize > MAX_PINNED_PUBKEY_SIZE)
      break;

    /*
     * if the size of our certificate is bigger than the file
     * size then it can't match
     */
    size = curlx_sotouz((curl_off_t) filesize);
    if(pubkeylen > size)
      break;

    /*
     * Allocate buffer for the pinned key
     * With 1 additional byte for null terminator in case of PEM key
     */
    buf = malloc(size + 1);
    if(!buf)
      break;

    /* Returns number of elements read, which should be 1 */
    if((int) fread(buf, size, 1, fp) != 1)
      break;

    /* If the sizes are the same, it can't be base64 encoded, must be der */
    if(pubkeylen == size) {
      if(!memcmp(pubkey, buf, pubkeylen))
        result = CURLE_OK;
      break;
    }

    /*
     * Otherwise we will assume it's PEM and try to decode it
     * after placing null terminator
     */
    buf[size] = '\0';
    pem_read = pubkey_pem_to_der((const char *)buf, &pem_ptr, &pem_len);
    /* if it wasn't read successfully, exit */
    if(pem_read)
      break;

    /*
     * if the size of our certificate doesn't match the size of
     * the decoded file, they can't be the same, otherwise compare
     */
    if(pubkeylen == pem_len && !memcmp(pubkey, pem_ptr, pubkeylen))
      result = CURLE_OK;
  } while(0);

  Curl_safefree(buf);
  Curl_safefree(pem_ptr);
  fclose(fp);

  return result;
}

#ifndef CURL_DISABLE_CRYPTO_AUTH
CURLcode Curl_ssl_md5sum(unsigned char *tmp, /* input */
                         size_t tmplen,
                         unsigned char *md5sum, /* output */
                         size_t md5len)
{
#ifdef curlssl_md5sum
  curlssl_md5sum(tmp, tmplen, md5sum, md5len);
#else
  MD5_context *MD5pw;

  (void) md5len;

  MD5pw = Curl_MD5_init(Curl_DIGEST_MD5);
  if(!MD5pw)
    return CURLE_OUT_OF_MEMORY;
  Curl_MD5_update(MD5pw, tmp, curlx_uztoui(tmplen));
  Curl_MD5_final(MD5pw, md5sum);
#endif
  return CURLE_OK;
}
#endif

/*
 * Check whether the SSL backend supports the status_request extension.
 */
bool Curl_ssl_cert_status_request(void)
{
#ifdef curlssl_cert_status_request
  return curlssl_cert_status_request();
#else
  return FALSE;
#endif
}

/*
 * Check whether the SSL backend supports false start.
 */
bool Curl_ssl_false_start(void)
{
#ifdef curlssl_false_start
  return curlssl_false_start();
#else
  return FALSE;
#endif
}

#endif /* USE_SSL */
