/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
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
   http://httpd.apache.org/docs-2.0/ssl/ssl_intro.html
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
#include "rawstr.h"
#include "url.h"
#include "curl_memory.h"
#include "progress.h"
#include "share.h"
#include "timeval.h"
#include "curl_md5.h"
#include "warnless.h"
#include "curl_base64.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

/* convenience macro to check if this handle is using a shared SSL session */
#define SSLSESSION_SHARED(data) (data->share &&                        \
                                 (data->share->specifier &             \
                                  (1<<CURL_LOCK_DATA_SSL_SESSION)))

static bool safe_strequal(char* str1, char* str2)
{
  if(str1 && str2)
    /* both pointers point to something then compare them */
    return (0 != Curl_raw_equal(str1, str2)) ? TRUE : FALSE;
  else
    /* if both pointers are NULL then treat them as equal */
    return (!str1 && !str2) ? TRUE : FALSE;
}

bool
Curl_ssl_config_matches(struct ssl_config_data* data,
                        struct ssl_config_data* needle)
{
  if((data->version == needle->version) &&
     (data->verifypeer == needle->verifypeer) &&
     (data->verifyhost == needle->verifyhost) &&
     safe_strequal(data->CApath, needle->CApath) &&
     safe_strequal(data->CAfile, needle->CAfile) &&
     safe_strequal(data->random_file, needle->random_file) &&
     safe_strequal(data->egdsocket, needle->egdsocket) &&
     safe_strequal(data->cipher_list, needle->cipher_list))
    return TRUE;

  return FALSE;
}

bool
Curl_clone_ssl_config(struct ssl_config_data *source,
                      struct ssl_config_data *dest)
{
  dest->sessionid = source->sessionid;
  dest->verifyhost = source->verifyhost;
  dest->verifypeer = source->verifypeer;
  dest->version = source->version;

  if(source->CAfile) {
    dest->CAfile = strdup(source->CAfile);
    if(!dest->CAfile)
      return FALSE;
  }
  else
    dest->CAfile = NULL;

  if(source->CApath) {
    dest->CApath = strdup(source->CApath);
    if(!dest->CApath)
      return FALSE;
  }
  else
    dest->CApath = NULL;

  if(source->cipher_list) {
    dest->cipher_list = strdup(source->cipher_list);
    if(!dest->cipher_list)
      return FALSE;
  }
  else
    dest->cipher_list = NULL;

  if(source->egdsocket) {
    dest->egdsocket = strdup(source->egdsocket);
    if(!dest->egdsocket)
      return FALSE;
  }
  else
    dest->egdsocket = NULL;

  if(source->random_file) {
    dest->random_file = strdup(source->random_file);
    if(!dest->random_file)
      return FALSE;
  }
  else
    dest->random_file = NULL;

  return TRUE;
}

void Curl_free_ssl_config(struct ssl_config_data* sslc)
{
  Curl_safefree(sslc->CAfile);
  Curl_safefree(sslc->CApath);
  Curl_safefree(sslc->cipher_list);
  Curl_safefree(sslc->egdsocket);
  Curl_safefree(sslc->random_file);
}


/*
 * Curl_rand() returns a random unsigned integer, 32bit.
 *
 * This non-SSL function is put here only because this file is the only one
 * with knowledge of what the underlying SSL libraries provide in terms of
 * randomizers.
 *
 * NOTE: 'data' may be passed in as NULL when coming from external API without
 * easy handle!
 *
 */

unsigned int Curl_rand(struct SessionHandle *data)
{
  unsigned int r = 0;
  static unsigned int randseed;
  static bool seeded = FALSE;

#ifdef CURLDEBUG
  char *force_entropy = getenv("CURL_ENTROPY");
  if(force_entropy) {
    if(!seeded) {
      size_t elen = strlen(force_entropy);
      size_t clen = sizeof(randseed);
      size_t min = elen < clen ? elen : clen;
      memcpy((char *)&randseed, force_entropy, min);
      seeded = TRUE;
    }
    else
      randseed++;
    return randseed;
  }
#endif

  /* data may be NULL! */
  if(!Curl_ssl_random(data, (unsigned char *)&r, sizeof(r)))
    return r;

  /* If Curl_ssl_random() returns non-zero it couldn't offer randomness and we
     instead perform a "best effort" */

#ifdef RANDOM_FILE
  if(!seeded) {
    /* if there's a random file to read a seed from, use it */
    int fd = open(RANDOM_FILE, O_RDONLY);
    if(fd > -1) {
      /* read random data into the randseed variable */
      ssize_t nread = read(fd, &randseed, sizeof(randseed));
      if(nread == sizeof(randseed))
        seeded = TRUE;
      close(fd);
    }
  }
#endif

  if(!seeded) {
    struct timeval now = curlx_tvnow();
    infof(data, "WARNING: Using weak random seed\n");
    randseed += (unsigned int)now.tv_usec + (unsigned int)now.tv_sec;
    randseed = randseed * 1103515245 + 12345;
    randseed = randseed * 1103515245 + 12345;
    randseed = randseed * 1103515245 + 12345;
    seeded = TRUE;
  }

  /* Return an unsigned 32-bit pseudo-random number. */
  r = randseed = randseed * 1103515245 + 12345;
  return (r << 16) | ((r >> 16) & 0xFFFF);
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

CURLcode
Curl_ssl_connect(struct connectdata *conn, int sockindex)
{
  CURLcode result;
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
 * Check if there's a session ID for the given connection in the cache, and if
 * there's one suitable, it is provided. Returns TRUE when no entry matched.
 */
bool Curl_ssl_getsessionid(struct connectdata *conn,
                           void **ssl_sessionid,
                           size_t *idsize) /* set 0 if unknown */
{
  struct curl_ssl_session *check;
  struct SessionHandle *data = conn->data;
  size_t i;
  long *general_age;
  bool no_match = TRUE;

  *ssl_sessionid = NULL;

  if(!conn->ssl_config.sessionid)
    /* session ID re-use is disabled */
    return TRUE;

  /* Lock if shared */
  if(SSLSESSION_SHARED(data)) {
    Curl_share_lock(data, CURL_LOCK_DATA_SSL_SESSION, CURL_LOCK_ACCESS_SINGLE);
    general_age = &data->share->sessionage;
  }
  else
    general_age = &data->state.sessionage;

  for(i = 0; i < data->set.ssl.max_ssl_sessions; i++) {
    check = &data->state.session[i];
    if(!check->sessionid)
      /* not session ID means blank entry */
      continue;
    if(Curl_raw_equal(conn->host.name, check->name) &&
       (conn->remote_port == check->remote_port) &&
       Curl_ssl_config_matches(&conn->ssl_config, &check->ssl_config)) {
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

  /* Unlock */
  if(SSLSESSION_SHARED(data))
    Curl_share_unlock(data, CURL_LOCK_DATA_SSL_SESSION);

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

    Curl_free_ssl_config(&session->ssl_config);

    Curl_safefree(session->name);
  }
}

/*
 * Delete the given session ID from the cache.
 */
void Curl_ssl_delsessionid(struct connectdata *conn, void *ssl_sessionid)
{
  size_t i;
  struct SessionHandle *data=conn->data;

  if(SSLSESSION_SHARED(data))
    Curl_share_lock(data, CURL_LOCK_DATA_SSL_SESSION, CURL_LOCK_ACCESS_SINGLE);

  for(i = 0; i < data->set.ssl.max_ssl_sessions; i++) {
    struct curl_ssl_session *check = &data->state.session[i];

    if(check->sessionid == ssl_sessionid) {
      Curl_ssl_kill_session(check);
      break;
    }
  }

  if(SSLSESSION_SHARED(data))
    Curl_share_unlock(data, CURL_LOCK_DATA_SSL_SESSION);
}

/*
 * Store session id in the session cache. The ID passed on to this function
 * must already have been extracted and allocated the proper way for the SSL
 * layer. Curl_XXXX_session_free() will be called to free/kill the session ID
 * later on.
 */
CURLcode Curl_ssl_addsessionid(struct connectdata *conn,
                               void *ssl_sessionid,
                               size_t idsize)
{
  size_t i;
  struct SessionHandle *data=conn->data; /* the mother of all structs */
  struct curl_ssl_session *store = &data->state.session[0];
  long oldest_age=data->state.session[0].age; /* zero if unused */
  char *clone_host;
  long *general_age;

  /* Even though session ID re-use might be disabled, that only disables USING
     IT. We still store it here in case the re-using is again enabled for an
     upcoming transfer */

  clone_host = strdup(conn->host.name);
  if(!clone_host)
    return CURLE_OUT_OF_MEMORY; /* bail out */

  /* Now we should add the session ID and the host name to the cache, (remove
     the oldest if necessary) */

  /* If using shared SSL session, lock! */
  if(SSLSESSION_SHARED(data)) {
    Curl_share_lock(data, CURL_LOCK_DATA_SSL_SESSION, CURL_LOCK_ACCESS_SINGLE);
    general_age = &data->share->sessionage;
  }
  else {
    general_age = &data->state.sessionage;
  }

  /* find an empty slot for us, or find the oldest */
  for(i = 1; (i < data->set.ssl.max_ssl_sessions) &&
        data->state.session[i].sessionid; i++) {
    if(data->state.session[i].age < oldest_age) {
      oldest_age = data->state.session[i].age;
      store = &data->state.session[i];
    }
  }
  if(i == data->set.ssl.max_ssl_sessions)
    /* cache is full, we must "kill" the oldest entry! */
    Curl_ssl_kill_session(store);
  else
    store = &data->state.session[i]; /* use this slot */

  /* now init the session struct wisely */
  store->sessionid = ssl_sessionid;
  store->idsize = idsize;
  store->age = *general_age;    /* set current age */
  if(store->name)
    /* free it if there's one already present */
    free(store->name);
  store->name = clone_host;               /* clone host name */
  store->remote_port = conn->remote_port; /* port number */


  /* Unlock */
  if(SSLSESSION_SHARED(data))
    Curl_share_unlock(data, CURL_LOCK_DATA_SSL_SESSION);

  if(!Curl_clone_ssl_config(&conn->ssl_config, &store->ssl_config)) {
    store->sessionid = NULL; /* let caller free sessionid */
    free(clone_host);
    return CURLE_OUT_OF_MEMORY;
  }

  return CURLE_OK;
}


void Curl_ssl_close_all(struct SessionHandle *data)
{
  size_t i;
  /* kill the session ID cache if not shared */
  if(data->state.session && !SSLSESSION_SHARED(data)) {
    for(i = 0; i < data->set.ssl.max_ssl_sessions; i++)
      /* the single-killer function handles empty table slots */
      Curl_ssl_kill_session(&data->state.session[i]);

    /* free the cache data */
    Curl_safefree(data->state.session);
  }

  curlssl_close_all(data);
}

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
CURLcode Curl_ssl_set_engine(struct SessionHandle *data, const char *engine)
{
  return curlssl_set_engine(data, engine);
}

/* Selects the default SSL crypto engine
 */
CURLcode Curl_ssl_set_engine_default(struct SessionHandle *data)
{
  return curlssl_set_engine_default(data);
}

/* Return list of OpenSSL crypto engine names. */
struct curl_slist *Curl_ssl_engines_list(struct SessionHandle *data)
{
  return curlssl_engines_list(data);
}

/*
 * This sets up a session ID cache to the specified size. Make sure this code
 * is agnostic to what underlying SSL technology we use.
 */
CURLcode Curl_ssl_initsessions(struct SessionHandle *data, size_t amount)
{
  struct curl_ssl_session *session;

  if(data->state.session)
    /* this is just a precaution to prevent multiple inits */
    return CURLE_OK;

  session = calloc(amount, sizeof(struct curl_ssl_session));
  if(!session)
    return CURLE_OUT_OF_MEMORY;

  /* store the info in the SSL section */
  data->set.ssl.max_ssl_sessions = amount;
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

void Curl_ssl_free_certinfo(struct SessionHandle *data)
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

CURLcode Curl_ssl_init_certinfo(struct SessionHandle *data, int num)
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
CURLcode Curl_ssl_push_certinfo_len(struct SessionHandle *data,
                                    int certnum,
                                    const char *label,
                                    const char *value,
                                    size_t valuelen)
{
  struct curl_certinfo * ci = &data->info.certs;
  char * output;
  struct curl_slist * nl;
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
CURLcode Curl_ssl_push_certinfo(struct SessionHandle *data,
                                int certnum,
                                const char *label,
                                const char *value)
{
  size_t valuelen = strlen(value);

  return Curl_ssl_push_certinfo_len(data, certnum, label, value, valuelen);
}

int Curl_ssl_random(struct SessionHandle *data,
                     unsigned char *entropy,
                     size_t length)
{
  return curlssl_random(data, entropy, length);
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

CURLcode Curl_pin_peer_pubkey(const char *pinnedpubkey,
                              const unsigned char *pubkey, size_t pubkeylen)
{
  FILE *fp;
  unsigned char *buf = NULL, *pem_ptr = NULL;
  long filesize;
  size_t size, pem_len;
  CURLcode pem_read;
  CURLcode result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;

  /* if a path wasn't specified, don't pin */
  if(!pinnedpubkey)
    return CURLE_OK;
  if(!pubkey || !pubkeylen)
    return result;
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

void Curl_ssl_md5sum(unsigned char *tmp, /* input */
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
  Curl_MD5_update(MD5pw, tmp, curlx_uztoui(tmplen));
  Curl_MD5_final(MD5pw, md5sum);
#endif
}

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

#endif /* USE_SSL */
