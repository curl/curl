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

/* This file is for "generic" SSL functions that all libcurl internals should
   use. It is responsible for calling the proper 'ossl' function in ssluse.c
   (OpenSSL based) or the 'gtls' function in gtls.c (GnuTLS based).

   SSL-functions in libcurl should call functions in this source file, and not
   to any specific SSL-layer.

   Curl_ssl_ - prefix for generic ones
   Curl_ossl_ - prefix for OpenSSL ones
   Curl_gtls_ - prefix for GnuTLS ones

   "SSL/TLS Strong Encryption: An Introduction"
   http://httpd.apache.org/docs-2.0/ssl/ssl_intro.html
*/

#include "setup.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "urldata.h"
#define SSLGEN_C
#include "sslgen.h" /* generic SSL protos etc */
#include "ssluse.h" /* OpenSSL versions */
#include "gtls.h"   /* GnuTLS versions */
#include "sendf.h"
#include "strequal.h"
#include "url.h"
#include "memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/* "global" init done? */
static bool init_ssl=FALSE;

static bool safe_strequal(char* str1, char* str2);

static bool safe_strequal(char* str1, char* str2)
{
  if(str1 && str2)
    /* both pointers point to something then compare them */
    return (bool)(0 != strequal(str1, str2));
  else
    /* if both pointers are NULL then treat them as equal */
    return (bool)(!str1 && !str2);
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
  dest->verifyhost = source->verifyhost;
  dest->verifypeer = source->verifypeer;
  dest->version = source->version;

  if(source->CAfile) {
    dest->CAfile = strdup(source->CAfile);
    if(!dest->CAfile)
      return FALSE;
  }

  if(source->CApath) {
    dest->CApath = strdup(source->CApath);
    if(!dest->CApath)
      return FALSE;
  }

  if(source->cipher_list) {
    dest->cipher_list = strdup(source->cipher_list);
    if(!dest->cipher_list)
      return FALSE;
  }

  if(source->egdsocket) {
    dest->egdsocket = strdup(source->egdsocket);
    if(!dest->egdsocket)
      return FALSE;
  }

  if(source->random_file) {
    dest->random_file = strdup(source->random_file);
    if(!dest->random_file)
      return FALSE;
  }

  return TRUE;
}

void Curl_free_ssl_config(struct ssl_config_data* sslc)
{
  if(sslc->CAfile)
    free(sslc->CAfile);

  if(sslc->CApath)
    free(sslc->CApath);

  if(sslc->cipher_list)
    free(sslc->cipher_list);

  if(sslc->egdsocket)
    free(sslc->egdsocket);

  if(sslc->random_file)
    free(sslc->random_file);
}

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

#ifdef USE_SSLEAY
  return Curl_ossl_init();
#else
#ifdef USE_GNUTLS
  return Curl_gtls_init();
#else
  /* no SSL support */
  return 1;
#endif /* USE_GNUTLS */
#endif /* USE_SSLEAY */
}


/* Global cleanup */
void Curl_ssl_cleanup(void)
{
  if(init_ssl) {
    /* only cleanup if we did a previous init */
#ifdef USE_SSLEAY
    Curl_ossl_cleanup();
#else
#ifdef USE_GNUTLS
    Curl_gtls_cleanup();
#endif /* USE_GNUTLS */
#endif /* USE_SSLEAY */
    init_ssl = FALSE;
  }
}

CURLcode
Curl_ssl_connect(struct connectdata *conn, int sockindex)
{
#ifdef USE_SSL
  /* mark this is being ssl enabled from here on. */
  conn->ssl[sockindex].use = TRUE;

#ifdef USE_SSLEAY
  return Curl_ossl_connect(conn, sockindex);
#else
#ifdef USE_GNUTLS
  return Curl_gtls_connect(conn, sockindex);
#endif /* USE_GNUTLS */
#endif /* USE_SSLEAY */

#else
  /* without SSL */
  (void)conn;
  (void)sockindex;
  return CURLE_OK;
#endif /* USE_SSL */
}

CURLcode
Curl_ssl_connect_nonblocking(struct connectdata *conn, int sockindex,
                             bool *done)
{
#if defined(USE_SSL) && defined(USE_SSLEAY)
  /* mark this is being ssl enabled from here on. */
  conn->ssl[sockindex].use = TRUE;
  return Curl_ossl_connect_nonblocking(conn, sockindex, done);

#else
  /* not implemented!
     fallback to BLOCKING call. */
  *done = TRUE;
  return Curl_ssl_connect(conn, sockindex);
#endif
}

#ifdef USE_SSL

/*
 * Check if there's a session ID for the given connection in the cache, and if
 * there's one suitable, it is provided. Returns TRUE when no entry matched.
 */
int Curl_ssl_getsessionid(struct connectdata *conn,
                          void **ssl_sessionid,
                          size_t *idsize) /* set 0 if unknown */
{
  struct curl_ssl_session *check;
  struct SessionHandle *data = conn->data;
  long i;

  if(!conn->ssl_config.sessionid)
    /* session ID re-use is disabled */
    return TRUE;

  for(i=0; i< data->set.ssl.numsessions; i++) {
    check = &data->state.session[i];
    if(!check->sessionid)
      /* not session ID means blank entry */
      continue;
    if(curl_strequal(conn->host.name, check->name) &&
       (conn->remote_port == check->remote_port) &&
       Curl_ssl_config_matches(&conn->ssl_config, &check->ssl_config)) {
      /* yes, we have a session ID! */
      data->state.sessionage++;            /* increase general age */
      check->age = data->state.sessionage; /* set this as used in this age */
      *ssl_sessionid = check->sessionid;
      if(idsize)
        *idsize = check->idsize;
      return FALSE;
    }
  }
  *ssl_sessionid = NULL;
  return TRUE;
}

/*
 * Kill a single session ID entry in the cache.
 */
static int kill_session(struct curl_ssl_session *session)
{
  if(session->sessionid) {
    /* defensive check */

    /* free the ID the SSL-layer specific way */
#ifdef USE_SSLEAY
    Curl_ossl_session_free(session->sessionid);
#else
    Curl_gtls_session_free(session->sessionid);
#endif
    session->sessionid=NULL;
    session->age = 0; /* fresh */

    Curl_free_ssl_config(&session->ssl_config);

    Curl_safefree(session->name);
    session->name = NULL; /* no name */

    return 0; /* ok */
  }
  else
    return 1;
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
  int i;
  struct SessionHandle *data=conn->data; /* the mother of all structs */
  struct curl_ssl_session *store = &data->state.session[0];
  long oldest_age=data->state.session[0].age; /* zero if unused */
  char *clone_host;

  /* Even though session ID re-use might be disabled, that only disables USING
     IT. We still store it here in case the re-using is again enabled for an
     upcoming transfer */

  clone_host = strdup(conn->host.name);
  if(!clone_host)
    return CURLE_OUT_OF_MEMORY; /* bail out */

  /* Now we should add the session ID and the host name to the cache, (remove
     the oldest if necessary) */

  /* find an empty slot for us, or find the oldest */
  for(i=1; (i<data->set.ssl.numsessions) &&
        data->state.session[i].sessionid; i++) {
    if(data->state.session[i].age < oldest_age) {
      oldest_age = data->state.session[i].age;
      store = &data->state.session[i];
    }
  }
  if(i == data->set.ssl.numsessions)
    /* cache is full, we must "kill" the oldest entry! */
    kill_session(store);
  else
    store = &data->state.session[i]; /* use this slot */

  /* now init the session struct wisely */
  store->sessionid = ssl_sessionid;
  store->idsize = idsize;
  store->age = data->state.sessionage;    /* set current age */
  store->name = clone_host;               /* clone host name */
  store->remote_port = conn->remote_port; /* port number */

  if (!Curl_clone_ssl_config(&conn->ssl_config, &store->ssl_config))
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}


#endif

void Curl_ssl_close_all(struct SessionHandle *data)
{
#ifdef USE_SSL
  int i;
  /* kill the session ID cache */
  if(data->state.session) {
    for(i=0; i< data->set.ssl.numsessions; i++)
      /* the single-killer function handles empty table slots */
      kill_session(&data->state.session[i]);

    /* free the cache data */
    free(data->state.session);
    data->state.session = NULL;
  }
#ifdef USE_SSLEAY
  Curl_ossl_close_all(data);
#else
#ifdef USE_GNUTLS
  Curl_gtls_close_all(data);
#endif /* USE_GNUTLS */
#endif /* USE_SSLEAY */
#else /* USE_SSL */
  (void)data;
#endif /* USE_SSL */
}

void Curl_ssl_close(struct connectdata *conn)
{
  if(conn->ssl[FIRSTSOCKET].use) {
#ifdef USE_SSLEAY
    Curl_ossl_close(conn);
#else
#ifdef USE_GNUTLS
    Curl_gtls_close(conn);
#else
  (void)conn;
#endif /* USE_GNUTLS */
#endif /* USE_SSLEAY */
  }
}

CURLcode Curl_ssl_shutdown(struct connectdata *conn, int sockindex)
{
  if(conn->ssl[sockindex].use) {
#ifdef USE_SSLEAY
    if(Curl_ossl_shutdown(conn, sockindex))
      return CURLE_SSL_SHUTDOWN_FAILED;
#else
#ifdef USE_GNUTLS
    if(Curl_gtls_shutdown(conn, sockindex))
      return CURLE_SSL_SHUTDOWN_FAILED;
#else
    (void)conn;
    (void)sockindex;
#endif /* USE_GNUTLS */
#endif /* USE_SSLEAY */
  }
  return CURLE_OK;
}

/* Selects an (Open)SSL crypto engine
 */
CURLcode Curl_ssl_set_engine(struct SessionHandle *data, const char *engine)
{
#ifdef USE_SSLEAY
  return Curl_ossl_set_engine(data, engine);
#else
#ifdef USE_GNUTLS
  /* FIX: add code here */
  (void)data;
  (void)engine;
  return CURLE_FAILED_INIT;
#else
  /* no SSL layer */
  (void)data;
  (void)engine;
  return CURLE_FAILED_INIT;
#endif /* USE_GNUTLS */
#endif /* USE_SSLEAY */
}

/* Selects an (Open?)SSL crypto engine
 */
CURLcode Curl_ssl_set_engine_default(struct SessionHandle *data)
{
#ifdef USE_SSLEAY
  return Curl_ossl_set_engine_default(data);
#else
#ifdef USE_GNUTLS
  /* FIX: add code here */
  (void)data;
  return CURLE_FAILED_INIT;
#else
  /* No SSL layer */
  (void)data;
  return CURLE_FAILED_INIT;
#endif /* USE_GNUTLS */
#endif /* USE_SSLEAY */
}

/* Return list of OpenSSL crypto engine names. */
struct curl_slist *Curl_ssl_engines_list(struct SessionHandle *data)
{
#ifdef USE_SSLEAY
  return Curl_ossl_engines_list(data);
#else
#ifdef USE_GNUTLS
  /* FIX: add code here? */
  (void)data;
  return NULL;
#else
  (void)data;
  return NULL;
#endif /* USE_GNUTLS */
#endif /* USE_SSLEAY */
}

/* return number of sent (non-SSL) bytes */
ssize_t Curl_ssl_send(struct connectdata *conn,
                      int sockindex,
                      void *mem,
                      size_t len)
{
#ifdef USE_SSLEAY
  return Curl_ossl_send(conn, sockindex, mem, len);
#else
#ifdef USE_GNUTLS
  return Curl_gtls_send(conn, sockindex, mem, len);
#else
  (void)conn;
  (void)sockindex;
  (void)mem;
  (void)len;
  return 0;
#endif /* USE_GNUTLS */
#endif /* USE_SSLEAY */
}

/* return number of received (decrypted) bytes */

/*
 * If the read would block (EWOULDBLOCK) we return -1. Otherwise we return
 * a regular CURLcode value.
 */
ssize_t Curl_ssl_recv(struct connectdata *conn, /* connection data */
                      int sockindex,            /* socketindex */
                      char *mem,                /* store read data here */
                      size_t len)               /* max amount to read */
{
#ifdef USE_SSL
  ssize_t nread;
  bool block = FALSE;

#ifdef USE_SSLEAY
  nread = Curl_ossl_recv(conn, sockindex, mem, len, &block);
#else
#ifdef USE_GNUTLS
  nread = Curl_gtls_recv(conn, sockindex, mem, len, &block);
#endif /* USE_GNUTLS */
#endif /* USE_SSLEAY */
  if(nread == -1) {
    if(!block)
      return 0; /* this is a true error, not EWOULDBLOCK */
    else
      return -1;
  }

  return (int)nread;

#else /* USE_SSL */
  (void)conn;
  (void)sockindex;
  (void)mem;
  (void)len;
  return 0;
#endif /* USE_SSL */
}


/*
 * This sets up a session ID cache to the specified size. Make sure this code
 * is agnostic to what underlying SSL technology we use.
 */
CURLcode Curl_ssl_initsessions(struct SessionHandle *data, long amount)
{
#ifdef USE_SSL
  struct curl_ssl_session *session;

  if(data->state.session)
    /* this is just a precaution to prevent multiple inits */
    return CURLE_OK;

  session = (struct curl_ssl_session *)
    calloc(sizeof(struct curl_ssl_session), amount);
  if(!session)
    return CURLE_OUT_OF_MEMORY;

  /* store the info in the SSL section */
  data->set.ssl.numsessions = amount;
  data->state.session = session;
  data->state.sessionage = 1; /* this is brand new */
#else
  /* without SSL, do nothing */
  (void)data;
  (void)amount;
#endif

  return CURLE_OK;
}

size_t Curl_ssl_version(char *buffer, size_t size)
{
#ifdef USE_SSLEAY
  return Curl_ossl_version(buffer, size);
#else
#ifdef USE_GNUTLS
  return Curl_gtls_version(buffer, size);
#else
  (void)buffer;
  (void)size;
  return 0; /* no SSL support */
#endif /* USE_GNUTLS */
#endif /* USE_SSLEAY */
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
#ifdef USE_SSLEAY
  return Curl_ossl_check_cxn(conn);
#else
  (void)conn;
  /* TODO: we lack implementation of this for GnuTLS */
  return -1; /* connection status unknown */
#endif /* USE_SSLEAY */
}

bool Curl_ssl_data_pending(struct connectdata *conn,
                           int connindex)
{
#ifdef USE_SSLEAY
  /* OpenSSL-specific */
  if(conn->ssl[connindex].handle)
    /* SSL is in use */
    return SSL_pending(conn->ssl[connindex].handle);
#else
  (void)conn;
  (void)connindex;
#endif
  return FALSE; /* nothing pending */

}
