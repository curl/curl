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

/*
 * Source file for all OpenSSL-specific code for the TLS/SSL layer. No code
 * but sslgen.c should ever call or use these functions.
 */

/*
 * The original SSLeay-using code for curl was written by Linas Vepstas and
 * Sampo Kellomaki 1998.
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
#include "sendf.h"
#include "formdata.h" /* for the boundary function */
#include "url.h" /* for the ssl config check function */
#include "inet_pton.h"
#include "ssluse.h"
#include "connect.h" /* Curl_sockerrno() proto */
#include "strequal.h"
#include "select.h"
#include "sslgen.h"

#define _MPRINTF_REPLACE /* use the internal *printf() functions */
#include <curl/mprintf.h>

#ifdef USE_SSLEAY

#ifdef USE_OPENSSL
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#else
#include <rand.h>
#include <x509v3.h>
#endif

#include "memory.h"
#include "easyif.h" /* for Curl_convert_from_utf8 prototype */

/* The last #include file should be: */
#include "memdebug.h"

#ifndef min
#define min(a, b)   ((a) < (b) ? (a) : (b))
#endif

#if OPENSSL_VERSION_NUMBER >= 0x0090581fL
#define HAVE_SSL_GET1_SESSION 1
#else
#undef HAVE_SSL_GET1_SESSION
#endif

#if OPENSSL_VERSION_NUMBER >= 0x00904100L
#define HAVE_USERDATA_IN_PWD_CALLBACK 1
#else
#undef HAVE_USERDATA_IN_PWD_CALLBACK
#endif

#if OPENSSL_VERSION_NUMBER >= 0x00907001L
/* ENGINE_load_private_key() takes four arguments */
#define HAVE_ENGINE_LOAD_FOUR_ARGS
#else
/* ENGINE_load_private_key() takes three arguments */
#undef HAVE_ENGINE_LOAD_FOUR_ARGS
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x00903001L) && defined(HAVE_OPENSSL_PKCS12_H)
/* OpenSSL has PKCS 12 support */
#define HAVE_PKCS12_SUPPORT
#else
/* OpenSSL/SSLEay does not have PKCS12 support */
#undef HAVE_PKCS12_SUPPORT
#endif

#if OPENSSL_VERSION_NUMBER >= 0x00906001L
#define HAVE_ERR_ERROR_STRING_N 1
#endif

#if OPENSSL_VERSION_NUMBER >= 0x00909000L
#define SSL_METHOD_QUAL const
#else
#define SSL_METHOD_QUAL
#endif

/*
 * Number of bytes to read from the random number seed file. This must be
 * a finite value (because some entropy "files" like /dev/urandom have
 * an infinite length), but must be large enough to provide enough
 * entopy to properly seed OpenSSL's PRNG.
 */
#define RAND_LOAD_LENGTH 1024

#ifndef HAVE_USERDATA_IN_PWD_CALLBACK
static char global_passwd[64];
#endif

static int passwd_callback(char *buf, int num, int verify
#if HAVE_USERDATA_IN_PWD_CALLBACK
                           /* This was introduced in 0.9.4, we can set this
                              using SSL_CTX_set_default_passwd_cb_userdata()
                              */
                           , void *global_passwd
#endif
                           )
{
  if(verify)
    fprintf(stderr, "%s\n", buf);
  else {
    if(num > (int)strlen((char *)global_passwd)) {
      strcpy(buf, global_passwd);
      return (int)strlen(buf);
    }
  }
  return 0;
}

/*
 * rand_enough() is a function that returns TRUE if we have seeded the random
 * engine properly. We use some preprocessor magic to provide a seed_enough()
 * macro to use, just to prevent a compiler warning on this function if we
 * pass in an argument that is never used.
 */

#ifdef HAVE_RAND_STATUS
#define seed_enough(x) rand_enough()
static bool rand_enough(void)
{
  return (bool)(0 != RAND_status());
}
#else
#define seed_enough(x) rand_enough(x)
static bool rand_enough(int nread)
{
  /* this is a very silly decision to make */
  return (bool)(nread > 500);
}
#endif

static int ossl_seed(struct SessionHandle *data)
{
  char *buf = data->state.buffer; /* point to the big buffer */
  int nread=0;

  /* Q: should we add support for a random file name as a libcurl option?
     A: Yes, it is here */

#ifndef RANDOM_FILE
  /* if RANDOM_FILE isn't defined, we only perform this if an option tells
     us to! */
  if(data->set.ssl.random_file)
#define RANDOM_FILE "" /* doesn't matter won't be used */
#endif
  {
    /* let the option override the define */
    nread += RAND_load_file((data->set.ssl.random_file?
                             data->set.ssl.random_file:RANDOM_FILE),
                            RAND_LOAD_LENGTH);
    if(seed_enough(nread))
      return nread;
  }

#if defined(HAVE_RAND_EGD)
  /* only available in OpenSSL 0.9.5 and later */
  /* EGD_SOCKET is set at configure time or not at all */
#ifndef EGD_SOCKET
  /* If we don't have the define set, we only do this if the egd-option
     is set */
  if(data->set.ssl.egdsocket)
#define EGD_SOCKET "" /* doesn't matter won't be used */
#endif
  {
    /* If there's an option and a define, the option overrides the
       define */
    int ret = RAND_egd(data->set.ssl.egdsocket?
                       data->set.ssl.egdsocket:EGD_SOCKET);
    if(-1 != ret) {
      nread += ret;
      if(seed_enough(nread))
        return nread;
    }
  }
#endif

  /* If we get here, it means we need to seed the PRNG using a "silly"
     approach! */
#ifdef HAVE_RAND_SCREEN
  /* This one gets a random value by reading the currently shown screen */
  RAND_screen();
  nread = 100; /* just a value */
#else
  {
    int len;
    char *area;

    /* Changed call to RAND_seed to use the underlying RAND_add implementation
     * directly.  Do this in a loop, with the amount of additional entropy
     * being dependent upon the algorithm used by Curl_FormBoundary(): N bytes
     * of a 7-bit ascii set. -- Richard Gorton, March 11 2003.
     */

    do {
      area = Curl_FormBoundary();
      if(!area)
        return 3; /* out of memory */

      len = (int)strlen(area);
      RAND_add(area, len, (len >> 1));

      free(area); /* now remove the random junk */
    } while (!RAND_status());
  }
#endif

  /* generates a default path for the random seed file */
  buf[0]=0; /* blank it first */
  RAND_file_name(buf, BUFSIZE);
  if(buf[0]) {
    /* we got a file name to try */
    nread += RAND_load_file(buf, RAND_LOAD_LENGTH);
    if(seed_enough(nread))
      return nread;
  }

  infof(data, "libcurl is now using a weak random seed!\n");
  return nread;
}

int Curl_ossl_seed(struct SessionHandle *data)
{
  /* we have the "SSL is seeded" boolean static to prevent multiple
     time-consuming seedings in vain */
  static bool ssl_seeded = FALSE;

  if(!ssl_seeded || data->set.ssl.random_file || data->set.ssl.egdsocket) {
    ossl_seed(data);
    ssl_seeded = TRUE;
  }
  return 0;
}


#ifndef SSL_FILETYPE_ENGINE
#define SSL_FILETYPE_ENGINE 42
#endif
#ifndef SSL_FILETYPE_PKCS12
#define SSL_FILETYPE_PKCS12 43
#endif
static int do_file_type(const char *type)
{
  if(!type || !type[0])
    return SSL_FILETYPE_PEM;
  if(curl_strequal(type, "PEM"))
    return SSL_FILETYPE_PEM;
  if(curl_strequal(type, "DER"))
    return SSL_FILETYPE_ASN1;
  if(curl_strequal(type, "ENG"))
    return SSL_FILETYPE_ENGINE;
  if(curl_strequal(type, "P12"))
    return SSL_FILETYPE_PKCS12;
  return -1;
}

static
int cert_stuff(struct connectdata *conn,
               SSL_CTX* ctx,
               char *cert_file,
               const char *cert_type,
               char *key_file,
               const char *key_type)
{
  struct SessionHandle *data = conn->data;
  int file_type;

  if(cert_file != NULL) {
    SSL *ssl;
    X509 *x509;
    int cert_done = 0;

    if(data->set.key_passwd) {
#ifndef HAVE_USERDATA_IN_PWD_CALLBACK
      /*
       * If password has been given, we store that in the global
       * area (*shudder*) for a while:
       */
      size_t len = strlen(data->set.key_passwd);
      if(len < sizeof(global_passwd))
        memcpy(global_passwd, data->set.key_passwd, len+1);
#else
      /*
       * We set the password in the callback userdata
       */
      SSL_CTX_set_default_passwd_cb_userdata(ctx,
                                             data->set.key_passwd);
#endif
      /* Set passwd callback: */
      SSL_CTX_set_default_passwd_cb(ctx, passwd_callback);
    }

    file_type = do_file_type(cert_type);

#define SSL_CLIENT_CERT_ERR \
    "unable to use client certificate (no key found or wrong pass phrase?)"

    switch(file_type) {
    case SSL_FILETYPE_PEM:
      /* SSL_CTX_use_certificate_chain_file() only works on PEM files */
      if(SSL_CTX_use_certificate_chain_file(ctx,
                                            cert_file) != 1) {
        failf(data, SSL_CLIENT_CERT_ERR);
        return 0;
      }
      break;

    case SSL_FILETYPE_ASN1:
      /* SSL_CTX_use_certificate_file() works with either PEM or ASN1, but
         we use the case above for PEM so this can only be performed with
         ASN1 files. */
      if(SSL_CTX_use_certificate_file(ctx,
                                      cert_file,
                                      file_type) != 1) {
        failf(data, SSL_CLIENT_CERT_ERR);
        return 0;
      }
      break;
    case SSL_FILETYPE_ENGINE:
      failf(data, "file type ENG for certificate not implemented");
      return 0;

    case SSL_FILETYPE_PKCS12:
    {
#ifdef HAVE_PKCS12_SUPPORT
      FILE *f;
      PKCS12 *p12;
      EVP_PKEY *pri;

      f = fopen(cert_file,"rb");
      if (!f) {
        failf(data, "could not open PKCS12 file '%s'", cert_file);
        return 0;
      }
      p12 = d2i_PKCS12_fp(f, NULL);
      fclose(f);

      PKCS12_PBE_add();

      if (!PKCS12_parse(p12, data->set.key_passwd, &pri, &x509, NULL)) {
        failf(data,
              "could not parse PKCS12 file, check password, OpenSSL error %s",
              ERR_error_string(ERR_get_error(), NULL) );
        return 0;
      }

      PKCS12_free(p12);

      if(SSL_CTX_use_certificate(ctx, x509) != 1) {
        failf(data, SSL_CLIENT_CERT_ERR);
        EVP_PKEY_free(pri);
        X509_free(x509);
        return 0;
      }

      if(SSL_CTX_use_PrivateKey(ctx, pri) != 1) {
        failf(data, "unable to use private key from PKCS12 file '%s'",
              cert_file);
        EVP_PKEY_free(pri);
        X509_free(x509);
        return 0;
      }

      EVP_PKEY_free(pri);
      X509_free(x509);
      cert_done = 1;
      break;
#else
      failf(data, "file type P12 for certificate not supported");
      return 0;
#endif
    }
    default:
      failf(data, "not supported file type '%s' for certificate", cert_type);
      return 0;
    }

    file_type = do_file_type(key_type);

    switch(file_type) {
    case SSL_FILETYPE_PEM:
      if(cert_done)
        break;
      if(key_file == NULL)
        /* cert & key can only be in PEM case in the same file */
        key_file=cert_file;
    case SSL_FILETYPE_ASN1:
      if(SSL_CTX_use_PrivateKey_file(ctx, key_file, file_type) != 1) {
        failf(data, "unable to set private key file: '%s' type %s\n",
              key_file, key_type?key_type:"PEM");
        return 0;
      }
      break;
    case SSL_FILETYPE_ENGINE:
#ifdef HAVE_OPENSSL_ENGINE_H
      {                         /* XXXX still needs some work */
        EVP_PKEY *priv_key = NULL;
        if(conn && conn->data && conn->data->state.engine) {
#ifdef HAVE_ENGINE_LOAD_FOUR_ARGS
          UI_METHOD *ui_method = UI_OpenSSL();
#endif
          if(!key_file || !key_file[0]) {
            failf(data, "no key set to load from crypto engine\n");
            return 0;
          }
          /* the typecast below was added to please mingw32 */
          priv_key = (EVP_PKEY *)
            ENGINE_load_private_key(conn->data->state.engine,key_file,
#ifdef HAVE_ENGINE_LOAD_FOUR_ARGS
                                    ui_method,
#endif
                                    data->set.key_passwd);
          if(!priv_key) {
            failf(data, "failed to load private key from crypto engine\n");
            return 0;
          }
          if(SSL_CTX_use_PrivateKey(ctx, priv_key) != 1) {
            failf(data, "unable to set private key\n");
            EVP_PKEY_free(priv_key);
            return 0;
          }
          EVP_PKEY_free(priv_key);  /* we don't need the handle any more... */
        }
        else {
          failf(data, "crypto engine not set, can't load private key\n");
          return 0;
        }
      }
      break;
#else
      failf(data, "file type ENG for private key not supported\n");
      return 0;
#endif
    case SSL_FILETYPE_PKCS12:
      if(!cert_done) {
        failf(data, "file type P12 for private key not supported\n");
        return 0;
      }
      break;
    default:
      failf(data, "not supported file type for private key\n");
      return 0;
    }

    ssl=SSL_new(ctx);
    if (NULL == ssl) {
      failf(data,"unable to create an SSL structure\n");
      return 0;
    }

    x509=SSL_get_certificate(ssl);

    /* This version was provided by Evan Jordan and is supposed to not
       leak memory as the previous version: */
    if(x509 != NULL) {
      EVP_PKEY *pktmp = X509_get_pubkey(x509);
      EVP_PKEY_copy_parameters(pktmp,SSL_get_privatekey(ssl));
      EVP_PKEY_free(pktmp);
    }

    SSL_free(ssl);

    /* If we are using DSA, we can copy the parameters from
     * the private key */


    /* Now we know that a key and cert have been set against
     * the SSL context */
    if(!SSL_CTX_check_private_key(ctx)) {
      failf(data, "Private key does not match the certificate public key");
      return(0);
    }
#ifndef HAVE_USERDATA_IN_PWD_CALLBACK
    /* erase it now */
    memset(global_passwd, 0, sizeof(global_passwd));
#endif
  }
  return(1);
}

static
int cert_verify_callback(int ok, X509_STORE_CTX *ctx)
{
  X509 *err_cert;
  char buf[256];

  err_cert=X509_STORE_CTX_get_current_cert(ctx);
  X509_NAME_oneline(X509_get_subject_name(err_cert), buf, sizeof(buf));
  return ok;
}

/* Return error string for last OpenSSL error
 */
static char *SSL_strerror(unsigned long error, char *buf, size_t size)
{
#ifdef HAVE_ERR_ERROR_STRING_N
  /* OpenSSL 0.9.6 and later has a function named
     ERRO_error_string_n() that takes the size of the buffer as a
     third argument */
  ERR_error_string_n(error, buf, size);
#else
  (void) size;
  ERR_error_string(error, buf);
#endif
  return (buf);
}

#endif /* USE_SSLEAY */

#ifdef USE_SSLEAY
/**
 * Global SSL init
 *
 * @retval 0 error initializing SSL
 * @retval 1 SSL initialized successfully
 */
int Curl_ossl_init(void)
{
#ifdef HAVE_ENGINE_LOAD_BUILTIN_ENGINES
  ENGINE_load_builtin_engines();
#endif

  /* Lets get nice error messages */
  SSL_load_error_strings();

  /* Setup all the global SSL stuff */
  if (!SSLeay_add_ssl_algorithms())
    return 0;

  return 1;
}

#endif /* USE_SSLEAY */

#ifdef USE_SSLEAY

/* Global cleanup */
void Curl_ossl_cleanup(void)
{
  /* Free the SSL error strings */
  ERR_free_strings();

  /* EVP_cleanup() removes all ciphers and digests from the
     table. */
  EVP_cleanup();

#ifdef HAVE_ENGINE_cleanup
  ENGINE_cleanup();
#endif

#ifdef HAVE_CRYPTO_CLEANUP_ALL_EX_DATA
  /* this function was not present in 0.9.6b, but was added sometimes
     later */
  CRYPTO_cleanup_all_ex_data();
#endif
}

/*
 * This function uses SSL_peek to determine connection status.
 *
 * Return codes:
 *     1 means the connection is still in place
 *     0 means the connection has been closed
 *    -1 means the connection status is unknown
 */
int Curl_ossl_check_cxn(struct connectdata *conn)
{
  int rc;
  char buf;

  rc = SSL_peek(conn->ssl[FIRSTSOCKET].handle, (void*)&buf, 1);
  if (rc > 0)
    return 1; /* connection still in place */

  if (rc == 0)
    return 0; /* connection has been closed */

  return -1; /* connection status unknown */
}

#endif /* USE_SSLEAY */

/* Selects an OpenSSL crypto engine
 */
CURLcode Curl_ossl_set_engine(struct SessionHandle *data, const char *engine)
{
#if defined(USE_SSLEAY) && defined(HAVE_OPENSSL_ENGINE_H)
  ENGINE *e = ENGINE_by_id(engine);

  if (!e) {
    failf(data, "SSL Engine '%s' not found", engine);
    return (CURLE_SSL_ENGINE_NOTFOUND);
  }

  if (data->state.engine) {
    ENGINE_finish(data->state.engine);
    ENGINE_free(data->state.engine);
    data->state.engine = NULL;
  }
  if (!ENGINE_init(e)) {
    char buf[256];

    ENGINE_free(e);
    failf(data, "Failed to initialise SSL Engine '%s':\n%s",
          engine, SSL_strerror(ERR_get_error(), buf, sizeof(buf)));
    return (CURLE_SSL_ENGINE_INITFAILED);
  }
  data->state.engine = e;
  return (CURLE_OK);
#else
  (void)engine;
  failf(data, "SSL Engine not supported");
  return (CURLE_SSL_ENGINE_NOTFOUND);
#endif
}

#ifdef USE_SSLEAY
/* Sets engine as default for all SSL operations
 */
CURLcode Curl_ossl_set_engine_default(struct SessionHandle *data)
{
#ifdef HAVE_OPENSSL_ENGINE_H
  if (data->state.engine) {
    if (ENGINE_set_default(data->state.engine, ENGINE_METHOD_ALL) > 0) {
      infof(data,"set default crypto engine '%s'\n", ENGINE_get_id(data->state.engine));
    }
    else {
      failf(data, "set default crypto engine '%s' failed", ENGINE_get_id(data->state.engine));
      return CURLE_SSL_ENGINE_SETFAILED;
    }
  }
#else
  (void) data;
#endif
  return CURLE_OK;
}
#endif /* USE_SSLEAY */

/* Return list of OpenSSL crypto engine names.
 */
struct curl_slist *Curl_ossl_engines_list(struct SessionHandle *data)
{
  struct curl_slist *list = NULL;
#if defined(USE_SSLEAY) && defined(HAVE_OPENSSL_ENGINE_H)
  ENGINE *e;

  for (e = ENGINE_get_first(); e; e = ENGINE_get_next(e))
    list = curl_slist_append(list, ENGINE_get_id(e));
#endif
  (void) data;
  return (list);
}


#ifdef USE_SSLEAY

/*
 * This function is called when an SSL connection is closed.
 */
void Curl_ossl_close(struct connectdata *conn)
{
  int i;
  /*
    ERR_remove_state() frees the error queue associated with
    thread pid.  If pid == 0, the current thread will have its
    error queue removed.

    Since error queue data structures are allocated
    automatically for new threads, they must be freed when
    threads are terminated in oder to avoid memory leaks.
  */
  ERR_remove_state(0);

  for(i=0; i<2; i++) {
    struct ssl_connect_data *connssl = &conn->ssl[i];

    if(connssl->handle) {
      (void)SSL_shutdown(connssl->handle);
      SSL_set_connect_state(connssl->handle);

      SSL_free (connssl->handle);
      connssl->handle = NULL;
    }
    if(connssl->ctx) {
      SSL_CTX_free (connssl->ctx);
      connssl->ctx = NULL;
    }
    connssl->use = FALSE; /* get back to ordinary socket usage */
  }
}

/*
 * This function is called to shut down the SSL layer but keep the
 * socket open (CCC - Clear Command Channel)
 */
int Curl_ossl_shutdown(struct connectdata *conn, int sockindex)
{
  int retval = 0;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct SessionHandle *data = conn->data;
  char buf[120]; /* We will use this for the OpenSSL error buffer, so it has
                    to be at least 120 bytes long. */
  unsigned long sslerror;
  ssize_t nread;
  int err;
  int done = 0;

  /* This has only been tested on the proftpd server, and the mod_tls code
     sends a close notify alert without waiting for a close notify alert in
     response. Thus we wait for a close notify alert from the server, but
     we do not send one. Let's hope other servers do the same... */

  if(connssl->handle) {
    while(!done) {
      int what = Curl_select(conn->sock[sockindex],
                             CURL_SOCKET_BAD, SSL_SHUTDOWN_TIMEOUT);
      if(what > 0) {
        /* Something to read, let's do it and hope that it is the close
           notify alert from the server */
        nread = (ssize_t)SSL_read(conn->ssl[sockindex].handle, buf,
                                  sizeof(buf));
        err = SSL_get_error(conn->ssl[sockindex].handle, (int)nread);

        switch(err) {
        case SSL_ERROR_NONE: /* this is not an error */
        case SSL_ERROR_ZERO_RETURN: /* no more data */
          /* This is the expected response. There was no data but only
             the close notify alert */
          done = 1;
          break;
        case SSL_ERROR_WANT_READ:
          /* there's data pending, re-invoke SSL_read() */
          infof(data, "SSL_ERROR_WANT_READ\n");
          break;
        case SSL_ERROR_WANT_WRITE:
          /* SSL wants a write. Really odd. Let's bail out. */
          infof(data, "SSL_ERROR_WANT_WRITE\n");
          done = 1;
          break;
        default:
          /* openssl/ssl.h says "look at error stack/return value/errno" */
          sslerror = ERR_get_error();
          failf(conn->data, "SSL read: %s, errno %d",
                ERR_error_string(sslerror, buf),
                Curl_sockerrno() );
          done = 1;
          break;
        }
      }
      else if(0 == what) {
        /* timeout */
        failf(data, "SSL shutdown timeout");
        done = 1;
        break;
      }
      else {
        /* anything that gets here is fatally bad */
        failf(data, "select on SSL socket, errno: %d", Curl_sockerrno());
        retval = -1;
        done = 1;
      }
    } /* while()-loop for the select() */

    if(data->set.verbose) {
      switch(SSL_get_shutdown(connssl->handle)) {
      case SSL_SENT_SHUTDOWN:
        infof(data, "SSL_get_shutdown() returned SSL_SENT_SHUTDOWN\n");
        break;
      case SSL_RECEIVED_SHUTDOWN:
        infof(data, "SSL_get_shutdown() returned SSL_RECEIVED_SHUTDOWN\n");
        break;
      case SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN:
        infof(data, "SSL_get_shutdown() returned SSL_SENT_SHUTDOWN|"
              "SSL_RECEIVED__SHUTDOWN\n");
        break;
      }
    }

    connssl->use = FALSE; /* get back to ordinary socket usage */

    SSL_free (connssl->handle);
    connssl->handle = NULL;
  }
  return retval;
}

void Curl_ossl_session_free(void *ptr)
{
  /* free the ID */
  SSL_SESSION_free(ptr);
}

/*
 * This function is called when the 'data' struct is going away. Close
 * down everything and free all resources!
 */
int Curl_ossl_close_all(struct SessionHandle *data)
{
#ifdef HAVE_OPENSSL_ENGINE_H
  if(data->state.engine) {
    ENGINE_finish(data->state.engine);
    ENGINE_free(data->state.engine);
    data->state.engine = NULL;
  }
#else
  (void)data;
#endif
  return 0;
}

static int Curl_ASN1_UTCTIME_output(struct connectdata *conn,
                                    const char *prefix,
                                    ASN1_UTCTIME *tm)
{
  char *asn1_string;
  int gmt=FALSE;
  int i;
  int year=0,month=0,day=0,hour=0,minute=0,second=0;
  struct SessionHandle *data = conn->data;

  if(!data->set.verbose)
    return 0;

  i=tm->length;
  asn1_string=(char *)tm->data;

  if(i < 10)
    return 1;
  if(asn1_string[i-1] == 'Z')
    gmt=TRUE;
  for (i=0; i<10; i++)
    if((asn1_string[i] > '9') || (asn1_string[i] < '0'))
      return 2;

  year= (asn1_string[0]-'0')*10+(asn1_string[1]-'0');
  if(year < 50)
    year+=100;

  month= (asn1_string[2]-'0')*10+(asn1_string[3]-'0');
  if((month > 12) || (month < 1))
    return 3;

  day= (asn1_string[4]-'0')*10+(asn1_string[5]-'0');
  hour= (asn1_string[6]-'0')*10+(asn1_string[7]-'0');
  minute=  (asn1_string[8]-'0')*10+(asn1_string[9]-'0');

  if((asn1_string[10] >= '0') && (asn1_string[10] <= '9') &&
     (asn1_string[11] >= '0') && (asn1_string[11] <= '9'))
    second= (asn1_string[10]-'0')*10+(asn1_string[11]-'0');

  infof(data,
        "%s%04d-%02d-%02d %02d:%02d:%02d %s\n",
        prefix, year+1900, month, day, hour, minute, second, (gmt?"GMT":""));

  return 0;
}

#endif

/* ====================================================== */
#ifdef USE_SSLEAY

/*
 * Match a hostname against a wildcard pattern.
 * E.g.
 *  "foo.host.com" matches "*.host.com".
 *
 * We are a bit more liberal than RFC2818 describes in that we
 * accept multiple "*" in pattern (similar to what some other browsers do).
 * E.g.
 *  "abc.def.domain.com" should strickly not match "*.domain.com", but we
 *  don't consider "." to be important in CERT checking.
 */
#define HOST_NOMATCH 0
#define HOST_MATCH   1

static int hostmatch(const char *hostname, const char *pattern)
{
  while (1) {
    int c = *pattern++;

    if (c == '\0')
      return (*hostname ? HOST_NOMATCH : HOST_MATCH);

    if (c == '*') {
      c = *pattern;
      if (c == '\0')      /* "*\0" matches anything remaining */
        return HOST_MATCH;

      while (*hostname) {
        /* The only recursive function in libcurl! */
        if (hostmatch(hostname++,pattern) == HOST_MATCH)
          return HOST_MATCH;
      }
      break;
    }

    if (toupper(c) != toupper(*hostname++))
      break;
  }
  return HOST_NOMATCH;
}

static int
cert_hostcheck(const char *match_pattern, const char *hostname)
{
  if (!match_pattern || !*match_pattern ||
      !hostname || !*hostname) /* sanity check */
    return 0;

  if(curl_strequal(hostname,match_pattern)) /* trivial case */
    return 1;

  if (hostmatch(hostname,match_pattern) == HOST_MATCH)
    return 1;
  return 0;
}

/* Quote from RFC2818 section 3.1 "Server Identity"

   If a subjectAltName extension of type dNSName is present, that MUST
   be used as the identity. Otherwise, the (most specific) Common Name
   field in the Subject field of the certificate MUST be used. Although
   the use of the Common Name is existing practice, it is deprecated and
   Certification Authorities are encouraged to use the dNSName instead.

   Matching is performed using the matching rules specified by
   [RFC2459].  If more than one identity of a given type is present in
   the certificate (e.g., more than one dNSName name, a match in any one
   of the set is considered acceptable.) Names may contain the wildcard
   character * which is considered to match any single domain name
   component or component fragment. E.g., *.a.com matches foo.a.com but
   not bar.foo.a.com. f*.com matches foo.com but not bar.com.

   In some cases, the URI is specified as an IP address rather than a
   hostname. In this case, the iPAddress subjectAltName must be present
   in the certificate and must exactly match the IP in the URI.

*/
static CURLcode verifyhost(struct connectdata *conn,
                           X509 *server_cert)
{
  bool matched = FALSE; /* no alternative match yet */
  int target = GEN_DNS; /* target type, GEN_DNS or GEN_IPADD */
  int addrlen = 0;
  struct SessionHandle *data = conn->data;
  STACK_OF(GENERAL_NAME) *altnames;
#ifdef ENABLE_IPV6
  struct in6_addr addr;
#else
  struct in_addr addr;
#endif
  CURLcode res = CURLE_OK;

#ifdef ENABLE_IPV6
  if(conn->bits.ipv6_ip &&
     Curl_inet_pton(AF_INET6, conn->host.name, &addr)) {
    target = GEN_IPADD;
    addrlen = sizeof(struct in6_addr);
  }
  else
#endif
    if(Curl_inet_pton(AF_INET, conn->host.name, &addr)) {
      target = GEN_IPADD;
      addrlen = sizeof(struct in_addr);
    }

  /* get a "list" of alternative names */
  altnames = X509_get_ext_d2i(server_cert, NID_subject_alt_name, NULL, NULL);

  if(altnames) {
    int numalts;
    int i;

    /* get amount of alternatives, RFC2459 claims there MUST be at least
       one, but we don't depend on it... */
    numalts = sk_GENERAL_NAME_num(altnames);

    /* loop through all alternatives while none has matched */
    for (i=0; (i<numalts) && !matched; i++) {
      /* get a handle to alternative name number i */
      const GENERAL_NAME *check = sk_GENERAL_NAME_value(altnames, i);

      /* only check alternatives of the same type the target is */
      if(check->type == target) {
        /* get data and length */
        const char *altptr = (char *)ASN1_STRING_data(check->d.ia5);
        int altlen;

        switch(target) {
        case GEN_DNS: /* name/pattern comparison */
          /* The OpenSSL man page explicitly says: "In general it cannot be
             assumed that the data returned by ASN1_STRING_data() is null
             terminated or does not contain embedded nulls." But also that
             "The actual format of the data will depend on the actual string
             type itself: for example for and IA5String the data will be ASCII"

             Gisle researched the OpenSSL sources:
             "I checked the 0.9.6 and 0.9.8 sources before my patch and
             it always 0-terminates an IA5String."
          */
          if (cert_hostcheck(altptr, conn->host.name))
            matched = TRUE;
          break;

        case GEN_IPADD: /* IP address comparison */
          /* compare alternative IP address if the data chunk is the same size
             our server IP address is */
          altlen = ASN1_STRING_length(check->d.ia5);
          if((altlen == addrlen) && !memcmp(altptr, &addr, altlen))
            matched = TRUE;
          break;
        }
      }
    }
    GENERAL_NAMES_free(altnames);
  }

  if(matched)
    /* an alternative name matched the server hostname */
    infof(data, "\t subjectAltName: %s matched\n", conn->host.dispname);
  else {
    /* we have to look to the last occurence of a commonName in the
       distinguished one to get the most significant one. */
    int j,i=-1 ;

/* The following is done because of a bug in 0.9.6b */

    unsigned char *nulstr = (unsigned char *)"";
    unsigned char *peer_CN = nulstr;

    X509_NAME *name = X509_get_subject_name(server_cert) ;
    if (name)
      while ((j=X509_NAME_get_index_by_NID(name,NID_commonName,i))>=0)
        i=j;

    /* we have the name entry and we will now convert this to a string
       that we can use for comparison. Doing this we support BMPstring,
       UTF8 etc. */

    if (i>=0) {
      ASN1_STRING *tmp = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name,i));

      /* In OpenSSL 0.9.7d and earlier, ASN1_STRING_to_UTF8 fails if the input
         is already UTF-8 encoded. We check for this case and copy the raw
         string manually to avoid the problem. This code can be made
         conditional in the future when OpenSSL has been fixed. Work-around
         brought by Alexis S. L. Carvalho. */
      if (tmp && ASN1_STRING_type(tmp) == V_ASN1_UTF8STRING) {
        j = ASN1_STRING_length(tmp);
        if (j >= 0) {
          peer_CN = OPENSSL_malloc(j+1);
          if (peer_CN) {
            memcpy(peer_CN, ASN1_STRING_data(tmp), j);
            peer_CN[j] = '\0';
          }
        }
      }
      else /* not a UTF8 name */
        j = ASN1_STRING_to_UTF8(&peer_CN, tmp);
    }

    if (peer_CN == nulstr)
       peer_CN = NULL;
#ifdef CURL_DOES_CONVERSIONS
    else {
      /* convert peer_CN from UTF8 */
      size_t rc;
      rc = Curl_convert_from_utf8(data, peer_CN, strlen(peer_CN));
      /* Curl_convert_from_utf8 calls failf if unsuccessful */
      if (rc != CURLE_OK) {
        return(rc);
      }
    }
#endif /* CURL_DOES_CONVERSIONS */

    if (!peer_CN) {
      if(data->set.ssl.verifyhost > 1) {
        failf(data,
              "SSL: unable to obtain common name from peer certificate");
        return CURLE_SSL_PEER_CERTIFICATE;
      }
      else {
        /* Consider verifyhost == 1 as an "OK" for a missing CN field, but we
           output a note about the situation */
        infof(data, "\t common name: WARNING couldn't obtain\n");
      }
    }
    else if(!cert_hostcheck((const char *)peer_CN, conn->host.name)) {
      if(data->set.ssl.verifyhost > 1) {
        failf(data, "SSL: certificate subject name '%s' does not match "
              "target host name '%s'", peer_CN, conn->host.dispname);
        res = CURLE_SSL_PEER_CERTIFICATE;
      }
      else
        infof(data, "\t common name: %s (does not match '%s')\n",
              peer_CN, conn->host.dispname);
    }
    else {
      infof(data, "\t common name: %s (matched)\n", peer_CN);
    }
    if(peer_CN)
      OPENSSL_free(peer_CN);
  }
  return res;
}
#endif

/* The SSL_CTRL_SET_MSG_CALLBACK doesn't exist in ancient OpenSSL versions
   and thus this cannot be done there. */
#ifdef SSL_CTRL_SET_MSG_CALLBACK

static const char *ssl_msg_type(int ssl_ver, int msg)
{
  if (ssl_ver == SSL2_VERSION_MAJOR) {
    switch (msg) {
      case SSL2_MT_ERROR:
        return "Error";
      case SSL2_MT_CLIENT_HELLO:
        return "Client hello";
      case SSL2_MT_CLIENT_MASTER_KEY:
        return "Client key";
      case SSL2_MT_CLIENT_FINISHED:
        return "Client finished";
      case SSL2_MT_SERVER_HELLO:
        return "Server hello";
      case SSL2_MT_SERVER_VERIFY:
        return "Server verify";
      case SSL2_MT_SERVER_FINISHED:
        return "Server finished";
      case SSL2_MT_REQUEST_CERTIFICATE:
        return "Request CERT";
      case SSL2_MT_CLIENT_CERTIFICATE:
        return "Client CERT";
    }
  }
  else if (ssl_ver == SSL3_VERSION_MAJOR) {
    switch (msg) {
      case SSL3_MT_HELLO_REQUEST:
        return "Hello request";
      case SSL3_MT_CLIENT_HELLO:
        return "Client hello";
      case SSL3_MT_SERVER_HELLO:
        return "Server hello";
      case SSL3_MT_CERTIFICATE:
        return "CERT";
      case SSL3_MT_SERVER_KEY_EXCHANGE:
        return "Server key exchange";
      case SSL3_MT_CLIENT_KEY_EXCHANGE:
        return "Client key exchange";
      case SSL3_MT_CERTIFICATE_REQUEST:
        return "Request CERT";
      case SSL3_MT_SERVER_DONE:
        return "Server finished";
      case SSL3_MT_CERTIFICATE_VERIFY:
        return "CERT verify";
      case SSL3_MT_FINISHED:
        return "Finished";
    }
  }
  return "Unknown";
}

static const char *tls_rt_type(int type)
{
  return (
    type == SSL3_RT_CHANGE_CIPHER_SPEC ? "TLS change cipher, " :
    type == SSL3_RT_ALERT              ? "TLS alert, "         :
    type == SSL3_RT_HANDSHAKE          ? "TLS handshake, "     :
    type == SSL3_RT_APPLICATION_DATA   ? "TLS app data, "      :
                                         "TLS Unknown, ");
}


/*
 * Our callback from the SSL/TLS layers.
 */
static void ssl_tls_trace(int direction, int ssl_ver, int content_type,
                          const void *buf, size_t len, const SSL *ssl,
                          struct connectdata *conn)
{
  struct SessionHandle *data;
  const char *msg_name, *tls_rt_name;
  char ssl_buf[1024];
  int  ver, msg_type, txt_len;

  if (!conn || !conn->data || !conn->data->set.fdebug ||
      (direction != 0 && direction != 1))
    return;

  data = conn->data;
  ssl_ver >>= 8;
  ver = (ssl_ver == SSL2_VERSION_MAJOR ? '2' :
         ssl_ver == SSL3_VERSION_MAJOR ? '3' : '?');

  /* SSLv2 doesn't seem to have TLS record-type headers, so OpenSSL
   * always pass-up content-type as 0. But the interesting message-type
   * is at 'buf[0]'.
   */
  if (ssl_ver == SSL3_VERSION_MAJOR && content_type != 0)
    tls_rt_name = tls_rt_type(content_type);
  else
    tls_rt_name = "";

  msg_type = *(char*)buf;
  msg_name = ssl_msg_type(ssl_ver, msg_type);

  txt_len = snprintf(ssl_buf, sizeof(ssl_buf), "SSLv%c, %s%s (%d):\n",
                     ver, tls_rt_name, msg_name, msg_type);
  Curl_debug(data, CURLINFO_TEXT, ssl_buf, (size_t)txt_len, NULL);

  Curl_debug(data, (direction == 1) ? CURLINFO_SSL_DATA_OUT :
             CURLINFO_SSL_DATA_IN, (char *)buf, len, NULL);
  (void) ssl;
}
#endif

#ifdef USE_SSLEAY
/* ====================================================== */

static CURLcode
Curl_ossl_connect_step1(struct connectdata *conn,
                        int sockindex)
{
  CURLcode retcode = CURLE_OK;

  struct SessionHandle *data = conn->data;
  SSL_METHOD_QUAL SSL_METHOD *req_method=NULL;
  void *ssl_sessionid=NULL;
  curl_socket_t sockfd = conn->sock[sockindex];
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  curlassert(ssl_connect_1 == connssl->connecting_state);

  /* Make funny stuff to get random input */
  Curl_ossl_seed(data);

  /* check to see if we've been told to use an explicit SSL/TLS version */
  switch(data->set.ssl.version) {
  default:
  case CURL_SSLVERSION_DEFAULT:
    /* we try to figure out version */
    req_method = SSLv23_client_method();
    break;
  case CURL_SSLVERSION_TLSv1:
    req_method = TLSv1_client_method();
    break;
  case CURL_SSLVERSION_SSLv2:
    req_method = SSLv2_client_method();
    break;
  case CURL_SSLVERSION_SSLv3:
    req_method = SSLv3_client_method();
    break;
  }

  if (connssl->ctx)
    SSL_CTX_free(connssl->ctx);
  connssl->ctx = SSL_CTX_new(req_method);

  if(!connssl->ctx) {
    failf(data, "SSL: couldn't create a context!");
    return CURLE_OUT_OF_MEMORY;
  }

#ifdef SSL_CTRL_SET_MSG_CALLBACK
  if (data->set.fdebug && data->set.verbose) {
    /* the SSL trace callback is only used for verbose logging so we only
       inform about failures of setting it */
    if (!SSL_CTX_callback_ctrl(connssl->ctx, SSL_CTRL_SET_MSG_CALLBACK,
                               (void (*)(void))ssl_tls_trace)) {
      infof(data, "SSL: couldn't set callback!\n");
    }
    else if (!SSL_CTX_ctrl(connssl->ctx, SSL_CTRL_SET_MSG_CALLBACK_ARG, 0,
                           conn)) {
      infof(data, "SSL: couldn't set callback argument!\n");
    }
  }
#endif

  /* OpenSSL contains code to work-around lots of bugs and flaws in various
     SSL-implementations. SSL_CTX_set_options() is used to enabled those
     work-arounds. The man page for this option states that SSL_OP_ALL enables
     all the work-arounds and that "It is usually safe to use SSL_OP_ALL to
     enable the bug workaround options if compatibility with somewhat broken
     implementations is desired."

  */
  SSL_CTX_set_options(connssl->ctx, SSL_OP_ALL);

#if 0
  /*
   * Not sure it's needed to tell SSL_connect() that socket is
   * non-blocking. It doesn't seem to care, but just return with
   * SSL_ERROR_WANT_x.
   */
  if (data->state.used_interface == Curl_if_multi)
    SSL_CTX_ctrl(connssl->ctx, BIO_C_SET_NBIO, 1, NULL);
#endif

  if(data->set.cert) {
    if(!cert_stuff(conn,
                   connssl->ctx,
                   data->set.cert,
                   data->set.cert_type,
                   data->set.key,
                   data->set.key_type)) {
      /* failf() is already done in cert_stuff() */
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  if(data->set.ssl.cipher_list) {
    if(!SSL_CTX_set_cipher_list(connssl->ctx,
                                data->set.ssl.cipher_list)) {
      failf(data, "failed setting cipher list");
      return CURLE_SSL_CIPHER;
    }
  }

  if (data->set.ssl.CAfile || data->set.ssl.CApath) {
    /* tell SSL where to find CA certificates that are used to verify
       the servers certificate. */
    if (!SSL_CTX_load_verify_locations(connssl->ctx, data->set.ssl.CAfile,
                                       data->set.ssl.CApath)) {
      if (data->set.ssl.verifypeer) {
        /* Fail if we insist on successfully verifying the server. */
        failf(data,"error setting certificate verify locations:\n"
              "  CAfile: %s\n  CApath: %s\n",
              data->set.ssl.CAfile ? data->set.ssl.CAfile : "none",
              data->set.ssl.CApath ? data->set.ssl.CApath : "none");
        return CURLE_SSL_CACERT_BADFILE;
      }
      else {
        /* Just continue with a warning if no strict  certificate verification
           is required. */
        infof(data, "error setting certificate verify locations,"
              " continuing anyway:\n");
      }
    }
    else {
      /* Everything is fine. */
      infof(data, "successfully set certificate verify locations:\n");
    }
    infof(data,
          "  CAfile: %s\n"
          "  CApath: %s\n",
          data->set.ssl.CAfile ? data->set.ssl.CAfile : "none",
          data->set.ssl.CApath ? data->set.ssl.CApath : "none");
  }
  /* SSL always tries to verify the peer, this only says whether it should
   * fail to connect if the verification fails, or if it should continue
   * anyway. In the latter case the result of the verification is checked with
   * SSL_get_verify_result() below. */
  SSL_CTX_set_verify(connssl->ctx,
                     data->set.ssl.verifypeer?SSL_VERIFY_PEER:SSL_VERIFY_NONE,
                     cert_verify_callback);

  /* give application a chance to interfere with SSL set up. */
  if(data->set.ssl.fsslctx) {
    retcode = (*data->set.ssl.fsslctx)(data, connssl->ctx,
                                       data->set.ssl.fsslctxp);
    if(retcode) {
      failf(data,"error signaled by ssl ctx callback");
      return retcode;
    }
  }

  /* Lets make an SSL structure */
  if (connssl->handle)
    SSL_free(connssl->handle);
  connssl->handle = SSL_new(connssl->ctx);
  if (!connssl->handle) {
    failf(data, "SSL: couldn't create a context (handle)!");
    return CURLE_OUT_OF_MEMORY;
  }
  SSL_set_connect_state(connssl->handle);

  connssl->server_cert = 0x0;

  /* Check if there's a cached ID we can/should use here! */
  if(!Curl_ssl_getsessionid(conn, &ssl_sessionid, NULL)) {
    /* we got a session id, use it! */
    if (!SSL_set_session(connssl->handle, ssl_sessionid)) {
      failf(data, "SSL: SSL_set_session failed: %s",
            ERR_error_string(ERR_get_error(),NULL));
      return CURLE_SSL_CONNECT_ERROR;
    }
    /* Informational message */
    infof (data, "SSL re-using session ID\n");
  }

  /* pass the raw socket into the SSL layers */
  if (!SSL_set_fd(connssl->handle, sockfd)) {
     failf(data, "SSL: SSL_set_fd failed: %s",
           ERR_error_string(ERR_get_error(),NULL));
     return CURLE_SSL_CONNECT_ERROR;
  }

  connssl->connecting_state = ssl_connect_2;
  return CURLE_OK;
}

static CURLcode
Curl_ossl_connect_step2(struct connectdata *conn,
                        int sockindex, long *timeout_ms)
{
  struct SessionHandle *data = conn->data;
  int err;
  long has_passed;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  curlassert(ssl_connect_2 == connssl->connecting_state
             || ssl_connect_2_reading == connssl->connecting_state
             || ssl_connect_2_writing == connssl->connecting_state);

  /* Find out if any timeout is set. If not, use 300 seconds.
     Otherwise, figure out the most strict timeout of the two possible one
     and then how much time that has elapsed to know how much time we
     allow for the connect call */
  if(data->set.timeout && data->set.connecttimeout) {
    /* get the most strict timeout of the ones converted to milliseconds */
    if(data->set.timeout<data->set.connecttimeout)
      *timeout_ms = data->set.timeout*1000;
    else
      *timeout_ms = data->set.connecttimeout*1000;
  }
  else if(data->set.timeout)
    *timeout_ms = data->set.timeout*1000;
  else if(data->set.connecttimeout)
    *timeout_ms = data->set.connecttimeout*1000;
  else
    /* no particular time-out has been set */
    *timeout_ms= DEFAULT_CONNECT_TIMEOUT;

  /* Evaluate in milliseconds how much time that has passed */
  has_passed = Curl_tvdiff(Curl_tvnow(), data->progress.t_startsingle);

  /* subtract the passed time */
  *timeout_ms -= has_passed;

  if(*timeout_ms < 0) {
    /* a precaution, no need to continue if time already is up */
    failf(data, "SSL connection timeout");
    return CURLE_OPERATION_TIMEOUTED;
  }

  err = SSL_connect(connssl->handle);

  /* 1  is fine
     0  is "not successful but was shut down controlled"
     <0 is "handshake was not successful, because a fatal error occurred" */
  if(1 != err) {
    int detail = SSL_get_error(connssl->handle, err);

    if(SSL_ERROR_WANT_READ == detail) {
      connssl->connecting_state = ssl_connect_2_reading;
      return CURLE_OK;
    }
    else if(SSL_ERROR_WANT_WRITE == detail) {
      connssl->connecting_state = ssl_connect_2_writing;
      return CURLE_OK;
    }
    else {
      /* untreated error */
      unsigned long errdetail;
      char error_buffer[256]; /* OpenSSL documents that this must be at least
                                 256 bytes long. */
      CURLcode rc;
      const char *cert_problem = NULL;

      connssl->connecting_state = ssl_connect_2; /* the connection failed,
                                                    we're not waiting for
                                                    anything else. */

      errdetail = ERR_get_error(); /* Gets the earliest error code from the
                                      thread's error queue and removes the
                                      entry. */

      switch(errdetail) {
      case 0x1407E086:
        /* 1407E086:
           SSL routines:
           SSL2_SET_CERTIFICATE:
           certificate verify failed */
        /* fall-through */
      case 0x14090086:
        /* 14090086:
           SSL routines:
           SSL3_GET_SERVER_CERTIFICATE:
           certificate verify failed */
        cert_problem = "SSL certificate problem, verify that the CA cert is"
          " OK. Details:\n";
        rc = CURLE_SSL_CACERT;
        break;
      default:
        rc = CURLE_SSL_CONNECT_ERROR;
        break;
      }

      /* detail is already set to the SSL error above */

      /* If we e.g. use SSLv2 request-method and the server doesn't like us
       * (RST connection etc.), OpenSSL gives no explanation whatsoever and
       * the SO_ERROR is also lost.
       */
      if (CURLE_SSL_CONNECT_ERROR == rc && errdetail == 0) {
        failf(data, "Unknown SSL protocol error in connection to %s:%d ",
              conn->host.name, conn->port);
        return rc;
      }
      /* Could be a CERT problem */

      SSL_strerror(errdetail, error_buffer, sizeof(error_buffer));
      failf(data, "%s%s", cert_problem ? cert_problem : "", error_buffer);
      return rc;
    }
  }
  else {
    /* we have been connected fine, we're not waiting for anything else. */
    connssl->connecting_state = ssl_connect_3;

    /* Informational message */
    infof (data, "SSL connection using %s\n",
           SSL_get_cipher(connssl->handle));

    return CURLE_OK;
  }
}

static CURLcode
Curl_ossl_connect_step3(struct connectdata *conn,
                  int sockindex)
{
  CURLcode retcode = CURLE_OK;
  char * str;
  long lerr;
  ASN1_TIME *certdate;
  void *ssl_sessionid=NULL;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  curlassert(ssl_connect_3 == connssl->connecting_state);

  if(Curl_ssl_getsessionid(conn, &ssl_sessionid, NULL)) {
    /* Since this is not a cached session ID, then we want to stach this one
       in the cache! */
    SSL_SESSION *our_ssl_sessionid;
#ifdef HAVE_SSL_GET1_SESSION
    our_ssl_sessionid = SSL_get1_session(connssl->handle);

    /* SSL_get1_session() will increment the reference
       count and the session will stay in memory until explicitly freed with
       SSL_SESSION_free(3), regardless of its state.
       This function was introduced in openssl 0.9.5a. */
#else
    our_ssl_sessionid = SSL_get_session(connssl->handle);

    /* if SSL_get1_session() is unavailable, use SSL_get_session().
       This is an inferior option because the session can be flushed
       at any time by openssl. It is included only so curl compiles
       under versions of openssl < 0.9.5a.

       WARNING: How curl behaves if it's session is flushed is
       untested.
    */
#endif
    retcode = Curl_ssl_addsessionid(conn, our_ssl_sessionid,
                                    0 /* unknown size */);
    if(retcode) {
      failf(data, "failed to store ssl session");
      return retcode;
    }
  }


  /* Get server's certificate (note: beware of dynamic allocation) - opt */
  /* major serious hack alert -- we should check certificates
   * to authenticate the server; otherwise we risk man-in-the-middle
   * attack
   */

  connssl->server_cert = SSL_get_peer_certificate(connssl->handle);
  if(!connssl->server_cert) {
    failf(data, "SSL: couldn't get peer certificate!");
    return CURLE_SSL_PEER_CERTIFICATE;
  }
  infof (data, "Server certificate:\n");

  str = X509_NAME_oneline(X509_get_subject_name(connssl->server_cert),
                          NULL, 0);
  if(!str) {
    failf(data, "SSL: couldn't get X509-subject!");
    X509_free(connssl->server_cert);
    connssl->server_cert = NULL;
    return CURLE_SSL_CONNECT_ERROR;
  }
  infof(data, "\t subject: %s\n", str);
  CRYPTO_free(str);

  certdate = X509_get_notBefore(connssl->server_cert);
  Curl_ASN1_UTCTIME_output(conn, "\t start date: ", certdate);

  certdate = X509_get_notAfter(connssl->server_cert);
  Curl_ASN1_UTCTIME_output(conn, "\t expire date: ", certdate);

  if(data->set.ssl.verifyhost) {
    retcode = verifyhost(conn, connssl->server_cert);
    if(retcode) {
      X509_free(connssl->server_cert);
      connssl->server_cert = NULL;
      return retcode;
    }
  }

  str = X509_NAME_oneline(X509_get_issuer_name(connssl->server_cert),
                          NULL, 0);
  if(!str) {
    failf(data, "SSL: couldn't get X509-issuer name!");
    retcode = CURLE_SSL_CONNECT_ERROR;
  }
  else {
    infof(data, "\t issuer: %s\n", str);
    CRYPTO_free(str);

    /* We could do all sorts of certificate verification stuff here before
       deallocating the certificate. */

    lerr = data->set.ssl.certverifyresult=
      SSL_get_verify_result(connssl->handle);
    if(data->set.ssl.certverifyresult != X509_V_OK) {
      if(data->set.ssl.verifypeer) {
        /* We probably never reach this, because SSL_connect() will fail
           and we return earlyer if verifypeer is set? */
        failf(data, "SSL certificate verify result: %s (%ld)",
              X509_verify_cert_error_string(lerr), lerr);
        retcode = CURLE_SSL_PEER_CERTIFICATE;
      }
      else
        infof(data, "SSL certificate verify result: %s (%ld),"
              " continuing anyway.\n",
              X509_verify_cert_error_string(lerr), lerr);
    }
    else
      infof(data, "SSL certificate verify ok.\n");
  }

  X509_free(connssl->server_cert);
  connssl->server_cert = NULL;
  connssl->connecting_state = ssl_connect_done;
  return retcode;
}

static CURLcode
Curl_ossl_connect_common(struct connectdata *conn,
                         int sockindex,
                         bool nonblocking,
                         bool *done)
{
  CURLcode retcode;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  curl_socket_t sockfd = conn->sock[sockindex];
  long timeout_ms;

  if (ssl_connect_1==connssl->connecting_state) {
    retcode = Curl_ossl_connect_step1(conn, sockindex);
    if (retcode)
      return retcode;
  }

  timeout_ms = 0;
  while (ssl_connect_2 == connssl->connecting_state ||
         ssl_connect_2_reading == connssl->connecting_state ||
         ssl_connect_2_writing == connssl->connecting_state) {

    /* if ssl is expecting something, check if it's available. */
    if (connssl->connecting_state == ssl_connect_2_reading
        || connssl->connecting_state == ssl_connect_2_writing) {

      int writefd = ssl_connect_2_writing==
        connssl->connecting_state?sockfd:CURL_SOCKET_BAD;
      int readfd = ssl_connect_2_reading==
        connssl->connecting_state?sockfd:CURL_SOCKET_BAD;

      while(1) {
        int what = Curl_select(readfd, writefd, nonblocking?0:(int)timeout_ms);
        if(what > 0)
          /* readable or writable, go loop in the outer loop */
          break;
        else if(0 == what) {
          if (nonblocking) {
            *done = FALSE;
            return CURLE_OK;
          }
          else {
            /* timeout */
            failf(data, "SSL connection timeout");
            return CURLE_OPERATION_TIMEDOUT;
          }
        }
        else {
          /* anything that gets here is fatally bad */
          failf(data, "select on SSL socket, errno: %d", Curl_sockerrno());
          return CURLE_SSL_CONNECT_ERROR;
        }
      } /* while()-loop for the select() */
    }

    /* get the timeout from step2 to avoid computing it twice. */
    retcode = Curl_ossl_connect_step2(conn, sockindex, &timeout_ms);
    if (retcode)
      return retcode;

  } /* repeat step2 until all transactions are done. */


  if (ssl_connect_3==connssl->connecting_state) {
    retcode = Curl_ossl_connect_step3(conn, sockindex);
    if (retcode)
      return retcode;
  }

  if (ssl_connect_done==connssl->connecting_state) {
    *done = TRUE;
  }
  else {
    *done = FALSE;
  }

  /* Reset our connect state machine */
  connssl->connecting_state = ssl_connect_1;

  return CURLE_OK;
}

CURLcode
Curl_ossl_connect_nonblocking(struct connectdata *conn,
                              int sockindex,
                              bool *done)
{
  return Curl_ossl_connect_common(conn, sockindex, TRUE, done);
}

CURLcode
Curl_ossl_connect(struct connectdata *conn,
                  int sockindex)
{
  CURLcode retcode;
  bool done = FALSE;

  retcode = Curl_ossl_connect_common(conn, sockindex, FALSE, &done);
  if (retcode)
    return retcode;

  curlassert(done);

  return CURLE_OK;
}

/* return number of sent (non-SSL) bytes */
ssize_t Curl_ossl_send(struct connectdata *conn,
                       int sockindex,
                       void *mem,
                       size_t len)
{
  /* SSL_write() is said to return 'int' while write() and send() returns
     'size_t' */
  int err;
  char error_buffer[120]; /* OpenSSL documents that this must be at least 120
                             bytes long. */
  unsigned long sslerror;
  int rc = SSL_write(conn->ssl[sockindex].handle, mem, (int)len);

  if(rc < 0) {
    err = SSL_get_error(conn->ssl[sockindex].handle, rc);

    switch(err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      /* The operation did not complete; the same TLS/SSL I/O function
         should be called again later. This is basicly an EWOULDBLOCK
         equivalent. */
      return 0;
    case SSL_ERROR_SYSCALL:
      failf(conn->data, "SSL_write() returned SYSCALL, errno = %d\n",
            Curl_sockerrno());
      return -1;
    case SSL_ERROR_SSL:
      /*  A failure in the SSL library occurred, usually a protocol error.
          The OpenSSL error queue contains more information on the error. */
      sslerror = ERR_get_error();
      failf(conn->data, "SSL_write() error: %s\n",
            ERR_error_string(sslerror, error_buffer));
      return -1;
    }
    /* a true error */
    failf(conn->data, "SSL_write() return error %d\n", err);
    return -1;
  }
  return (ssize_t)rc; /* number of bytes */
}

/*
 * If the read would block we return -1 and set 'wouldblock' to TRUE.
 * Otherwise we return the amount of data read. Other errors should return -1
 * and set 'wouldblock' to FALSE.
 */
ssize_t Curl_ossl_recv(struct connectdata *conn, /* connection data */
                       int num,                  /* socketindex */
                       char *buf,                /* store read data here */
                       size_t buffersize,        /* max amount to read */
                       bool *wouldblock)
{
  char error_buffer[120]; /* OpenSSL documents that this must be at
                             least 120 bytes long. */
  unsigned long sslerror;
  ssize_t nread = (ssize_t)SSL_read(conn->ssl[num].handle, buf,
                                    (int)buffersize);
  *wouldblock = FALSE;
  if(nread < 0) {
    /* failed SSL_read */
    int err = SSL_get_error(conn->ssl[num].handle, (int)nread);

    switch(err) {
    case SSL_ERROR_NONE: /* this is not an error */
    case SSL_ERROR_ZERO_RETURN: /* no more data */
      break;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      /* there's data pending, re-invoke SSL_read() */
      *wouldblock = TRUE;
      return -1; /* basically EWOULDBLOCK */
    default:
      /* openssl/ssl.h says "look at error stack/return value/errno" */
      sslerror = ERR_get_error();
      failf(conn->data, "SSL read: %s, errno %d",
            ERR_error_string(sslerror, error_buffer),
            Curl_sockerrno() );
      return -1;
    }
  }
  return nread;
}

size_t Curl_ossl_version(char *buffer, size_t size)
{
#ifdef YASSL_VERSION
  /* yassl provides an OpenSSL API compatiblity layer so it looks identical
     to OpenSSL in all other aspects */
  return snprintf(buffer, size, " yassl/%s", YASSL_VERSION);
#else /* YASSL_VERSION */

#if (SSLEAY_VERSION_NUMBER >= 0x905000)
  {
    char sub[2];
    unsigned long ssleay_value;
    sub[1]='\0';
    ssleay_value=SSLeay();
    if(ssleay_value < 0x906000) {
      ssleay_value=SSLEAY_VERSION_NUMBER;
      sub[0]='\0';
    }
    else {
      if(ssleay_value&0xff0) {
        sub[0]=(char)(((ssleay_value>>4)&0xff) + 'a' -1);
      }
      else
        sub[0]='\0';
    }

    return snprintf(buffer, size, " OpenSSL/%lx.%lx.%lx%s",
                    (ssleay_value>>28)&0xf,
                    (ssleay_value>>20)&0xff,
                    (ssleay_value>>12)&0xff,
                    sub);
  }

#else /* SSLEAY_VERSION_NUMBER is less than 0.9.5 */

#if (SSLEAY_VERSION_NUMBER >= 0x900000)
  return snprintf(buffer, size, " OpenSSL/%lx.%lx.%lx",
                  (SSLEAY_VERSION_NUMBER>>28)&0xff,
                  (SSLEAY_VERSION_NUMBER>>20)&0xff,
                  (SSLEAY_VERSION_NUMBER>>12)&0xf);

#else /* (SSLEAY_VERSION_NUMBER >= 0x900000) */
  {
    char sub[2];
    sub[1]='\0';
    if(SSLEAY_VERSION_NUMBER&0x0f) {
      sub[0]=(SSLEAY_VERSION_NUMBER&0x0f) + 'a' -1;
    }
    else
      sub[0]='\0';

    return snprintf(buffer, size, " SSL/%x.%x.%x%s",
                    (SSLEAY_VERSION_NUMBER>>12)&0xff,
                    (SSLEAY_VERSION_NUMBER>>8)&0xf,
                    (SSLEAY_VERSION_NUMBER>>4)&0xf, sub);
  }
#endif /* (SSLEAY_VERSION_NUMBER >= 0x900000) */
#endif /* SSLEAY_VERSION_NUMBER is less than 0.9.5 */

#endif /* YASSL_VERSION */
}
#endif /* USE_SSLEAY */
