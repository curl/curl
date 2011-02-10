/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#ifdef HAVE_LIMITS_H
#include <limits.h>
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
#include "connect.h"
#include "strequal.h"
#include "select.h"
#include "sslgen.h"
#include "rawstr.h"

#define _MPRINTF_REPLACE /* use the internal *printf() functions */
#include <curl/mprintf.h>

#ifdef USE_SSLEAY

#ifdef USE_OPENSSL
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#else
#include <rand.h>
#include <x509v3.h>
#endif

#include "curl_memory.h"
#include "easyif.h" /* for Curl_convert_from_utf8 prototype */

/* The last #include file should be: */
#include "memdebug.h"

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
#include <openssl/ui.h>
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

#if OPENSSL_VERSION_NUMBER >= 0x00907000L
/* 0.9.6 didn't have X509_STORE_set_flags() */
#define HAVE_X509_STORE_SET_FLAGS 1
#else
#define X509_STORE_set_flags(x,y)
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
#ifdef HAVE_USERDATA_IN_PWD_CALLBACK
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
    nread += RAND_load_file((data->set.str[STRING_SSL_RANDOM_FILE]?
                             data->set.str[STRING_SSL_RANDOM_FILE]:
                             RANDOM_FILE),
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
  if(data->set.str[STRING_SSL_EGDSOCKET])
#define EGD_SOCKET "" /* doesn't matter won't be used */
#endif
  {
    /* If there's an option and a define, the option overrides the
       define */
    int ret = RAND_egd(data->set.str[STRING_SSL_EGDSOCKET]?
                       data->set.str[STRING_SSL_EGDSOCKET]:EGD_SOCKET);
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
  /* if RAND_screen() is present, this is windows and thus we assume that the
     randomness is already taken care of */
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
    } while(!RAND_status());
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

  if(!ssl_seeded || data->set.str[STRING_SSL_RANDOM_FILE] ||
     data->set.str[STRING_SSL_EGDSOCKET]) {
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
  if(Curl_raw_equal(type, "PEM"))
    return SSL_FILETYPE_PEM;
  if(Curl_raw_equal(type, "DER"))
    return SSL_FILETYPE_ASN1;
  if(Curl_raw_equal(type, "ENG"))
    return SSL_FILETYPE_ENGINE;
  if(Curl_raw_equal(type, "P12"))
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

  int file_type = do_file_type(cert_type);

  if(cert_file != NULL || file_type == SSL_FILETYPE_ENGINE) {
    SSL *ssl;
    X509 *x509;
    int cert_done = 0;

    if(data->set.str[STRING_KEY_PASSWD]) {
#ifndef HAVE_USERDATA_IN_PWD_CALLBACK
      /*
       * If password has been given, we store that in the global
       * area (*shudder*) for a while:
       */
      size_t len = strlen(data->set.str[STRING_KEY_PASSWD]);
      if(len < sizeof(global_passwd))
        memcpy(global_passwd, data->set.str[STRING_KEY_PASSWD], len+1);
#else
      /*
       * We set the password in the callback userdata
       */
      SSL_CTX_set_default_passwd_cb_userdata(ctx,
                                             data->set.str[STRING_KEY_PASSWD]);
#endif
      /* Set passwd callback: */
      SSL_CTX_set_default_passwd_cb(ctx, passwd_callback);
    }


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
#if defined(HAVE_OPENSSL_ENGINE_H) && defined(ENGINE_CTRL_GET_CMD_FROM_NAME)
      {
        if(data->state.engine) {
          const char *cmd_name = "LOAD_CERT_CTRL";
          struct {
            const char *cert_id;
            X509 *cert;
          } params;

          params.cert_id = cert_file;
          params.cert = NULL;

          /* Does the engine supports LOAD_CERT_CTRL ? */
          if (!ENGINE_ctrl(data->state.engine, ENGINE_CTRL_GET_CMD_FROM_NAME,
                           0, (void *)cmd_name, NULL)) {
            failf(data, "ssl engine does not support loading certificates");
            return 0;
          }

          /* Load the certificate from the engine */
          if (!ENGINE_ctrl_cmd(data->state.engine, cmd_name,
                               0, &params, NULL, 1)) {
            failf(data, "ssl engine cannot load client cert with id"
                  " '%s' [%s]", cert_file,
                  ERR_error_string(ERR_get_error(), NULL));
            return 0;
          }

          if (!params.cert) {
            failf(data, "ssl engine didn't initialized the certificate "
                  "properly.");
            return 0;
          }

          if(SSL_CTX_use_certificate(ctx, params.cert) != 1) {
            failf(data, "unable to set client certificate");
            X509_free(params.cert);
            return 0;
          }
          X509_free(params.cert); /* we don't need the handle any more... */
        }
        else {
          failf(data, "crypto engine not set, can't load certificate");
          return 0;
        }
      }
      break;
#else
      failf(data, "file type ENG for certificate not implemented");
      return 0;
#endif

    case SSL_FILETYPE_PKCS12:
    {
#ifdef HAVE_PKCS12_SUPPORT
      FILE *f;
      PKCS12 *p12;
      EVP_PKEY *pri;
      STACK_OF(X509) *ca = NULL;
      int i;

      f = fopen(cert_file,"rb");
      if(!f) {
        failf(data, "could not open PKCS12 file '%s'", cert_file);
        return 0;
      }
      p12 = d2i_PKCS12_fp(f, NULL);
      fclose(f);

      if(!p12) {
        failf(data, "error reading PKCS12 file '%s'", cert_file );
        return 0;
      }

      PKCS12_PBE_add();

      if(!PKCS12_parse(p12, data->set.str[STRING_KEY_PASSWD], &pri, &x509,
                        &ca)) {
        failf(data,
              "could not parse PKCS12 file, check password, OpenSSL error %s",
              ERR_error_string(ERR_get_error(), NULL) );
        PKCS12_free(p12);
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

      if (!SSL_CTX_check_private_key (ctx)) {
        failf(data, "private key from PKCS12 file '%s' "
              "does not match certificate in same file", cert_file);
        EVP_PKEY_free(pri);
        X509_free(x509);
        return 0;
      }
      /* Set Certificate Verification chain */
      if (ca && sk_X509_num(ca)) {
        for (i = 0; i < sk_X509_num(ca); i++) {
          if (!SSL_CTX_add_extra_chain_cert(ctx,sk_X509_value(ca, i))) {
            failf(data, "cannot add certificate to certificate chain");
            EVP_PKEY_free(pri);
            X509_free(x509);
            return 0;
          }
          if (!SSL_CTX_add_client_CA(ctx, sk_X509_value(ca, i))) {
            failf(data, "cannot add certificate to client CA list");
            EVP_PKEY_free(pri);
            X509_free(x509);
            return 0;
          }
        }
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
        failf(data, "unable to set private key file: '%s' type %s",
              key_file, key_type?key_type:"PEM");
        return 0;
      }
      break;
    case SSL_FILETYPE_ENGINE:
#ifdef HAVE_OPENSSL_ENGINE_H
      {                         /* XXXX still needs some work */
        EVP_PKEY *priv_key = NULL;
        if(data->state.engine) {
#ifdef HAVE_ENGINE_LOAD_FOUR_ARGS
          UI_METHOD *ui_method = UI_OpenSSL();
#endif
          /* the typecast below was added to please mingw32 */
          priv_key = (EVP_PKEY *)
            ENGINE_load_private_key(data->state.engine,key_file,
#ifdef HAVE_ENGINE_LOAD_FOUR_ARGS
                                    ui_method,
#endif
                                    data->set.str[STRING_KEY_PASSWD]);
          if(!priv_key) {
            failf(data, "failed to load private key from crypto engine");
            return 0;
          }
          if(SSL_CTX_use_PrivateKey(ctx, priv_key) != 1) {
            failf(data, "unable to set private key");
            EVP_PKEY_free(priv_key);
            return 0;
          }
          EVP_PKEY_free(priv_key);  /* we don't need the handle any more... */
        }
        else {
          failf(data, "crypto engine not set, can't load private key");
          return 0;
        }
      }
      break;
#else
      failf(data, "file type ENG for private key not supported");
      return 0;
#endif
    case SSL_FILETYPE_PKCS12:
      if(!cert_done) {
        failf(data, "file type P12 for private key not supported");
        return 0;
      }
      break;
    default:
      failf(data, "not supported file type for private key");
      return 0;
    }

    ssl=SSL_new(ctx);
    if(NULL == ssl) {
      failf(data,"unable to create an SSL structure");
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
      return 0;
    }
#ifndef HAVE_USERDATA_IN_PWD_CALLBACK
    /* erase it now */
    memset(global_passwd, 0, sizeof(global_passwd));
#endif
  }
  return 1;
}

/* returns non-zero on failure */
static int x509_name_oneline(X509_NAME *a, char *buf, size_t size)
{
#if 0
  return X509_NAME_oneline(a, buf, size);
#else
  BIO *bio_out = BIO_new(BIO_s_mem());
  BUF_MEM *biomem;
  int rc;

  if(!bio_out)
    return 1; /* alloc failed! */

  rc = X509_NAME_print_ex(bio_out, a, 0, XN_FLAG_SEP_SPLUS_SPC);
  BIO_get_mem_ptr(bio_out, &biomem);

  if((size_t)biomem->length < size)
    size = biomem->length;
  else
    size--; /* don't overwrite the buffer end */

  memcpy(buf, biomem->data, size);
  buf[size]=0;

  BIO_free(bio_out);

  return !rc;
#endif
}

static
int cert_verify_callback(int ok, X509_STORE_CTX *ctx)
{
  X509 *err_cert;
  char buf[256];

  err_cert=X509_STORE_CTX_get_current_cert(ctx);
  (void)x509_name_oneline(X509_get_subject_name(err_cert), buf, sizeof(buf));
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
  return buf;
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

  /* Init the global ciphers and digests */
  if(!SSLeay_add_ssl_algorithms())
    return 0;

  OpenSSL_add_all_algorithms();

  return 1;
}

#endif /* USE_SSLEAY */

#ifdef USE_SSLEAY

/* Global cleanup */
void Curl_ossl_cleanup(void)
{
  /* Free the SSL error strings */
  ERR_free_strings();

  /* EVP_cleanup() removes all ciphers and digests from the table. */
  EVP_cleanup();

#ifdef HAVE_ENGINE_CLEANUP
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
  if(rc > 0)
    return 1; /* connection still in place */

  if(rc == 0)
    return 0; /* connection has been closed */

  return -1; /* connection status unknown */
}

/* Selects an OpenSSL crypto engine
 */
CURLcode Curl_ossl_set_engine(struct SessionHandle *data, const char *engine)
{
#if defined(USE_SSLEAY) && defined(HAVE_OPENSSL_ENGINE_H)
  ENGINE *e;

#if OPENSSL_VERSION_NUMBER >= 0x00909000L
  e = ENGINE_by_id(engine);
#else
  /* avoid memory leak */
  for(e = ENGINE_get_first(); e; e = ENGINE_get_next(e)) {
    const char *e_id = ENGINE_get_id(e);
    if(!strcmp(engine, e_id))
      break;
  }
#endif

  if(!e) {
    failf(data, "SSL Engine '%s' not found", engine);
    return CURLE_SSL_ENGINE_NOTFOUND;
  }

  if(data->state.engine) {
    ENGINE_finish(data->state.engine);
    ENGINE_free(data->state.engine);
    data->state.engine = NULL;
  }
  if(!ENGINE_init(e)) {
    char buf[256];

    ENGINE_free(e);
    failf(data, "Failed to initialise SSL Engine '%s':\n%s",
          engine, SSL_strerror(ERR_get_error(), buf, sizeof(buf)));
    return CURLE_SSL_ENGINE_INITFAILED;
  }
  data->state.engine = e;
  return CURLE_OK;
#else
  (void)engine;
  failf(data, "SSL Engine not supported");
  return CURLE_SSL_ENGINE_NOTFOUND;
#endif
}

/* Sets engine as default for all SSL operations
 */
CURLcode Curl_ossl_set_engine_default(struct SessionHandle *data)
{
#ifdef HAVE_OPENSSL_ENGINE_H
  if(data->state.engine) {
    if(ENGINE_set_default(data->state.engine, ENGINE_METHOD_ALL) > 0) {
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

/* Return list of OpenSSL crypto engine names.
 */
struct curl_slist *Curl_ossl_engines_list(struct SessionHandle *data)
{
  struct curl_slist *list = NULL;
#if defined(USE_SSLEAY) && defined(HAVE_OPENSSL_ENGINE_H)
  struct curl_slist *beg = NULL;
  ENGINE *e;

  for (e = ENGINE_get_first(); e; e = ENGINE_get_next(e)) {
    list = curl_slist_append(list, ENGINE_get_id(e));
    if(list == NULL) {
      curl_slist_free_all(beg);
      return NULL;
    }
    else if(beg == NULL) {
      beg = list;
    }
  }
#endif
  (void) data;
  return list;
}


/*
 * This function is called when an SSL connection is closed.
 */
void Curl_ossl_close(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

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
  int buffsize;
  int err;
  int done = 0;

  /* This has only been tested on the proftpd server, and the mod_tls code
     sends a close notify alert without waiting for a close notify alert in
     response. Thus we wait for a close notify alert from the server, but
     we do not send one. Let's hope other servers do the same... */

  if(data->set.ftp_ccc == CURLFTPSSL_CCC_ACTIVE)
      (void)SSL_shutdown(connssl->handle);

  if(connssl->handle) {
    buffsize = (int)sizeof(buf);
    while(!done) {
      int what = Curl_socket_ready(conn->sock[sockindex],
                             CURL_SOCKET_BAD, SSL_SHUTDOWN_TIMEOUT);
      if(what > 0) {
        ERR_clear_error();

        /* Something to read, let's do it and hope that it is the close
           notify alert from the server */
        nread = (ssize_t)SSL_read(conn->ssl[sockindex].handle, buf,
                                  buffsize);
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
                SOCKERRNO);
          done = 1;
          break;
        }
      }
      else if(0 == what) {
        /* timeout */
        failf(data, "SSL shutdown timeout");
        done = 1;
      }
      else {
        /* anything that gets here is fatally bad */
        failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
        retval = -1;
        done = 1;
      }
    } /* while()-loop for the select() */

    if(data->set.verbose) {
#ifdef HAVE_SSL_GET_SHUTDOWN
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
#endif
    }

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
  /*
    ERR_remove_state() frees the error queue associated with
    thread pid.  If pid == 0, the current thread will have its
    error queue removed.

    Since error queue data structures are allocated
    automatically for new threads, they must be freed when
    threads are terminated in oder to avoid memory leaks.
  */
  ERR_remove_state(0);

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

static int asn1_output(const ASN1_UTCTIME *tm,
                       char *buf,
                       size_t sizeofbuf)
{
  const char *asn1_string;
  int gmt=FALSE;
  int i;
  int year=0,month=0,day=0,hour=0,minute=0,second=0;

  i=tm->length;
  asn1_string=(const char *)tm->data;

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

  snprintf(buf, sizeofbuf,
           "%04d-%02d-%02d %02d:%02d:%02d %s",
           year+1900, month, day, hour, minute, second, (gmt?"GMT":""));

  return 0;
}

/* ====================================================== */

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
  for(;;) {
    char c = *pattern++;

    if(c == '\0')
      return (*hostname ? HOST_NOMATCH : HOST_MATCH);

    if(c == '*') {
      c = *pattern;
      if(c == '\0')      /* "*\0" matches anything remaining */
        return HOST_MATCH;

      while(*hostname) {
        /* The only recursive function in libcurl! */
        if(hostmatch(hostname++,pattern) == HOST_MATCH)
          return HOST_MATCH;
      }
      break;
    }

    if(Curl_raw_toupper(c) != Curl_raw_toupper(*hostname++))
      break;
  }
  return HOST_NOMATCH;
}

static int
cert_hostcheck(const char *match_pattern, const char *hostname)
{
  if(!match_pattern || !*match_pattern ||
      !hostname || !*hostname) /* sanity check */
    return 0;

  if(Curl_raw_equal(hostname, match_pattern)) /* trivial case */
    return 1;

  if(hostmatch(hostname,match_pattern) == HOST_MATCH)
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
  int matched = -1; /* -1 is no alternative match yet, 1 means match and 0
                       means mismatch */
  int target = GEN_DNS; /* target type, GEN_DNS or GEN_IPADD */
  size_t addrlen = 0;
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
    for (i=0; (i<numalts) && (matched != 1); i++) {
      /* get a handle to alternative name number i */
      const GENERAL_NAME *check = sk_GENERAL_NAME_value(altnames, i);

      /* only check alternatives of the same type the target is */
      if(check->type == target) {
        /* get data and length */
        const char *altptr = (char *)ASN1_STRING_data(check->d.ia5);
        size_t altlen = (size_t) ASN1_STRING_length(check->d.ia5);

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
          if((altlen == strlen(altptr)) &&
             /* if this isn't true, there was an embedded zero in the name
                string and we cannot match it. */
             cert_hostcheck(altptr, conn->host.name))
            matched = 1;
          else
            matched = 0;
          break;

        case GEN_IPADD: /* IP address comparison */
          /* compare alternative IP address if the data chunk is the same size
             our server IP address is */
          if((altlen == addrlen) && !memcmp(altptr, &addr, altlen))
            matched = 1;
          else
            matched = 0;
          break;
        }
      }
    }
    GENERAL_NAMES_free(altnames);
  }

  if(matched == 1)
    /* an alternative name matched the server hostname */
    infof(data, "\t subjectAltName: %s matched\n", conn->host.dispname);
  else if(matched == 0) {
    /* an alternative name field existed, but didn't match and then
       we MUST fail */
    infof(data, "\t subjectAltName does not match %s\n", conn->host.dispname);
    res = CURLE_PEER_FAILED_VERIFICATION;
  }
  else {
    /* we have to look to the last occurence of a commonName in the
       distinguished one to get the most significant one. */
    int j,i=-1 ;

/* The following is done because of a bug in 0.9.6b */

    unsigned char *nulstr = (unsigned char *)"";
    unsigned char *peer_CN = nulstr;

    X509_NAME *name = X509_get_subject_name(server_cert) ;
    if(name)
      while((j = X509_NAME_get_index_by_NID(name, NID_commonName, i))>=0)
        i=j;

    /* we have the name entry and we will now convert this to a string
       that we can use for comparison. Doing this we support BMPstring,
       UTF8 etc. */

    if(i>=0) {
      ASN1_STRING *tmp = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name,i));

      /* In OpenSSL 0.9.7d and earlier, ASN1_STRING_to_UTF8 fails if the input
         is already UTF-8 encoded. We check for this case and copy the raw
         string manually to avoid the problem. This code can be made
         conditional in the future when OpenSSL has been fixed. Work-around
         brought by Alexis S. L. Carvalho. */
      if(tmp) {
        if(ASN1_STRING_type(tmp) == V_ASN1_UTF8STRING) {
          j = ASN1_STRING_length(tmp);
          if(j >= 0) {
            peer_CN = OPENSSL_malloc(j+1);
            if(peer_CN) {
              memcpy(peer_CN, ASN1_STRING_data(tmp), j);
              peer_CN[j] = '\0';
            }
          }
        }
        else /* not a UTF8 name */
          j = ASN1_STRING_to_UTF8(&peer_CN, tmp);

        if(peer_CN && ((int)strlen((char *)peer_CN) != j)) {
          /* there was a terminating zero before the end of string, this
             cannot match and we return failure! */
          failf(data, "SSL: illegal cert name field");
          res = CURLE_PEER_FAILED_VERIFICATION;
        }
      }
    }

    if(peer_CN == nulstr)
       peer_CN = NULL;
#ifdef CURL_DOES_CONVERSIONS
    else {
      /* convert peer_CN from UTF8 */
      size_t rc;
      rc = Curl_convert_from_utf8(data, peer_CN, strlen(peer_CN));
      /* Curl_convert_from_utf8 calls failf if unsuccessful */
      if(rc != CURLE_OK) {
        OPENSSL_free(peer_CN);
        return rc;
      }
    }
#endif /* CURL_DOES_CONVERSIONS */

    if(res)
      /* error already detected, pass through */
      ;
    else if(!peer_CN) {
      failf(data,
            "SSL: unable to obtain common name from peer certificate");
      res = CURLE_PEER_FAILED_VERIFICATION;
    }
    else if(!cert_hostcheck((const char *)peer_CN, conn->host.name)) {
      if(data->set.ssl.verifyhost > 1) {
        failf(data, "SSL: certificate subject name '%s' does not match "
              "target host name '%s'", peer_CN, conn->host.dispname);
        res = CURLE_PEER_FAILED_VERIFICATION;
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
#endif /* USE_SSLEAY */

/* The SSL_CTRL_SET_MSG_CALLBACK doesn't exist in ancient OpenSSL versions
   and thus this cannot be done there. */
#ifdef SSL_CTRL_SET_MSG_CALLBACK

static const char *ssl_msg_type(int ssl_ver, int msg)
{
  if(ssl_ver == SSL2_VERSION_MAJOR) {
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
  else if(ssl_ver == SSL3_VERSION_MAJOR) {
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

  if(!conn || !conn->data || !conn->data->set.fdebug ||
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
  if(ssl_ver == SSL3_VERSION_MAJOR && content_type != 0)
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

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
#  define use_sni(x)  sni = (x)
#else
#  define use_sni(x)  do { } while (0)
#endif

static CURLcode
ossl_connect_step1(struct connectdata *conn,
                   int sockindex)
{
  CURLcode retcode = CURLE_OK;

  struct SessionHandle *data = conn->data;
  SSL_METHOD_QUAL SSL_METHOD *req_method=NULL;
  void *ssl_sessionid=NULL;
  X509_LOOKUP *lookup=NULL;
  curl_socket_t sockfd = conn->sock[sockindex];
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
  bool sni;
#ifdef ENABLE_IPV6
  struct in6_addr addr;
#else
  struct in_addr addr;
#endif
#endif

  DEBUGASSERT(ssl_connect_1 == connssl->connecting_state);

  /* Make funny stuff to get random input */
  Curl_ossl_seed(data);

  /* check to see if we've been told to use an explicit SSL/TLS version */
  switch(data->set.ssl.version) {
  default:
  case CURL_SSLVERSION_DEFAULT:
    /* we try to figure out version */
    req_method = SSLv23_client_method();
    use_sni(TRUE);
    break;
  case CURL_SSLVERSION_TLSv1:
    req_method = TLSv1_client_method();
    use_sni(TRUE);
    break;
  case CURL_SSLVERSION_SSLv2:
    req_method = SSLv2_client_method();
    use_sni(FALSE);
    break;
  case CURL_SSLVERSION_SSLv3:
    req_method = SSLv3_client_method();
    use_sni(FALSE);
    break;
  }

  if(connssl->ctx)
    SSL_CTX_free(connssl->ctx);
  connssl->ctx = SSL_CTX_new(req_method);

  if(!connssl->ctx) {
    failf(data, "SSL: couldn't create a context: %s",
          ERR_error_string(ERR_peek_error(), NULL));
    return CURLE_OUT_OF_MEMORY;
  }

#ifdef SSL_CTRL_SET_MSG_CALLBACK
  if(data->set.fdebug && data->set.verbose) {
    /* the SSL trace callback is only used for verbose logging so we only
       inform about failures of setting it */
    if(!SSL_CTX_callback_ctrl(connssl->ctx, SSL_CTRL_SET_MSG_CALLBACK,
                               (void (*)(void))ssl_tls_trace)) {
      infof(data, "SSL: couldn't set callback!\n");
    }
    else if(!SSL_CTX_ctrl(connssl->ctx, SSL_CTRL_SET_MSG_CALLBACK_ARG, 0,
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

     The "-no_ticket" option was introduced in Openssl0.9.8j. It's a flag to
     disable "rfc4507bis session ticket support".  rfc4507bis was later turned
     into the proper RFC5077 it seems: http://tools.ietf.org/html/rfc5077

     The enabled extension concerns the session management. I wonder how often
     libcurl stops a connection and then resumes a TLS session. also, sending
     the session data is some overhead. .I suggest that you just use your
     proposed patch (which explicitly disables TICKET).

     If someone writes an application with libcurl and openssl who wants to
     enable the feature, one can do this in the SSL callback.

  */
#ifdef SSL_OP_NO_TICKET
  /* expect older openssl releases to not have this define so only use it if
     present */
#define CURL_CTX_OPTIONS SSL_OP_ALL|SSL_OP_NO_TICKET
#else
#define CURL_CTX_OPTIONS SSL_OP_ALL
#endif

  SSL_CTX_set_options(connssl->ctx, CURL_CTX_OPTIONS);

  /* disable SSLv2 in the default case (i.e. allow SSLv3 and TLSv1) */
  if(data->set.ssl.version == CURL_SSLVERSION_DEFAULT)
    SSL_CTX_set_options(connssl->ctx, SSL_OP_NO_SSLv2);

#if 0
  /*
   * Not sure it's needed to tell SSL_connect() that socket is
   * non-blocking. It doesn't seem to care, but just return with
   * SSL_ERROR_WANT_x.
   */
  if(data->state.used_interface == Curl_if_multi)
    SSL_CTX_ctrl(connssl->ctx, BIO_C_SET_NBIO, 1, NULL);
#endif

  if(data->set.str[STRING_CERT] || data->set.str[STRING_CERT_TYPE]) {
    if(!cert_stuff(conn,
                   connssl->ctx,
                   data->set.str[STRING_CERT],
                   data->set.str[STRING_CERT_TYPE],
                   data->set.str[STRING_KEY],
                   data->set.str[STRING_KEY_TYPE])) {
      /* failf() is already done in cert_stuff() */
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  if(data->set.str[STRING_SSL_CIPHER_LIST]) {
    if(!SSL_CTX_set_cipher_list(connssl->ctx,
                                data->set.str[STRING_SSL_CIPHER_LIST])) {
      failf(data, "failed setting cipher list");
      return CURLE_SSL_CIPHER;
    }
  }

  if(data->set.str[STRING_SSL_CAFILE] || data->set.str[STRING_SSL_CAPATH]) {
    /* tell SSL where to find CA certificates that are used to verify
       the servers certificate. */
    if(!SSL_CTX_load_verify_locations(connssl->ctx,
                                       data->set.str[STRING_SSL_CAFILE],
                                       data->set.str[STRING_SSL_CAPATH])) {
      if(data->set.ssl.verifypeer) {
        /* Fail if we insist on successfully verifying the server. */
        failf(data,"error setting certificate verify locations:\n"
              "  CAfile: %s\n  CApath: %s\n",
              data->set.str[STRING_SSL_CAFILE]?
              data->set.str[STRING_SSL_CAFILE]: "none",
              data->set.str[STRING_SSL_CAPATH]?
              data->set.str[STRING_SSL_CAPATH] : "none");
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
          data->set.str[STRING_SSL_CAFILE] ? data->set.str[STRING_SSL_CAFILE]:
          "none",
          data->set.str[STRING_SSL_CAPATH] ? data->set.str[STRING_SSL_CAPATH]:
          "none");
  }

  if (data->set.str[STRING_SSL_CRLFILE]) {
    /* tell SSL where to find CRL file that is used to check certificate
     * revocation */
    lookup=X509_STORE_add_lookup(connssl->ctx->cert_store,X509_LOOKUP_file());
    if ( !lookup ||
         (!X509_load_crl_file(lookup,data->set.str[STRING_SSL_CRLFILE],
                              X509_FILETYPE_PEM)) ) {
      failf(data,"error loading CRL file: %s\n",
            data->set.str[STRING_SSL_CRLFILE]);
      return CURLE_SSL_CRL_BADFILE;
    }
    else {
      /* Everything is fine. */
      infof(data, "successfully load CRL file:\n");
      X509_STORE_set_flags(connssl->ctx->cert_store,
                           X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
    }
    infof(data,
          "  CRLfile: %s\n", data->set.str[STRING_SSL_CRLFILE] ?
          data->set.str[STRING_SSL_CRLFILE]: "none");
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
  if(connssl->handle)
    SSL_free(connssl->handle);
  connssl->handle = SSL_new(connssl->ctx);
  if(!connssl->handle) {
    failf(data, "SSL: couldn't create a context (handle)!");
    return CURLE_OUT_OF_MEMORY;
  }
  SSL_set_connect_state(connssl->handle);

  connssl->server_cert = 0x0;

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
  if ((0 == Curl_inet_pton(AF_INET, conn->host.name, &addr)) &&
#ifdef ENABLE_IPV6
      (0 == Curl_inet_pton(AF_INET6, conn->host.name, &addr)) &&
#endif
      sni &&
      !SSL_set_tlsext_host_name(connssl->handle, conn->host.name))
    infof(data, "WARNING: failed to configure server name indication (SNI) "
          "TLS extension\n");
#endif

  /* Check if there's a cached ID we can/should use here! */
  if(!Curl_ssl_getsessionid(conn, &ssl_sessionid, NULL)) {
    /* we got a session id, use it! */
    if(!SSL_set_session(connssl->handle, ssl_sessionid)) {
      failf(data, "SSL: SSL_set_session failed: %s",
            ERR_error_string(ERR_get_error(),NULL));
      return CURLE_SSL_CONNECT_ERROR;
    }
    /* Informational message */
    infof (data, "SSL re-using session ID\n");
  }

  /* pass the raw socket into the SSL layers */
  if(!SSL_set_fd(connssl->handle, (int)sockfd)) {
     failf(data, "SSL: SSL_set_fd failed: %s",
           ERR_error_string(ERR_get_error(),NULL));
     return CURLE_SSL_CONNECT_ERROR;
  }

  connssl->connecting_state = ssl_connect_2;
  return CURLE_OK;
}

static CURLcode
ossl_connect_step2(struct connectdata *conn, int sockindex)
{
  struct SessionHandle *data = conn->data;
  int err;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  DEBUGASSERT(ssl_connect_2 == connssl->connecting_state
             || ssl_connect_2_reading == connssl->connecting_state
             || ssl_connect_2_writing == connssl->connecting_state);

  ERR_clear_error();

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
      if(CURLE_SSL_CONNECT_ERROR == rc && errdetail == 0) {
        failf(data, "Unknown SSL protocol error in connection to %s:%ld ",
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

static int asn1_object_dump(ASN1_OBJECT *a, char *buf, size_t len)
{
  int i, ilen;

  if((ilen = (int)len) < 0)
    return 1; /* buffer too big */

  i = i2t_ASN1_OBJECT(buf, ilen, a);

  if(i >= ilen)
    return 1; /* buffer too small */

  return 0;
}

static CURLcode push_certinfo_len(struct SessionHandle *data,
                                  int certnum,
                                  const char *label,
                                  const char *value,
                                  size_t valuelen)
{
  struct curl_certinfo *ci = &data->info.certs;
  char *output;
  struct curl_slist *nl;
  CURLcode res = CURLE_OK;
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

  /* TODO: we should rather introduce an internal API that can do the
     equivalent of curl_slist_append but doesn't strdup() the given data as
     like in this place the extra malloc/free is totally pointless */
  nl = curl_slist_append(ci->certinfo[certnum], output);
  if(!nl) {
    curl_slist_free_all(ci->certinfo[certnum]);
    res = CURLE_OUT_OF_MEMORY;
  }
  else
    ci->certinfo[certnum] = nl;

  free(output);

  return res;
}

/* this is a convenience function for push_certinfo_len that takes a zero
   terminated value */
static CURLcode push_certinfo(struct SessionHandle *data,
                              int certnum,
                              const char *label,
                              const char *value)
{
  size_t valuelen = strlen(value);

  return push_certinfo_len(data, certnum, label, value, valuelen);
}

static void pubkey_show(struct SessionHandle *data,
                        int num,
                        const char *type,
                        const char *name,
                        unsigned char *raw,
                        int len)
{
  size_t left;
  int i;
  char namebuf[32];
  char *buffer;

  left = sizeof(len*3 + 1);
  buffer = malloc(left);
  if(buffer) {
    char *ptr=buffer;
    snprintf(namebuf, sizeof(namebuf), "%s(%s)", type, name);
    for(i=0; i< len; i++) {
      snprintf(ptr, left, "%02x:", raw[i]);
      ptr += 3;
      left -= 3;
    }
    infof(data, "   %s: %s\n", namebuf, buffer);
    push_certinfo(data, num, namebuf, buffer);
    free(buffer);
  }
}

#define print_pubkey_BN(_type, _name, _num)    \
do {                              \
  if (pubkey->pkey._type->_name != NULL) { \
    int len = BN_num_bytes(pubkey->pkey._type->_name); \
    if(len < CERTBUFFERSIZE) {                       \
      BN_bn2bin(pubkey->pkey._type->_name, (unsigned char*)bufp); \
      bufp[len] = 0; \
      pubkey_show(data, _num, #_type, #_name, (unsigned char*)bufp, len); \
    } \
  } \
} while (0)

static int X509V3_ext(struct SessionHandle *data,
                      int certnum,
                      STACK_OF(X509_EXTENSION) *exts)
{
  int i;
  size_t j;

  if(sk_X509_EXTENSION_num(exts) <= 0)
    /* no extensions, bail out */
    return 1;

  for (i=0; i<sk_X509_EXTENSION_num(exts); i++) {
    ASN1_OBJECT *obj;
    X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
    BUF_MEM *biomem;
    char buf[512];
    char *ptr=buf;
    char namebuf[128];
    BIO *bio_out = BIO_new(BIO_s_mem());

    if(!bio_out)
      return 1;

    obj = X509_EXTENSION_get_object(ext);

    asn1_object_dump(obj, namebuf, sizeof(namebuf));

    infof(data, "%s: %s\n", namebuf,
          X509_EXTENSION_get_critical(ext)?"(critical)":"");

    if(!X509V3_EXT_print(bio_out, ext, 0, 0))
      M_ASN1_OCTET_STRING_print(bio_out, ext->value);

    BIO_get_mem_ptr(bio_out, &biomem);

    /* biomem->length bytes at biomem->data, this little loop here is only
       done for the infof() call, we send the "raw" data to the certinfo
       function */
    for(j=0; j<(size_t)biomem->length; j++) {
      const char *sep="";
      if(biomem->data[j] == '\n') {
        sep=", ";
        j++; /* skip the newline */
      };
      while((biomem->data[j] == ' ') && (j<(size_t)biomem->length))
        j++;
      if(j<(size_t)biomem->length)
        ptr+=snprintf(ptr, sizeof(buf)-(ptr-buf), "%s%c", sep, biomem->data[j]);
    }
    infof(data, "  %s\n", buf);

    push_certinfo(data, certnum, namebuf, buf);

    BIO_free(bio_out);

  }
  return 0; /* all is fine */
}


static void X509_signature(struct SessionHandle *data,
                           int numcert,
                           ASN1_STRING *sig)
{
  char buf[1024];
  char *ptr = buf;
  int i;
  for (i=0; i<sig->length; i++)
    ptr+=snprintf(ptr, sizeof(buf)-(ptr-buf), "%02x:", sig->data[i]);

  infof(data, " Signature: %s\n", buf);
  push_certinfo(data, numcert, "Signature", buf);
}

static void dumpcert(struct SessionHandle *data, X509 *x, int numcert)
{
  BIO *bio_out = BIO_new(BIO_s_mem());
  BUF_MEM *biomem;

  /* this outputs the cert in this 64 column wide style with newlines and
     -----BEGIN CERTIFICATE----- texts and more */
  PEM_write_bio_X509(bio_out, x);

  BIO_get_mem_ptr(bio_out, &biomem);

  infof(data, "%s\n", biomem->data);

  push_certinfo_len(data, numcert, "Cert", biomem->data, biomem->length);

  BIO_free(bio_out);

}


static int init_certinfo(struct SessionHandle *data,
                         int num)
{
  struct curl_certinfo *ci = &data->info.certs;
  struct curl_slist **table;

  Curl_ssl_free_certinfo(data);

  ci->num_of_certs = num;
  table = calloc((size_t)num, sizeof(struct curl_slist *));
  if(!table)
    return 1;

  ci->certinfo = table;
  return 0;
}

/*
 * This size was previously 512 which has been reported "too small" without
 * any specifics, so it was enlarged to allow more data to get shown uncut.
 * The "perfect" size is yet to figure out.
 */
#define CERTBUFFERSIZE 8192

static CURLcode get_cert_chain(struct connectdata *conn,
                               struct ssl_connect_data *connssl)

{
  STACK_OF(X509) *sk;
  int i;
  char *bufp;
  struct SessionHandle *data = conn->data;
  int numcerts;

  bufp = malloc(CERTBUFFERSIZE);
  if(!bufp)
    return CURLE_OUT_OF_MEMORY;

  sk = SSL_get_peer_cert_chain(connssl->handle);
  if(!sk) {
    free(bufp);
    return CURLE_OUT_OF_MEMORY;
  }

  numcerts = sk_X509_num(sk);
  if(init_certinfo(data, numcerts)) {
    free(bufp);
    return CURLE_OUT_OF_MEMORY;
  }

  infof(data, "--- Certificate chain\n");
  for (i=0; i<numcerts; i++) {
    long value;
    ASN1_INTEGER *num;
    ASN1_TIME *certdate;

    /* get the certs in "importance order" */
#if 0
    X509 *x = sk_X509_value(sk, numcerts - i - 1);
#else
    X509 *x = sk_X509_value(sk, i);
#endif

    X509_CINF *cinf;
    EVP_PKEY *pubkey=NULL;
    int j;
    char *ptr;

    (void)x509_name_oneline(X509_get_subject_name(x), bufp, CERTBUFFERSIZE);
    infof(data, "%2d Subject: %s\n", i, bufp);
    push_certinfo(data, i, "Subject", bufp);

    (void)x509_name_oneline(X509_get_issuer_name(x), bufp, CERTBUFFERSIZE);
    infof(data, "   Issuer: %s\n", bufp);
    push_certinfo(data, i, "Issuer", bufp);

    value = X509_get_version(x);
    infof(data, "   Version: %lu (0x%lx)\n", value+1, value);
    snprintf(bufp, CERTBUFFERSIZE, "%lx", value);
    push_certinfo(data, i, "Version", bufp); /* hex */

    num=X509_get_serialNumber(x);
    if (num->length <= 4) {
      value = ASN1_INTEGER_get(num);
      infof(data,"   Serial Number: %ld (0x%lx)\n", value, value);
      snprintf(bufp, CERTBUFFERSIZE, "%lx", value);
    }
    else {
      int left = CERTBUFFERSIZE;

      ptr = bufp;
      *ptr++ = 0;
      if(num->type == V_ASN1_NEG_INTEGER)
        *ptr++='-';

      for (j=0; (j<num->length) && (left>=4); j++) {
        /* TODO: length restrictions */
        snprintf(ptr, 3, "%02x%c",num->data[j],
                 ((j+1 == num->length)?'\n':':'));
        ptr += 3;
        left-=4;
      }
      if(num->length)
        infof(data,"   Serial Number: %s\n", bufp);
      else
        bufp[0]=0;
    }
    if(bufp[0])
      push_certinfo(data, i, "Serial Number", bufp); /* hex */

    cinf = x->cert_info;

    j = asn1_object_dump(cinf->signature->algorithm, bufp, CERTBUFFERSIZE);
    if(!j) {
      infof(data, "   Signature Algorithm: %s\n", bufp);
      push_certinfo(data, i, "Signature Algorithm", bufp);
    }

    certdate = X509_get_notBefore(x);
    asn1_output(certdate, bufp, CERTBUFFERSIZE);
    infof(data, "   Start date: %s\n", bufp);
    push_certinfo(data, i, "Start date", bufp);

    certdate = X509_get_notAfter(x);
    asn1_output(certdate, bufp, CERTBUFFERSIZE);
    infof(data, "   Expire date: %s\n", bufp);
    push_certinfo(data, i, "Expire date", bufp);

    j = asn1_object_dump(cinf->key->algor->algorithm, bufp, CERTBUFFERSIZE);
    if(!j) {
      infof(data, "   Public Key Algorithm: %s\n", bufp);
      push_certinfo(data, i, "Public Key Algorithm", bufp);
    }

    pubkey = X509_get_pubkey(x);
    if(!pubkey)
      infof(data, "   Unable to load public key\n");
    else {
      switch(pubkey->type) {
      case EVP_PKEY_RSA:
        infof(data,  "   RSA Public Key (%d bits)\n",
              BN_num_bits(pubkey->pkey.rsa->n));
        snprintf(bufp, CERTBUFFERSIZE, "%d", BN_num_bits(pubkey->pkey.rsa->n));
        push_certinfo(data, i, "RSA Public Key", bufp);

        print_pubkey_BN(rsa, n, i);
        print_pubkey_BN(rsa, e, i);
        print_pubkey_BN(rsa, d, i);
        print_pubkey_BN(rsa, p, i);
        print_pubkey_BN(rsa, q, i);
        print_pubkey_BN(rsa, dmp1, i);
        print_pubkey_BN(rsa, dmq1, i);
        print_pubkey_BN(rsa, iqmp, i);
        break;
      case EVP_PKEY_DSA:
        print_pubkey_BN(dsa, p, i);
        print_pubkey_BN(dsa, q, i);
        print_pubkey_BN(dsa, g, i);
        print_pubkey_BN(dsa, priv_key, i);
        print_pubkey_BN(dsa, pub_key, i);
        break;
      case EVP_PKEY_DH:
        print_pubkey_BN(dh, p, i);
        print_pubkey_BN(dh, g, i);
        print_pubkey_BN(dh, priv_key, i);
        print_pubkey_BN(dh, pub_key, i);
        break;
#if 0
      case EVP_PKEY_EC: /* symbol not present in OpenSSL 0.9.6 */
        /* left TODO */
        break;
#endif
      }
      EVP_PKEY_free(pubkey);
    }

    X509V3_ext(data, i, cinf->extensions);

    X509_signature(data, i, x->signature);

    dumpcert(data, x, i);
  }

  free(bufp);

  return CURLE_OK;
}

/*
 * Get the server cert, verify it and show it etc, only call failf() if the
 * 'strict' argument is TRUE as otherwise all this is for informational
 * purposes only!
 *
 * We check certificates to authenticate the server; otherwise we risk
 * man-in-the-middle attack.
 */
static CURLcode servercert(struct connectdata *conn,
                           struct ssl_connect_data *connssl,
                           bool strict)
{
  CURLcode retcode = CURLE_OK;
  int rc;
  long lerr;
  ASN1_TIME *certdate;
  struct SessionHandle *data = conn->data;
  X509 *issuer;
  FILE *fp;
  char buffer[256];

  if(data->set.ssl.certinfo)
    /* we've been asked to gather certificate info! */
    (void)get_cert_chain(conn, connssl);

  data->set.ssl.certverifyresult = !X509_V_OK;

  connssl->server_cert = SSL_get_peer_certificate(connssl->handle);
  if(!connssl->server_cert) {
    if(strict)
      failf(data, "SSL: couldn't get peer certificate!");
    return CURLE_PEER_FAILED_VERIFICATION;
  }
  infof (data, "Server certificate:\n");

  rc = x509_name_oneline(X509_get_subject_name(connssl->server_cert),
                          buffer, sizeof(buffer));
  if(rc) {
    if(strict)
      failf(data, "SSL: couldn't get X509-subject!");
    X509_free(connssl->server_cert);
    connssl->server_cert = NULL;
    return CURLE_SSL_CONNECT_ERROR;
  }
  infof(data, "\t subject: %s\n", buffer);

  certdate = X509_get_notBefore(connssl->server_cert);
  asn1_output(certdate, buffer, sizeof(buffer));
  infof(data, "\t start date: %s\n", buffer);

  certdate = X509_get_notAfter(connssl->server_cert);
  asn1_output(certdate, buffer, sizeof(buffer));
  infof(data, "\t expire date: %s\n", buffer);

  if(data->set.ssl.verifyhost) {
    retcode = verifyhost(conn, connssl->server_cert);
    if(retcode) {
      X509_free(connssl->server_cert);
      connssl->server_cert = NULL;
      return retcode;
    }
  }

  rc = x509_name_oneline(X509_get_issuer_name(connssl->server_cert),
                         buffer, sizeof(buffer));
  if(rc) {
    if(strict)
      failf(data, "SSL: couldn't get X509-issuer name!");
    retcode = CURLE_SSL_CONNECT_ERROR;
  }
  else {
    infof(data, "\t issuer: %s\n", buffer);

    /* We could do all sorts of certificate verification stuff here before
       deallocating the certificate. */

    /* e.g. match issuer name with provided issuer certificate */
    if (data->set.str[STRING_SSL_ISSUERCERT]) {
      if (! (fp=fopen(data->set.str[STRING_SSL_ISSUERCERT],"r"))) {
        if (strict)
          failf(data, "SSL: Unable to open issuer cert (%s)\n",
                data->set.str[STRING_SSL_ISSUERCERT]);
        X509_free(connssl->server_cert);
        connssl->server_cert = NULL;
        return CURLE_SSL_ISSUER_ERROR;
      }
      issuer = PEM_read_X509(fp,NULL,ZERO_NULL,NULL);
      if (!issuer) {
        if (strict)
          failf(data, "SSL: Unable to read issuer cert (%s)\n",
                data->set.str[STRING_SSL_ISSUERCERT]);
        X509_free(connssl->server_cert);
        X509_free(issuer);
        fclose(fp);
        return CURLE_SSL_ISSUER_ERROR;
      }
      fclose(fp);
      if (X509_check_issued(issuer,connssl->server_cert) != X509_V_OK) {
        if (strict)
          failf(data, "SSL: Certificate issuer check failed (%s)\n",
                data->set.str[STRING_SSL_ISSUERCERT]);
        X509_free(connssl->server_cert);
        X509_free(issuer);
        connssl->server_cert = NULL;
        return CURLE_SSL_ISSUER_ERROR;
      }
      infof(data, "\t SSL certificate issuer check ok (%s)\n",
            data->set.str[STRING_SSL_ISSUERCERT]);
      X509_free(issuer);
    }

    lerr = data->set.ssl.certverifyresult=
      SSL_get_verify_result(connssl->handle);
    if(data->set.ssl.certverifyresult != X509_V_OK) {
      if(data->set.ssl.verifypeer) {
        /* We probably never reach this, because SSL_connect() will fail
           and we return earlier if verifypeer is set? */
        if(strict)
          failf(data, "SSL certificate verify result: %s (%ld)",
                X509_verify_cert_error_string(lerr), lerr);
        retcode = CURLE_PEER_FAILED_VERIFICATION;
      }
      else
        infof(data, "\t SSL certificate verify result: %s (%ld),"
              " continuing anyway.\n",
              X509_verify_cert_error_string(lerr), lerr);
    }
    else
      infof(data, "\t SSL certificate verify ok.\n");
  }

  X509_free(connssl->server_cert);
  connssl->server_cert = NULL;
  connssl->connecting_state = ssl_connect_done;

  return retcode;
}


static CURLcode
ossl_connect_step3(struct connectdata *conn,
                   int sockindex)
{
  CURLcode retcode = CURLE_OK;
  void *old_ssl_sessionid=NULL;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  int incache;
  SSL_SESSION *our_ssl_sessionid;

  DEBUGASSERT(ssl_connect_3 == connssl->connecting_state);

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

  incache = !(Curl_ssl_getsessionid(conn, &old_ssl_sessionid, NULL));
  if (incache) {
    if (old_ssl_sessionid != our_ssl_sessionid) {
      infof(data, "old SSL session ID is stale, removing\n");
      Curl_ssl_delsessionid(conn, old_ssl_sessionid);
      incache = FALSE;
    }
  }
  if (!incache) {
    retcode = Curl_ssl_addsessionid(conn, our_ssl_sessionid,
                                    0 /* unknown size */);
    if(retcode) {
      failf(data, "failed to store ssl session");
      return retcode;
    }
  }
#ifdef HAVE_SSL_GET1_SESSION
  else {
    /* Session was incache, so refcount already incremented earlier.
     * Avoid further increments with each SSL_get1_session() call.
     * This does not free the session as refcount remains > 0
     */
    SSL_SESSION_free(our_ssl_sessionid);
  }
#endif

  /*
   * We check certificates to authenticate the server; otherwise we risk
   * man-in-the-middle attack; NEVERTHELESS, if we're told explicitly not to
   * verify the peer ignore faults and failures from the server cert
   * operations.
   */

  if(!data->set.ssl.verifypeer)
    (void)servercert(conn, connssl, FALSE);
  else
    retcode = servercert(conn, connssl, TRUE);

  if(CURLE_OK == retcode)
    connssl->connecting_state = ssl_connect_done;
  return retcode;
}

static Curl_recv ossl_recv;
static Curl_send ossl_send;

static CURLcode
ossl_connect_common(struct connectdata *conn,
                    int sockindex,
                    bool nonblocking,
                    bool *done)
{
  CURLcode retcode;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  curl_socket_t sockfd = conn->sock[sockindex];
  long timeout_ms;
  int what;

  /* check if the connection has already been established */
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(ssl_connect_1==connssl->connecting_state) {
    /* Find out how much more time we're allowed */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }
    retcode = ossl_connect_step1(conn, sockindex);
    if(retcode)
      return retcode;
  }

  while(ssl_connect_2 == connssl->connecting_state ||
        ssl_connect_2_reading == connssl->connecting_state ||
        ssl_connect_2_writing == connssl->connecting_state) {

    /* check allowed time left */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    /* if ssl is expecting something, check if it's available. */
    if(connssl->connecting_state == ssl_connect_2_reading
        || connssl->connecting_state == ssl_connect_2_writing) {

      curl_socket_t writefd = ssl_connect_2_writing==
        connssl->connecting_state?sockfd:CURL_SOCKET_BAD;
      curl_socket_t readfd = ssl_connect_2_reading==
        connssl->connecting_state?sockfd:CURL_SOCKET_BAD;

      what = Curl_socket_ready(readfd, writefd,
                               nonblocking?0:(int)timeout_ms);
      if(what < 0) {
        /* fatal error */
        failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
        return CURLE_SSL_CONNECT_ERROR;
      }
      else if(0 == what) {
        if(nonblocking) {
          *done = FALSE;
          return CURLE_OK;
        }
        else {
          /* timeout */
          failf(data, "SSL connection timeout");
          return CURLE_OPERATION_TIMEDOUT;
        }
      }
      /* socket is readable or writable */
    }

    /* Run transaction, and return to the caller if it failed or if this
     * connection is done nonblocking and this loop would execute again. This
     * permits the owner of a multi handle to abort a connection attempt
     * before step2 has completed while ensuring that a client using select()
     * or epoll() will always have a valid fdset to wait on.
     */
    retcode = ossl_connect_step2(conn, sockindex);
    if(retcode || (nonblocking &&
                   (ssl_connect_2 == connssl->connecting_state ||
                    ssl_connect_2_reading == connssl->connecting_state ||
                    ssl_connect_2_writing == connssl->connecting_state)))
      return retcode;

  } /* repeat step2 until all transactions are done. */


  if(ssl_connect_3==connssl->connecting_state) {
    retcode = ossl_connect_step3(conn, sockindex);
    if(retcode)
      return retcode;
  }

  if(ssl_connect_done==connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    conn->recv[sockindex] = ossl_recv;
    conn->send[sockindex] = ossl_send;
    *done = TRUE;
  }
  else
    *done = FALSE;

  /* Reset our connect state machine */
  connssl->connecting_state = ssl_connect_1;

  return CURLE_OK;
}

CURLcode
Curl_ossl_connect_nonblocking(struct connectdata *conn,
                              int sockindex,
                              bool *done)
{
  return ossl_connect_common(conn, sockindex, TRUE, done);
}

CURLcode
Curl_ossl_connect(struct connectdata *conn,
                  int sockindex)
{
  CURLcode retcode;
  bool done = FALSE;

  retcode = ossl_connect_common(conn, sockindex, FALSE, &done);
  if(retcode)
    return retcode;

  DEBUGASSERT(done);

  return CURLE_OK;
}

bool Curl_ossl_data_pending(const struct connectdata *conn,
                            int connindex)
{
  if(conn->ssl[connindex].handle)
    /* SSL is in use */
    return (bool)(0 != SSL_pending(conn->ssl[connindex].handle));
  else
    return FALSE;
}

static ssize_t ossl_send(struct connectdata *conn,
                         int sockindex,
                         const void *mem,
                         size_t len,
                         CURLcode *curlcode)
{
  /* SSL_write() is said to return 'int' while write() and send() returns
     'size_t' */
  int err;
  char error_buffer[120]; /* OpenSSL documents that this must be at least 120
                             bytes long. */
  unsigned long sslerror;
  int memlen;
  int rc;

  ERR_clear_error();

  memlen = (len > (size_t)INT_MAX) ? INT_MAX : (int)len;
  rc = SSL_write(conn->ssl[sockindex].handle, mem, memlen);

  if(rc < 0) {
    err = SSL_get_error(conn->ssl[sockindex].handle, rc);

    switch(err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      /* The operation did not complete; the same TLS/SSL I/O function
         should be called again later. This is basicly an EWOULDBLOCK
         equivalent. */
      *curlcode = CURLE_AGAIN;
      return -1;
    case SSL_ERROR_SYSCALL:
      failf(conn->data, "SSL_write() returned SYSCALL, errno = %d",
            SOCKERRNO);
      *curlcode = CURLE_SEND_ERROR;
      return -1;
    case SSL_ERROR_SSL:
      /*  A failure in the SSL library occurred, usually a protocol error.
          The OpenSSL error queue contains more information on the error. */
      sslerror = ERR_get_error();
      failf(conn->data, "SSL_write() error: %s",
            ERR_error_string(sslerror, error_buffer));
      *curlcode = CURLE_SEND_ERROR;
      return -1;
    }
    /* a true error */
    failf(conn->data, "SSL_write() return error %d", err);
    *curlcode = CURLE_SEND_ERROR;
    return -1;
  }
  return (ssize_t)rc; /* number of bytes */
}

static ssize_t ossl_recv(struct connectdata *conn, /* connection data */
                         int num,                  /* socketindex */
                         char *buf,                /* store read data here */
                         size_t buffersize,        /* max amount to read */
                         CURLcode *curlcode)
{
  char error_buffer[120]; /* OpenSSL documents that this must be at
                             least 120 bytes long. */
  unsigned long sslerror;
  ssize_t nread;
  int buffsize;

  ERR_clear_error();

  buffsize = (buffersize > (size_t)INT_MAX) ? INT_MAX : (int)buffersize;
  nread = (ssize_t)SSL_read(conn->ssl[num].handle, buf, buffsize);
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
      *curlcode = CURLE_AGAIN;
      return -1;
    default:
      /* openssl/ssl.h says "look at error stack/return value/errno" */
      sslerror = ERR_get_error();
      failf(conn->data, "SSL read: %s, errno %d",
            ERR_error_string(sslerror, error_buffer),
            SOCKERRNO);
      *curlcode = CURLE_RECV_ERROR;
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
  return snprintf(buffer, size, "yassl/%s", YASSL_VERSION);
#else /* YASSL_VERSION */

#if(SSLEAY_VERSION_NUMBER >= 0x905000)
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

    return snprintf(buffer, size, "OpenSSL/%lx.%lx.%lx%s",
                    (ssleay_value>>28)&0xf,
                    (ssleay_value>>20)&0xff,
                    (ssleay_value>>12)&0xff,
                    sub);
  }

#else /* SSLEAY_VERSION_NUMBER is less than 0.9.5 */

#if(SSLEAY_VERSION_NUMBER >= 0x900000)
  return snprintf(buffer, size, "OpenSSL/%lx.%lx.%lx",
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

    return snprintf(buffer, size, "SSL/%x.%x.%x%s",
                    (SSLEAY_VERSION_NUMBER>>12)&0xff,
                    (SSLEAY_VERSION_NUMBER>>8)&0xf,
                    (SSLEAY_VERSION_NUMBER>>4)&0xf, sub);
  }
#endif /* (SSLEAY_VERSION_NUMBER >= 0x900000) */
#endif /* SSLEAY_VERSION_NUMBER is less than 0.9.5 */

#endif /* YASSL_VERSION */
}
#endif /* USE_SSLEAY */
