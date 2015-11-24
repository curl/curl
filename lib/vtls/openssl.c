/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * but vtls.c should ever call or use these functions.
 */

/*
 * The original SSLeay-using code for curl was written by Linas Vepstas and
 * Sampo Kellomaki 1998.
 */

#include "curl_setup.h"

#ifdef USE_OPENSSL

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#include "urldata.h"
#include "sendf.h"
#include "formdata.h" /* for the boundary function */
#include "url.h" /* for the ssl config check function */
#include "inet_pton.h"
#include "openssl.h"
#include "connect.h"
#include "slist.h"
#include "strequal.h"
#include "select.h"
#include "vtls.h"
#include "rawstr.h"
#include "hostcheck.h"
#include "curl_printf.h"

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/conf.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

#ifdef HAVE_OPENSSL_PKCS12_H
#include <openssl/pkcs12.h>
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x0090808fL) && !defined(OPENSSL_IS_BORINGSSL)
#include <openssl/ocsp.h>
#endif

#include "warnless.h"
#include "non-ascii.h" /* for Curl_convert_from_utf8 prototype */

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

#ifndef OPENSSL_VERSION_NUMBER
#error "OPENSSL_VERSION_NUMBER not defined"
#endif

#if !defined(OPENSSL_IS_BORINGSSL)
/* ENGINE_load_private_key() takes four arguments */
#define HAVE_ENGINE_LOAD_FOUR_ARGS
#include <openssl/ui.h>
#else
/* ENGINE_load_private_key() takes three arguments */
#undef HAVE_ENGINE_LOAD_FOUR_ARGS
#endif

#if defined(HAVE_OPENSSL_PKCS12_H) && !defined(OPENSSL_IS_BORINGSSL)
/* OpenSSL has PKCS 12 support, BoringSSL does not */
#define HAVE_PKCS12_SUPPORT
#else
/* OpenSSL does not have PKCS12 support */
#undef HAVE_PKCS12_SUPPORT
#endif

#if OPENSSL_VERSION_NUMBER >= 0x00909000L
#define SSL_METHOD_QUAL const
#else
#define SSL_METHOD_QUAL
#endif

#ifdef OPENSSL_IS_BORINGSSL
/* BoringSSL has no ERR_remove_state() */
#define ERR_remove_state(x)
#elif (OPENSSL_VERSION_NUMBER >= 0x10000000L)
#define HAVE_ERR_REMOVE_THREAD_STATE 1
#endif

#if !defined(HAVE_SSLV2_CLIENT_METHOD) || \
  OPENSSL_VERSION_NUMBER >= 0x10100000L /* 1.1.0+ has no SSLv2 */
#undef OPENSSL_NO_SSL2 /* undef first to avoid compiler warnings */
#define OPENSSL_NO_SSL2
#endif

#if defined(OPENSSL_IS_BORINGSSL)
#define NO_RAND_SEED 1
/* In BoringSSL OpenSSL_add_all_algorithms does nothing */
#define OpenSSL_add_all_algorithms()
/* BoringSSL does not have CONF_modules_load_file */
#define CONF_modules_load_file(a,b,c)
#endif

#if (OPENSSL_VERSION_NUMBER < 0x0090808fL) || defined(OPENSSL_IS_BORINGSSL)
/* not present in BoringSSL  or older OpenSSL */
#define OPENSSL_load_builtin_modules(x)
#endif

/*
 * Number of bytes to read from the random number seed file. This must be
 * a finite value (because some entropy "files" like /dev/urandom have
 * an infinite length), but must be large enough to provide enough
 * entopy to properly seed OpenSSL's PRNG.
 */
#define RAND_LOAD_LENGTH 1024

static int passwd_callback(char *buf, int num, int encrypting,
                           void *global_passwd)
{
  DEBUGASSERT(0 == encrypting);

  if(!encrypting) {
    int klen = curlx_uztosi(strlen((char *)global_passwd));
    if(num > klen) {
      memcpy(buf, global_passwd, klen+1);
      return klen;
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

#ifndef NO_RAND_SEED
#ifdef HAVE_RAND_STATUS
#define seed_enough(x) rand_enough()
static bool rand_enough(void)
{
  return (0 != RAND_status()) ? TRUE : FALSE;
}
#else
#define seed_enough(x) rand_enough(x)
static bool rand_enough(int nread)
{
  /* this is a very silly decision to make */
  return (nread > 500) ? TRUE : FALSE;
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
  do {
    unsigned char randb[64];
    int len = sizeof(randb);
    RAND_bytes(randb, len);
    RAND_add(randb, len, (len >> 1));
  } while(!RAND_status());

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

static void Curl_ossl_seed(struct SessionHandle *data)
{
  /* we have the "SSL is seeded" boolean static to prevent multiple
     time-consuming seedings in vain */
  static bool ssl_seeded = FALSE;

  if(!ssl_seeded || data->set.str[STRING_SSL_RANDOM_FILE] ||
     data->set.str[STRING_SSL_EGDSOCKET]) {
    ossl_seed(data);
    ssl_seeded = TRUE;
  }
}
#else
/* BoringSSL needs no seeding */
#define Curl_ossl_seed(x)
#endif


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

#if defined(HAVE_OPENSSL_ENGINE_H) && defined(HAVE_ENGINE_LOAD_FOUR_ARGS)
/*
 * Supply default password to the engine user interface conversation.
 * The password is passed by OpenSSL engine from ENGINE_load_private_key()
 * last argument to the ui and can be obtained by UI_get0_user_data(ui) here.
 */
static int ssl_ui_reader(UI *ui, UI_STRING *uis)
{
  const char *password;
  switch(UI_get_string_type(uis)) {
  case UIT_PROMPT:
  case UIT_VERIFY:
    password = (const char*)UI_get0_user_data(ui);
    if(password && (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD)) {
      UI_set_result(ui, uis, password);
      return 1;
    }
  default:
    break;
  }
  return (UI_method_get_reader(UI_OpenSSL()))(ui, uis);
}

/*
 * Suppress interactive request for a default password if available.
 */
static int ssl_ui_writer(UI *ui, UI_STRING *uis)
{
  switch(UI_get_string_type(uis)) {
  case UIT_PROMPT:
  case UIT_VERIFY:
    if(UI_get0_user_data(ui) &&
       (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD)) {
      return 1;
    }
  default:
    break;
  }
  return (UI_method_get_writer(UI_OpenSSL()))(ui, uis);
}
#endif

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

  if(cert_file || (file_type == SSL_FILETYPE_ENGINE)) {
    SSL *ssl;
    X509 *x509;
    int cert_done = 0;

    if(data->set.str[STRING_KEY_PASSWD]) {
      /* set the password in the callback userdata */
      SSL_CTX_set_default_passwd_cb_userdata(ctx,
                                             data->set.str[STRING_KEY_PASSWD]);
      /* Set passwd callback: */
      SSL_CTX_set_default_passwd_cb(ctx, passwd_callback);
    }


    switch(file_type) {
    case SSL_FILETYPE_PEM:
      /* SSL_CTX_use_certificate_chain_file() only works on PEM files */
      if(SSL_CTX_use_certificate_chain_file(ctx,
                                            cert_file) != 1) {
        failf(data,
              "could not load PEM client certificate, OpenSSL error %s, "
              "(no key found, wrong pass phrase, or wrong file format?)",
              ERR_error_string(ERR_get_error(), NULL) );
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
        failf(data,
              "could not load ASN1 client certificate, OpenSSL error %s, "
              "(no key found, wrong pass phrase, or wrong file format?)",
              ERR_error_string(ERR_get_error(), NULL) );
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
          if(!ENGINE_ctrl(data->state.engine, ENGINE_CTRL_GET_CMD_FROM_NAME,
                          0, (void *)cmd_name, NULL)) {
            failf(data, "ssl engine does not support loading certificates");
            return 0;
          }

          /* Load the certificate from the engine */
          if(!ENGINE_ctrl_cmd(data->state.engine, cmd_name,
                              0, &params, NULL, 1)) {
            failf(data, "ssl engine cannot load client cert with id"
                  " '%s' [%s]", cert_file,
                  ERR_error_string(ERR_get_error(), NULL));
            return 0;
          }

          if(!params.cert) {
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

      f = fopen(cert_file, "rb");
      if(!f) {
        failf(data, "could not open PKCS12 file '%s'", cert_file);
        return 0;
      }
      p12 = d2i_PKCS12_fp(f, NULL);
      fclose(f);

      if(!p12) {
        failf(data, "error reading PKCS12 file '%s'", cert_file);
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
        failf(data,
              "could not load PKCS12 client certificate, OpenSSL error %s",
              ERR_error_string(ERR_get_error(), NULL) );
        goto fail;
      }

      if(SSL_CTX_use_PrivateKey(ctx, pri) != 1) {
        failf(data, "unable to use private key from PKCS12 file '%s'",
              cert_file);
        goto fail;
      }

      if(!SSL_CTX_check_private_key (ctx)) {
        failf(data, "private key from PKCS12 file '%s' "
              "does not match certificate in same file", cert_file);
        goto fail;
      }
      /* Set Certificate Verification chain */
      if(ca) {
        while(sk_X509_num(ca)) {
          /*
           * Note that sk_X509_pop() is used below to make sure the cert is
           * removed from the stack properly before getting passed to
           * SSL_CTX_add_extra_chain_cert(). Previously we used
           * sk_X509_value() instead, but then we'd clean it in the subsequent
           * sk_X509_pop_free() call.
           */
          X509 *x = sk_X509_pop(ca);
          if(!SSL_CTX_add_extra_chain_cert(ctx, x)) {
            X509_free(x);
            failf(data, "cannot add certificate to certificate chain");
            goto fail;
          }
          /* SSL_CTX_add_client_CA() seems to work with either sk_* function,
           * presumably because it duplicates what we pass to it.
           */
          if(!SSL_CTX_add_client_CA(ctx, x)) {
            failf(data, "cannot add certificate to client CA list");
            goto fail;
          }
        }
      }

      cert_done = 1;
  fail:
      EVP_PKEY_free(pri);
      X509_free(x509);
      sk_X509_pop_free(ca, X509_free);

      if(!cert_done)
        return 0; /* failure! */
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
      if(!key_file)
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
          UI_METHOD *ui_method =
            UI_create_method((char *)"cURL user interface");
          if(!ui_method) {
            failf(data, "unable do create OpenSSL user-interface method");
            return 0;
          }
          UI_method_set_opener(ui_method, UI_method_get_opener(UI_OpenSSL()));
          UI_method_set_closer(ui_method, UI_method_get_closer(UI_OpenSSL()));
          UI_method_set_reader(ui_method, ssl_ui_reader);
          UI_method_set_writer(ui_method, ssl_ui_writer);
#endif
          /* the typecast below was added to please mingw32 */
          priv_key = (EVP_PKEY *)
            ENGINE_load_private_key(data->state.engine, key_file,
#ifdef HAVE_ENGINE_LOAD_FOUR_ARGS
                                    ui_method,
#endif
                                    data->set.str[STRING_KEY_PASSWD]);
#ifdef HAVE_ENGINE_LOAD_FOUR_ARGS
          UI_destroy_method(ui_method);
#endif
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
    if(!ssl) {
      failf(data, "unable to create an SSL structure");
      return 0;
    }

    x509=SSL_get_certificate(ssl);

    /* This version was provided by Evan Jordan and is supposed to not
       leak memory as the previous version: */
    if(x509) {
      EVP_PKEY *pktmp = X509_get_pubkey(x509);
      EVP_PKEY_copy_parameters(pktmp, SSL_get_privatekey(ssl));
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

/* Return error string for last OpenSSL error
 */
static char *SSL_strerror(unsigned long error, char *buf, size_t size)
{
  /* OpenSSL 0.9.6 and later has a function named
     ERR_error_string_n() that takes the size of the buffer as a
     third argument */
  ERR_error_string_n(error, buf, size);
  return buf;
}

/**
 * Global SSL init
 *
 * @retval 0 error initializing SSL
 * @retval 1 SSL initialized successfully
 */
int Curl_ossl_init(void)
{
  OPENSSL_load_builtin_modules();

#ifdef HAVE_ENGINE_LOAD_BUILTIN_ENGINES
  ENGINE_load_builtin_engines();
#endif

  /* OPENSSL_config(NULL); is "strongly recommended" to use but unfortunately
     that function makes an exit() call on wrongly formatted config files
     which makes it hard to use in some situations. OPENSSL_config() itself
     calls CONF_modules_load_file() and we use that instead and we ignore
     its return code! */

  /* CONF_MFLAGS_DEFAULT_SECTION introduced some time between 0.9.8b and
     0.9.8e */
#ifndef CONF_MFLAGS_DEFAULT_SECTION
#define CONF_MFLAGS_DEFAULT_SECTION 0x0
#endif

  CONF_modules_load_file(NULL, NULL,
                         CONF_MFLAGS_DEFAULT_SECTION|
                         CONF_MFLAGS_IGNORE_MISSING_FILE);

  /* Lets get nice error messages */
  SSL_load_error_strings();

  /* Init the global ciphers and digests */
  if(!SSLeay_add_ssl_algorithms())
    return 0;

  OpenSSL_add_all_algorithms();

  return 1;
}

/* Global cleanup */
void Curl_ossl_cleanup(void)
{
  /* Free ciphers and digests lists */
  EVP_cleanup();

#ifdef HAVE_ENGINE_CLEANUP
  /* Free engine list */
  ENGINE_cleanup();
#endif

#ifdef HAVE_CRYPTO_CLEANUP_ALL_EX_DATA
  /* Free OpenSSL ex_data table */
  CRYPTO_cleanup_all_ex_data();
#endif

  /* Free OpenSSL error strings */
  ERR_free_strings();

  /* Free thread local error state, destroying hash upon zero refcount */
#ifdef HAVE_ERR_REMOVE_THREAD_STATE
  ERR_remove_thread_state(NULL);
#else
  ERR_remove_state(0);
#endif

  /* Free all memory allocated by all configuration modules */
  CONF_modules_free();
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
#if defined(USE_OPENSSL) && defined(HAVE_OPENSSL_ENGINE_H)
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
      infof(data, "set default crypto engine '%s'\n",
            ENGINE_get_id(data->state.engine));
    }
    else {
      failf(data, "set default crypto engine '%s' failed",
            ENGINE_get_id(data->state.engine));
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
#if defined(USE_OPENSSL) && defined(HAVE_OPENSSL_ENGINE_H)
  struct curl_slist *beg;
  ENGINE *e;

  for(e = ENGINE_get_first(); e; e = ENGINE_get_next(e)) {
    beg = curl_slist_append(list, ENGINE_get_id(e));
    if(!beg) {
      curl_slist_free_all(list);
      return NULL;
    }
    list = beg;
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
void Curl_ossl_close_all(struct SessionHandle *data)
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
}

/* ====================================================== */


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
static CURLcode verifyhost(struct connectdata *conn, X509 *server_cert)
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
  CURLcode result = CURLE_OK;

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
    for(i=0; (i<numalts) && (matched != 1); i++) {
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
             Curl_cert_hostcheck(altptr, conn->host.name))
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
    failf(data, "SSL: no alternative certificate subject name matches "
          "target host name '%s'", conn->host.dispname);
    result = CURLE_PEER_FAILED_VERIFICATION;
  }
  else {
    /* we have to look to the last occurrence of a commonName in the
       distinguished one to get the most significant one. */
    int j, i=-1;

/* The following is done because of a bug in 0.9.6b */

    unsigned char *nulstr = (unsigned char *)"";
    unsigned char *peer_CN = nulstr;

    X509_NAME *name = X509_get_subject_name(server_cert);
    if(name)
      while((j = X509_NAME_get_index_by_NID(name, NID_commonName, i))>=0)
        i=j;

    /* we have the name entry and we will now convert this to a string
       that we can use for comparison. Doing this we support BMPstring,
       UTF8 etc. */

    if(i>=0) {
      ASN1_STRING *tmp =
        X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, i));

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

        if(peer_CN && (curlx_uztosi(strlen((char *)peer_CN)) != j)) {
          /* there was a terminating zero before the end of string, this
             cannot match and we return failure! */
          failf(data, "SSL: illegal cert name field");
          result = CURLE_PEER_FAILED_VERIFICATION;
        }
      }
    }

    if(peer_CN == nulstr)
       peer_CN = NULL;
    else {
      /* convert peer_CN from UTF8 */
      CURLcode rc = Curl_convert_from_utf8(data, peer_CN, strlen(peer_CN));
      /* Curl_convert_from_utf8 calls failf if unsuccessful */
      if(rc) {
        OPENSSL_free(peer_CN);
        return rc;
      }
    }

    if(result)
      /* error already detected, pass through */
      ;
    else if(!peer_CN) {
      failf(data,
            "SSL: unable to obtain common name from peer certificate");
      result = CURLE_PEER_FAILED_VERIFICATION;
    }
    else if(!Curl_cert_hostcheck((const char *)peer_CN, conn->host.name)) {
      failf(data, "SSL: certificate subject name '%s' does not match "
            "target host name '%s'", peer_CN, conn->host.dispname);
      result = CURLE_PEER_FAILED_VERIFICATION;
    }
    else {
      infof(data, "\t common name: %s (matched)\n", peer_CN);
    }
    if(peer_CN)
      OPENSSL_free(peer_CN);
  }

  return result;
}

#if (OPENSSL_VERSION_NUMBER >= 0x0090808fL) && !defined(OPENSSL_NO_TLSEXT) && \
    !defined(OPENSSL_IS_BORINGSSL)
static CURLcode verifystatus(struct connectdata *conn,
                             struct ssl_connect_data *connssl)
{
  int i, ocsp_status;
  const unsigned char *p;
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  OCSP_RESPONSE *rsp = NULL;
  OCSP_BASICRESP *br = NULL;
  X509_STORE     *st = NULL;
  STACK_OF(X509) *ch = NULL;

  long len = SSL_get_tlsext_status_ocsp_resp(connssl->handle, &p);

  if(!p) {
    failf(data, "No OCSP response received");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  rsp = d2i_OCSP_RESPONSE(NULL, &p, len);
  if(!rsp) {
    failf(data, "Invalid OCSP response");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  ocsp_status = OCSP_response_status(rsp);
  if(ocsp_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
    failf(data, "Invalid OCSP response status: %s (%d)",
          OCSP_response_status_str(ocsp_status), ocsp_status);
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  br = OCSP_response_get1_basic(rsp);
  if(!br) {
    failf(data, "Invalid OCSP response");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  ch = SSL_get_peer_cert_chain(connssl->handle);
  st = SSL_CTX_get_cert_store(connssl->ctx);

#if ((OPENSSL_VERSION_NUMBER <= 0x1000201fL) /* Fixed after 1.0.2a */ || \
     defined(LIBRESSL_VERSION_NUMBER))
  /* The authorized responder cert in the OCSP response MUST be signed by the
     peer cert's issuer (see RFC6960 section 4.2.2.2). If that's a root cert,
     no problem, but if it's an intermediate cert OpenSSL has a bug where it
     expects this issuer to be present in the chain embedded in the OCSP
     response. So we add it if necessary. */

  /* First make sure the peer cert chain includes both a peer and an issuer,
     and the OCSP response contains a responder cert. */
  if(sk_X509_num(ch) >= 2 && sk_X509_num(br->certs) >= 1) {
    X509 *responder = sk_X509_value(br->certs, sk_X509_num(br->certs) - 1);

    /* Find issuer of responder cert and add it to the OCSP response chain */
    for(i = 0; i < sk_X509_num(ch); i++) {
      X509 *issuer = sk_X509_value(ch, i);
      if(X509_check_issued(issuer, responder) == X509_V_OK) {
        if(!OCSP_basic_add1_cert(br, issuer)) {
          failf(data, "Could not add issuer cert to OCSP response");
          result = CURLE_SSL_INVALIDCERTSTATUS;
          goto end;
        }
      }
    }
  }
#endif

  if(OCSP_basic_verify(br, ch, st, 0) <= 0) {
    failf(data, "OCSP response verification failed");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  for(i = 0; i < OCSP_resp_count(br); i++) {
    int cert_status, crl_reason;
    OCSP_SINGLERESP *single = NULL;

    ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;

    if(!(single = OCSP_resp_get0(br, i)))
      continue;

    cert_status = OCSP_single_get0_status(single, &crl_reason, &rev,
                                          &thisupd, &nextupd);

    if(!OCSP_check_validity(thisupd, nextupd, 300L, -1L)) {
      failf(data, "OCSP response has expired");
      result = CURLE_SSL_INVALIDCERTSTATUS;
      goto end;
    }

    infof(data, "SSL certificate status: %s (%d)\n",
          OCSP_cert_status_str(cert_status), cert_status);

    switch(cert_status) {
      case V_OCSP_CERTSTATUS_GOOD:
        break;

      case V_OCSP_CERTSTATUS_REVOKED:
        result = CURLE_SSL_INVALIDCERTSTATUS;

        failf(data, "SSL certificate revocation reason: %s (%d)",
              OCSP_crl_reason_str(crl_reason), crl_reason);
        goto end;

      case V_OCSP_CERTSTATUS_UNKNOWN:
        result = CURLE_SSL_INVALIDCERTSTATUS;
        goto end;
    }
  }

end:
  if(br) OCSP_BASICRESP_free(br);
  OCSP_RESPONSE_free(rsp);

  return result;
}
#endif

#endif /* USE_OPENSSL */

/* The SSL_CTRL_SET_MSG_CALLBACK doesn't exist in ancient OpenSSL versions
   and thus this cannot be done there. */
#ifdef SSL_CTRL_SET_MSG_CALLBACK

static const char *ssl_msg_type(int ssl_ver, int msg)
{
#ifdef SSL2_VERSION_MAJOR
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
  else
#endif
  if(ssl_ver == SSL3_VERSION_MAJOR) {
    switch (msg) {
      case SSL3_MT_HELLO_REQUEST:
        return "Hello request";
      case SSL3_MT_CLIENT_HELLO:
        return "Client hello";
      case SSL3_MT_SERVER_HELLO:
        return "Server hello";
#ifdef SSL3_MT_NEWSESSION_TICKET
      case SSL3_MT_NEWSESSION_TICKET:
        return "Newsession Ticket";
#endif
      case SSL3_MT_CERTIFICATE:
        return "Certificate";
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
#ifdef SSL3_MT_CERTIFICATE_STATUS
      case SSL3_MT_CERTIFICATE_STATUS:
        return "Certificate Status";
#endif
    }
  }
  return "Unknown";
}

static const char *tls_rt_type(int type)
{
  switch(type) {
#ifdef SSL3_RT_HEADER
  case SSL3_RT_HEADER:
    return "TLS header";
#endif
  case SSL3_RT_CHANGE_CIPHER_SPEC:
    return "TLS change cipher";
  case SSL3_RT_ALERT:
    return "TLS alert";
  case SSL3_RT_HANDSHAKE:
    return "TLS handshake";
  case SSL3_RT_APPLICATION_DATA:
    return "TLS app data";
  default:
    return "TLS Unknown";
  }
}


/*
 * Our callback from the SSL/TLS layers.
 */
static void ssl_tls_trace(int direction, int ssl_ver, int content_type,
                          const void *buf, size_t len, SSL *ssl,
                          void *userp)
{
  struct SessionHandle *data;
  const char *msg_name, *tls_rt_name;
  char ssl_buf[1024];
  char unknown[32];
  int msg_type, txt_len;
  const char *verstr = NULL;
  struct connectdata *conn = userp;

  if(!conn || !conn->data || !conn->data->set.fdebug ||
     (direction != 0 && direction != 1))
    return;

  data = conn->data;

  switch(ssl_ver) {
#ifdef SSL2_VERSION /* removed in recent versions */
  case SSL2_VERSION:
    verstr = "SSLv2";
    break;
#endif
#ifdef SSL3_VERSION
  case SSL3_VERSION:
    verstr = "SSLv3";
    break;
#endif
  case TLS1_VERSION:
    verstr = "TLSv1.0";
    break;
#ifdef TLS1_1_VERSION
  case TLS1_1_VERSION:
    verstr = "TLSv1.1";
    break;
#endif
#ifdef TLS1_2_VERSION
  case TLS1_2_VERSION:
    verstr = "TLSv1.2";
    break;
#endif
  case 0:
    break;
  default:
    snprintf(unknown, sizeof(unknown), "(%x)", ssl_ver);
    verstr = unknown;
    break;
  }

  if(ssl_ver) {
    /* the info given when the version is zero is not that useful for us */

    ssl_ver >>= 8; /* check the upper 8 bits only below */

    /* SSLv2 doesn't seem to have TLS record-type headers, so OpenSSL
     * always pass-up content-type as 0. But the interesting message-type
     * is at 'buf[0]'.
     */
    if(ssl_ver == SSL3_VERSION_MAJOR && content_type)
      tls_rt_name = tls_rt_type(content_type);
    else
      tls_rt_name = "";

    msg_type = *(char*)buf;
    msg_name = ssl_msg_type(ssl_ver, msg_type);

    txt_len = snprintf(ssl_buf, sizeof(ssl_buf), "%s (%s), %s, %s (%d):\n",
                       verstr, direction?"OUT":"IN",
                       tls_rt_name, msg_name, msg_type);
    Curl_debug(data, CURLINFO_TEXT, ssl_buf, (size_t)txt_len, NULL);
  }

  Curl_debug(data, (direction == 1) ? CURLINFO_SSL_DATA_OUT :
             CURLINFO_SSL_DATA_IN, (char *)buf, len, NULL);
  (void) ssl;
}
#endif

#ifdef USE_OPENSSL
/* ====================================================== */

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
#  define use_sni(x)  sni = (x)
#else
#  define use_sni(x)  Curl_nop_stmt
#endif

/* Check for OpenSSL 1.0.2 which has ALPN support. */
#undef HAS_ALPN
#if OPENSSL_VERSION_NUMBER >= 0x10002000L \
    && !defined(OPENSSL_NO_TLSEXT)
#  define HAS_ALPN 1
#endif

/* Check for OpenSSL 1.0.1 which has NPN support. */
#undef HAS_NPN
#if OPENSSL_VERSION_NUMBER >= 0x10001000L \
    && !defined(OPENSSL_NO_TLSEXT) \
    && !defined(OPENSSL_NO_NEXTPROTONEG)
#  define HAS_NPN 1
#endif

#ifdef HAS_NPN

/*
 * in is a list of lenght prefixed strings. this function has to select
 * the protocol we want to use from the list and write its string into out.
 */

static int
select_next_protocol(unsigned char **out, unsigned char *outlen,
                     const unsigned char *in, unsigned int inlen,
                     const char *key, unsigned int keylen)
{
  unsigned int i;
  for(i = 0; i + keylen <= inlen; i += in[i] + 1) {
    if(memcmp(&in[i + 1], key, keylen) == 0) {
      *out = (unsigned char *) &in[i + 1];
      *outlen = in[i];
      return 0;
    }
  }
  return -1;
}

static int
select_next_proto_cb(SSL *ssl,
                     unsigned char **out, unsigned char *outlen,
                     const unsigned char *in, unsigned int inlen,
                     void *arg)
{
  struct connectdata *conn = (struct connectdata*) arg;

  (void)ssl;

#ifdef USE_NGHTTP2
  if(conn->data->set.httpversion == CURL_HTTP_VERSION_2_0 &&
     !select_next_protocol(out, outlen, in, inlen, NGHTTP2_PROTO_VERSION_ID,
                           NGHTTP2_PROTO_VERSION_ID_LEN)) {
    infof(conn->data, "NPN, negotiated HTTP2 (%s)\n",
          NGHTTP2_PROTO_VERSION_ID);
    conn->negnpn = CURL_HTTP_VERSION_2_0;
    return SSL_TLSEXT_ERR_OK;
  }
#endif

  if(!select_next_protocol(out, outlen, in, inlen, ALPN_HTTP_1_1,
                           ALPN_HTTP_1_1_LENGTH)) {
    infof(conn->data, "NPN, negotiated HTTP1.1\n");
    conn->negnpn = CURL_HTTP_VERSION_1_1;
    return SSL_TLSEXT_ERR_OK;
  }

  infof(conn->data, "NPN, no overlap, use HTTP1.1\n");
  *out = (unsigned char *)ALPN_HTTP_1_1;
  *outlen = ALPN_HTTP_1_1_LENGTH;
  conn->negnpn = CURL_HTTP_VERSION_1_1;

  return SSL_TLSEXT_ERR_OK;
}
#endif /* HAS_NPN */

static const char *
get_ssl_version_txt(SSL *ssl)
{
  if(!ssl)
    return "";

  switch(SSL_version(ssl)) {
#if OPENSSL_VERSION_NUMBER >= 0x1000100FL
  case TLS1_2_VERSION:
    return "TLSv1.2";
  case TLS1_1_VERSION:
    return "TLSv1.1";
#endif
  case TLS1_VERSION:
    return "TLSv1.0";
  case SSL3_VERSION:
    return "SSLv3";
  case SSL2_VERSION:
    return "SSLv2";
  }
  return "unknown";
}

static CURLcode ossl_connect_step1(struct connectdata *conn, int sockindex)
{
  CURLcode result = CURLE_OK;
  char *ciphers;
  struct SessionHandle *data = conn->data;
  SSL_METHOD_QUAL SSL_METHOD *req_method = NULL;
  void *ssl_sessionid = NULL;
  X509_LOOKUP *lookup = NULL;
  curl_socket_t sockfd = conn->sock[sockindex];
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  long ctx_options;
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

  data->set.ssl.certverifyresult = !X509_V_OK;

  /* check to see if we've been told to use an explicit SSL/TLS version */

  switch(data->set.ssl.version) {
  default:
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
  case CURL_SSLVERSION_TLSv1_0:
  case CURL_SSLVERSION_TLSv1_1:
  case CURL_SSLVERSION_TLSv1_2:
    /* it will be handled later with the context options */
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && \
    !defined(LIBRESSL_VERSION_NUMBER) && !defined(OPENSSL_IS_BORINGSSL)
    req_method = TLS_client_method();
#else
    req_method = SSLv23_client_method();
#endif
    use_sni(TRUE);
    break;
  case CURL_SSLVERSION_SSLv2:
#ifdef OPENSSL_NO_SSL2
    failf(data, "OpenSSL was built without SSLv2 support");
    return CURLE_NOT_BUILT_IN;
#else
#ifdef USE_TLS_SRP
    if(data->set.ssl.authtype == CURL_TLSAUTH_SRP)
      return CURLE_SSL_CONNECT_ERROR;
#endif
    req_method = SSLv2_client_method();
    use_sni(FALSE);
    break;
#endif
  case CURL_SSLVERSION_SSLv3:
#ifdef OPENSSL_NO_SSL3_METHOD
    failf(data, "OpenSSL was built without SSLv3 support");
    return CURLE_NOT_BUILT_IN;
#else
#ifdef USE_TLS_SRP
    if(data->set.ssl.authtype == CURL_TLSAUTH_SRP)
      return CURLE_SSL_CONNECT_ERROR;
#endif
    req_method = SSLv3_client_method();
    use_sni(FALSE);
    break;
#endif
  }

  if(connssl->ctx)
    SSL_CTX_free(connssl->ctx);
  connssl->ctx = SSL_CTX_new(req_method);

  if(!connssl->ctx) {
    failf(data, "SSL: couldn't create a context: %s",
          ERR_error_string(ERR_peek_error(), NULL));
    return CURLE_OUT_OF_MEMORY;
  }

#ifdef SSL_MODE_RELEASE_BUFFERS
  SSL_CTX_set_mode(connssl->ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

#ifdef SSL_CTRL_SET_MSG_CALLBACK
  if(data->set.fdebug && data->set.verbose) {
    /* the SSL trace callback is only used for verbose logging */
    SSL_CTX_set_msg_callback(connssl->ctx, ssl_tls_trace);
    SSL_CTX_set_msg_callback_arg(connssl->ctx, conn);
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
     into the proper RFC5077 it seems: https://tools.ietf.org/html/rfc5077

     The enabled extension concerns the session management. I wonder how often
     libcurl stops a connection and then resumes a TLS session. also, sending
     the session data is some overhead. .I suggest that you just use your
     proposed patch (which explicitly disables TICKET).

     If someone writes an application with libcurl and openssl who wants to
     enable the feature, one can do this in the SSL callback.

     SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG option enabling allowed proper
     interoperability with web server Netscape Enterprise Server 2.0.1 which
     was released back in 1996.

     Due to CVE-2010-4180, option SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG has
     become ineffective as of OpenSSL 0.9.8q and 1.0.0c. In order to mitigate
     CVE-2010-4180 when using previous OpenSSL versions we no longer enable
     this option regardless of OpenSSL version and SSL_OP_ALL definition.

     OpenSSL added a work-around for a SSL 3.0/TLS 1.0 CBC vulnerability
     (https://www.openssl.org/~bodo/tls-cbc.txt). In 0.9.6e they added a bit to
     SSL_OP_ALL that _disables_ that work-around despite the fact that
     SSL_OP_ALL is documented to do "rather harmless" workarounds. In order to
     keep the secure work-around, the SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS bit
     must not be set.
  */

  ctx_options = SSL_OP_ALL;

#ifdef SSL_OP_NO_TICKET
  ctx_options |= SSL_OP_NO_TICKET;
#endif

#ifdef SSL_OP_NO_COMPRESSION
  ctx_options |= SSL_OP_NO_COMPRESSION;
#endif

#ifdef SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
  /* mitigate CVE-2010-4180 */
  ctx_options &= ~SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG;
#endif

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
  /* unless the user explicitly ask to allow the protocol vulnerability we
     use the work-around */
  if(!conn->data->set.ssl_enable_beast)
    ctx_options &= ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
#endif

  switch(data->set.ssl.version) {
  case CURL_SSLVERSION_SSLv3:
#ifdef USE_TLS_SRP
    if(data->set.ssl.authtype == CURL_TLSAUTH_SRP) {
      infof(data, "Set version TLSv1.x for SRP authorisation\n");
    }
#endif
    ctx_options |= SSL_OP_NO_SSLv2;
    ctx_options |= SSL_OP_NO_TLSv1;
#if OPENSSL_VERSION_NUMBER >= 0x1000100FL
    ctx_options |= SSL_OP_NO_TLSv1_1;
    ctx_options |= SSL_OP_NO_TLSv1_2;
#endif
    break;

  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
    ctx_options |= SSL_OP_NO_SSLv2;
    ctx_options |= SSL_OP_NO_SSLv3;
    break;

  case CURL_SSLVERSION_TLSv1_0:
    ctx_options |= SSL_OP_NO_SSLv2;
    ctx_options |= SSL_OP_NO_SSLv3;
#if OPENSSL_VERSION_NUMBER >= 0x1000100FL
    ctx_options |= SSL_OP_NO_TLSv1_1;
    ctx_options |= SSL_OP_NO_TLSv1_2;
#endif
    break;

#if OPENSSL_VERSION_NUMBER >= 0x1000100FL
  case CURL_SSLVERSION_TLSv1_1:
    ctx_options |= SSL_OP_NO_SSLv2;
    ctx_options |= SSL_OP_NO_SSLv3;
    ctx_options |= SSL_OP_NO_TLSv1;
    ctx_options |= SSL_OP_NO_TLSv1_2;
    break;

  case CURL_SSLVERSION_TLSv1_2:
    ctx_options |= SSL_OP_NO_SSLv2;
    ctx_options |= SSL_OP_NO_SSLv3;
    ctx_options |= SSL_OP_NO_TLSv1;
    ctx_options |= SSL_OP_NO_TLSv1_1;
    break;
#endif

#ifndef OPENSSL_NO_SSL2
  case CURL_SSLVERSION_SSLv2:
    ctx_options |= SSL_OP_NO_SSLv3;
    ctx_options |= SSL_OP_NO_TLSv1;
#if OPENSSL_VERSION_NUMBER >= 0x1000100FL
    ctx_options |= SSL_OP_NO_TLSv1_1;
    ctx_options |= SSL_OP_NO_TLSv1_2;
#endif
    break;
#endif

  default:
    failf(data, "Unsupported SSL protocol version");
    return CURLE_SSL_CONNECT_ERROR;
  }

  SSL_CTX_set_options(connssl->ctx, ctx_options);

#ifdef HAS_NPN
  if(data->set.ssl_enable_npn)
    SSL_CTX_set_next_proto_select_cb(connssl->ctx, select_next_proto_cb, conn);
#endif

#ifdef HAS_ALPN
  if(data->set.ssl_enable_alpn) {
    int cur = 0;
    unsigned char protocols[128];

#ifdef USE_NGHTTP2
    if(data->set.httpversion == CURL_HTTP_VERSION_2_0) {
      protocols[cur++] = NGHTTP2_PROTO_VERSION_ID_LEN;

      memcpy(&protocols[cur], NGHTTP2_PROTO_VERSION_ID,
          NGHTTP2_PROTO_VERSION_ID_LEN);
      cur += NGHTTP2_PROTO_VERSION_ID_LEN;
      infof(data, "ALPN, offering %s\n", NGHTTP2_PROTO_VERSION_ID);
    }
#endif

    protocols[cur++] = ALPN_HTTP_1_1_LENGTH;
    memcpy(&protocols[cur], ALPN_HTTP_1_1, ALPN_HTTP_1_1_LENGTH);
    cur += ALPN_HTTP_1_1_LENGTH;
    infof(data, "ALPN, offering %s\n", ALPN_HTTP_1_1);

    /* expects length prefixed preference ordered list of protocols in wire
     * format
     */
    SSL_CTX_set_alpn_protos(connssl->ctx, protocols, cur);
  }
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

  ciphers = data->set.str[STRING_SSL_CIPHER_LIST];
  if(!ciphers)
    ciphers = (char *)DEFAULT_CIPHER_SELECTION;
  if(!SSL_CTX_set_cipher_list(connssl->ctx, ciphers)) {
    failf(data, "failed setting cipher list: %s", ciphers);
    return CURLE_SSL_CIPHER;
  }
  infof(data, "Cipher selection: %s\n", ciphers);

#ifdef USE_TLS_SRP
  if(data->set.ssl.authtype == CURL_TLSAUTH_SRP) {
    infof(data, "Using TLS-SRP username: %s\n", data->set.ssl.username);

    if(!SSL_CTX_set_srp_username(connssl->ctx, data->set.ssl.username)) {
      failf(data, "Unable to set SRP user name");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if(!SSL_CTX_set_srp_password(connssl->ctx, data->set.ssl.password)) {
      failf(data, "failed setting SRP password");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if(!data->set.str[STRING_SSL_CIPHER_LIST]) {
      infof(data, "Setting cipher list SRP\n");

      if(!SSL_CTX_set_cipher_list(connssl->ctx, "SRP")) {
        failf(data, "failed setting SRP cipher list");
        return CURLE_SSL_CIPHER;
      }
    }
  }
#endif
  if(data->set.str[STRING_SSL_CAFILE] || data->set.str[STRING_SSL_CAPATH]) {
    /* tell SSL where to find CA certificates that are used to verify
       the servers certificate. */
    if(!SSL_CTX_load_verify_locations(connssl->ctx,
                                       data->set.str[STRING_SSL_CAFILE],
                                       data->set.str[STRING_SSL_CAPATH])) {
      if(data->set.ssl.verifypeer) {
        /* Fail if we insist on successfully verifying the server. */
        failf(data, "error setting certificate verify locations:\n"
              "  CAfile: %s\n  CApath: %s",
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

  if(data->set.str[STRING_SSL_CRLFILE]) {
    /* tell SSL where to find CRL file that is used to check certificate
     * revocation */
    lookup=X509_STORE_add_lookup(SSL_CTX_get_cert_store(connssl->ctx),
                                 X509_LOOKUP_file());
    if(!lookup ||
       (!X509_load_crl_file(lookup, data->set.str[STRING_SSL_CRLFILE],
                            X509_FILETYPE_PEM)) ) {
      failf(data, "error loading CRL file: %s",
            data->set.str[STRING_SSL_CRLFILE]);
      return CURLE_SSL_CRL_BADFILE;
    }
    else {
      /* Everything is fine. */
      infof(data, "successfully load CRL file:\n");
      X509_STORE_set_flags(SSL_CTX_get_cert_store(connssl->ctx),
                           X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
    }
    infof(data,
          "  CRLfile: %s\n", data->set.str[STRING_SSL_CRLFILE] ?
          data->set.str[STRING_SSL_CRLFILE]: "none");
  }

  /* Try building a chain using issuers in the trusted store first to avoid
  problems with server-sent legacy intermediates.
  Newer versions of OpenSSL do alternate chain checking by default which
  gives us the same fix without as much of a performance hit (slight), so we
  prefer that if available.
  https://rt.openssl.org/Ticket/Display.html?id=3621&user=guest&pass=guest
  */
#if defined(X509_V_FLAG_TRUSTED_FIRST) && !defined(X509_V_FLAG_NO_ALT_CHAINS)
  if(data->set.ssl.verifypeer) {
    X509_STORE_set_flags(SSL_CTX_get_cert_store(connssl->ctx),
                         X509_V_FLAG_TRUSTED_FIRST);
  }
#endif

  /* SSL always tries to verify the peer, this only says whether it should
   * fail to connect if the verification fails, or if it should continue
   * anyway. In the latter case the result of the verification is checked with
   * SSL_get_verify_result() below. */
  SSL_CTX_set_verify(connssl->ctx,
                     data->set.ssl.verifypeer?SSL_VERIFY_PEER:SSL_VERIFY_NONE,
                     NULL);

  /* give application a chance to interfere with SSL set up. */
  if(data->set.ssl.fsslctx) {
    result = (*data->set.ssl.fsslctx)(data, connssl->ctx,
                                      data->set.ssl.fsslctxp);
    if(result) {
      failf(data, "error signaled by ssl ctx callback");
      return result;
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

#if (OPENSSL_VERSION_NUMBER >= 0x0090808fL) && !defined(OPENSSL_NO_TLSEXT) && \
    !defined(OPENSSL_IS_BORINGSSL)
  if(data->set.ssl.verifystatus)
    SSL_set_tlsext_status_type(connssl->handle, TLSEXT_STATUSTYPE_ocsp);
#endif

  SSL_set_connect_state(connssl->handle);

  connssl->server_cert = 0x0;

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
  if((0 == Curl_inet_pton(AF_INET, conn->host.name, &addr)) &&
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
            ERR_error_string(ERR_get_error(), NULL));
      return CURLE_SSL_CONNECT_ERROR;
    }
    /* Informational message */
    infof (data, "SSL re-using session ID\n");
  }

  /* pass the raw socket into the SSL layers */
  if(!SSL_set_fd(connssl->handle, (int)sockfd)) {
    failf(data, "SSL: SSL_set_fd failed: %s",
          ERR_error_string(ERR_get_error(), NULL));
    return CURLE_SSL_CONNECT_ERROR;
  }

  connssl->connecting_state = ssl_connect_2;

  return CURLE_OK;
}

static CURLcode ossl_connect_step2(struct connectdata *conn, int sockindex)
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
      char error_buffer[256]=""; /* OpenSSL documents that this must be at
                                    least 256 bytes long. */
      CURLcode result;
      long lerr;

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
        result = CURLE_SSL_CACERT;

        lerr = SSL_get_verify_result(connssl->handle);
        if(lerr != X509_V_OK) {
          snprintf(error_buffer, sizeof(error_buffer),
                   "SSL certificate problem: %s",
                   X509_verify_cert_error_string(lerr));
        }
        else
          /* strcpy() is fine here as long as the string fits within
             error_buffer */
          strcpy(error_buffer,
                 "SSL certificate problem, check your CA cert");
        break;
      default:
        result = CURLE_SSL_CONNECT_ERROR;
        SSL_strerror(errdetail, error_buffer, sizeof(error_buffer));
        break;
      }

      /* detail is already set to the SSL error above */

      /* If we e.g. use SSLv2 request-method and the server doesn't like us
       * (RST connection etc.), OpenSSL gives no explanation whatsoever and
       * the SO_ERROR is also lost.
       */
      if(CURLE_SSL_CONNECT_ERROR == result && errdetail == 0) {
        failf(data, "Unknown SSL protocol error in connection to %s:%ld ",
              conn->host.name, conn->remote_port);
        return result;
      }

      /* Could be a CERT problem */
      failf(data, "%s", error_buffer);

      return result;
    }
  }
  else {
    /* we have been connected fine, we're not waiting for anything else. */
    connssl->connecting_state = ssl_connect_3;

    /* Informational message */
    infof(data, "SSL connection using %s / %s\n",
          get_ssl_version_txt(connssl->handle),
          SSL_get_cipher(connssl->handle));

#ifdef HAS_ALPN
    /* Sets data and len to negotiated protocol, len is 0 if no protocol was
     * negotiated
     */
    if(data->set.ssl_enable_alpn) {
      const unsigned char* neg_protocol;
      unsigned int len;
      SSL_get0_alpn_selected(connssl->handle, &neg_protocol, &len);
      if(len != 0) {
        infof(data, "ALPN, server accepted to use %.*s\n", len, neg_protocol);

#ifdef USE_NGHTTP2
        if(len == NGHTTP2_PROTO_VERSION_ID_LEN &&
           !memcmp(NGHTTP2_PROTO_VERSION_ID, neg_protocol, len)) {
          conn->negnpn = CURL_HTTP_VERSION_2_0;
        }
        else
#endif
        if(len == ALPN_HTTP_1_1_LENGTH &&
           !memcmp(ALPN_HTTP_1_1, neg_protocol, ALPN_HTTP_1_1_LENGTH)) {
          conn->negnpn = CURL_HTTP_VERSION_1_1;
        }
      }
      else
        infof(data, "ALPN, server did not agree to a protocol\n");
    }
#endif

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

#define push_certinfo(_label, _num) \
do {                              \
  long info_len = BIO_get_mem_data(mem, &ptr); \
  Curl_ssl_push_certinfo_len(data, _num, _label, ptr, info_len); \
  BIO_reset(mem); \
} WHILE_FALSE

static void pubkey_show(struct SessionHandle *data,
                        BIO *mem,
                        int num,
                        const char *type,
                        const char *name,
                        BIGNUM *bn)
{
  char *ptr;
  char namebuf[32];

  snprintf(namebuf, sizeof(namebuf), "%s(%s)", type, name);

  BN_print(mem, bn);
  push_certinfo(namebuf, num);
}

#define print_pubkey_BN(_type, _name, _num)    \
do {                              \
  if(pubkey->pkey._type->_name) { \
    pubkey_show(data, mem, _num, #_type, #_name, pubkey->pkey._type->_name); \
  } \
} WHILE_FALSE

static int X509V3_ext(struct SessionHandle *data,
                      int certnum,
                      STACK_OF(X509_EXTENSION) *exts)
{
  int i;
  size_t j;

  if(sk_X509_EXTENSION_num(exts) <= 0)
    /* no extensions, bail out */
    return 1;

  for(i=0; i<sk_X509_EXTENSION_num(exts); i++) {
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

    if(!X509V3_EXT_print(bio_out, ext, 0, 0))
      ASN1_STRING_print(bio_out, (ASN1_STRING *)X509_EXTENSION_get_data(ext));

    BIO_get_mem_ptr(bio_out, &biomem);

    for(j = 0; j < (size_t)biomem->length; j++) {
      const char *sep="";
      if(biomem->data[j] == '\n') {
        sep=", ";
        j++; /* skip the newline */
      };
      while((j<(size_t)biomem->length) && (biomem->data[j] == ' '))
        j++;
      if(j<(size_t)biomem->length)
        ptr+=snprintf(ptr, sizeof(buf)-(ptr-buf), "%s%c", sep,
                      biomem->data[j]);
    }

    Curl_ssl_push_certinfo(data, certnum, namebuf, buf);

    BIO_free(bio_out);

  }
  return 0; /* all is fine */
}

static CURLcode get_cert_chain(struct connectdata *conn,
                               struct ssl_connect_data *connssl)

{
  CURLcode result;
  STACK_OF(X509) *sk;
  int i;
  struct SessionHandle *data = conn->data;
  int numcerts;
  BIO *mem;

  sk = SSL_get_peer_cert_chain(connssl->handle);
  if(!sk) {
    return CURLE_OUT_OF_MEMORY;
  }

  numcerts = sk_X509_num(sk);

  result = Curl_ssl_init_certinfo(data, numcerts);
  if(result) {
    return result;
  }

  mem = BIO_new(BIO_s_mem());

  for(i = 0; i < numcerts; i++) {
    ASN1_INTEGER *num;

    X509 *x = sk_X509_value(sk, i);

    X509_CINF *cinf;
    EVP_PKEY *pubkey=NULL;
    int j;
    char *ptr;

    X509_NAME_print_ex(mem, X509_get_subject_name(x), 0, XN_FLAG_ONELINE);
    push_certinfo("Subject", i);

    X509_NAME_print_ex(mem, X509_get_issuer_name(x), 0, XN_FLAG_ONELINE);
    push_certinfo("Issuer", i);

    BIO_printf(mem, "%lx", X509_get_version(x));
    push_certinfo("Version", i);

    num = X509_get_serialNumber(x);
    if(num->type == V_ASN1_NEG_INTEGER)
      BIO_puts(mem, "-");
    for(j = 0; j < num->length; j++)
      BIO_printf(mem, "%02x", num->data[j]);
    push_certinfo("Serial Number", i);

    cinf = x->cert_info;

    i2a_ASN1_OBJECT(mem, cinf->signature->algorithm);
    push_certinfo("Signature Algorithm", i);

    ASN1_TIME_print(mem, X509_get_notBefore(x));
    push_certinfo("Start date", i);

    ASN1_TIME_print(mem, X509_get_notAfter(x));
    push_certinfo("Expire date", i);

    i2a_ASN1_OBJECT(mem, cinf->key->algor->algorithm);
    push_certinfo("Public Key Algorithm", i);

    pubkey = X509_get_pubkey(x);
    if(!pubkey)
      infof(data, "   Unable to load public key\n");
    else {
      switch(pubkey->type) {
      case EVP_PKEY_RSA:
        BIO_printf(mem, "%d", BN_num_bits(pubkey->pkey.rsa->n));
        push_certinfo("RSA Public Key", i);

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

    for(j = 0; j < x->signature->length; j++)
      BIO_printf(mem, "%02x:", x->signature->data[j]);
    push_certinfo("Signature", i);

    PEM_write_bio_X509(mem, x);
    push_certinfo("Cert", i);
  }

  BIO_free(mem);

  return CURLE_OK;
}

/*
 * Heavily modified from:
 * https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#OpenSSL
 */
static CURLcode pkp_pin_peer_pubkey(struct SessionHandle *data, X509* cert,
                                    const char *pinnedpubkey)
{
  /* Scratch */
  int len1 = 0, len2 = 0;
  unsigned char *buff1 = NULL, *temp = NULL;

  /* Result is returned to caller */
  CURLcode result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;

  /* if a path wasn't specified, don't pin */
  if(!pinnedpubkey)
    return CURLE_OK;

  if(!cert)
    return result;

  do {
    /* Begin Gyrations to get the subjectPublicKeyInfo     */
    /* Thanks to Viktor Dukhovni on the OpenSSL mailing list */

    /* https://groups.google.com/group/mailing.openssl.users/browse_thread
     /thread/d61858dae102c6c7 */
    len1 = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), NULL);
    if(len1 < 1)
      break; /* failed */

    /* https://www.openssl.org/docs/crypto/buffer.html */
    buff1 = temp = OPENSSL_malloc(len1);
    if(!buff1)
      break; /* failed */

    /* https://www.openssl.org/docs/crypto/d2i_X509.html */
    len2 = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &temp);

    /*
     * These checks are verifying we got back the same values as when we
     * sized the buffer. It's pretty weak since they should always be the
     * same. But it gives us something to test.
     */
    if((len1 != len2) || !temp || ((temp - buff1) != len1))
      break; /* failed */

    /* End Gyrations */

    /* The one good exit point */
    result = Curl_pin_peer_pubkey(data, pinnedpubkey, buff1, len1);
  } while(0);

  /* https://www.openssl.org/docs/crypto/buffer.html */
  if(buff1)
    OPENSSL_free(buff1);

  return result;
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
  CURLcode result = CURLE_OK;
  int rc;
  long lerr, len;
  struct SessionHandle *data = conn->data;
  X509 *issuer;
  FILE *fp;
  char *buffer = data->state.buffer;
  const char *ptr;
  BIO *mem = BIO_new(BIO_s_mem());

  if(data->set.ssl.certinfo)
    /* we've been asked to gather certificate info! */
    (void)get_cert_chain(conn, connssl);

  connssl->server_cert = SSL_get_peer_certificate(connssl->handle);
  if(!connssl->server_cert) {
    if(!strict)
      return CURLE_OK;

    failf(data, "SSL: couldn't get peer certificate!");
    return CURLE_PEER_FAILED_VERIFICATION;
  }

  infof(data, "Server certificate:\n");

  rc = x509_name_oneline(X509_get_subject_name(connssl->server_cert),
                         buffer, BUFSIZE);
  infof(data, "\t subject: %s\n", rc?"[NONE]":buffer);

  ASN1_TIME_print(mem, X509_get_notBefore(connssl->server_cert));
  len = BIO_get_mem_data(mem, (char **) &ptr);
  infof(data, "\t start date: %.*s\n", len, ptr);
  BIO_reset(mem);

  ASN1_TIME_print(mem, X509_get_notAfter(connssl->server_cert));
  len = BIO_get_mem_data(mem, (char **) &ptr);
  infof(data, "\t expire date: %.*s\n", len, ptr);
  BIO_reset(mem);

  BIO_free(mem);

  if(data->set.ssl.verifyhost) {
    result = verifyhost(conn, connssl->server_cert);
    if(result) {
      X509_free(connssl->server_cert);
      connssl->server_cert = NULL;
      return result;
    }
  }

  rc = x509_name_oneline(X509_get_issuer_name(connssl->server_cert),
                         buffer, BUFSIZE);
  if(rc) {
    if(strict)
      failf(data, "SSL: couldn't get X509-issuer name!");
    result = CURLE_SSL_CONNECT_ERROR;
  }
  else {
    infof(data, "\t issuer: %s\n", buffer);

    /* We could do all sorts of certificate verification stuff here before
       deallocating the certificate. */

    /* e.g. match issuer name with provided issuer certificate */
    if(data->set.str[STRING_SSL_ISSUERCERT]) {
      fp = fopen(data->set.str[STRING_SSL_ISSUERCERT], FOPEN_READTEXT);
      if(!fp) {
        if(strict)
          failf(data, "SSL: Unable to open issuer cert (%s)",
                data->set.str[STRING_SSL_ISSUERCERT]);
        X509_free(connssl->server_cert);
        connssl->server_cert = NULL;
        return CURLE_SSL_ISSUER_ERROR;
      }

      issuer = PEM_read_X509(fp, NULL, ZERO_NULL, NULL);
      if(!issuer) {
        if(strict)
          failf(data, "SSL: Unable to read issuer cert (%s)",
                data->set.str[STRING_SSL_ISSUERCERT]);
        X509_free(connssl->server_cert);
        X509_free(issuer);
        fclose(fp);
        return CURLE_SSL_ISSUER_ERROR;
      }

      fclose(fp);

      if(X509_check_issued(issuer, connssl->server_cert) != X509_V_OK) {
        if(strict)
          failf(data, "SSL: Certificate issuer check failed (%s)",
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

    lerr = data->set.ssl.certverifyresult =
      SSL_get_verify_result(connssl->handle);

    if(data->set.ssl.certverifyresult != X509_V_OK) {
      if(data->set.ssl.verifypeer) {
        /* We probably never reach this, because SSL_connect() will fail
           and we return earlier if verifypeer is set? */
        if(strict)
          failf(data, "SSL certificate verify result: %s (%ld)",
                X509_verify_cert_error_string(lerr), lerr);
        result = CURLE_PEER_FAILED_VERIFICATION;
      }
      else
        infof(data, "\t SSL certificate verify result: %s (%ld),"
              " continuing anyway.\n",
              X509_verify_cert_error_string(lerr), lerr);
    }
    else
      infof(data, "\t SSL certificate verify ok.\n");
  }

#if (OPENSSL_VERSION_NUMBER >= 0x0090808fL) && !defined(OPENSSL_NO_TLSEXT) && \
    !defined(OPENSSL_IS_BORINGSSL)
  if(data->set.ssl.verifystatus) {
    result = verifystatus(conn, connssl);
    if(result) {
      X509_free(connssl->server_cert);
      connssl->server_cert = NULL;
      return result;
    }
  }
#endif

  if(!strict)
    /* when not strict, we don't bother about the verify cert problems */
    result = CURLE_OK;

  ptr = data->set.str[STRING_SSL_PINNEDPUBLICKEY];
  if(!result && ptr) {
    result = pkp_pin_peer_pubkey(data, connssl->server_cert, ptr);
    if(result)
      failf(data, "SSL: public key does not match pinned public key!");
  }

  X509_free(connssl->server_cert);
  connssl->server_cert = NULL;
  connssl->connecting_state = ssl_connect_done;

  return result;
}

static CURLcode ossl_connect_step3(struct connectdata *conn, int sockindex)
{
  CURLcode result = CURLE_OK;
  void *old_ssl_sessionid = NULL;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  bool incache;
  SSL_SESSION *our_ssl_sessionid;

  DEBUGASSERT(ssl_connect_3 == connssl->connecting_state);

  our_ssl_sessionid = SSL_get1_session(connssl->handle);

  /* SSL_get1_session() will increment the reference count and the session
     will stay in memory until explicitly freed with SSL_SESSION_free(3),
     regardless of its state. */

  incache = !(Curl_ssl_getsessionid(conn, &old_ssl_sessionid, NULL));
  if(incache) {
    if(old_ssl_sessionid != our_ssl_sessionid) {
      infof(data, "old SSL session ID is stale, removing\n");
      Curl_ssl_delsessionid(conn, old_ssl_sessionid);
      incache = FALSE;
    }
  }

  if(!incache) {
    result = Curl_ssl_addsessionid(conn, our_ssl_sessionid,
                                   0 /* unknown size */);
    if(result) {
      failf(data, "failed to store ssl session");
      return result;
    }
  }
  else {
    /* Session was incache, so refcount already incremented earlier.
     * Avoid further increments with each SSL_get1_session() call.
     * This does not free the session as refcount remains > 0
     */
    SSL_SESSION_free(our_ssl_sessionid);
  }

  /*
   * We check certificates to authenticate the server; otherwise we risk
   * man-in-the-middle attack; NEVERTHELESS, if we're told explicitly not to
   * verify the peer ignore faults and failures from the server cert
   * operations.
   */

  result = servercert(conn, connssl,
                      (data->set.ssl.verifypeer || data->set.ssl.verifyhost));

  if(!result)
    connssl->connecting_state = ssl_connect_done;

  return result;
}

static Curl_recv ossl_recv;
static Curl_send ossl_send;

static CURLcode ossl_connect_common(struct connectdata *conn,
                                    int sockindex,
                                    bool nonblocking,
                                    bool *done)
{
  CURLcode result;
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

  if(ssl_connect_1 == connssl->connecting_state) {
    /* Find out how much more time we're allowed */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    result = ossl_connect_step1(conn, sockindex);
    if(result)
      return result;
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
    if(connssl->connecting_state == ssl_connect_2_reading ||
       connssl->connecting_state == ssl_connect_2_writing) {

      curl_socket_t writefd = ssl_connect_2_writing==
        connssl->connecting_state?sockfd:CURL_SOCKET_BAD;
      curl_socket_t readfd = ssl_connect_2_reading==
        connssl->connecting_state?sockfd:CURL_SOCKET_BAD;

      what = Curl_socket_ready(readfd, writefd, nonblocking?0:timeout_ms);
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
    result = ossl_connect_step2(conn, sockindex);
    if(result || (nonblocking &&
                  (ssl_connect_2 == connssl->connecting_state ||
                   ssl_connect_2_reading == connssl->connecting_state ||
                   ssl_connect_2_writing == connssl->connecting_state)))
      return result;

  } /* repeat step2 until all transactions are done. */

  if(ssl_connect_3 == connssl->connecting_state) {
    result = ossl_connect_step3(conn, sockindex);
    if(result)
      return result;
  }

  if(ssl_connect_done == connssl->connecting_state) {
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

CURLcode Curl_ossl_connect_nonblocking(struct connectdata *conn,
                                       int sockindex,
                                       bool *done)
{
  return ossl_connect_common(conn, sockindex, TRUE, done);
}

CURLcode Curl_ossl_connect(struct connectdata *conn, int sockindex)
{
  CURLcode result;
  bool done = FALSE;

  result = ossl_connect_common(conn, sockindex, FALSE, &done);
  if(result)
    return result;

  DEBUGASSERT(done);

  return CURLE_OK;
}

bool Curl_ossl_data_pending(const struct connectdata *conn, int connindex)
{
  if(conn->ssl[connindex].handle)
    /* SSL is in use */
    return (0 != SSL_pending(conn->ssl[connindex].handle)) ? TRUE : FALSE;
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

  if(rc <= 0) {
    err = SSL_get_error(conn->ssl[sockindex].handle, rc);

    switch(err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      /* The operation did not complete; the same TLS/SSL I/O function
         should be called again later. This is basically an EWOULDBLOCK
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
  *curlcode = CURLE_OK;
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
  if(nread <= 0) {
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
      /* openssl/ssl.h for SSL_ERROR_SYSCALL says "look at error stack/return
         value/errno" */
      /* https://www.openssl.org/docs/crypto/ERR_get_error.html */
      sslerror = ERR_get_error();
      if((nread < 0) || sslerror) {
        /* If the return code was negative or there actually is an error in the
           queue */
        failf(conn->data, "SSL read: %s, errno %d",
              ERR_error_string(sslerror, error_buffer),
              SOCKERRNO);
        *curlcode = CURLE_RECV_ERROR;
        return -1;
      }
    }
  }
  return nread;
}

size_t Curl_ossl_version(char *buffer, size_t size)
{
#ifdef OPENSSL_IS_BORINGSSL
  return snprintf(buffer, size, "BoringSSL");
#else /* OPENSSL_IS_BORINGSSL */
  char sub[3];
  unsigned long ssleay_value;
  sub[2]='\0';
  sub[1]='\0';
  ssleay_value=SSLeay();
  if(ssleay_value < 0x906000) {
    ssleay_value=SSLEAY_VERSION_NUMBER;
    sub[0]='\0';
  }
  else {
    if(ssleay_value&0xff0) {
      int minor_ver = (ssleay_value >> 4) & 0xff;
      if(minor_ver > 26) {
        /* handle extended version introduced for 0.9.8za */
        sub[1] = (char) ((minor_ver - 1) % 26 + 'a' + 1);
        sub[0] = 'z';
      }
      else {
        sub[0]=(char)(((ssleay_value>>4)&0xff) + 'a' -1);
      }
    }
    else
      sub[0]='\0';
  }

  return snprintf(buffer, size, "%s/%lx.%lx.%lx%s",
#ifdef LIBRESSL_VERSION_NUMBER
                  "LibreSSL"
#else
                  "OpenSSL"
#endif
                  , (ssleay_value>>28)&0xf,
                  (ssleay_value>>20)&0xff,
                  (ssleay_value>>12)&0xff,
                  sub);
#endif /* OPENSSL_IS_BORINGSSL */
}

/* can be called with data == NULL */
int Curl_ossl_random(struct SessionHandle *data, unsigned char *entropy,
                     size_t length)
{
  if(data) {
    Curl_ossl_seed(data); /* Initiate the seed if not already done */
  }
  RAND_bytes(entropy, curlx_uztosi(length));
  return 0; /* 0 as in no problem */
}

void Curl_ossl_md5sum(unsigned char *tmp, /* input */
                      size_t tmplen,
                      unsigned char *md5sum /* output */,
                      size_t unused)
{
  MD5_CTX MD5pw;
  (void)unused;
  MD5_Init(&MD5pw);
  MD5_Update(&MD5pw, tmp, tmplen);
  MD5_Final(md5sum, &MD5pw);
}

#if (OPENSSL_VERSION_NUMBER >= 0x0090800fL) && !defined(OPENSSL_NO_SHA256)
void Curl_ossl_sha256sum(const unsigned char *tmp, /* input */
                      size_t tmplen,
                      unsigned char *sha256sum /* output */,
                      size_t unused)
{
  SHA256_CTX SHA256pw;
  (void)unused;
  SHA256_Init(&SHA256pw);
  SHA256_Update(&SHA256pw, tmp, tmplen);
  SHA256_Final(sha256sum, &SHA256pw);
}
#endif

bool Curl_ossl_cert_status_request(void)
{
#if (OPENSSL_VERSION_NUMBER >= 0x0090808fL) && !defined(OPENSSL_NO_TLSEXT) && \
    !defined(OPENSSL_IS_BORINGSSL)
  return TRUE;
#else
  return FALSE;
#endif
}
#endif /* USE_OPENSSL */
