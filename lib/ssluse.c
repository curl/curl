/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2000, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * In order to be useful for every potential user, curl and libcurl are
 * dual-licensed under the MPL and the MIT/X-derivate licenses.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the MPL or the MIT/X-derivate
 * licenses. You may pick one of these licenses.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 *****************************************************************************/

/*
 * The original SSL code was written by
 * Linas Vepstas <linas@linas.org> and Sampo Kellomaki <sampo@iki.fi>
 */

#include "setup.h"
#include <string.h>
#include <stdlib.h>

#include "urldata.h"
#include "sendf.h"
#include "formdata.h" /* for the boundary function */

#ifdef USE_SSLEAY
#include <openssl/rand.h>

static char global_passwd[64];

static int passwd_callback(char *buf, int num, int verify
#if OPENSSL_VERSION_NUMBER >= 0x00904100L
                           /* This was introduced in 0.9.4, we can set this
                              using SSL_CTX_set_default_passwd_cb_userdata()
                              */
                           , void *userdata
#endif
                           )
{
  if(verify)
    fprintf(stderr, "%s\n", buf);
  else {
    if(num > strlen(global_passwd)) {
      strcpy(buf, global_passwd);
      return strlen(buf);
    }
  }  
  return 0;
}

static
bool seed_enough(struct connectdata *conn, /* unused for now */
                 int nread)
{
#ifdef HAVE_RAND_STATUS
  /* only available in OpenSSL 0.9.5a and later */
  if(RAND_status())
    return TRUE;
#else
  if(nread > 500)
    /* this is a very silly decision to make */
    return TRUE;
#endif
  return FALSE; /* not enough */
}

static
int random_the_seed(struct connectdata *conn)
{
  char *buf = conn->data->buffer; /* point to the big buffer */
  int nread=0;
  struct UrlData *data=conn->data;

  /* Q: should we add support for a random file name as a libcurl option?
     A: Yes, it is here */

#ifndef RANDOM_FILE
  /* if RANDOM_FILE isn't defined, we only perform this if an option tells
     us to! */
  if(data->ssl.random_file)
#define RANDOM_FILE "" /* doesn't matter won't be used */
#endif
  {
    /* let the option override the define */
    nread += RAND_load_file((data->ssl.random_file?
                             data->ssl.random_file:RANDOM_FILE),
                            16384);
    if(seed_enough(conn, nread))
      return nread;
  }

#if defined(HAVE_RAND_EGD)
  /* only available in OpenSSL 0.9.5 and later */
  /* EGD_SOCKET is set at configure time or not at all */
#ifndef EGD_SOCKET
  /* If we don't have the define set, we only do this if the egd-option
     is set */
  if(data->ssl.egdsocket)
#define EGD_SOCKET "" /* doesn't matter won't be used */
#endif
  {
    /* If there's an option and a define, the option overrides the
       define */
    int ret = RAND_egd(data->ssl.egdsocket?data->ssl.egdsocket:EGD_SOCKET);
    if(-1 != ret) {
      nread += ret;
      if(seed_enough(conn, nread))
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
    char *area = Curl_FormBoundary();
    if(!area)
      return 3; /* out of memory */
	
    len = strlen(area);
    RAND_seed(area, len);

    free(area); /* now remove the random junk */
  }
#endif

  /* generates a default path for the random seed file */
  buf[0]=0; /* blank it first */
  RAND_file_name(buf, BUFSIZE);
  if ( buf[0] ) {
    /* we got a file name to try */
    nread += RAND_load_file(buf, 16384);
    if(seed_enough(conn, nread))
      return nread;
  }

  infof(conn->data, "Your connection is using a weak random seed!\n");
  return nread;
}

static
int cert_stuff(struct connectdata *conn,
               char *cert_file,
               char *key_file)
{
  struct UrlData *data = conn->data;
  if (cert_file != NULL) {
    SSL *ssl;
    X509 *x509;

    if(data->cert_passwd) {
      /*
       * If password has been given, we store that in the global
       * area (*shudder*) for a while:
       */
      strcpy(global_passwd, data->cert_passwd);
      /* Set passwd callback: */
      SSL_CTX_set_default_passwd_cb(conn->ssl.ctx, passwd_callback);
    }

    if (SSL_CTX_use_certificate_file(conn->ssl.ctx,
				     cert_file,
				     SSL_FILETYPE_PEM) <= 0) {
      failf(data, "unable to set certificate file (wrong password?)\n");
      return(0);
    }
    if (key_file == NULL)
      key_file=cert_file;

    if (SSL_CTX_use_PrivateKey_file(conn->ssl.ctx,
				    key_file,
				    SSL_FILETYPE_PEM) <= 0) {
      failf(data, "unable to set public key file\n");
      return(0);
    }
    
    ssl=SSL_new(conn->ssl.ctx);
    x509=SSL_get_certificate(ssl);
    
    if (x509 != NULL)
      EVP_PKEY_copy_parameters(X509_get_pubkey(x509),
			       SSL_get_privatekey(ssl));
    SSL_free(ssl);

    /* If we are using DSA, we can copy the parameters from
     * the private key */
		
    
    /* Now we know that a key and cert have been set against
     * the SSL context */
    if (!SSL_CTX_check_private_key(conn->ssl.ctx)) {
      failf(data, "Private key does not match the certificate public key\n");
      return(0);
    }
    
    /* erase it now */
    memset(global_passwd, 0, sizeof(global_passwd));
  }
  return(1);
}

static
int cert_verify_callback(int ok, X509_STORE_CTX *ctx)
{
  X509 *err_cert;
  char buf[256];

  err_cert=X509_STORE_CTX_get_current_cert(ctx);
  X509_NAME_oneline(X509_get_subject_name(err_cert),buf,256);

  return 1;
}

#endif

/* ====================================================== */
int
Curl_SSLConnect(struct connectdata *conn)
{
#ifdef USE_SSLEAY
  struct UrlData *data = conn->data;
  int err;
  char * str;
  SSL_METHOD *req_method;

  /* mark this is being ssl enabled from here on out. */
  conn->ssl.use = TRUE;

  /* Lets get nice error messages */
  SSL_load_error_strings();

  /* Make funny stuff to get random input */
  random_the_seed(conn);
    
  /* Setup all the global SSL stuff */
  SSLeay_add_ssl_algorithms();

  switch(data->ssl.version) {
  default:
    req_method = SSLv23_client_method();
    break;
  case 2:
    req_method = SSLv2_client_method();
    break;
  case 3:
    req_method = SSLv3_client_method();
    break;
  }
    
  conn->ssl.ctx = SSL_CTX_new(req_method);

  if(!conn->ssl.ctx) {
    failf(data, "SSL: couldn't create a context!");
    return 1;
  }
    
  if(data->cert) {
    if (!cert_stuff(conn, data->cert, data->cert)) {
      failf(data, "couldn't use certificate!\n");
      return 2;
    }
  }

  if(data->ssl.verifypeer){
    SSL_CTX_set_verify(conn->ssl.ctx,
                       SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT|
                       SSL_VERIFY_CLIENT_ONCE,
                       cert_verify_callback);
    if (!SSL_CTX_load_verify_locations(conn->ssl.ctx,
                                       data->ssl.CAfile,
                                       data->ssl.CApath)) {
      failf(data,"error setting cerficate verify locations\n");
      return 2;
    }
  }
  else
    SSL_CTX_set_verify(conn->ssl.ctx, SSL_VERIFY_NONE, cert_verify_callback);


  /* Lets make an SSL structure */
  conn->ssl.handle = SSL_new (conn->ssl.ctx);
  SSL_set_connect_state (conn->ssl.handle);

  conn->ssl.server_cert = 0x0;

  /* pass the raw socket into the SSL layers */
  SSL_set_fd (conn->ssl.handle, conn->firstsocket);
  err = SSL_connect (conn->ssl.handle);

  if (-1 == err) {
    err = ERR_get_error(); 
    failf(data, "SSL: %s", ERR_error_string(err, NULL));
    return 10;
  }

  /* Informational message */
  infof (data, "SSL connection using %s\n",
         SSL_get_cipher(conn->ssl.handle));
  
  /* Get server's certificate (note: beware of dynamic allocation) - opt */
  /* major serious hack alert -- we should check certificates
   * to authenticate the server; otherwise we risk man-in-the-middle
   * attack
   */

  conn->ssl.server_cert = SSL_get_peer_certificate (conn->ssl.handle);
  if(!conn->ssl.server_cert) {
    failf(data, "SSL: couldn't get peer certificate!");
    return 3;
  }
  infof (data, "Server certificate:\n");
  
  str = X509_NAME_oneline (X509_get_subject_name (conn->ssl.server_cert),
                           NULL, 0);
  if(!str) {
    failf(data, "SSL: couldn't get X509-subject!");
    return 4;
  }
  infof(data, "\t subject: %s\n", str);
  CRYPTO_free(str);

  str = X509_NAME_oneline (X509_get_issuer_name  (conn->ssl.server_cert),
                           NULL, 0);
  if(!str) {
    failf(data, "SSL: couldn't get X509-issuer name!");
    return 5;
  }
  infof(data, "\t issuer: %s\n", str);
  CRYPTO_free(str);

  /* We could do all sorts of certificate verification stuff here before
     deallocating the certificate. */

  if(data->ssl.verifypeer) {
    data->ssl.certverifyresult=SSL_get_verify_result(conn->ssl.handle);
    infof(data, "Verify result: %d\n", data->ssl.certverifyresult);
  }
  else
    data->ssl.certverifyresult=0;

  X509_free(conn->ssl.server_cert);
#else /* USE_SSLEAY */
  /* this is for "-ansi -Wall -pedantic" to stop complaining!   (rabe) */
  (void) conn;
#endif
  return 0;
}
