/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 *  The contents of this file are subject to the Mozilla Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *  License for the specific language governing rights and limitations
 *  under the License.
 *
 *  The Original Code is Curl.
 *
 *  The Initial Developer of the Original Code is Daniel Stenberg.
 *
 *  Portions created by the Initial Developer are Copyright (C) 1998.
 *  All Rights Reserved.
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <Daniel.Stenberg@haxx.nu>
 *
 * 	http://curl.haxx.nu
 *
 * $Source$
 * $Revision$
 * $Date$
 * $Author$
 * $State$
 * $Locker$
 *
 * ------------------------------------------------------------
 ****************************************************************************/

#include <string.h>
#include <stdlib.h>

#include "urldata.h"
#include "sendf.h"
#include "formdata.h" /* for the boundary function */

#ifdef USE_SSLEAY

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

/* This function is *highly* inspired by (and parts are directly stolen
 * from) source from the SSLeay package written by Eric Young
 * (eay@cryptsoft.com).  */

int SSL_cert_stuff(struct UrlData *data, 
		   char *cert_file,
		   char *key_file)
{
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
      SSL_CTX_set_default_passwd_cb(data->ctx, passwd_callback);
    }

    if (SSL_CTX_use_certificate_file(data->ctx,
				     cert_file,
				     SSL_FILETYPE_PEM) <= 0) {
      failf(data, "unable to set certificate file (wrong password?)\n");
      return(0);
    }
    if (key_file == NULL)
      key_file=cert_file;

    if (SSL_CTX_use_PrivateKey_file(data->ctx,
				    key_file,
				    SSL_FILETYPE_PEM) <= 0) {
      failf(data, "unable to set public key file\n");
      return(0);
    }
    
    ssl=SSL_new(data->ctx);
    x509=SSL_get_certificate(ssl);
    
    if (x509 != NULL)
      EVP_PKEY_copy_parameters(X509_get_pubkey(x509),
			       SSL_get_privatekey(ssl));
    SSL_free(ssl);

    /* If we are using DSA, we can copy the parameters from
     * the private key */
		
    
    /* Now we know that a key and cert have been set against
     * the SSL context */
    if (!SSL_CTX_check_private_key(data->ctx)) {
      failf(data, "Private key does not match the certificate public key\n");
      return(0);
    }
    
    /* erase it now */
    memset(global_passwd, 0, sizeof(global_passwd));
  }
  return(1);
}

#endif

#if SSL_VERIFY_CERT
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
UrgSSLConnect (struct UrlData *data)
{
#ifdef USE_SSLEAY
    int err;
    char * str;
    SSL_METHOD *req_method;

    /* mark this is being ssl enabled from here on out. */
    data->use_ssl = 1;

    /* Lets get nice error messages */
    SSL_load_error_strings();

#ifdef HAVE_RAND_STATUS
    /* RAND_status() was introduced in OpenSSL 0.9.5 */
    if(0 == RAND_status())
#endif
    {
      /* We need to seed the PRNG properly! */
#ifdef WIN32
      /* This one gets a random value by reading the currently shown screen */
      RAND_screen();
#else
      int len;
      char *area = MakeFormBoundary();
      if(!area)
	return 3; /* out of memory */
	
      len = strlen(area);

      RAND_seed(area, len);

      free(area); /* now remove the random junk */
#endif
    }
    
    /* Setup all the global SSL stuff */
    SSLeay_add_ssl_algorithms();

    switch(data->ssl_version) {
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
    
    data->ctx = SSL_CTX_new(req_method);

    if(!data->ctx) {
      failf(data, "SSL: couldn't create a context!");
      return 1;
    }
    
    if(data->cert) {
      if (!SSL_cert_stuff(data, data->cert, data->cert)) {
	failf(data, "couldn't use certificate!\n");
	return 2;
      }
    }

#if SSL_VERIFY_CERT
    SSL_CTX_set_verify(data->ctx,
                       SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT|
                       SSL_VERIFY_CLIENT_ONCE,
                       cert_verify_callback);
#endif

    /* Lets make an SSL structure */
    data->ssl = SSL_new (data->ctx);
    SSL_set_connect_state (data->ssl);

    data->server_cert = 0x0;

    /* pass the raw socket into the SSL layers */
    SSL_set_fd (data->ssl, data->firstsocket);
    err = SSL_connect (data->ssl);

    if (-1 == err) {
      err = ERR_get_error(); 
      failf(data, "SSL: %s", ERR_error_string(err, NULL));
      return 10;
    }


    infof (data, "SSL connection using %s\n", SSL_get_cipher (data->ssl));
  
    /* Get server's certificate (note: beware of dynamic allocation) - opt */
    /* major serious hack alert -- we should check certificates
     * to authenticate the server; otherwise we risk man-in-the-middle
     * attack
     */

    data->server_cert = SSL_get_peer_certificate (data->ssl);
    if(!data->server_cert) {
      failf(data, "SSL: couldn't get peer certificate!");
      return 3;
    }
    infof (data, "Server certificate:\n");
  
    str = X509_NAME_oneline (X509_get_subject_name (data->server_cert), NULL, 0);
    if(!str) {
      failf(data, "SSL: couldn't get X509-subject!");
      return 4;
    }
    infof (data, "\t subject: %s\n", str);
    Free (str);

    str = X509_NAME_oneline (X509_get_issuer_name  (data->server_cert), NULL, 0);
    if(!str) {
      failf(data, "SSL: couldn't get X509-issuer name!");
      return 5;
    }
    infof (data, "\t issuer: %s\n", str);
    Free (str);

    /* We could do all sorts of certificate verification stuff here before
       deallocating the certificate. */


#if SSL_VERIFY_CERT
    infof(data, "Verify result: %d\n", SSL_get_verify_result(data->ssl));
#endif



    X509_free (data->server_cert);
#else /* USE_SSLEAY */
    /* this is for "-ansi -Wall -pedantic" to stop complaining!   (rabe) */
    (void) data;
#endif
    return 0;
}
