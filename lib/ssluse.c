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

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

#if OPENSSL_VERSION_NUMBER >= 0x00904100L
#define HAVE_USERDATA_IN_PWD_CALLBACK 1
#else
#undef HAVE_USERDATA_IN_PWD_CALLBACK
#endif

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
      return strlen(buf);
    }
  }  
  return 0;
}

static
bool seed_enough(struct connectdata *conn, /* unused for now */
                 int nread)
{
  conn = NULL; /* to prevent compiler warnings */
#ifdef HAVE_RAND_STATUS
  nread = 0; /* to prevent compiler warnings */

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
  char *buf = conn->data->state.buffer; /* point to the big buffer */
  int nread=0;
  struct SessionHandle *data=conn->data;

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
  if(data->set.ssl.egdsocket)
#define EGD_SOCKET "" /* doesn't matter won't be used */
#endif
  {
    /* If there's an option and a define, the option overrides the
       define */
    int ret = RAND_egd(data->set.ssl.egdsocket?data->set.ssl.egdsocket:EGD_SOCKET);
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
  struct SessionHandle *data = conn->data;
  if (cert_file != NULL) {
    SSL *ssl;
    X509 *x509;

    if(data->set.cert_passwd) {
#ifndef HAVE_USERDATA_IN_PWD_CALLBACK
      /*
       * If password has been given, we store that in the global
       * area (*shudder*) for a while:
       */
      strcpy(global_passwd, data->set.cert_passwd);
#else
      /*
       * We set the password in the callback userdata
       */
      SSL_CTX_set_default_passwd_cb_userdata(conn->ssl.ctx, data->set.cert_passwd);
#endif
      /* Set passwd callback: */
      SSL_CTX_set_default_passwd_cb(conn->ssl.ctx, passwd_callback);
    }

    if (SSL_CTX_use_certificate_file(conn->ssl.ctx,
				     cert_file,
				     SSL_FILETYPE_PEM) != 1) {
      failf(data, "unable to set certificate file (wrong password?)\n");
      return(0);
    }
    if (key_file == NULL)
      key_file=cert_file;

    if (SSL_CTX_use_PrivateKey_file(conn->ssl.ctx,
				    key_file,
				    SSL_FILETYPE_PEM) != 1) {
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
  X509_NAME_oneline(X509_get_subject_name(err_cert),buf,256);

  return ok;
}

#endif

#ifdef USE_SSLEAY
/* "global" init done? */
static int init_ssl=0;
#endif

/* Global init */
void Curl_SSL_init(void)
{
#ifdef USE_SSLEAY
  /* make sure this is only done once */
  if(0 != init_ssl)
    return;

  init_ssl++; /* never again */

  /* Lets get nice error messages */
  SSL_load_error_strings();

  /* Setup all the global SSL stuff */
  SSLeay_add_ssl_algorithms();
#else
  /* SSL disabled, do nothing */
#endif
}

/* Global cleanup */
void Curl_SSL_cleanup(void)
{
#ifdef USE_SSLEAY
  if(init_ssl) {
    /* only cleanup if we did a previous init */

    /* Free the SSL error strings */
    ERR_free_strings();
  
    /* EVP_cleanup() removes all ciphers and digests from the
       table. */
    EVP_cleanup();
  }
#else
  /* SSL disabled, do nothing */
#endif
}

#ifdef USE_SSLEAY

/*
 * This function is called when an SSL connection is closed.
 */
void Curl_SSL_Close(struct connectdata *conn)
{
  if (conn->ssl.use) {
    /*
      ERR_remove_state() frees the error queue associated with
      thread pid.  If pid == 0, the current thread will have its
      error queue removed.

      Since error queue data structures are allocated
      automatically for new threads, they must be freed when
      threads are terminated in oder to avoid memory leaks.
    */
    ERR_remove_state(0);

    if(conn->ssl.handle) {
      (void)SSL_shutdown(conn->ssl.handle);
      SSL_set_connect_state(conn->ssl.handle);

      SSL_free (conn->ssl.handle);
      conn->ssl.handle = NULL;
    }
    if(conn->ssl.ctx) {
      SSL_CTX_free (conn->ssl.ctx);
      conn->ssl.ctx = NULL;
    }
    conn->ssl.use = FALSE; /* get back to ordinary socket usage */
  }
}


/*
 * This sets up a session cache to the specified size.
 */
CURLcode Curl_SSL_InitSessions(struct SessionHandle *data, long amount)
{
  struct curl_ssl_session *session;

  if(data->state.session)
    /* this is just a precaution to prevent multiple inits */
    return CURLE_OK;

  session = (struct curl_ssl_session *)
    malloc(amount * sizeof(struct curl_ssl_session));
  if(!session)
    return CURLE_OUT_OF_MEMORY;

  /* "blank out" the newly allocated memory */
  memset(session, 0, amount * sizeof(struct curl_ssl_session));

  /* store the info in the SSL section */
  data->set.ssl.numsessions = amount;
  data->state.session = session;
  data->state.sessionage = 1; /* this is brand new */

  return CURLE_OK;
}

/*
 * Check if there's a session ID for the given connection in the cache,
 * and if there's one suitable, it is returned.
 */
static int Get_SSL_Session(struct connectdata *conn,
                           SSL_SESSION **ssl_sessionid)
{
  struct curl_ssl_session *check;
  struct SessionHandle *data = conn->data;
  long i;

  for(i=0; i< data->set.ssl.numsessions; i++) {
    check = &data->state.session[i];
    if(!check->sessionid)
      /* not session ID means blank entry */
      continue;
    if(strequal(conn->name, check->name) &&
       (conn->remote_port == check->remote_port) ) {
      /* yes, we have a session ID! */
      data->state.sessionage++;            /* increase general age */
      check->age = data->state.sessionage; /* set this as used in this age */
      *ssl_sessionid = check->sessionid;
      return FALSE;
    }
  }
  *ssl_sessionid = (SSL_SESSION *)NULL;
  return TRUE;
}

/*
 * Kill a single session ID entry in the cache.
 */
static int Kill_Single_Session(struct curl_ssl_session *session)
{
  if(session->sessionid) {
    /* defensive check */

    /* free the ID */
    SSL_SESSION_free(session->sessionid);
    session->sessionid=NULL;
    session->age = 0; /* fresh */
    free(session->name);
    session->name = NULL; /* no name */

    return 0; /* ok */
  }
  else
    return 1;
}

/*
 * This function is called when the 'data' struct is going away. Close
 * down everything and free all resources!
 */
int Curl_SSL_Close_All(struct SessionHandle *data)
{
  int i;

  if(data->state.session) {    
    for(i=0; i< data->set.ssl.numsessions; i++)
      /* the single-killer function handles empty table slots */
      Kill_Single_Session(&data->state.session[i]);
    
    /* free the cache data */
    free(data->state.session);
  }
  return 0;
}

/*
 * Extract the session id and store it in the session cache.
 */
static int Store_SSL_Session(struct connectdata *conn)
{
  SSL_SESSION *ssl_sessionid;
  struct curl_ssl_session *store;
  int i;
  struct SessionHandle *data=conn->data; /* the mother of all structs */
  int oldest_age=data->state.session[0].age; /* zero if unused */

  /* ask OpenSSL, say please */
  ssl_sessionid = SSL_get1_session(conn->ssl.handle);

  /* SSL_get1_session() will increment the reference
     count and the session will stay in memory until explicitly freed with
     SSL_SESSION_free(3), regardless of its state. */

  /* Now we should add the session ID and the host name to the cache, (remove
     the oldest if necessary) */

  /* find an empty slot for us, or find the oldest */
  for(i=0; (i<data->set.ssl.numsessions) && data->state.session[i].sessionid; i++) {
    if(data->state.session[i].age < oldest_age) {
      oldest_age = data->state.session[i].age;
      store = &data->state.session[i];
    }
  }
  if(i == data->set.ssl.numsessions)
    /* cache is full, we must "kill" the oldest entry! */
    Kill_Single_Session(store);
  else
    store = &data->state.session[i]; /* use this slot */
  
  /* now init the session struct wisely */
  store->sessionid = ssl_sessionid;
  store->age = data->state.sessionage;      /* set current age */
  store->name = strdup(conn->name);       /* clone host name */
  store->remote_port = conn->remote_port; /* port number */

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

  if (i < 10)
    return 1;
  if (asn1_string[i-1] == 'Z')
    gmt=TRUE;
  for (i=0; i<10; i++)
    if ((asn1_string[i] > '9') || (asn1_string[i] < '0'))
      return 2;

  year= (asn1_string[0]-'0')*10+(asn1_string[1]-'0');
  if (year < 50)
    year+=100;

  month= (asn1_string[2]-'0')*10+(asn1_string[3]-'0');
  if ((month > 12) || (month < 1))
    return 3;

  day= (asn1_string[4]-'0')*10+(asn1_string[5]-'0');
  hour= (asn1_string[6]-'0')*10+(asn1_string[7]-'0');
  minute=  (asn1_string[8]-'0')*10+(asn1_string[9]-'0');

  if ( (asn1_string[10] >= '0') && (asn1_string[10] <= '9') &&
       (asn1_string[11] >= '0') && (asn1_string[11] <= '9'))
    second= (asn1_string[10]-'0')*10+(asn1_string[11]-'0');
  
  infof(data,
        "%s%04d-%02d-%02d %02d:%02d:%02d %s\n",
        prefix, year+1900, month, day, hour, minute, second, (gmt?"GMT":""));

  return 0;
}

#endif  

/* ====================================================== */
CURLcode
Curl_SSLConnect(struct connectdata *conn)
{
  CURLcode retcode = CURLE_OK;

#ifdef USE_SSLEAY
  struct SessionHandle *data = conn->data;
  int err;
  char * str;
  SSL_METHOD *req_method;
  SSL_SESSION *ssl_sessionid=NULL;
  ASN1_TIME *certdate;

  /* mark this is being ssl enabled from here on out. */
  conn->ssl.use = TRUE;

  /* Make funny stuff to get random input */
  random_the_seed(conn);
    
  switch(data->set.ssl.version) {
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
    return CURLE_OUT_OF_MEMORY;
  }
    
  if(data->set.cert) {
    if (!cert_stuff(conn, data->set.cert, data->set.cert)) {
      /* failf() is already done in cert_stuff() */
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  if(data->set.ssl.cipher_list) {
    if (!SSL_CTX_set_cipher_list(conn->ssl.ctx,
                                 data->set.ssl.cipher_list)) {
      failf(data, "failed setting cipher list\n");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  if(data->set.ssl.verifypeer){
    SSL_CTX_set_verify(conn->ssl.ctx,
                       SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT|
                       SSL_VERIFY_CLIENT_ONCE,
                       cert_verify_callback);
    if (!SSL_CTX_load_verify_locations(conn->ssl.ctx,
                                       data->set.ssl.CAfile,
                                       data->set.ssl.CApath)) {
      failf(data,"error setting cerficate verify locations\n");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
  else
    SSL_CTX_set_verify(conn->ssl.ctx, SSL_VERIFY_NONE, cert_verify_callback);


  /* Lets make an SSL structure */
  conn->ssl.handle = SSL_new (conn->ssl.ctx);
  SSL_set_connect_state (conn->ssl.handle);

  conn->ssl.server_cert = 0x0;

  if(!conn->bits.reuse) {
    /* We're not re-using a connection, check if there's a cached ID we
       can/should use here! */
    if(!Get_SSL_Session(conn, &ssl_sessionid)) {
      /* we got a session id, use it! */
      SSL_set_session(conn->ssl.handle, ssl_sessionid);
      /* Informational message */
      infof (data, "SSL re-using session ID\n");
    }
  }

  /* pass the raw socket into the SSL layers */
  SSL_set_fd (conn->ssl.handle, conn->firstsocket);
  err = SSL_connect (conn->ssl.handle);

  /* 1  is fine
     0  is "not successful but was shut down controlled"
     <0 is "handshake was not successful, because a fatal error occurred" */
  if (err <= 0) {
    err = ERR_get_error(); 
    failf(data, "SSL: %s", ERR_error_string(err, NULL));
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* Informational message */
  infof (data, "SSL connection using %s\n",
         SSL_get_cipher(conn->ssl.handle));

  if(!ssl_sessionid) {
    /* Since this is not a cached session ID, then we want to stach this one
       in the cache! */
    Store_SSL_Session(conn);
  }

  
  /* Get server's certificate (note: beware of dynamic allocation) - opt */
  /* major serious hack alert -- we should check certificates
   * to authenticate the server; otherwise we risk man-in-the-middle
   * attack
   */

  conn->ssl.server_cert = SSL_get_peer_certificate (conn->ssl.handle);
  if(!conn->ssl.server_cert) {
    failf(data, "SSL: couldn't get peer certificate!");
    return CURLE_SSL_PEER_CERTIFICATE;
  }
  infof (data, "Server certificate:\n");
  
  str = X509_NAME_oneline (X509_get_subject_name (conn->ssl.server_cert),
                           NULL, 0);
  if(!str) {
    failf(data, "SSL: couldn't get X509-subject!");
    X509_free(conn->ssl.server_cert);
    return CURLE_SSL_CONNECT_ERROR;
  }
  infof(data, "\t subject: %s\n", str);
  CRYPTO_free(str);

  certdate = X509_get_notBefore(conn->ssl.server_cert);
  Curl_ASN1_UTCTIME_output(conn, "\t start date: ", certdate);

  certdate = X509_get_notAfter(conn->ssl.server_cert);
  Curl_ASN1_UTCTIME_output(conn, "\t expire date: ", certdate);

  if (data->set.ssl.verifyhost) {
    char peer_CN[257];
    if (X509_NAME_get_text_by_NID(X509_get_subject_name(conn->ssl.server_cert),
                                  NID_commonName,
                                  peer_CN,
                                  sizeof(peer_CN)) < 0) {
      failf(data, "SSL: unable to obtain common name from peer certificate");
      X509_free(conn->ssl.server_cert);
      return CURLE_SSL_PEER_CERTIFICATE;
    }

    if (!strequal(peer_CN, conn->hostname)) {
      if (data->set.ssl.verifyhost > 1) {
        failf(data, "SSL: certificate subject name '%s' does not match "
              "target host name '%s'",
              peer_CN, conn->hostname);
        X509_free(conn->ssl.server_cert);
        return CURLE_SSL_PEER_CERTIFICATE;
      }
      else
        infof(data,
              "\t common name: %s (does not match '%s')\n",
              peer_CN, conn->hostname);
    }
    else
      infof(data, "\t common name: %s (matched)\n", peer_CN);
  }

  str = X509_NAME_oneline (X509_get_issuer_name  (conn->ssl.server_cert),
                           NULL, 0);
  if(!str) {
    failf(data, "SSL: couldn't get X509-issuer name!");
    X509_free(conn->ssl.server_cert);
    return CURLE_SSL_CONNECT_ERROR;
  }
  infof(data, "\t issuer: %s\n", str);
  CRYPTO_free(str);

  /* We could do all sorts of certificate verification stuff here before
     deallocating the certificate. */

  if(data->set.ssl.verifypeer) {
    data->set.ssl.certverifyresult=SSL_get_verify_result(conn->ssl.handle);
    if (data->set.ssl.certverifyresult != X509_V_OK) {
      failf(data, "SSL certificate verify result: %d\n",
            data->set.ssl.certverifyresult);
      retcode = CURLE_SSL_PEER_CERTIFICATE;
    }
  }
  else
    data->set.ssl.certverifyresult=0;

  X509_free(conn->ssl.server_cert);
#else /* USE_SSLEAY */
  /* this is for "-ansi -Wall -pedantic" to stop complaining!   (rabe) */
  (void) conn;
#endif
  return retcode;
}

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
