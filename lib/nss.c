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
 * Source file for all NSS-specific code for the TLS/SSL layer. No code
 * but sslgen.c should ever call or use these functions.
 */

#include "setup.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "urldata.h"
#include "sendf.h"
#include "formdata.h" /* for the boundary function */
#include "url.h" /* for the ssl config check function */
#include "connect.h"
#include "strequal.h"
#include "select.h"
#include "sslgen.h"

#define _MPRINTF_REPLACE /* use the internal *printf() functions */
#include <curl/mprintf.h>

#ifdef USE_NSS

#include "nssg.h"
#include <nspr.h>
#include <nss.h>
#include <ssl.h>
#include <sslerr.h>
#include <secerr.h>
#include <sslproto.h>
#include <prtypes.h>
#include <pk11pub.h>

#include "memory.h"
#include "easyif.h" /* for Curl_convert_from_utf8 prototype */

/* The last #include file should be: */
#include "memdebug.h"

#ifndef min
#define min(a, b)   ((a) < (b) ? (a) : (b))
#endif

PRFileDesc *PR_ImportTCPSocket(PRInt32 osfd);

static int initialized = 0;
static int noverify = 0;

typedef struct {
  PRInt32 retryCount;
  struct SessionHandle *data;
} pphrase_arg_t;

typedef struct {
  const char *name;
  int num;
  PRInt32 version; /* protocol version valid for this cipher */
} cipher_s;

/* the table itself is defined in nss_engine_init.c */
#ifdef NSS_ENABLE_ECC
#define ciphernum 48
#else
#define ciphernum 23
#endif

enum sslversion { SSL2 = 1, SSL3 = 2, TLS = 4 };

cipher_s cipherlist[ciphernum] = {
  /* SSL2 cipher suites */
  {"rc4", SSL_EN_RC4_128_WITH_MD5, SSL2},
  {"rc4export", SSL_EN_RC4_128_EXPORT40_WITH_MD5, SSL2},
  {"rc2", SSL_EN_RC2_128_CBC_WITH_MD5, SSL2},
  {"rc2export", SSL_EN_RC2_128_CBC_EXPORT40_WITH_MD5, SSL2},
  {"des", SSL_EN_DES_64_CBC_WITH_MD5, SSL2},
  {"desede3", SSL_EN_DES_192_EDE3_CBC_WITH_MD5, SSL2},
  /* SSL3/TLS cipher suites */
  {"rsa_rc4_128_md5", SSL_RSA_WITH_RC4_128_MD5, SSL3 | TLS},
  {"rsa_rc4_128_sha", SSL_RSA_WITH_RC4_128_SHA, SSL3 | TLS},
  {"rsa_3des_sha", SSL_RSA_WITH_3DES_EDE_CBC_SHA, SSL3 | TLS},
  {"rsa_des_sha", SSL_RSA_WITH_DES_CBC_SHA, SSL3 | TLS},
  {"rsa_rc4_40_md5", SSL_RSA_EXPORT_WITH_RC4_40_MD5, SSL3 | TLS},
  {"rsa_rc2_40_md5", SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5, SSL3 | TLS},
  {"rsa_null_md5", SSL_RSA_WITH_NULL_MD5, SSL3 | TLS},
  {"rsa_null_sha", SSL_RSA_WITH_NULL_SHA, SSL3 | TLS},
  {"fips_3des_sha", SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA, SSL3 | TLS},
  {"fips_des_sha", SSL_RSA_FIPS_WITH_DES_CBC_SHA, SSL3 | TLS},
  {"fortezza", SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA, SSL3 | TLS},
  {"fortezza_rc4_128_sha", SSL_FORTEZZA_DMS_WITH_RC4_128_SHA, SSL3 | TLS},
  {"fortezza_null", SSL_FORTEZZA_DMS_WITH_NULL_SHA, SSL3 | TLS},
  /* TLS 1.0: Exportable 56-bit Cipher Suites. */
  {"rsa_des_56_sha", TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA, SSL3 | TLS},
  {"rsa_rc4_56_sha", TLS_RSA_EXPORT1024_WITH_RC4_56_SHA, SSL3 | TLS},
  /* AES ciphers. */
  {"rsa_aes_128_sha", TLS_RSA_WITH_AES_128_CBC_SHA, SSL3 | TLS},
  {"rsa_aes_256_sha", TLS_RSA_WITH_AES_256_CBC_SHA, SSL3 | TLS},
#ifdef NSS_ENABLE_ECC
  /* ECC ciphers. */
  {"ecdh_ecdsa_null_sha", TLS_ECDH_ECDSA_WITH_NULL_SHA, TLS},
  {"ecdh_ecdsa_rc4_128_sha", TLS_ECDH_ECDSA_WITH_RC4_128_SHA, TLS},
  {"ecdh_ecdsa_3des_sha", TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA, TLS},
  {"ecdh_ecdsa_aes_128_sha", TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, TLS},
  {"ecdh_ecdsa_aes_256_sha", TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, TLS},
  {"ecdhe_ecdsa_null_sha", TLS_ECDHE_ECDSA_WITH_NULL_SHA, TLS},
  {"ecdhe_ecdsa_rc4_128_sha", TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TLS},
  {"ecdhe_ecdsa_3des_sha", TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, TLS},
  {"ecdhe_ecdsa_aes_128_sha", TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS},
  {"ecdhe_ecdsa_aes_256_sha", TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS},
  {"ecdh_rsa_null_sha", TLS_ECDH_RSA_WITH_NULL_SHA, TLS},
  {"ecdh_rsa_128_sha", TLS_ECDH_RSA_WITH_RC4_128_SHA, TLS},
  {"ecdh_rsa_3des_sha", TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, TLS},
  {"ecdh_rsa_aes_128_sha", TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, TLS},
  {"ecdh_rsa_aes_256_sha", TLS_ECDH_RSA_WITH_AES_256_CBC_SHA, TLS},
  {"echde_rsa_null", TLS_ECDHE_RSA_WITH_NULL_SHA, TLS},
  {"ecdhe_rsa_rc4_128_sha", TLS_ECDHE_RSA_WITH_RC4_128_SHA, TLS},
  {"ecdhe_rsa_3des_sha", TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS},
  {"ecdhe_rsa_aes_128_sha", TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS},
  {"ecdhe_rsa_aes_256_sha", TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS},
  {"ecdh_anon_null_sha", TLS_ECDH_anon_WITH_NULL_SHA, TLS},
  {"ecdh_anon_rc4_128sha", TLS_ECDH_anon_WITH_RC4_128_SHA, TLS},
  {"ecdh_anon_3des_sha", TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA, TLS},
  {"ecdh_anon_aes_128_sha", TLS_ECDH_anon_WITH_AES_128_CBC_SHA, TLS},
  {"ecdh_anon_aes_256_sha", TLS_ECDH_anon_WITH_AES_256_CBC_SHA, TLS},
#endif
};

static SECStatus set_ciphers(struct SessionHandle *data, PRFileDesc * model,
                             char *cipher_list)
{
  int i;
  PRBool cipher_state[ciphernum];
  PRBool found;
  char *cipher;
  SECStatus rv;

  /* First disable all ciphers. This uses a different max value in case
   * NSS adds more ciphers later we don't want them available by
   * accident
   */
  for(i=0; i<SSL_NumImplementedCiphers; i++) {
    SSL_CipherPrefSet(model, SSL_ImplementedCiphers[i], SSL_NOT_ALLOWED);
  }

  /* Set every entry in our list to false */
  for(i=0; i<ciphernum; i++) {
    cipher_state[i] = PR_FALSE;
  }

  cipher = cipher_list;

  while(cipher_list && (cipher_list[0])) {
    while((*cipher) && (ISSPACE(*cipher)))
      ++cipher;

    if((cipher_list = strchr(cipher, ','))) {
      *cipher_list++ = '\0';
    }

    found = PR_FALSE;

    for(i=0; i<ciphernum; i++) {
      if(!strcasecmp(cipher, cipherlist[i].name)) {
        cipher_state[i] = PR_TRUE;
        found = PR_TRUE;
        break;
      }
    }

    if(found == PR_FALSE) {
      char buf[1024];
      snprintf(buf, 1024, "Unknown cipher in list: %s", cipher);
      failf(data, buf);
      return SECFailure;
    }

    if(cipher_list) {
      cipher = cipher_list;
    }
  }

  /* Finally actually enable the selected ciphers */
  for(i=0; i<ciphernum; i++) {
    rv = SSL_CipherPrefSet(model, cipherlist[i].num, cipher_state[i]);
    if(rv != SECSuccess) {
      failf(data, "Unknown cipher in cipher list");
      return SECFailure;
    }
  }

  return SECSuccess;
}

static char * nss_get_password(PK11SlotInfo * slot, PRBool retry, void *arg)
{
  pphrase_arg_t *parg = (pphrase_arg_t *) arg;
  (void)slot; /* unused */
  (void)retry; /* unused */
  if(parg->data->set.key_passwd)
    return (char *)PORT_Strdup((char *)parg->data->set.key_passwd);
  else
    return NULL;
}

static SECStatus nss_Init_Tokens(struct connectdata * conn)
{
  PK11SlotList *slotList;
  PK11SlotListElement *listEntry;
  SECStatus ret, status = SECSuccess;
  pphrase_arg_t *parg;

  parg = (pphrase_arg_t *) malloc(sizeof(*parg));
  parg->retryCount = 0;
  parg->data = conn->data;

  PK11_SetPasswordFunc(nss_get_password);

  slotList =
    PK11_GetAllTokens(CKM_INVALID_MECHANISM, PR_FALSE, PR_TRUE, NULL);

  for(listEntry = PK11_GetFirstSafe(slotList);
      listEntry; listEntry = listEntry->next) {
    PK11SlotInfo *slot = listEntry->slot;

    if(PK11_NeedLogin(slot) && PK11_NeedUserInit(slot)) {
      if(slot == PK11_GetInternalKeySlot()) {
        failf(conn->data, "The NSS database has not been initialized.\n");
      }
      else {
        failf(conn->data, "The token %s has not been initialized.",
              PK11_GetTokenName(slot));
      }
      PK11_FreeSlot(slot);
      continue;
    }

    ret = PK11_Authenticate(slot, PR_TRUE, parg);
    if(SECSuccess != ret) {
      status = SECFailure;
      break;
    }
    parg->retryCount = 0; /* reset counter to 0 for the next token */
    PK11_FreeSlot(slot);
  }

  free(parg);
  return status;
}

static SECStatus BadCertHandler(void *arg, PRFileDesc * socket)
{
  SECStatus success = SECSuccess;
  (void)arg;
  (void)socket;

  return success;
}

/**
 * Inform the application that the handshake is complete.
 */
static SECStatus HandshakeCallback(PRFileDesc * socket, void *arg)
{
  (void)socket;
  (void)arg;
  return SECSuccess;
}

/**
 *
 * Callback to pick the SSL client certificate.
 */
static SECStatus SelectClientCert(void *arg, PRFileDesc * socket,
                                  struct CERTDistNamesStr * caNames,
                                  struct CERTCertificateStr ** pRetCert,
                                  struct SECKEYPrivateKeyStr ** pRetKey)
{
  CERTCertificate *cert;
  SECKEYPrivateKey *privKey;
  char *nickname = (char *)arg;
  void *proto_win = NULL;
  SECStatus secStatus = SECFailure;
  (void)caNames;

  proto_win = SSL_RevealPinArg(socket);

  cert = PK11_FindCertFromNickname(nickname, proto_win);
  if(cert) {
    privKey = PK11_FindKeyByAnyCert(cert, proto_win);
    if(privKey) {
      secStatus = SECSuccess;
    }
    else {
      CERT_DestroyCertificate(cert);
    }
  }

  if(secStatus == SECSuccess) {
    *pRetCert = cert;
    *pRetKey = privKey;
  }

  return secStatus;
}

/**
 * Global SSL init
 *
 * @retval 0 error initializing SSL
 * @retval 1 SSL initialized successfully
 */
int Curl_nss_init(void)
{
  if(!initialized)
    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 256);

  /* We will actually initialize NSS later */

  return 1;
}

/* Global cleanup */
void Curl_nss_cleanup(void)
{
  NSS_Shutdown();
  initialized = 0;
}

/*
 * This function uses SSL_peek to determine connection status.
 *
 * Return codes:
 *     1 means the connection is still in place
 *     0 means the connection has been closed
 *    -1 means the connection status is unknown
 */
int
Curl_nss_check_cxn(struct connectdata *conn)
{
  int rc;
  char buf;

  rc =
    PR_Recv(conn->ssl[FIRSTSOCKET].handle, (void *)&buf, 1, PR_MSG_PEEK,
            PR_SecondsToInterval(1));
  if(rc > 0)
    return 1; /* connection still in place */

  if(rc == 0)
    return 0; /* connection has been closed */

  return -1;  /* connection status unknown */
}

/*
 * This function is called when an SSL connection is closed.
 */
void Curl_nss_close(struct connectdata *conn)
{
  int i;

  for(i=0; i<2; i++) {
    struct ssl_connect_data *connssl = &conn->ssl[i];

    if(connssl->handle) {
      PR_Close(connssl->handle);
      connssl->handle = NULL;
    }
    connssl->use = FALSE; /* get back to ordinary socket usage */
  }
}

/*
 * This function is called when the 'data' struct is going away. Close
 * down everything and free all resources!
 */
int Curl_nss_close_all(struct SessionHandle *data)
{
  (void)data;
  return 0;
}

CURLcode Curl_nss_connect(struct connectdata * conn, int sockindex)
{
  PRInt32 err;
  PRFileDesc *model = NULL;
  PRBool ssl2, ssl3, tlsv1;
  struct SessionHandle *data = conn->data;
  curl_socket_t sockfd = conn->sock[sockindex];
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  SECStatus rv;
  int curlerr = CURLE_SSL_CONNECT_ERROR;

  /* FIXME. NSS doesn't support multiple databases open at the same time. */
  if(!initialized) {
    if(!data->set.ssl.CAfile) {
      if(data->set.ssl.verifypeer) {
        failf(data, "No NSS cacert database specified.");
        return CURLE_SSL_CACERT_BADFILE;
      }
      else {
        rv = NSS_NoDB_Init(NULL);
        noverify = 1;
      }
    }
    else {
      rv = NSS_Initialize(data->set.ssl.CAfile, NULL, NULL, "secmod.db",
                          NSS_INIT_READONLY);
    }
    if(rv != SECSuccess) {
      curlerr = CURLE_SSL_CACERT_BADFILE;
      goto error;
    }
  }

  NSS_SetDomesticPolicy();

  model = PR_NewTCPSocket();
  if(!model)
    goto error;
  model = SSL_ImportFD(NULL, model);

  if(SSL_OptionSet(model, SSL_SECURITY, PR_TRUE) != SECSuccess)
    goto error;
  if(SSL_OptionSet(model, SSL_HANDSHAKE_AS_SERVER, PR_FALSE) != SECSuccess)
    goto error;
  if(SSL_OptionSet(model, SSL_HANDSHAKE_AS_CLIENT, PR_TRUE) != SECSuccess)
    goto error;

  ssl2 = ssl3 = tlsv1 = PR_FALSE;

  switch (data->set.ssl.version) {
  default:
  case CURL_SSLVERSION_DEFAULT:
    ssl2 = ssl3 = tlsv1 = PR_TRUE;
    break;
  case CURL_SSLVERSION_TLSv1:
    tlsv1 = PR_TRUE;
    break;
  case CURL_SSLVERSION_SSLv2:
    ssl2 = PR_TRUE;
    break;
  case CURL_SSLVERSION_SSLv3:
    ssl3 = PR_TRUE;
    break;
  }

  if(SSL_OptionSet(model, SSL_ENABLE_SSL2, ssl2) != SECSuccess)
    goto error;
  if(SSL_OptionSet(model, SSL_ENABLE_SSL3, ssl3) != SECSuccess)
    goto error;
  if(SSL_OptionSet(model, SSL_ENABLE_TLS, tlsv1) != SECSuccess)
    goto error;

  if(data->set.ssl.cipher_list) {
    if(set_ciphers(data, model, data->set.ssl.cipher_list) != SECSuccess)
      goto error;
  }

  if(SSL_BadCertHook(model, (SSLBadCertHandler) BadCertHandler, NULL)
     != SECSuccess)
    goto error;
  if(SSL_HandshakeCallback(model, (SSLHandshakeCallback) HandshakeCallback,
                           NULL) != SECSuccess)
    goto error;

  if(data->set.cert) {
    if(SSL_GetClientAuthDataHook(model,
                                 (SSLGetClientAuthData) SelectClientCert,
                                 (void *)data->set.cert) != SECSuccess) {
      curlerr = CURLE_SSL_CERTPROBLEM;
      goto error;
    }
    if(nss_Init_Tokens(conn) != SECSuccess)
      goto error;
  }

  /* Import our model socket  onto the existing file descriptor */
  connssl->handle = PR_ImportTCPSocket(sockfd);
  connssl->handle = SSL_ImportFD(model, connssl->handle);
  if(!connssl->handle)
    goto error;

  /* Force handshake on next I/O */
  SSL_ResetHandshake(connssl->handle, /* asServer */ PR_FALSE);

  SSL_SetURL(connssl->handle, conn->host.name);

  return CURLE_OK;

error:
  err = PR_GetError();
  failf(data, "NSS error %d", err);
  if(model)
    PR_Close(model);
  return curlerr;
}

/* return number of sent (non-SSL) bytes */
int Curl_nss_send(struct connectdata *conn,  /* connection data */
                  int sockindex,             /* socketindex */
                  void *mem,                 /* send this data */
                  size_t len)                /* amount to write */
{
  PRInt32 err;
  struct SessionHandle *data = conn->data;
  PRInt32 timeout;
  int rc;

  if(data->set.timeout)
    timeout = PR_MillisecondsToInterval(data->set.timeout);
  else
    timeout = PR_MillisecondsToInterval(DEFAULT_CONNECT_TIMEOUT);

  rc = PR_Send(conn->ssl[sockindex].handle, mem, (int)len, 0, timeout);

  if(rc < 0) {
    err = PR_GetError();

    if(err == PR_IO_TIMEOUT_ERROR) {
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEOUTED;
    }

    failf(conn->data, "SSL write: error %d\n", err);
    return -1;
  }
  return rc; /* number of bytes */
}

/*
 * If the read would block we return -1 and set 'wouldblock' to TRUE.
 * Otherwise we return the amount of data read. Other errors should return -1
 * and set 'wouldblock' to FALSE.
 */
ssize_t Curl_nss_recv(struct connectdata * conn, /* connection data */
                      int num,                   /* socketindex */
                      char *buf,                 /* store read data here */
                      size_t buffersize,         /* max amount to read */
                      bool * wouldblock)
{
  ssize_t nread;
  struct SessionHandle *data = conn->data;
  PRInt32 timeout;

  if(data->set.timeout)
    timeout = PR_SecondsToInterval(data->set.timeout);
  else
    timeout = PR_MillisecondsToInterval(DEFAULT_CONNECT_TIMEOUT);

  nread = PR_Recv(conn->ssl[num].handle, buf, (int)buffersize, 0, timeout);
  *wouldblock = FALSE;
  if(nread < 0) {
    /* failed SSL read */
    PRInt32 err = PR_GetError();

    if(err == PR_WOULD_BLOCK_ERROR) {
      *wouldblock = TRUE;
      return -1; /* basically EWOULDBLOCK */
    }
    if(err == PR_IO_TIMEOUT_ERROR) {
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEOUTED;
    }
    failf(conn->data, "SSL read: errno %d", err);
    return -1;
  }
  return nread;
}

size_t Curl_nss_version(char *buffer, size_t size)
{
  return snprintf(buffer, size, " NSS/%s", NSS_VERSION);
}
#endif /* USE_NSS */
