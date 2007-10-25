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
#include <secmod.h>
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

#define SSL_DIR "/etc/pki/nssdb"

/* enough to fit the string "PEM Token #[0|1]" */
#define SLOTSIZE 13

PRFileDesc *PR_ImportTCPSocket(PRInt32 osfd);

int initialized = 0;

#define HANDSHAKE_TIMEOUT 30

typedef struct {
  PRInt32 retryCount;
  struct SessionHandle *data;
} pphrase_arg_t;

typedef struct {
  const char *name;
  int num;
  PRInt32 version; /* protocol version valid for this cipher */
} cipher_s;

#ifdef NSS_ENABLE_ECC
#define ciphernum 48
#else
#define ciphernum 23
#endif

#define PK11_SETATTRS(x,id,v,l) (x)->type = (id); \
                     (x)->pValue=(v); (x)->ulValueLen = (l)

#define CERT_NewTempCertificate __CERT_NewTempCertificate

enum sslversion { SSL2 = 1, SSL3 = 2, TLS = 4 };

static const cipher_s cipherlist[ciphernum] = {
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

#ifdef HAVE_PK11_CREATEGENERICOBJECT
static const char* pem_library = "libnsspem.so";
#endif
SECMODModule* mod = NULL;

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
      failf(data, "Unknown cipher in list: %s", cipher);
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

/*
 * Determine whether the nickname passed in is a filename that needs to
 * be loaded as a PEM or a regular NSS nickname.
 *
 * returns 1 for a file
 * returns 0 for not a file (NSS nickname)
 */
static int is_file(const char *filename)
{
  struct stat st;

  if(filename == NULL)
    return 0;

  if(stat(filename, &st) == 0)
    if(S_ISREG(st.st_mode))
      return 1;

  return 0;
}

static int
nss_load_cert(const char *filename, PRBool cacert)
{
#ifdef HAVE_PK11_CREATEGENERICOBJECT
  CK_SLOT_ID slotID;
  PK11SlotInfo * slot = NULL;
  PK11GenericObject *rv;
  CK_ATTRIBUTE *attrs;
  CK_ATTRIBUTE theTemplate[20];
  CK_BBOOL cktrue = CK_TRUE;
  CK_BBOOL ckfalse = CK_FALSE;
  CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;
  char *slotname = NULL;
#endif
  CERTCertificate *cert;
  char *nickname = NULL;
  char *n = NULL;

  /* If there is no slash in the filename it is assumed to be a regular
   * NSS nickname.
   */
  if(is_file(filename)) {
    n = strrchr(filename, '/');
    if(n)
      n++;
    if(!mod)
      return 1;
  }
  else {
    /* A nickname from the NSS internal database */
    if (cacert)
      return 0; /* You can't specify an NSS CA nickname this way */
    nickname = strdup(filename);
    goto done;
  }

#ifdef HAVE_PK11_CREATEGENERICOBJECT
  attrs = theTemplate;

  /* All CA and trust objects go into slot 0. Other slots are used
   * for storing certificates. With each new user certificate we increment
   * the slot count. We only support 1 user certificate right now.
   */
  if (cacert)
    slotID = 0;
  else
    slotID = 1;

  slotname = (char *)malloc(SLOTSIZE);
  nickname = (char *)malloc(PATH_MAX);
  snprintf(slotname, SLOTSIZE, "PEM Token #%ld", slotID);
  snprintf(nickname, PATH_MAX, "PEM Token #%ld:%s", slotID, n);

  slot = PK11_FindSlotByName(slotname);

  if (!slot) {
    free(slotname);
    free(nickname);
    return 0;
  }

  PK11_SETATTRS(attrs, CKA_CLASS, &objClass, sizeof(objClass) ); attrs++;
  PK11_SETATTRS(attrs, CKA_TOKEN, &cktrue, sizeof(CK_BBOOL) ); attrs++;
  PK11_SETATTRS(attrs, CKA_LABEL, (unsigned char *)filename,
                strlen(filename)+1); attrs++;
  if (cacert) {
    PK11_SETATTRS(attrs, CKA_TRUST, &cktrue, sizeof(CK_BBOOL) ); attrs++;
  }
  else {
    PK11_SETATTRS(attrs, CKA_TRUST, &ckfalse, sizeof(CK_BBOOL) ); attrs++;
  }

  /* This load the certificate in our PEM module into the appropriate
   * slot.
   */
  rv = PK11_CreateGenericObject(slot, theTemplate, 4, PR_FALSE /* isPerm */);

  PK11_FreeSlot(slot);

  free(slotname);
  if(rv == NULL) {
    free(nickname);
    return 0;
  }
#else
  /* We don't have PK11_CreateGenericObject but a file-based cert was passed
   * in. We need to fail.
   */
  return 0;
#endif

done:
  /* Double-check that the certificate or nickname requested exists in
   * either the token or the NSS certificate database.
   */
  if (!cacert) {
    cert = PK11_FindCertFromNickname((char *)nickname, NULL);

    /* An invalid nickname was passed in */
    if (cert == NULL) {
      free(nickname);
      PR_SetError(SEC_ERROR_UNKNOWN_CERT, 0);
      return 0;
    }

    CERT_DestroyCertificate(cert);
  }

  free(nickname);

  return 1;
}

static int nss_load_key(struct connectdata *conn, char *key_file)
{
#ifdef HAVE_PK11_CREATEGENERICOBJECT
  PK11SlotInfo * slot = NULL;
  PK11GenericObject *rv;
  CK_ATTRIBUTE *attrs;
  CK_ATTRIBUTE theTemplate[20];
  CK_BBOOL cktrue = CK_TRUE;
  CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
  CK_SLOT_ID slotID;
  char *slotname = NULL;
  pphrase_arg_t *parg = NULL;

  attrs = theTemplate;

  /* FIXME: grok the various file types */

  slotID = 1; /* hardcoded for now */

  slotname = (char *)malloc(SLOTSIZE);
  snprintf(slotname, SLOTSIZE, "PEM Token #%ld", slotID);

  slot = PK11_FindSlotByName(slotname);
  free(slotname);

  if(!slot)
    return 0;

  PK11_SETATTRS(attrs, CKA_CLASS, &objClass, sizeof(objClass) ); attrs++;
  PK11_SETATTRS(attrs, CKA_TOKEN, &cktrue, sizeof(CK_BBOOL) ); attrs++;
  PK11_SETATTRS(attrs, CKA_LABEL, (unsigned char *)key_file,
                strlen(key_file)+1); attrs++;

  /* When adding an encrypted key the PKCS#11 will be set as removed */
  rv = PK11_CreateGenericObject(slot, theTemplate, 3, PR_FALSE /* isPerm */);
  if(rv == NULL) {
    PR_SetError(SEC_ERROR_BAD_KEY, 0);
    return 0;
  }

  /* This will force the token to be seen as re-inserted */
  SECMOD_WaitForAnyTokenEvent(mod, 0, 0);
  PK11_IsPresent(slot);

  parg = (pphrase_arg_t *) malloc(sizeof(*parg));
  parg->retryCount = 0;
  parg->data = conn->data;
  /* parg is initialized in nss_Init_Tokens() */
  if(PK11_Authenticate(slot, PR_TRUE, parg) != SECSuccess) {
    free(parg);
    return 0;
  }
  free(parg);

  return 1;
#else
  /* If we don't have PK11_CreateGenericObject then we can't load a file-based
   * key.
   */
  (void)conn; /* unused */
  (void)key_file; /* unused */
  return 0;
#endif
}

static int display_error(struct connectdata *conn, PRInt32 err,
                         const char *filename)
{
  switch(err) {
  case SEC_ERROR_BAD_PASSWORD:
    failf(conn->data, "Unable to load client key: Incorrect password\n");
    return 1;
  case SEC_ERROR_UNKNOWN_CERT:
    failf(conn->data, "Unable to load certificate %s\n", filename);
    return 1;
  default:
    break;
  }
  return 0; /* The caller will print a generic error */
}

static int cert_stuff(struct connectdata *conn, char *cert_file, char *key_file)
{
  struct SessionHandle *data = conn->data;
  int rv = 0;

  if(cert_file) {
    rv = nss_load_cert(cert_file, PR_FALSE);
    if(!rv) {
      if(!display_error(conn, PR_GetError(), cert_file))
        failf(data, "Unable to load client cert %d.", PR_GetError());
      return 0;
    }
  }
  if(key_file || (is_file(cert_file))) {
    if(key_file)
      rv = nss_load_key(conn, key_file);
    else
      /* In case the cert file also has the key */
      rv = nss_load_key(conn, cert_file);
    if(!rv) {
      if(!display_error(conn, PR_GetError(), key_file))
        failf(data, "Unable to load client key %d.", PR_GetError());

      return 0;
    }
  }
  return 1;
}

static char * nss_get_password(PK11SlotInfo * slot, PRBool retry, void *arg)
{
  pphrase_arg_t *parg;
  parg = (pphrase_arg_t *) arg;

  (void)slot; /* unused */
  if(retry > 2)
    return NULL;
  if(parg->data->set.str[STRING_KEY_PASSWD])
    return (char *)PORT_Strdup((char *)parg->data->set.str[STRING_KEY_PASSWD]);
  else
    return NULL;
}

/* No longer ask for the password, parg has been freed */
static char * nss_no_password(PK11SlotInfo *slot, PRBool retry, void *arg)
{
  (void)slot; /* unused */
  (void)retry; /* unused */
  (void)arg; /* unused */
  return NULL;
}

static SECStatus nss_Init_Tokens(struct connectdata * conn)
{
  PK11SlotList *slotList;
  PK11SlotListElement *listEntry;
  SECStatus ret, status = SECSuccess;
  pphrase_arg_t *parg = NULL;

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
      if (PR_GetError() == SEC_ERROR_BAD_PASSWORD)
        infof(conn->data, "The password for token '%s' is incorrect\n",
              PK11_GetTokenName(slot));
      status = SECFailure;
      break;
    }
    parg->retryCount = 0; /* reset counter to 0 for the next token */
    PK11_FreeSlot(slot);
  }

  free(parg);

  return status;
}

static SECStatus BadCertHandler(void *arg, PRFileDesc *sock)
{
  SECStatus success = SECSuccess;
  struct connectdata *conn = (struct connectdata *)arg;
  PRErrorCode err = PR_GetError();
  CERTCertificate *cert = NULL;
  char *subject, *issuer;

  if (conn->data->set.ssl.certverifyresult!=0)
    return success;

  conn->data->set.ssl.certverifyresult=err;
  cert = SSL_PeerCertificate(sock);
  subject = CERT_NameToAscii(&cert->subject);
  issuer = CERT_NameToAscii(&cert->issuer);
  CERT_DestroyCertificate(cert);

  switch(err) {
  case SEC_ERROR_CA_CERT_INVALID:
    infof(conn->data, "Issuer certificate is invalid: '%s'\n", issuer);
    if (conn->data->set.ssl.verifypeer)
      success = SECFailure;
    break;
  case SEC_ERROR_UNTRUSTED_ISSUER:
    if (conn->data->set.ssl.verifypeer)
      success = SECFailure;
    infof(conn->data, "Certificate is signed by an untrusted issuer: '%s'\n",
          issuer);
    break;
  case SSL_ERROR_BAD_CERT_DOMAIN:
    if (conn->data->set.ssl.verifypeer)
      success = SECFailure;
    infof(conn->data, "common name: %s (does not match '%s')\n",
          subject, conn->host.dispname);
    break;
  case SEC_ERROR_EXPIRED_CERTIFICATE:
    if (conn->data->set.ssl.verifypeer)
      success = SECFailure;
    infof(conn->data, "Remote Certificate has expired.\n");
    break;
  default:
    if (conn->data->set.ssl.verifypeer)
      success = SECFailure;
    infof(conn->data, "Bad certificate received. Subject = '%s', "
          "Issuer = '%s'\n", subject, issuer);
    break;
  }
  if (success == SECSuccess)
    infof(conn->data, "SSL certificate verify ok.\n");
  PR_Free(subject);
  PR_Free(issuer);

  return success;
}

/**
 * Inform the application that the handshake is complete.
 */
static SECStatus HandshakeCallback(PRFileDesc *sock, void *arg)
{
  (void)sock;
  (void)arg;
  return SECSuccess;
}

static void display_conn_info(struct connectdata *conn, PRFileDesc *sock)
{
  SSLChannelInfo channel;
  SSLCipherSuiteInfo suite;
  CERTCertificate *cert;
  char *subject, *issuer, *common_name;
  PRExplodedTime printableTime;
  char timeString[256];
  PRTime notBefore, notAfter;

  if (SSL_GetChannelInfo(sock, &channel, sizeof channel) ==
    SECSuccess && channel.length == sizeof channel &&
    channel.cipherSuite) {
    if (SSL_GetCipherSuiteInfo(channel.cipherSuite,
      &suite, sizeof suite) == SECSuccess) {
      infof(conn->data, "SSL connection using %s\n", suite.cipherSuiteName);
    }
  }

  infof(conn->data, "Server certificate:\n");

  cert = SSL_PeerCertificate(sock);
  subject = CERT_NameToAscii(&cert->subject);
  issuer = CERT_NameToAscii(&cert->issuer);
  common_name = CERT_GetCommonName(&cert->subject);
  infof(conn->data, "\tsubject: %s\n", subject);

  CERT_GetCertTimes(cert, &notBefore, &notAfter);
  PR_ExplodeTime(notBefore, PR_GMTParameters, &printableTime);
  PR_FormatTime(timeString, 256, "%b %d %H:%M:%S %Y GMT", &printableTime);
  infof(conn->data, "\tstart date: %s\n", timeString);
  PR_ExplodeTime(notAfter, PR_GMTParameters, &printableTime);
  PR_FormatTime(timeString, 256, "%b %d %H:%M:%S %Y GMT", &printableTime);
  infof(conn->data, "\texpire date: %s\n", timeString);
  infof(conn->data, "\tcommon name: %s\n", common_name);
  infof(conn->data, "\tissuer: %s\n", issuer);

  PR_Free(subject);
  PR_Free(issuer);
  PR_Free(common_name);

  CERT_DestroyCertificate(cert);

  return;
}

/**
 *
 * Callback to pick the SSL client certificate.
 */
static SECStatus SelectClientCert(void *arg, PRFileDesc *sock,
                                  struct CERTDistNamesStr *caNames,
                                  struct CERTCertificateStr **pRetCert,
                                  struct SECKEYPrivateKeyStr **pRetKey)
{
  CERTCertificate *cert;
  SECKEYPrivateKey *privKey;
  char *nickname = (char *)arg;
  void *proto_win = NULL;
  SECStatus secStatus = SECFailure;
  PK11SlotInfo *slot;
  (void)caNames;

  proto_win = SSL_RevealPinArg(sock);

  if (!nickname)
    return secStatus;

  cert = PK11_FindCertFromNickname(nickname, proto_win);
  if(cert) {

    if(!strncmp(nickname, "PEM Token", 9)) {
      CK_SLOT_ID slotID = 1; /* hardcoded for now */
      char * slotname = (char *)malloc(SLOTSIZE);
      snprintf(slotname, SLOTSIZE, "PEM Token #%ld", slotID);
      slot = PK11_FindSlotByName(slotname);
      privKey = PK11_FindPrivateKeyFromCert(slot, cert, NULL);
      PK11_FreeSlot(slot);
      free(slotname);
      if(privKey) {
        secStatus = SECSuccess;
      }
    }
    else {
      privKey = PK11_FindKeyByAnyCert(cert, proto_win);
      if(privKey)
        secStatus = SECSuccess;
    }
  }

  if(secStatus == SECSuccess) {
    *pRetCert = cert;
    *pRetKey = privKey;
  }
  else {
    if (cert)
      CERT_DestroyCertificate(cert);
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
void Curl_nss_close(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  if(connssl->handle) {
    PR_Close(connssl->handle);
    if(connssl->client_nickname != NULL) {
      free(connssl->client_nickname);
      connssl->client_nickname = NULL;
    }
    connssl->handle = NULL;
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
#ifdef HAVE_PK11_CREATEGENERICOBJECT
  char *configstring = NULL;
#endif
  char *certDir = NULL;
  int curlerr;

  curlerr = CURLE_SSL_CONNECT_ERROR;

  /* FIXME. NSS doesn't support multiple databases open at the same time. */
  if(!initialized) {
    initialized = 1;

    certDir = getenv("SSL_DIR"); /* Look in $SSL_DIR */

    if (!certDir) {
      struct stat st;

      if (stat(SSL_DIR, &st) == 0)
        if (S_ISDIR(st.st_mode)) {
          certDir = (char *)SSL_DIR;
        }
    }

    if(!certDir) {
      rv = NSS_NoDB_Init(NULL);
    }
    else {
      rv = NSS_Initialize(certDir, NULL, NULL, "secmod.db",
                          NSS_INIT_READONLY);
    }
    if(rv != SECSuccess) {
      infof(conn->data, "Unable to initialize NSS database\n");
      curlerr = CURLE_SSL_CACERT_BADFILE;
      goto error;
    }

    NSS_SetDomesticPolicy();

#ifdef HAVE_PK11_CREATEGENERICOBJECT
    configstring = (char *)malloc(PATH_MAX);

    PR_snprintf(configstring, PATH_MAX, "library=%s name=PEM", pem_library);

    mod = SECMOD_LoadUserModule(configstring, NULL, PR_FALSE);
    free(configstring);
    if (!mod || !mod->loaded) {
      if (mod) {
        SECMOD_DestroyModule(mod);
        mod = NULL;
      }
      infof(data, "WARNING: failed to load NSS PEM library %s. Using OpenSSL "
            "PEM certificates will not work.\n", pem_library);
    }
#endif
  }

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
    if(set_ciphers(data, model, data->set.ssl.cipher_list) != SECSuccess) {
      curlerr = CURLE_SSL_CIPHER;
      goto error;
    }
  }

  data->set.ssl.certverifyresult=0; /* not checked yet */
  if(SSL_BadCertHook(model, (SSLBadCertHandler) BadCertHandler, conn)
     != SECSuccess) {
    goto error;
  }
  if(SSL_HandshakeCallback(model, (SSLHandshakeCallback) HandshakeCallback,
                           NULL) != SECSuccess)
    goto error;

  if(!data->set.ssl.verifypeer)
    /* skip the verifying of the peer */
    ;
  else if (data->set.ssl.CAfile) {
    int rc = nss_load_cert(data->set.ssl.CAfile, PR_TRUE);
    if (!rc) {
      curlerr = CURLE_SSL_CACERT_BADFILE;
      goto error;
    }
  }
  else if (data->set.ssl.CApath) {
    struct stat st;
    PRDir      *dir;
    PRDirEntry *entry;

    if (stat(data->set.ssl.CApath, &st) == -1) {
      curlerr = CURLE_SSL_CACERT_BADFILE;
      goto error;
    }

    if (S_ISDIR(st.st_mode)) {
      int rc;

      dir = PR_OpenDir(data->set.ssl.CApath);
      do {
        entry = PR_ReadDir(dir, PR_SKIP_BOTH | PR_SKIP_HIDDEN);

        if (entry) {
          char fullpath[PATH_MAX];

          snprintf(fullpath, sizeof(fullpath), "%s/%s", data->set.ssl.CApath,
                   entry->name);
          rc = nss_load_cert(fullpath, PR_TRUE);
          /* FIXME: check this return value! */
        }
      /* This is purposefully tolerant of errors so non-PEM files
       * can be in the same directory */
      } while (entry != NULL);
      PR_CloseDir(dir);
    }
  }
  infof(data,
        "  CAfile: %s\n"
        "  CApath: %s\n",
        data->set.ssl.CAfile ? data->set.ssl.CAfile : "none",
        data->set.ssl.CApath ? data->set.ssl.CApath : "none");

  if(data->set.str[STRING_CERT]) {
    char *n;
    char *nickname;

    nickname = (char *)malloc(PATH_MAX);
    if(is_file(data->set.str[STRING_CERT])) {
      n = strrchr(data->set.str[STRING_CERT], '/');
      if (n) {
        n++; /* skip last slash */
        snprintf(nickname, PATH_MAX, "PEM Token #%ld:%s", 1, n);
      }
    }
    else {
      strncpy(nickname, data->set.str[STRING_CERT], PATH_MAX);
    }
    if(nss_Init_Tokens(conn) != SECSuccess) {
      free(nickname);
      goto error;
    }
    if (!cert_stuff(conn, data->set.str[STRING_CERT],
                    data->set.str[STRING_KEY])) {
      /* failf() is already done in cert_stuff() */
      free(nickname);
      return CURLE_SSL_CERTPROBLEM;
    }

    connssl->client_nickname = strdup(nickname);
    if(SSL_GetClientAuthDataHook(model,
                                 (SSLGetClientAuthData) SelectClientCert,
                                 (void *)connssl->client_nickname) !=
       SECSuccess) {
      curlerr = CURLE_SSL_CERTPROBLEM;
      goto error;
    }

    free(nickname);

    PK11_SetPasswordFunc(nss_no_password);
  }
  else
    connssl->client_nickname = NULL;

  /* Import our model socket  onto the existing file descriptor */
  connssl->handle = PR_ImportTCPSocket(sockfd);
  connssl->handle = SSL_ImportFD(model, connssl->handle);
  if(!connssl->handle)
    goto error;
  PR_Close(model); /* We don't need this any more */

  /* Force handshake on next I/O */
  SSL_ResetHandshake(connssl->handle, /* asServer */ PR_FALSE);

  SSL_SetURL(connssl->handle, conn->host.name);

  /* Force the handshake now */
  if (SSL_ForceHandshakeWithTimeout(connssl->handle,
                                    PR_SecondsToInterval(HANDSHAKE_TIMEOUT))
      != SECSuccess) {
    if (conn->data->set.ssl.certverifyresult!=0)
      curlerr = CURLE_SSL_CACERT;
    goto error;
  }

  display_conn_info(conn, connssl->handle);

  return CURLE_OK;

error:
  err = PR_GetError();
  infof(data, "NSS error %d\n", err);
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
      return CURLE_OPERATION_TIMEDOUT;
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
      return CURLE_OPERATION_TIMEDOUT;
    }
    failf(conn->data, "SSL read: errno %d", err);
    return -1;
  }
  return nread;
}

size_t Curl_nss_version(char *buffer, size_t size)
{
  return snprintf(buffer, size, "NSS/%s", NSS_VERSION);
}
#endif /* USE_NSS */
