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

/*
 * Source file for all NSS-specific code for the TLS/SSL layer. No code
 * but vtls.c should ever call or use these functions.
 */

#include "curl_setup.h"

#ifdef USE_NSS

#include "urldata.h"
#include "sendf.h"
#include "formdata.h" /* for the boundary function */
#include "url.h" /* for the ssl config check function */
#include "connect.h"
#include "strequal.h"
#include "select.h"
#include "vtls.h"
#include "llist.h"

#define _MPRINTF_REPLACE /* use the internal *printf() functions */
#include <curl/mprintf.h>

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
#include <prio.h>
#include <secitem.h>
#include <secport.h>
#include <certdb.h>
#include <base64.h>
#include <cert.h>
#include <prerror.h>

#include "curl_memory.h"
#include "rawstr.h"
#include "warnless.h"
#include "x509asn1.h"

/* The last #include file should be: */
#include "memdebug.h"

#define SSL_DIR "/etc/pki/nssdb"

/* enough to fit the string "PEM Token #[0|1]" */
#define SLOTSIZE 13

PRFileDesc *PR_ImportTCPSocket(PRInt32 osfd);

PRLock * nss_initlock = NULL;
PRLock * nss_crllock = NULL;
NSSInitContext * nss_context = NULL;

volatile int initialized = 0;

typedef struct {
  const char *name;
  int num;
} cipher_s;

#define PK11_SETATTRS(_attr, _idx, _type, _val, _len) do {  \
  CK_ATTRIBUTE *ptr = (_attr) + ((_idx)++);                 \
  ptr->type = (_type);                                      \
  ptr->pValue = (_val);                                     \
  ptr->ulValueLen = (_len);                                 \
} WHILE_FALSE

#define CERT_NewTempCertificate __CERT_NewTempCertificate

#define NUM_OF_CIPHERS sizeof(cipherlist)/sizeof(cipherlist[0])
static const cipher_s cipherlist[] = {
  /* SSL2 cipher suites */
  {"rc4",                        SSL_EN_RC4_128_WITH_MD5},
  {"rc4-md5",                    SSL_EN_RC4_128_WITH_MD5},
  {"rc4export",                  SSL_EN_RC4_128_EXPORT40_WITH_MD5},
  {"rc2",                        SSL_EN_RC2_128_CBC_WITH_MD5},
  {"rc2export",                  SSL_EN_RC2_128_CBC_EXPORT40_WITH_MD5},
  {"des",                        SSL_EN_DES_64_CBC_WITH_MD5},
  {"desede3",                    SSL_EN_DES_192_EDE3_CBC_WITH_MD5},
  /* SSL3/TLS cipher suites */
  {"rsa_rc4_128_md5",            SSL_RSA_WITH_RC4_128_MD5},
  {"rsa_rc4_128_sha",            SSL_RSA_WITH_RC4_128_SHA},
  {"rsa_3des_sha",               SSL_RSA_WITH_3DES_EDE_CBC_SHA},
  {"rsa_des_sha",                SSL_RSA_WITH_DES_CBC_SHA},
  {"rsa_rc4_40_md5",             SSL_RSA_EXPORT_WITH_RC4_40_MD5},
  {"rsa_rc2_40_md5",             SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5},
  {"rsa_null_md5",               SSL_RSA_WITH_NULL_MD5},
  {"rsa_null_sha",               SSL_RSA_WITH_NULL_SHA},
  {"fips_3des_sha",              SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA},
  {"fips_des_sha",               SSL_RSA_FIPS_WITH_DES_CBC_SHA},
  {"fortezza",                   SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA},
  {"fortezza_rc4_128_sha",       SSL_FORTEZZA_DMS_WITH_RC4_128_SHA},
  {"fortezza_null",              SSL_FORTEZZA_DMS_WITH_NULL_SHA},
  /* TLS 1.0: Exportable 56-bit Cipher Suites. */
  {"rsa_des_56_sha",             TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA},
  {"rsa_rc4_56_sha",             TLS_RSA_EXPORT1024_WITH_RC4_56_SHA},
  /* AES ciphers. */
  {"dhe_dss_aes_128_cbc_sha",    TLS_DHE_DSS_WITH_AES_128_CBC_SHA},
  {"dhe_dss_aes_256_cbc_sha",    TLS_DHE_DSS_WITH_AES_256_CBC_SHA},
  {"dhe_rsa_aes_128_cbc_sha",    TLS_DHE_RSA_WITH_AES_128_CBC_SHA},
  {"dhe_rsa_aes_256_cbc_sha",    TLS_DHE_RSA_WITH_AES_256_CBC_SHA},
  {"rsa_aes_128_sha",            TLS_RSA_WITH_AES_128_CBC_SHA},
  {"rsa_aes_256_sha",            TLS_RSA_WITH_AES_256_CBC_SHA},
  /* ECC ciphers. */
  {"ecdh_ecdsa_null_sha",        TLS_ECDH_ECDSA_WITH_NULL_SHA},
  {"ecdh_ecdsa_rc4_128_sha",     TLS_ECDH_ECDSA_WITH_RC4_128_SHA},
  {"ecdh_ecdsa_3des_sha",        TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA},
  {"ecdh_ecdsa_aes_128_sha",     TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA},
  {"ecdh_ecdsa_aes_256_sha",     TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA},
  {"ecdhe_ecdsa_null_sha",       TLS_ECDHE_ECDSA_WITH_NULL_SHA},
  {"ecdhe_ecdsa_rc4_128_sha",    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA},
  {"ecdhe_ecdsa_3des_sha",       TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA},
  {"ecdhe_ecdsa_aes_128_sha",    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
  {"ecdhe_ecdsa_aes_256_sha",    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
  {"ecdh_rsa_null_sha",          TLS_ECDH_RSA_WITH_NULL_SHA},
  {"ecdh_rsa_128_sha",           TLS_ECDH_RSA_WITH_RC4_128_SHA},
  {"ecdh_rsa_3des_sha",          TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA},
  {"ecdh_rsa_aes_128_sha",       TLS_ECDH_RSA_WITH_AES_128_CBC_SHA},
  {"ecdh_rsa_aes_256_sha",       TLS_ECDH_RSA_WITH_AES_256_CBC_SHA},
  {"echde_rsa_null",             TLS_ECDHE_RSA_WITH_NULL_SHA},
  {"ecdhe_rsa_rc4_128_sha",      TLS_ECDHE_RSA_WITH_RC4_128_SHA},
  {"ecdhe_rsa_3des_sha",         TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA},
  {"ecdhe_rsa_aes_128_sha",      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
  {"ecdhe_rsa_aes_256_sha",      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA},
  {"ecdh_anon_null_sha",         TLS_ECDH_anon_WITH_NULL_SHA},
  {"ecdh_anon_rc4_128sha",       TLS_ECDH_anon_WITH_RC4_128_SHA},
  {"ecdh_anon_3des_sha",         TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA},
  {"ecdh_anon_aes_128_sha",      TLS_ECDH_anon_WITH_AES_128_CBC_SHA},
  {"ecdh_anon_aes_256_sha",      TLS_ECDH_anon_WITH_AES_256_CBC_SHA},
#ifdef TLS_RSA_WITH_NULL_SHA256
  /* new HMAC-SHA256 cipher suites specified in RFC */
  {"rsa_null_sha_256",                TLS_RSA_WITH_NULL_SHA256},
  {"rsa_aes_128_cbc_sha_256",         TLS_RSA_WITH_AES_128_CBC_SHA256},
  {"rsa_aes_256_cbc_sha_256",         TLS_RSA_WITH_AES_256_CBC_SHA256},
  {"dhe_rsa_aes_128_cbc_sha_256",     TLS_DHE_RSA_WITH_AES_128_CBC_SHA256},
  {"dhe_rsa_aes_256_cbc_sha_256",     TLS_DHE_RSA_WITH_AES_256_CBC_SHA256},
  {"ecdhe_ecdsa_aes_128_cbc_sha_256", TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256},
  {"ecdhe_rsa_aes_128_cbc_sha_256",   TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256},
#endif
#ifdef TLS_RSA_WITH_AES_128_GCM_SHA256
  /* AES GCM cipher suites in RFC 5288 and RFC 5289 */
  {"rsa_aes_128_gcm_sha_256",         TLS_RSA_WITH_AES_128_GCM_SHA256},
  {"dhe_rsa_aes_128_gcm_sha_256",     TLS_DHE_RSA_WITH_AES_128_GCM_SHA256},
  {"dhe_dss_aes_128_gcm_sha_256",     TLS_DHE_DSS_WITH_AES_128_GCM_SHA256},
  {"ecdhe_ecdsa_aes_128_gcm_sha_256", TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
  {"ecdh_ecdsa_aes_128_gcm_sha_256",  TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256},
  {"ecdhe_rsa_aes_128_gcm_sha_256",   TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
  {"ecdh_rsa_aes_128_gcm_sha_256",    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256},
#endif
};

static const char* pem_library = "libnsspem.so";
SECMODModule* mod = NULL;

static const char* nss_error_to_name(PRErrorCode code)
{
  const char *name = PR_ErrorToName(code);
  if(name)
    return name;

  return "unknown error";
}

static void nss_print_error_message(struct SessionHandle *data, PRUint32 err)
{
  failf(data, "%s", PR_ErrorToString(err, PR_LANGUAGE_I_DEFAULT));
}

static SECStatus set_ciphers(struct SessionHandle *data, PRFileDesc * model,
                             char *cipher_list)
{
  unsigned int i;
  PRBool cipher_state[NUM_OF_CIPHERS];
  PRBool found;
  char *cipher;

  /* First disable all ciphers. This uses a different max value in case
   * NSS adds more ciphers later we don't want them available by
   * accident
   */
  for(i=0; i<SSL_NumImplementedCiphers; i++) {
    SSL_CipherPrefSet(model, SSL_ImplementedCiphers[i], PR_FALSE);
  }

  /* Set every entry in our list to false */
  for(i=0; i<NUM_OF_CIPHERS; i++) {
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

    for(i=0; i<NUM_OF_CIPHERS; i++) {
      if(Curl_raw_equal(cipher, cipherlist[i].name)) {
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
  for(i=0; i<NUM_OF_CIPHERS; i++) {
    if(!cipher_state[i])
      continue;

    if(SSL_CipherPrefSet(model, cipherlist[i].num, PR_TRUE) != SECSuccess) {
      failf(data, "cipher-suite not supported by NSS: %s", cipherlist[i].name);
      return SECFailure;
    }
  }

  return SECSuccess;
}

/*
 * Get the number of ciphers that are enabled. We use this to determine
 * if we need to call NSS_SetDomesticPolicy() to enable the default ciphers.
 */
static int num_enabled_ciphers(void)
{
  PRInt32 policy = 0;
  int count = 0;
  unsigned int i;

  for(i=0; i<NUM_OF_CIPHERS; i++) {
    SSL_CipherPolicyGet(cipherlist[i].num, &policy);
    if(policy)
      count++;
  }
  return count;
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
  struct_stat st;

  if(filename == NULL)
    return 0;

  if(stat(filename, &st) == 0)
    if(S_ISREG(st.st_mode))
      return 1;

  return 0;
}

/* Check if the given string is filename or nickname of a certificate.  If the
 * given string is recognized as filename, return NULL.  If the given string is
 * recognized as nickname, return a duplicated string.  The returned string
 * should be later deallocated using free().  If the OOM failure occurs, we
 * return NULL, too.
 */
static char* dup_nickname(struct SessionHandle *data, enum dupstring cert_kind)
{
  const char *str = data->set.str[cert_kind];
  const char *n;

  if(!is_file(str))
    /* no such file exists, use the string as nickname */
    return strdup(str);

  /* search the last slash; we require at least one slash in a file name */
  n = strrchr(str, '/');
  if(!n) {
    infof(data, "warning: certificate file name \"%s\" handled as nickname; "
          "please use \"./%s\" to force file name\n", str, str);
    return strdup(str);
  }

  /* we'll use the PEM reader to read the certificate from file */
  return NULL;
}

/* Call PK11_CreateGenericObject() with the given obj_class and filename.  If
 * the call succeeds, append the object handle to the list of objects so that
 * the object can be destroyed in Curl_nss_close(). */
static CURLcode nss_create_object(struct ssl_connect_data *ssl,
                                  CK_OBJECT_CLASS obj_class,
                                  const char *filename, bool cacert)
{
  PK11SlotInfo *slot;
  PK11GenericObject *obj;
  CK_BBOOL cktrue = CK_TRUE;
  CK_BBOOL ckfalse = CK_FALSE;
  CK_ATTRIBUTE attrs[/* max count of attributes */ 4];
  int attr_cnt = 0;
  CURLcode err = (cacert)
    ? CURLE_SSL_CACERT_BADFILE
    : CURLE_SSL_CERTPROBLEM;

  const int slot_id = (cacert) ? 0 : 1;
  char *slot_name = aprintf("PEM Token #%d", slot_id);
  if(!slot_name)
    return CURLE_OUT_OF_MEMORY;

  slot = PK11_FindSlotByName(slot_name);
  free(slot_name);
  if(!slot)
    return err;

  PK11_SETATTRS(attrs, attr_cnt, CKA_CLASS, &obj_class, sizeof(obj_class));
  PK11_SETATTRS(attrs, attr_cnt, CKA_TOKEN, &cktrue, sizeof(CK_BBOOL));
  PK11_SETATTRS(attrs, attr_cnt, CKA_LABEL, (unsigned char *)filename,
                strlen(filename) + 1);

  if(CKO_CERTIFICATE == obj_class) {
    CK_BBOOL *pval = (cacert) ? (&cktrue) : (&ckfalse);
    PK11_SETATTRS(attrs, attr_cnt, CKA_TRUST, pval, sizeof(*pval));
  }

  obj = PK11_CreateGenericObject(slot, attrs, attr_cnt, PR_FALSE);
  PK11_FreeSlot(slot);
  if(!obj)
    return err;

  if(!Curl_llist_insert_next(ssl->obj_list, ssl->obj_list->tail, obj)) {
    PK11_DestroyGenericObject(obj);
    return CURLE_OUT_OF_MEMORY;
  }

  if(!cacert && CKO_CERTIFICATE == obj_class)
    /* store reference to a client certificate */
    ssl->obj_clicert = obj;

  return CURLE_OK;
}

/* Destroy the NSS object whose handle is given by ptr.  This function is
 * a callback of Curl_llist_alloc() used by Curl_llist_destroy() to destroy
 * NSS objects in Curl_nss_close() */
static void nss_destroy_object(void *user, void *ptr)
{
  PK11GenericObject *obj = (PK11GenericObject *)ptr;
  (void) user;
  PK11_DestroyGenericObject(obj);
}

static CURLcode nss_load_cert(struct ssl_connect_data *ssl,
                              const char *filename, PRBool cacert)
{
  CURLcode err = (cacert)
    ? CURLE_SSL_CACERT_BADFILE
    : CURLE_SSL_CERTPROBLEM;

  /* libnsspem.so leaks memory if the requested file does not exist.  For more
   * details, go to <https://bugzilla.redhat.com/734760>. */
  if(is_file(filename))
    err = nss_create_object(ssl, CKO_CERTIFICATE, filename, cacert);

  if(CURLE_OK == err && !cacert) {
    /* we have successfully loaded a client certificate */
    CERTCertificate *cert;
    char *nickname = NULL;
    char *n = strrchr(filename, '/');
    if(n)
      n++;

    /* The following undocumented magic helps to avoid a SIGSEGV on call
     * of PK11_ReadRawAttribute() from SelectClientCert() when using an
     * immature version of libnsspem.so.  For more details, go to
     * <https://bugzilla.redhat.com/733685>. */
    nickname = aprintf("PEM Token #1:%s", n);
    if(nickname) {
      cert = PK11_FindCertFromNickname(nickname, NULL);
      if(cert)
        CERT_DestroyCertificate(cert);

      free(nickname);
    }
  }

  return err;
}

/* add given CRL to cache if it is not already there */
static SECStatus nss_cache_crl(SECItem *crlDER)
{
  CERTCertDBHandle *db = CERT_GetDefaultCertDB();
  CERTSignedCrl *crl = SEC_FindCrlByDERCert(db, crlDER, 0);
  if(crl) {
    /* CRL already cached */
    SEC_DestroyCrl(crl);
    SECITEM_FreeItem(crlDER, PR_FALSE);
    return SECSuccess;
  }

  /* acquire lock before call of CERT_CacheCRL() */
  PR_Lock(nss_crllock);
  if(SECSuccess != CERT_CacheCRL(db, crlDER)) {
    /* unable to cache CRL */
    PR_Unlock(nss_crllock);
    SECITEM_FreeItem(crlDER, PR_FALSE);
    return SECFailure;
  }

  /* we need to clear session cache, so that the CRL could take effect */
  SSL_ClearSessionCache();
  PR_Unlock(nss_crllock);
  return SECSuccess;
}

static SECStatus nss_load_crl(const char* crlfilename)
{
  PRFileDesc *infile;
  PRFileInfo  info;
  SECItem filedata = { 0, NULL, 0 };
  SECItem crlDER = { 0, NULL, 0 };
  char *body;

  infile = PR_Open(crlfilename, PR_RDONLY, 0);
  if(!infile)
    return SECFailure;

  if(PR_SUCCESS != PR_GetOpenFileInfo(infile, &info))
    goto fail;

  if(!SECITEM_AllocItem(NULL, &filedata, info.size + /* zero ended */ 1))
    goto fail;

  if(info.size != PR_Read(infile, filedata.data, info.size))
    goto fail;

  /* place a trailing zero right after the visible data */
  body = (char*)filedata.data;
  body[--filedata.len] = '\0';

  body = strstr(body, "-----BEGIN");
  if(body) {
    /* assume ASCII */
    char *trailer;
    char *begin = PORT_Strchr(body, '\n');
    if(!begin)
      begin = PORT_Strchr(body, '\r');
    if(!begin)
      goto fail;

    trailer = strstr(++begin, "-----END");
    if(!trailer)
      goto fail;

    /* retrieve DER from ASCII */
    *trailer = '\0';
    if(ATOB_ConvertAsciiToItem(&crlDER, begin))
      goto fail;

    SECITEM_FreeItem(&filedata, PR_FALSE);
  }
  else
    /* assume DER */
    crlDER = filedata;

  PR_Close(infile);
  return nss_cache_crl(&crlDER);

fail:
  PR_Close(infile);
  SECITEM_FreeItem(&filedata, PR_FALSE);
  return SECFailure;
}

static CURLcode nss_load_key(struct connectdata *conn, int sockindex,
                             char *key_file)
{
  PK11SlotInfo *slot;
  SECStatus status;
  CURLcode rv;
  struct ssl_connect_data *ssl = conn->ssl;
  (void)sockindex; /* unused */

  rv = nss_create_object(ssl, CKO_PRIVATE_KEY, key_file, FALSE);
  if(CURLE_OK != rv) {
    PR_SetError(SEC_ERROR_BAD_KEY, 0);
    return rv;
  }

  slot = PK11_FindSlotByName("PEM Token #1");
  if(!slot)
    return CURLE_SSL_CERTPROBLEM;

  /* This will force the token to be seen as re-inserted */
  SECMOD_WaitForAnyTokenEvent(mod, 0, 0);
  PK11_IsPresent(slot);

  status = PK11_Authenticate(slot, PR_TRUE,
                             conn->data->set.str[STRING_KEY_PASSWD]);
  PK11_FreeSlot(slot);
  return (SECSuccess == status)
    ? CURLE_OK
    : CURLE_SSL_CERTPROBLEM;
}

static int display_error(struct connectdata *conn, PRInt32 err,
                         const char *filename)
{
  switch(err) {
  case SEC_ERROR_BAD_PASSWORD:
    failf(conn->data, "Unable to load client key: Incorrect password");
    return 1;
  case SEC_ERROR_UNKNOWN_CERT:
    failf(conn->data, "Unable to load certificate %s", filename);
    return 1;
  default:
    break;
  }
  return 0; /* The caller will print a generic error */
}

static CURLcode cert_stuff(struct connectdata *conn, int sockindex,
                           char *cert_file, char *key_file)
{
  struct SessionHandle *data = conn->data;
  CURLcode rv;

  if(cert_file) {
    rv = nss_load_cert(&conn->ssl[sockindex], cert_file, PR_FALSE);
    if(CURLE_OK != rv) {
      const PRErrorCode err = PR_GetError();
      if(!display_error(conn, err, cert_file)) {
        const char *err_name = nss_error_to_name(err);
        failf(data, "unable to load client cert: %d (%s)", err, err_name);
      }

      return rv;
    }
  }

  if(key_file || (is_file(cert_file))) {
    if(key_file)
      rv = nss_load_key(conn, sockindex, key_file);
    else
      /* In case the cert file also has the key */
      rv = nss_load_key(conn, sockindex, cert_file);
    if(CURLE_OK != rv) {
      const PRErrorCode err = PR_GetError();
      if(!display_error(conn, err, key_file)) {
        const char *err_name = nss_error_to_name(err);
        failf(data, "unable to load client key: %d (%s)", err, err_name);
      }

      return rv;
    }
  }

  return CURLE_OK;
}

static char * nss_get_password(PK11SlotInfo * slot, PRBool retry, void *arg)
{
  (void)slot; /* unused */
  if(retry || NULL == arg)
    return NULL;
  else
    return (char *)PORT_Strdup((char *)arg);
}

/* bypass the default SSL_AuthCertificate() hook in case we do not want to
 * verify peer */
static SECStatus nss_auth_cert_hook(void *arg, PRFileDesc *fd, PRBool checksig,
                                    PRBool isServer)
{
  struct connectdata *conn = (struct connectdata *)arg;
  if(!conn->data->set.ssl.verifypeer) {
    infof(conn->data, "skipping SSL peer certificate verification\n");
    return SECSuccess;
  }

  return SSL_AuthCertificate(CERT_GetDefaultCertDB(), fd, checksig, isServer);
}

/**
 * Inform the application that the handshake is complete.
 */
static void HandshakeCallback(PRFileDesc *sock, void *arg)
{
#ifdef USE_NGHTTP2
  struct connectdata *conn = (struct connectdata*) arg;
  unsigned int buflenmax = 50;
  unsigned char buf[50];
  unsigned int buflen;
  SSLNextProtoState state;

  if(!conn->data->set.ssl_enable_npn && !conn->data->set.ssl_enable_alpn) {
    return;
  }

  if(SSL_GetNextProto(sock, &state, buf, &buflen, buflenmax) == SECSuccess) {

    switch(state) {
      case SSL_NEXT_PROTO_NO_SUPPORT:
      case SSL_NEXT_PROTO_NO_OVERLAP:
        infof(conn->data, "TLS, neither ALPN nor NPN succeeded\n");
        return;
#ifdef SSL_ENABLE_ALPN
      case SSL_NEXT_PROTO_SELECTED:
        infof(conn->data, "ALPN, server accepted to use %.*s\n", buflen, buf);
        break;
#endif
      case SSL_NEXT_PROTO_NEGOTIATED:
        infof(conn->data, "NPN, server accepted to use %.*s\n", buflen, buf);
        break;
    }

    if(buflen == NGHTTP2_PROTO_VERSION_ID_LEN &&
       memcmp(NGHTTP2_PROTO_VERSION_ID, buf, NGHTTP2_PROTO_VERSION_ID_LEN)
       == 0) {
      conn->negnpn = NPN_HTTP2_DRAFT09;
    }
    else if(buflen == ALPN_HTTP_1_1_LENGTH && memcmp(ALPN_HTTP_1_1, buf,
                                                     ALPN_HTTP_1_1_LENGTH)) {
      conn->negnpn = NPN_HTTP1_1;
    }
  }
#else
  (void)sock;
  (void)arg;
#endif
}

static void display_cert_info(struct SessionHandle *data,
                              CERTCertificate *cert)
{
  char *subject, *issuer, *common_name;
  PRExplodedTime printableTime;
  char timeString[256];
  PRTime notBefore, notAfter;

  subject = CERT_NameToAscii(&cert->subject);
  issuer = CERT_NameToAscii(&cert->issuer);
  common_name = CERT_GetCommonName(&cert->subject);
  infof(data, "\tsubject: %s\n", subject);

  CERT_GetCertTimes(cert, &notBefore, &notAfter);
  PR_ExplodeTime(notBefore, PR_GMTParameters, &printableTime);
  PR_FormatTime(timeString, 256, "%b %d %H:%M:%S %Y GMT", &printableTime);
  infof(data, "\tstart date: %s\n", timeString);
  PR_ExplodeTime(notAfter, PR_GMTParameters, &printableTime);
  PR_FormatTime(timeString, 256, "%b %d %H:%M:%S %Y GMT", &printableTime);
  infof(data, "\texpire date: %s\n", timeString);
  infof(data, "\tcommon name: %s\n", common_name);
  infof(data, "\tissuer: %s\n", issuer);

  PR_Free(subject);
  PR_Free(issuer);
  PR_Free(common_name);
}

static void display_conn_info(struct connectdata *conn, PRFileDesc *sock)
{
  SSLChannelInfo channel;
  SSLCipherSuiteInfo suite;
  CERTCertificate *cert;
  CERTCertificate *cert2;
  CERTCertificate *cert3;
  PRTime now;
  int i;

  if(SSL_GetChannelInfo(sock, &channel, sizeof channel) ==
     SECSuccess && channel.length == sizeof channel &&
     channel.cipherSuite) {
    if(SSL_GetCipherSuiteInfo(channel.cipherSuite,
                              &suite, sizeof suite) == SECSuccess) {
      infof(conn->data, "SSL connection using %s\n", suite.cipherSuiteName);
    }
  }

  cert = SSL_PeerCertificate(sock);

  if(cert) {
    infof(conn->data, "Server certificate:\n");

    if(!conn->data->set.ssl.certinfo) {
      display_cert_info(conn->data, cert);
      CERT_DestroyCertificate(cert);
    }
    else {
      /* Count certificates in chain. */
      now = PR_Now();
      i = 1;
      if(!cert->isRoot) {
        cert2 = CERT_FindCertIssuer(cert, now, certUsageSSLCA);
        while(cert2) {
          i++;
          if(cert2->isRoot) {
            CERT_DestroyCertificate(cert2);
            break;
          }
          cert3 = CERT_FindCertIssuer(cert2, now, certUsageSSLCA);
          CERT_DestroyCertificate(cert2);
          cert2 = cert3;
        }
      }
      Curl_ssl_init_certinfo(conn->data, i);
      for(i = 0; cert; cert = cert2) {
        Curl_extract_certinfo(conn, i++, (char *)cert->derCert.data,
                              (char *)cert->derCert.data + cert->derCert.len);
        if(cert->isRoot) {
          CERT_DestroyCertificate(cert);
          break;
        }
        cert2 = CERT_FindCertIssuer(cert, now, certUsageSSLCA);
        CERT_DestroyCertificate(cert);
      }
    }
  }

  return;
}

static SECStatus BadCertHandler(void *arg, PRFileDesc *sock)
{
  struct connectdata *conn = (struct connectdata *)arg;
  struct SessionHandle *data = conn->data;
  PRErrorCode err = PR_GetError();
  CERTCertificate *cert;

  /* remember the cert verification result */
  data->set.ssl.certverifyresult = err;

  if(err == SSL_ERROR_BAD_CERT_DOMAIN && !data->set.ssl.verifyhost)
    /* we are asked not to verify the host name */
    return SECSuccess;

  /* print only info about the cert, the error is printed off the callback */
  cert = SSL_PeerCertificate(sock);
  if(cert) {
    infof(data, "Server certificate:\n");
    display_cert_info(data, cert);
    CERT_DestroyCertificate(cert);
  }

  return SECFailure;
}

/**
 *
 * Check that the Peer certificate's issuer certificate matches the one found
 * by issuer_nickname.  This is not exactly the way OpenSSL and GNU TLS do the
 * issuer check, so we provide comments that mimic the OpenSSL
 * X509_check_issued function (in x509v3/v3_purp.c)
 */
static SECStatus check_issuer_cert(PRFileDesc *sock,
                                   char *issuer_nickname)
{
  CERTCertificate *cert,*cert_issuer,*issuer;
  SECStatus res=SECSuccess;
  void *proto_win = NULL;

  /*
    PRArenaPool   *tmpArena = NULL;
    CERTAuthKeyID *authorityKeyID = NULL;
    SECITEM       *caname = NULL;
  */

  cert = SSL_PeerCertificate(sock);
  cert_issuer = CERT_FindCertIssuer(cert,PR_Now(),certUsageObjectSigner);

  proto_win = SSL_RevealPinArg(sock);
  issuer = PK11_FindCertFromNickname(issuer_nickname, proto_win);

  if((!cert_issuer) || (!issuer))
    res = SECFailure;
  else if(SECITEM_CompareItem(&cert_issuer->derCert,
                              &issuer->derCert)!=SECEqual)
    res = SECFailure;

  CERT_DestroyCertificate(cert);
  CERT_DestroyCertificate(issuer);
  CERT_DestroyCertificate(cert_issuer);
  return res;
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
  struct ssl_connect_data *connssl = (struct ssl_connect_data *)arg;
  struct SessionHandle *data = connssl->data;
  const char *nickname = connssl->client_nickname;

  if(connssl->obj_clicert) {
    /* use the cert/key provided by PEM reader */
    static const char pem_slotname[] = "PEM Token #1";
    SECItem cert_der = { 0, NULL, 0 };
    void *proto_win = SSL_RevealPinArg(sock);
    struct CERTCertificateStr *cert;
    struct SECKEYPrivateKeyStr *key;

    PK11SlotInfo *slot = PK11_FindSlotByName(pem_slotname);
    if(NULL == slot) {
      failf(data, "NSS: PK11 slot not found: %s", pem_slotname);
      return SECFailure;
    }

    if(PK11_ReadRawAttribute(PK11_TypeGeneric, connssl->obj_clicert, CKA_VALUE,
                             &cert_der) != SECSuccess) {
      failf(data, "NSS: CKA_VALUE not found in PK11 generic object");
      PK11_FreeSlot(slot);
      return SECFailure;
    }

    cert = PK11_FindCertFromDERCertItem(slot, &cert_der, proto_win);
    SECITEM_FreeItem(&cert_der, PR_FALSE);
    if(NULL == cert) {
      failf(data, "NSS: client certificate from file not found");
      PK11_FreeSlot(slot);
      return SECFailure;
    }

    key = PK11_FindPrivateKeyFromCert(slot, cert, NULL);
    PK11_FreeSlot(slot);
    if(NULL == key) {
      failf(data, "NSS: private key from file not found");
      CERT_DestroyCertificate(cert);
      return SECFailure;
    }

    infof(data, "NSS: client certificate from file\n");
    display_cert_info(data, cert);

    *pRetCert = cert;
    *pRetKey = key;
    return SECSuccess;
  }

  /* use the default NSS hook */
  if(SECSuccess != NSS_GetClientAuthData((void *)nickname, sock, caNames,
                                          pRetCert, pRetKey)
      || NULL == *pRetCert) {

    if(NULL == nickname)
      failf(data, "NSS: client certificate not found (nickname not "
            "specified)");
    else
      failf(data, "NSS: client certificate not found: %s", nickname);

    return SECFailure;
  }

  /* get certificate nickname if any */
  nickname = (*pRetCert)->nickname;
  if(NULL == nickname)
    nickname = "[unknown]";

  if(NULL == *pRetKey) {
    failf(data, "NSS: private key not found for certificate: %s", nickname);
    return SECFailure;
  }

  infof(data, "NSS: using client certificate: %s\n", nickname);
  display_cert_info(data, *pRetCert);
  return SECSuccess;
}

/* This function is supposed to decide, which error codes should be used
 * to conclude server is TLS intolerant.
 *
 * taken from xulrunner - nsNSSIOLayer.cpp
 */
static PRBool
isTLSIntoleranceError(PRInt32 err)
{
  switch (err) {
  case SSL_ERROR_BAD_MAC_ALERT:
  case SSL_ERROR_BAD_MAC_READ:
  case SSL_ERROR_HANDSHAKE_FAILURE_ALERT:
  case SSL_ERROR_HANDSHAKE_UNEXPECTED_ALERT:
  case SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE:
  case SSL_ERROR_ILLEGAL_PARAMETER_ALERT:
  case SSL_ERROR_NO_CYPHER_OVERLAP:
  case SSL_ERROR_BAD_SERVER:
  case SSL_ERROR_BAD_BLOCK_PADDING:
  case SSL_ERROR_UNSUPPORTED_VERSION:
  case SSL_ERROR_PROTOCOL_VERSION_ALERT:
  case SSL_ERROR_RX_MALFORMED_FINISHED:
  case SSL_ERROR_BAD_HANDSHAKE_HASH_VALUE:
  case SSL_ERROR_DECODE_ERROR_ALERT:
  case SSL_ERROR_RX_UNKNOWN_ALERT:
    return PR_TRUE;
  default:
    return PR_FALSE;
  }
}

static CURLcode nss_init_core(struct SessionHandle *data, const char *cert_dir)
{
  NSSInitParameters initparams;

  if(nss_context != NULL)
    return CURLE_OK;

  memset((void *) &initparams, '\0', sizeof(initparams));
  initparams.length = sizeof(initparams);

  if(cert_dir) {
    const bool use_sql = NSS_VersionCheck("3.12.0");
    char *certpath = aprintf("%s%s", use_sql ? "sql:" : "", cert_dir);
    if(!certpath)
      return CURLE_OUT_OF_MEMORY;

    infof(data, "Initializing NSS with certpath: %s\n", certpath);
    nss_context = NSS_InitContext(certpath, "", "", "", &initparams,
            NSS_INIT_READONLY | NSS_INIT_PK11RELOAD);
    free(certpath);

    if(nss_context != NULL)
      return CURLE_OK;

    infof(data, "Unable to initialize NSS database\n");
  }

  infof(data, "Initializing NSS with certpath: none\n");
  nss_context = NSS_InitContext("", "", "", "", &initparams, NSS_INIT_READONLY
         | NSS_INIT_NOCERTDB   | NSS_INIT_NOMODDB       | NSS_INIT_FORCEOPEN
         | NSS_INIT_NOROOTINIT | NSS_INIT_OPTIMIZESPACE | NSS_INIT_PK11RELOAD);
  if(nss_context != NULL)
    return CURLE_OK;

  infof(data, "Unable to initialize NSS\n");
  return CURLE_SSL_CACERT_BADFILE;
}

static CURLcode nss_init(struct SessionHandle *data)
{
  char *cert_dir;
  struct_stat st;
  CURLcode rv;

  if(initialized)
    return CURLE_OK;

  /* First we check if $SSL_DIR points to a valid dir */
  cert_dir = getenv("SSL_DIR");
  if(cert_dir) {
    if((stat(cert_dir, &st) != 0) ||
        (!S_ISDIR(st.st_mode))) {
      cert_dir = NULL;
    }
  }

  /* Now we check if the default location is a valid dir */
  if(!cert_dir) {
    if((stat(SSL_DIR, &st) == 0) &&
        (S_ISDIR(st.st_mode))) {
      cert_dir = (char *)SSL_DIR;
    }
  }

  rv = nss_init_core(data, cert_dir);
  if(rv)
    return rv;

  if(num_enabled_ciphers() == 0)
    NSS_SetDomesticPolicy();

  initialized = 1;
  return CURLE_OK;
}

/**
 * Global SSL init
 *
 * @retval 0 error initializing SSL
 * @retval 1 SSL initialized successfully
 */
int Curl_nss_init(void)
{
  /* curl_global_init() is not thread-safe so this test is ok */
  if(nss_initlock == NULL) {
    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 256);
    nss_initlock = PR_NewLock();
    nss_crllock = PR_NewLock();
  }

  /* We will actually initialize NSS later */

  return 1;
}

CURLcode Curl_nss_force_init(struct SessionHandle *data)
{
  CURLcode rv;
  if(!nss_initlock) {
    failf(data,
          "unable to initialize NSS, curl_global_init() should have been "
          "called with CURL_GLOBAL_SSL or CURL_GLOBAL_ALL");
    return CURLE_FAILED_INIT;
  }

  PR_Lock(nss_initlock);
  rv = nss_init(data);
  PR_Unlock(nss_initlock);
  return rv;
}

/* Global cleanup */
void Curl_nss_cleanup(void)
{
  /* This function isn't required to be threadsafe and this is only done
   * as a safety feature.
   */
  PR_Lock(nss_initlock);
  if(initialized) {
    /* Free references to client certificates held in the SSL session cache.
     * Omitting this hampers destruction of the security module owning
     * the certificates. */
    SSL_ClearSessionCache();

    if(mod && SECSuccess == SECMOD_UnloadUserModule(mod)) {
      SECMOD_DestroyModule(mod);
      mod = NULL;
    }
    NSS_ShutdownContext(nss_context);
    nss_context = NULL;
  }
  PR_Unlock(nss_initlock);

  PR_DestroyLock(nss_initlock);
  PR_DestroyLock(nss_crllock);
  nss_initlock = NULL;

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
    /* NSS closes the socket we previously handed to it, so we must mark it
       as closed to avoid double close */
    fake_sclose(conn->sock[sockindex]);
    conn->sock[sockindex] = CURL_SOCKET_BAD;

    if((connssl->client_nickname != NULL) || (connssl->obj_clicert != NULL))
      /* A server might require different authentication based on the
       * particular path being requested by the client.  To support this
       * scenario, we must ensure that a connection will never reuse the
       * authentication data from a previous connection. */
      SSL_InvalidateSession(connssl->handle);

    if(connssl->client_nickname != NULL) {
      free(connssl->client_nickname);
      connssl->client_nickname = NULL;
    }
    /* destroy all NSS objects in order to avoid failure of NSS shutdown */
    Curl_llist_destroy(connssl->obj_list, NULL);
    connssl->obj_list = NULL;
    connssl->obj_clicert = NULL;

    PR_Close(connssl->handle);
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

/* return true if NSS can provide error code (and possibly msg) for the
   error */
static bool is_nss_error(CURLcode err)
{
  switch(err) {
  case CURLE_PEER_FAILED_VERIFICATION:
  case CURLE_SSL_CACERT:
  case CURLE_SSL_CERTPROBLEM:
  case CURLE_SSL_CONNECT_ERROR:
  case CURLE_SSL_ISSUER_ERROR:
    return true;

  default:
    return false;
  }
}

/* return true if the given error code is related to a client certificate */
static bool is_cc_error(PRInt32 err)
{
  switch(err) {
  case SSL_ERROR_BAD_CERT_ALERT:
  case SSL_ERROR_EXPIRED_CERT_ALERT:
  case SSL_ERROR_REVOKED_CERT_ALERT:
    return true;

  default:
    return false;
  }
}

static Curl_recv nss_recv;
static Curl_send nss_send;

static CURLcode nss_load_ca_certificates(struct connectdata *conn,
                                         int sockindex)
{
  struct SessionHandle *data = conn->data;
  const char *cafile = data->set.ssl.CAfile;
  const char *capath = data->set.ssl.CApath;

  if(cafile) {
    CURLcode rv = nss_load_cert(&conn->ssl[sockindex], cafile, PR_TRUE);
    if(CURLE_OK != rv)
      return rv;
  }

  if(capath) {
    struct_stat st;
    if(stat(capath, &st) == -1)
      return CURLE_SSL_CACERT_BADFILE;

    if(S_ISDIR(st.st_mode)) {
      PRDirEntry *entry;
      PRDir *dir = PR_OpenDir(capath);
      if(!dir)
        return CURLE_SSL_CACERT_BADFILE;

      while((entry = PR_ReadDir(dir, PR_SKIP_BOTH | PR_SKIP_HIDDEN))) {
        char *fullpath = aprintf("%s/%s", capath, entry->name);
        if(!fullpath) {
          PR_CloseDir(dir);
          return CURLE_OUT_OF_MEMORY;
        }

        if(CURLE_OK != nss_load_cert(&conn->ssl[sockindex], fullpath, PR_TRUE))
          /* This is purposefully tolerant of errors so non-PEM files can
           * be in the same directory */
          infof(data, "failed to load '%s' from CURLOPT_CAPATH\n", fullpath);

        free(fullpath);
      }

      PR_CloseDir(dir);
    }
    else
      infof(data, "warning: CURLOPT_CAPATH not a directory (%s)\n", capath);
  }

  infof(data, "  CAfile: %s\n  CApath: %s\n",
      cafile ? cafile : "none",
      capath ? capath : "none");

  return CURLE_OK;
}

static CURLcode nss_init_sslver(SSLVersionRange *sslver,
                                struct SessionHandle *data)
{
  switch (data->set.ssl.version) {
  default:
  case CURL_SSLVERSION_DEFAULT:
    if(data->state.ssl_connect_retry) {
      infof(data, "TLS disabled due to previous handshake failure\n");
      sslver->max = SSL_LIBRARY_VERSION_3_0;
      return CURLE_OK;
    }
  /* intentional fall-through to default to highest TLS version if possible */

  case CURL_SSLVERSION_TLSv1:
    sslver->min = SSL_LIBRARY_VERSION_TLS_1_0;
#ifdef SSL_LIBRARY_VERSION_TLS_1_2
    sslver->max = SSL_LIBRARY_VERSION_TLS_1_2;
#elif defined SSL_LIBRARY_VERSION_TLS_1_1
    sslver->max = SSL_LIBRARY_VERSION_TLS_1_1;
#else
    sslver->max = SSL_LIBRARY_VERSION_TLS_1_0;
#endif
    return CURLE_OK;

  case CURL_SSLVERSION_SSLv2:
    sslver->min = SSL_LIBRARY_VERSION_2;
    sslver->max = SSL_LIBRARY_VERSION_2;
    return CURLE_OK;

  case CURL_SSLVERSION_SSLv3:
    sslver->min = SSL_LIBRARY_VERSION_3_0;
    sslver->max = SSL_LIBRARY_VERSION_3_0;
    return CURLE_OK;

  case CURL_SSLVERSION_TLSv1_0:
    sslver->min = SSL_LIBRARY_VERSION_TLS_1_0;
    sslver->max = SSL_LIBRARY_VERSION_TLS_1_0;
    return CURLE_OK;

  case CURL_SSLVERSION_TLSv1_1:
#ifdef SSL_LIBRARY_VERSION_TLS_1_1
    sslver->min = SSL_LIBRARY_VERSION_TLS_1_1;
    sslver->max = SSL_LIBRARY_VERSION_TLS_1_1;
    return CURLE_OK;
#endif
    break;

  case CURL_SSLVERSION_TLSv1_2:
#ifdef SSL_LIBRARY_VERSION_TLS_1_2
    sslver->min = SSL_LIBRARY_VERSION_TLS_1_2;
    sslver->max = SSL_LIBRARY_VERSION_TLS_1_2;
    return CURLE_OK;
#endif
    break;
  }

  failf(data, "TLS minor version cannot be set");
  return CURLE_SSL_CONNECT_ERROR;
}

CURLcode Curl_nss_connect(struct connectdata *conn, int sockindex)
{
  PRErrorCode err = 0;
  PRFileDesc *model = NULL;
  PRBool ssl_no_cache;
  PRBool ssl_cbc_random_iv;
  struct SessionHandle *data = conn->data;
  curl_socket_t sockfd = conn->sock[sockindex];
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  CURLcode curlerr;
  PRSocketOptionData sock_opt;
  long time_left;
  PRUint32 timeout;

  SSLVersionRange sslver = {
    SSL_LIBRARY_VERSION_3_0,      /* min */
    SSL_LIBRARY_VERSION_TLS_1_0   /* max */
  };

#ifdef USE_NGHTTP2
#if defined(SSL_ENABLE_NPN) || defined(SSL_ENABLE_ALPN)
  unsigned int alpn_protos_len = NGHTTP2_PROTO_VERSION_ID_LEN +
      ALPN_HTTP_1_1_LENGTH + 2;
  unsigned char alpn_protos[NGHTTP2_PROTO_VERSION_ID_LEN + ALPN_HTTP_1_1_LENGTH
      + 2];
  int cur = 0;
#endif
#endif


  if(connssl->state == ssl_connection_complete)
    return CURLE_OK;

  connssl->data = data;

  /* list of all NSS objects we need to destroy in Curl_nss_close() */
  connssl->obj_list = Curl_llist_alloc(nss_destroy_object);
  if(!connssl->obj_list)
    return CURLE_OUT_OF_MEMORY;

  /* FIXME. NSS doesn't support multiple databases open at the same time. */
  PR_Lock(nss_initlock);
  curlerr = nss_init(conn->data);
  if(CURLE_OK != curlerr) {
    PR_Unlock(nss_initlock);
    goto error;
  }

  curlerr = CURLE_SSL_CONNECT_ERROR;

  if(!mod) {
    char *configstring = aprintf("library=%s name=PEM", pem_library);
    if(!configstring) {
      PR_Unlock(nss_initlock);
      goto error;
    }
    mod = SECMOD_LoadUserModule(configstring, NULL, PR_FALSE);
    free(configstring);

    if(!mod || !mod->loaded) {
      if(mod) {
        SECMOD_DestroyModule(mod);
        mod = NULL;
      }
      infof(data, "WARNING: failed to load NSS PEM library %s. Using "
            "OpenSSL PEM certificates will not work.\n", pem_library);
    }
  }

  PK11_SetPasswordFunc(nss_get_password);
  PR_Unlock(nss_initlock);

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

  /* do not use SSL cache if disabled or we are not going to verify peer */
  ssl_no_cache = (conn->ssl_config.sessionid && data->set.ssl.verifypeer) ?
    PR_FALSE : PR_TRUE;
  if(SSL_OptionSet(model, SSL_NO_CACHE, ssl_no_cache) != SECSuccess)
    goto error;

  /* enable/disable the requested SSL version(s) */
  if(nss_init_sslver(&sslver, data) != CURLE_OK)
    goto error;
  if(SSL_VersionRangeSet(model, &sslver) != SECSuccess)
    goto error;

  ssl_cbc_random_iv = !data->set.ssl_enable_beast;
#ifdef SSL_CBC_RANDOM_IV
  /* unless the user explicitly asks to allow the protocol vulnerability, we
     use the work-around */
  if(SSL_OptionSet(model, SSL_CBC_RANDOM_IV, ssl_cbc_random_iv) != SECSuccess)
    infof(data, "warning: failed to set SSL_CBC_RANDOM_IV = %d\n",
          ssl_cbc_random_iv);
#else
  if(ssl_cbc_random_iv)
    infof(data, "warning: support for SSL_CBC_RANDOM_IV not compiled in\n");
#endif

  /* reset the flag to avoid an infinite loop */
  data->state.ssl_connect_retry = FALSE;

  if(data->set.ssl.cipher_list) {
    if(set_ciphers(data, model, data->set.ssl.cipher_list) != SECSuccess) {
      curlerr = CURLE_SSL_CIPHER;
      goto error;
    }
  }

  if(!data->set.ssl.verifypeer && data->set.ssl.verifyhost)
    infof(data, "warning: ignoring value of ssl.verifyhost\n");

  /* bypass the default SSL_AuthCertificate() hook in case we do not want to
   * verify peer */
  if(SSL_AuthCertificateHook(model, nss_auth_cert_hook, conn) != SECSuccess)
    goto error;

  data->set.ssl.certverifyresult=0; /* not checked yet */
  if(SSL_BadCertHook(model, BadCertHandler, conn) != SECSuccess)
    goto error;

  if(SSL_HandshakeCallback(model, HandshakeCallback, conn) != SECSuccess)
    goto error;

  if(data->set.ssl.verifypeer) {
    const CURLcode rv = nss_load_ca_certificates(conn, sockindex);
    if(CURLE_OK != rv) {
      curlerr = rv;
      goto error;
    }
  }

  if(data->set.ssl.CRLfile) {
    if(SECSuccess != nss_load_crl(data->set.ssl.CRLfile)) {
      curlerr = CURLE_SSL_CRL_BADFILE;
      goto error;
    }
    infof(data,
          "  CRLfile: %s\n",
          data->set.ssl.CRLfile ? data->set.ssl.CRLfile : "none");
  }

  if(data->set.str[STRING_CERT]) {
    char *nickname = dup_nickname(data, STRING_CERT);
    if(nickname) {
      /* we are not going to use libnsspem.so to read the client cert */
      connssl->obj_clicert = NULL;
    }
    else {
      CURLcode rv = cert_stuff(conn, sockindex, data->set.str[STRING_CERT],
                               data->set.str[STRING_KEY]);
      if(CURLE_OK != rv) {
        /* failf() is already done in cert_stuff() */
        curlerr = rv;
        goto error;
      }
    }

    /* store the nickname for SelectClientCert() called during handshake */
    connssl->client_nickname = nickname;
  }
  else
    connssl->client_nickname = NULL;

  if(SSL_GetClientAuthDataHook(model, SelectClientCert,
                               (void *)connssl) != SECSuccess) {
    curlerr = CURLE_SSL_CERTPROBLEM;
    goto error;
  }

  /* Import our model socket  onto the existing file descriptor */
  connssl->handle = PR_ImportTCPSocket(sockfd);
  connssl->handle = SSL_ImportFD(model, connssl->handle);
  if(!connssl->handle)
    goto error;

  PR_Close(model); /* We don't need this any more */
  model = NULL;

  /* This is the password associated with the cert that we're using */
  if(data->set.str[STRING_KEY_PASSWD]) {
    SSL_SetPKCS11PinArg(connssl->handle, data->set.str[STRING_KEY_PASSWD]);
  }

#ifdef USE_NGHTTP2
  if(data->set.httpversion == CURL_HTTP_VERSION_2_0) {
#ifdef SSL_ENABLE_NPN
    if(data->set.ssl_enable_npn) {
      if(SSL_OptionSet(connssl->handle, SSL_ENABLE_NPN, PR_TRUE) != SECSuccess)
        goto error;
    }
#endif

#ifdef SSL_ENABLE_ALPN
    if(data->set.ssl_enable_alpn) {
      if(SSL_OptionSet(connssl->handle, SSL_ENABLE_ALPN, PR_TRUE)
          != SECSuccess)
        goto error;
    }
#endif

#if defined(SSL_ENABLE_NPN) || defined(SSL_ENABLE_ALPN)
    if(data->set.ssl_enable_npn || data->set.ssl_enable_alpn) {
      alpn_protos[cur] = NGHTTP2_PROTO_VERSION_ID_LEN;
      cur++;
      memcpy(&alpn_protos[cur], NGHTTP2_PROTO_VERSION_ID,
          NGHTTP2_PROTO_VERSION_ID_LEN);
      cur += NGHTTP2_PROTO_VERSION_ID_LEN;
      alpn_protos[cur] = ALPN_HTTP_1_1_LENGTH;
      cur++;
      memcpy(&alpn_protos[cur], ALPN_HTTP_1_1, ALPN_HTTP_1_1_LENGTH);

      if(SSL_SetNextProtoNego(connssl->handle, alpn_protos, alpn_protos_len)
          != SECSuccess)
        goto error;
    }
    else {
      infof(data, "SSL, can't negotiate HTTP/2.0 with neither NPN nor ALPN\n");
    }
#endif
  }
#endif


  /* Force handshake on next I/O */
  SSL_ResetHandshake(connssl->handle, /* asServer */ PR_FALSE);

  SSL_SetURL(connssl->handle, conn->host.name);

  /* check timeout situation */
  time_left = Curl_timeleft(data, NULL, TRUE);
  if(time_left < 0L) {
    failf(data, "timed out before SSL handshake");
    curlerr = CURLE_OPERATION_TIMEDOUT;
    goto error;
  }
  timeout = PR_MillisecondsToInterval((PRUint32) time_left);

  /* Force the handshake now */
  if(SSL_ForceHandshakeWithTimeout(connssl->handle, timeout) != SECSuccess) {
    if(conn->data->set.ssl.certverifyresult == SSL_ERROR_BAD_CERT_DOMAIN)
      curlerr = CURLE_PEER_FAILED_VERIFICATION;
    else if(conn->data->set.ssl.certverifyresult!=0)
      curlerr = CURLE_SSL_CACERT;
    goto error;
  }

  /* switch the SSL socket into non-blocking mode */
  sock_opt.option = PR_SockOpt_Nonblocking;
  sock_opt.value.non_blocking = PR_TRUE;
  if(PR_SetSocketOption(connssl->handle, &sock_opt) != PR_SUCCESS)
    goto error;

  connssl->state = ssl_connection_complete;
  conn->recv[sockindex] = nss_recv;
  conn->send[sockindex] = nss_send;

  display_conn_info(conn, connssl->handle);

  if(data->set.str[STRING_SSL_ISSUERCERT]) {
    SECStatus ret = SECFailure;
    char *nickname = dup_nickname(data, STRING_SSL_ISSUERCERT);
    if(nickname) {
      /* we support only nicknames in case of STRING_SSL_ISSUERCERT for now */
      ret = check_issuer_cert(connssl->handle, nickname);
      free(nickname);
    }

    if(SECFailure == ret) {
      infof(data,"SSL certificate issuer check failed\n");
      curlerr = CURLE_SSL_ISSUER_ERROR;
      goto error;
    }
    else {
      infof(data, "SSL certificate issuer check ok\n");
    }
  }

  return CURLE_OK;

  error:
  /* reset the flag to avoid an infinite loop */
  data->state.ssl_connect_retry = FALSE;

  if(is_nss_error(curlerr)) {
    /* read NSPR error code */
    err = PR_GetError();
    if(is_cc_error(err))
      curlerr = CURLE_SSL_CERTPROBLEM;

    /* print the error number and error string */
    infof(data, "NSS error %d (%s)\n", err, nss_error_to_name(err));

    /* print a human-readable message describing the error if available */
    nss_print_error_message(data, err);
  }

  if(model)
    PR_Close(model);

  /* cleanup on connection failure */
  Curl_llist_destroy(connssl->obj_list, NULL);
  connssl->obj_list = NULL;

  if((sslver.min == SSL_LIBRARY_VERSION_3_0)
      && (sslver.max == SSL_LIBRARY_VERSION_TLS_1_0)
      && isTLSIntoleranceError(err)) {
    /* schedule reconnect through Curl_retry_request() */
    data->state.ssl_connect_retry = TRUE;
    infof(data, "Error in TLS handshake, trying SSLv3...\n");
    return CURLE_OK;
  }

  return curlerr;
}

static ssize_t nss_send(struct connectdata *conn,  /* connection data */
                        int sockindex,             /* socketindex */
                        const void *mem,           /* send this data */
                        size_t len,                /* amount to write */
                        CURLcode *curlcode)
{
  ssize_t rc = PR_Send(conn->ssl[sockindex].handle, mem, (int)len, 0,
                       PR_INTERVAL_NO_WAIT);
  if(rc < 0) {
    PRInt32 err = PR_GetError();
    if(err == PR_WOULD_BLOCK_ERROR)
      *curlcode = CURLE_AGAIN;
    else {
      /* print the error number and error string */
      const char *err_name = nss_error_to_name(err);
      infof(conn->data, "SSL write: error %d (%s)\n", err, err_name);

      /* print a human-readable message describing the error if available */
      nss_print_error_message(conn->data, err);

      *curlcode = (is_cc_error(err))
        ? CURLE_SSL_CERTPROBLEM
        : CURLE_SEND_ERROR;
    }
    return -1;
  }
  return rc; /* number of bytes */
}

static ssize_t nss_recv(struct connectdata * conn, /* connection data */
                        int num,                   /* socketindex */
                        char *buf,                 /* store read data here */
                        size_t buffersize,         /* max amount to read */
                        CURLcode *curlcode)
{
  ssize_t nread = PR_Recv(conn->ssl[num].handle, buf, (int)buffersize, 0,
                          PR_INTERVAL_NO_WAIT);
  if(nread < 0) {
    /* failed SSL read */
    PRInt32 err = PR_GetError();

    if(err == PR_WOULD_BLOCK_ERROR)
      *curlcode = CURLE_AGAIN;
    else {
      /* print the error number and error string */
      const char *err_name = nss_error_to_name(err);
      infof(conn->data, "SSL read: errno %d (%s)\n", err, err_name);

      /* print a human-readable message describing the error if available */
      nss_print_error_message(conn->data, err);

      *curlcode = (is_cc_error(err))
        ? CURLE_SSL_CERTPROBLEM
        : CURLE_RECV_ERROR;
    }
    return -1;
  }
  return nread;
}

size_t Curl_nss_version(char *buffer, size_t size)
{
  return snprintf(buffer, size, "NSS/%s", NSS_VERSION);
}

int Curl_nss_seed(struct SessionHandle *data)
{
  /* make sure that NSS is initialized */
  return !!Curl_nss_force_init(data);
}

void Curl_nss_random(struct SessionHandle *data,
                     unsigned char *entropy,
                     size_t length)
{
  Curl_nss_seed(data);  /* Initiate the seed if not already done */
  if(SECSuccess != PK11_GenerateRandom(entropy, curlx_uztosi(length))) {
    /* no way to signal a failure from here, we have to abort */
    failf(data, "PK11_GenerateRandom() failed, calling abort()...");
    abort();
  }
}

void Curl_nss_md5sum(unsigned char *tmp, /* input */
                     size_t tmplen,
                     unsigned char *md5sum, /* output */
                     size_t md5len)
{
  PK11Context *MD5pw = PK11_CreateDigestContext(SEC_OID_MD5);
  unsigned int MD5out;
  PK11_DigestOp(MD5pw, tmp, curlx_uztoui(tmplen));
  PK11_DigestFinal(MD5pw, md5sum, &MD5out, curlx_uztoui(md5len));
  PK11_DestroyContext(MD5pw, PR_TRUE);
}

#endif /* USE_NSS */
