/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#ifdef USE_GSKIT

#include <gskssl.h>
#include <qsoasync.h>

/* Some symbols are undefined/unsupported on OS400 versions < V7R1. */
#ifndef GSK_SSL_EXTN_SERVERNAME_REQUEST
#define GSK_SSL_EXTN_SERVERNAME_REQUEST                 230
#endif

#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif

#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"
#include "gskit.h"
#include "sslgen.h"
#include "connect.h" /* for the connect timeout */
#include "select.h"
#include "strequal.h"
#include "x509asn1.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"


/* Supported ciphers. */
typedef struct {
  const char *  name;           /* Cipher name. */
  const char *  gsktoken;       /* Corresponding token for GSKit String. */
  int           sslver;         /* SSL version. */
}  gskit_cipher;

static const gskit_cipher  ciphertable[] = {
  { "null-md5",         "01",   CURL_SSLVERSION_SSLv3 },
  { "null-sha",         "02",   CURL_SSLVERSION_SSLv3 },
  { "exp-rc4-md5",      "03",   CURL_SSLVERSION_SSLv3 },
  { "rc4-md5",          "04",   CURL_SSLVERSION_SSLv3 },
  { "rc4-sha",          "05",   CURL_SSLVERSION_SSLv3 },
  { "exp-rc2-cbc-md5",  "06",   CURL_SSLVERSION_SSLv3 },
  { "exp-des-cbc-sha",  "09",   CURL_SSLVERSION_SSLv3 },
  { "des-cbc3-sha",     "0A",   CURL_SSLVERSION_SSLv3 },
  { "aes128-sha",       "2F",   CURL_SSLVERSION_TLSv1 },
  { "aes256-sha",       "35",   CURL_SSLVERSION_TLSv1 },
  { "rc4-md5",          "1",    CURL_SSLVERSION_SSLv2 },
  { "exp-rc4-md5",      "2",    CURL_SSLVERSION_SSLv2 },
  { "rc2-md5",          "3",    CURL_SSLVERSION_SSLv2 },
  { "exp-rc2-md5",      "4",    CURL_SSLVERSION_SSLv2 },
  { "des-cbc-md5",      "6",    CURL_SSLVERSION_SSLv2 },
  { "des-cbc3-md5",     "7",    CURL_SSLVERSION_SSLv2 },
  { (const char *) NULL, (const char *) NULL, 0       }
};


static bool is_separator(char c)
{
  /* Return whether character is a cipher list separator. */
  switch (c) {
  case ' ':
  case '\t':
  case ':':
  case ',':
  case ';':
    return true;
  }
  return false;
}


static CURLcode gskit_status(struct SessionHandle * data, int rc,
                             const char * procname, CURLcode defcode)
{
  CURLcode cc;

  /* Process GSKit status and map it to a CURLcode. */
  switch (rc) {
  case GSK_OK:
  case GSK_OS400_ASYNCHRONOUS_SOC_INIT:
    return CURLE_OK;
  case GSK_KEYRING_OPEN_ERROR:
  case GSK_OS400_ERROR_NO_ACCESS:
    return CURLE_SSL_CACERT_BADFILE;
  case GSK_INSUFFICIENT_STORAGE:
    return CURLE_OUT_OF_MEMORY;
  case GSK_ERROR_BAD_V2_CIPHER:
  case GSK_ERROR_BAD_V3_CIPHER:
  case GSK_ERROR_NO_CIPHERS:
    return CURLE_SSL_CIPHER;
  case GSK_OS400_ERROR_NOT_TRUSTED_ROOT:
  case GSK_ERROR_CERT_VALIDATION:
    return CURLE_PEER_FAILED_VERIFICATION;
  case GSK_OS400_ERROR_TIMED_OUT:
    return CURLE_OPERATION_TIMEDOUT;
  case GSK_WOULD_BLOCK:
    return CURLE_AGAIN;
  case GSK_OS400_ERROR_NOT_REGISTERED:
    break;
  case GSK_ERROR_IO:
    switch (errno) {
    case ENOMEM:
      return CURLE_OUT_OF_MEMORY;
    default:
      failf(data, "%s I/O error: %s", procname, strerror(errno));
      break;
    }
    break;
  default:
    failf(data, "%s: %s", procname, gsk_strerror(rc));
    break;
    }
  return defcode;
}


static CURLcode set_enum(struct SessionHandle * data,
                         gsk_handle h, GSK_ENUM_ID id, GSK_ENUM_VALUE value)
{
  int rc = gsk_attribute_set_enum(h, id, value);

  switch (rc) {
  case GSK_OK:
    return CURLE_OK;
  case GSK_ERROR_IO:
    failf(data, "gsk_attribute_set_enum() I/O error: %s", strerror(errno));
    break;
  default:
    failf(data, "gsk_attribute_set_enum(): %s", gsk_strerror(rc));
    break;
  }
  return CURLE_SSL_CONNECT_ERROR;
}


static CURLcode set_buffer(struct SessionHandle * data,
                           gsk_handle h, GSK_BUF_ID id, const char * buffer)
{
  int rc = gsk_attribute_set_buffer(h, id, buffer, 0);

  switch (rc) {
  case GSK_OK:
    return CURLE_OK;
  case GSK_ERROR_IO:
    failf(data, "gsk_attribute_set_buffer() I/O error: %s", strerror(errno));
    break;
  default:
    failf(data, "gsk_attribute_set_buffer(): %s", gsk_strerror(rc));
    break;
  }
  return CURLE_SSL_CONNECT_ERROR;
}


static CURLcode set_numeric(struct SessionHandle * data,
                            gsk_handle h, GSK_NUM_ID id, int value)
{
  int rc = gsk_attribute_set_numeric_value(h, id, value);

  switch (rc) {
  case GSK_OK:
    return CURLE_OK;
  case GSK_ERROR_IO:
    failf(data, "gsk_attribute_set_numeric_value() I/O error: %s",
          strerror(errno));
    break;
  default:
    failf(data, "gsk_attribute_set_numeric_value(): %s", gsk_strerror(rc));
    break;
  }
  return CURLE_SSL_CONNECT_ERROR;
}


static CURLcode set_callback(struct SessionHandle * data,
                             gsk_handle h, GSK_CALLBACK_ID id, void * info)
{
  int rc = gsk_attribute_set_callback(h, id, info);

  switch (rc) {
  case GSK_OK:
    return CURLE_OK;
  case GSK_ERROR_IO:
    failf(data, "gsk_attribute_set_callback() I/O error: %s", strerror(errno));
    break;
  default:
    failf(data, "gsk_attribute_set_callback(): %s", gsk_strerror(rc));
    break;
  }
  return CURLE_SSL_CONNECT_ERROR;
}


static CURLcode set_ciphers(struct SessionHandle * data, gsk_handle h)
{
  const char * cipherlist = data->set.str[STRING_SSL_CIPHER_LIST];
  char * sslv2ciphers;
  char * sslv3ciphers;
  const char * clp;
  const gskit_cipher * ctp;
  char * v2p;
  char * v3p;
  int i;
  CURLcode cc;

  /* Compile cipher list into GSKit-compatible cipher lists. */

  if(!cipherlist)
    return CURLE_OK;
  while(is_separator(*cipherlist))     /* Skip initial separators. */
    cipherlist++;
  if(!*cipherlist)
    return CURLE_OK;

  /* We allocate GSKit buffers of the same size as the input string: since
     GSKit tokens are always shorter than their cipher names, allocated buffers
     will always be large enough to accomodate the result. */
  i = strlen(cipherlist) + 1;
  v2p = malloc(i);
  if(!v2p)
    return CURLE_OUT_OF_MEMORY;
  v3p = malloc(i);
  if(!v3p) {
    free(v2p);
    return CURLE_OUT_OF_MEMORY;
  }
  sslv2ciphers = v2p;
  sslv3ciphers = v3p;

  /* Process each cipher in input string. */
  for(;;) {
    for(clp = cipherlist; *cipherlist && !is_separator(*cipherlist);)
      cipherlist++;
    i = cipherlist - clp;
    if(!i)
      break;
    /* Search the cipher in our table. */
    for(ctp = ciphertable; ctp->name; ctp++)
      if(strnequal(ctp->name, clp, i) && !ctp->name[i])
        break;
    if(!ctp->name)
      failf(data, "Unknown cipher %.*s: ignored", i, clp);
    else {
      switch (ctp->sslver) {
      case CURL_SSLVERSION_SSLv2:
        strcpy(v2p, ctp->gsktoken);
        v2p += strlen(v2p);
        break;
      default:
        /* GSKit wants TLSv1 ciphers with SSLv3 ciphers. */
        strcpy(v3p, ctp->gsktoken);
        v3p += strlen(v3p);
        break;
      }
    }

   /* Advance to next cipher name or end of string. */
    while(is_separator(*cipherlist))
      cipherlist++;
  }
  *v2p = '\0';
  *v3p = '\0';
  cc = set_buffer(data, h, GSK_V2_CIPHER_SPECS, sslv2ciphers);
  if(cc == CURLE_OK)
    cc = set_buffer(data, h, GSK_V3_CIPHER_SPECS, sslv3ciphers);
  free(sslv2ciphers);
  free(sslv3ciphers);
  return cc;
}


int Curl_gskit_init(void)
{
  /* No initialisation needed. */

  return 1;
}


void Curl_gskit_cleanup(void)
{
  /* Nothing to do. */
}


static CURLcode init_environment(struct SessionHandle * data,
                                 gsk_handle * envir, const char * appid,
                                 const char * file, const char * label,
                                 const char * password)
{
  int rc;
  CURLcode c;
  gsk_handle h;

  /* Creates the GSKit environment. */

  rc = gsk_environment_open(&h);
  switch (rc) {
  case GSK_OK:
    break;
  case GSK_INSUFFICIENT_STORAGE:
    return CURLE_OUT_OF_MEMORY;
  default:
    failf(data, "gsk_environment_open(): %s", gsk_strerror(rc));
    return CURLE_SSL_CONNECT_ERROR;
  }

  c = set_enum(data, h, GSK_SESSION_TYPE, GSK_CLIENT_SESSION);
  if(c == CURLE_OK && appid)
    c = set_buffer(data, h, GSK_OS400_APPLICATION_ID, appid);
  if(c == CURLE_OK && file)
    c = set_buffer(data, h, GSK_KEYRING_FILE, file);
  if(c == CURLE_OK && label)
    c = set_buffer(data, h, GSK_KEYRING_LABEL, label);
  if(c == CURLE_OK && password)
    c = set_buffer(data, h, GSK_KEYRING_PW, password);

  if(c == CURLE_OK) {
    /* Locate CAs, Client certificate and key according to our settings.
       Note: this call may be blocking for some tenths of seconds. */
    c = gskit_status(data, gsk_environment_init(h),
                     "gsk_environment_init()", CURLE_SSL_CERTPROBLEM);
    if(c == CURLE_OK) {
      *envir = h;
      return c;
    }
  }
  /* Error: rollback. */
  gsk_environment_close(&h);
  return c;
}


static void cancel_async_handshake(struct connectdata * conn, int sockindex)
{
  struct ssl_connect_data * connssl = &conn->ssl[sockindex];
  Qso_OverlappedIO_t cstat;

  if(QsoCancelOperation(conn->sock[sockindex], 0) > 0)
    QsoWaitForIOCompletion(connssl->iocport, &cstat, (struct timeval *) NULL);
}


static void close_async_handshake(struct ssl_connect_data * connssl)
{
  QsoDestroyIOCompletionPort(connssl->iocport);
  connssl->iocport = -1;
}


static void close_one(struct ssl_connect_data * conn,
                      struct SessionHandle * data)
{
  if(conn->handle) {
    gskit_status(data, gsk_secure_soc_close(&conn->handle),
              "gsk_secure_soc_close()", 0);
    conn->handle = (gsk_handle) NULL;
  }
  if(conn->iocport >= 0)
    close_async_handshake(conn);
}


static ssize_t gskit_send(struct connectdata * conn, int sockindex,
                           const void * mem, size_t len, CURLcode * curlcode)
{
  struct SessionHandle * data = conn->data;
  CURLcode cc;
  int written;

  cc = gskit_status(data,
                    gsk_secure_soc_write(conn->ssl[sockindex].handle,
                                         (char *) mem, (int) len, &written),
                    "gsk_secure_soc_write()", CURLE_SEND_ERROR);
  if(cc != CURLE_OK) {
    *curlcode = cc;
    written = -1;
  }
  return (ssize_t) written; /* number of bytes */
}


static ssize_t gskit_recv(struct connectdata * conn, int num, char * buf,
                           size_t buffersize, CURLcode * curlcode)
{
  struct SessionHandle * data = conn->data;
  int buffsize;
  int nread;
  CURLcode cc;

  buffsize = buffersize > (size_t) INT_MAX? INT_MAX: (int) buffersize;
  cc = gskit_status(data, gsk_secure_soc_read(conn->ssl[num].handle,
                                              buf, buffsize, &nread),
                    "gsk_secure_soc_read()", CURLE_RECV_ERROR);
  if(cc != CURLE_OK) {
    *curlcode = cc;
    nread = -1;
  }
  return (ssize_t) nread;
}


static CURLcode gskit_connect_step1(struct connectdata * conn, int sockindex)
{
  struct SessionHandle * data = conn->data;
  struct ssl_connect_data * connssl = &conn->ssl[sockindex];
  gsk_handle envir;
  CURLcode cc;
  int rc;
  char * keyringfile;
  char * keyringpwd;
  char * keyringlabel;
  char * v2ciphers;
  char * v3ciphers;
  char * sni;
  bool sslv2enable, sslv3enable, tlsv1enable;
  long timeout;
  Qso_OverlappedIO_t commarea;

  /* Create SSL environment, start (preferably asynchronous) handshake. */

  connssl->handle = (gsk_handle) NULL;
  connssl->iocport = -1;

  /* GSKit supports two ways of specifying an SSL context: either by
   *  application identifier (that should have been defined at the system
   *  level) or by keyring file, password and certificate label.
   * Local certificate name (CURLOPT_SSLCERT) is used to hold either the
   *  application identifier of the certificate label.
   * Key password (CURLOPT_KEYPASSWD) holds the keyring password.
   * It is not possible to have different keyrings for the CAs and the
   *  local certificate. We thus use the CA file (CURLOPT_CAINFO) to identify
   *  the keyring file.
   * If no key password is given and the keyring is the system keyring,
   *  application identifier mode is tried first, as recommended in IBM doc.
   */

  keyringfile = data->set.str[STRING_SSL_CAFILE];
  keyringpwd = data->set.str[STRING_KEY_PASSWD];
  keyringlabel = data->set.str[STRING_CERT];
  envir = (gsk_handle) NULL;

  if(keyringlabel && *keyringlabel && !keyringpwd &&
      !strcmp(keyringfile, CURL_CA_BUNDLE)) {
    /* Try application identifier mode. */
    init_environment(data, &envir, keyringlabel, (const char *) NULL,
                     (const char *) NULL, (const char *) NULL);
  }

  if(!envir) {
    /* Use keyring mode. */
    cc = init_environment(data, &envir, (const char *) NULL,
                          keyringfile, keyringlabel, keyringpwd);
    if(cc != CURLE_OK)
      return cc;
  }

  /* Create secure session. */
  cc = gskit_status(data, gsk_secure_soc_open(envir, &connssl->handle),
                    "gsk_secure_soc_open()", CURLE_SSL_CONNECT_ERROR);
  gsk_environment_close(&envir);
  if(cc != CURLE_OK)
    return cc;

  /* Determine which SSL/TLS version should be enabled. */
  sslv2enable = sslv3enable = tlsv1enable = false;
  sni = conn->host.name;
  switch (data->set.ssl.version) {
  case CURL_SSLVERSION_SSLv2:
    sslv2enable = true;
    sni = (char *) NULL;
    break;
  case CURL_SSLVERSION_SSLv3:
    sslv3enable = true;
    sni = (char *) NULL;
    break;
  case CURL_SSLVERSION_TLSv1:
    tlsv1enable = true;
    break;
  default:              /* CURL_SSLVERSION_DEFAULT. */
    sslv3enable = true;
    tlsv1enable = true;
    break;
  }

  /* Process SNI. Ignore if not supported (on OS400 < V7R1). */
  if(sni) {
    rc = gsk_attribute_set_buffer(connssl->handle,
                                  GSK_SSL_EXTN_SERVERNAME_REQUEST, sni, 0);
    switch (rc) {
    case GSK_OK:
    case GSK_ATTRIBUTE_INVALID_ID:
      break;
    case GSK_ERROR_IO:
      failf(data, "gsk_attribute_set_buffer() I/O error: %s", strerror(errno));
      cc = CURLE_SSL_CONNECT_ERROR;
      break;
    default:
      failf(data, "gsk_attribute_set_buffer(): %s", gsk_strerror(rc));
      cc = CURLE_SSL_CONNECT_ERROR;
      break;
    }
  }

  /* Set session parameters. */
  if(cc == CURLE_OK) {
    /* Compute the handshake timeout. Since GSKit granularity is 1 second,
       we round up the required value. */
    timeout = Curl_timeleft(data, NULL, TRUE);
    if(timeout < 0)
      cc = CURLE_OPERATION_TIMEDOUT;
    else
      cc = set_numeric(data, connssl->handle, GSK_HANDSHAKE_TIMEOUT,
                       (timeout + 999) / 1000);
  }
  if(cc == CURLE_OK)
    cc = set_numeric(data, connssl->handle, GSK_FD, conn->sock[sockindex]);
  if(cc == CURLE_OK)
    cc = set_ciphers(data, connssl->handle);
  if(cc == CURLE_OK)
      cc = set_enum(data, connssl->handle, GSK_PROTOCOL_SSLV2,
                    sslv2enable? GSK_PROTOCOL_SSLV2_ON:
                    GSK_PROTOCOL_SSLV2_OFF);
  if(cc == CURLE_OK)
    cc = set_enum(data, connssl->handle, GSK_PROTOCOL_SSLV3,
                  sslv3enable? GSK_PROTOCOL_SSLV3_ON:
                  GSK_PROTOCOL_SSLV3_OFF);
  if(cc == CURLE_OK)
    cc = set_enum(data, connssl->handle, GSK_PROTOCOL_TLSV1,
                  sslv3enable?  GSK_PROTOCOL_TLSV1_ON:
                  GSK_PROTOCOL_TLSV1_OFF);
  if(cc == CURLE_OK)
    cc = set_enum(data, connssl->handle, GSK_SERVER_AUTH_TYPE,
                  data->set.ssl.verifypeer? GSK_SERVER_AUTH_FULL:
                  GSK_SERVER_AUTH_PASSTHRU);

  if(cc == CURLE_OK) {
    /* Start handshake. Try asynchronous first. */
    memset(&commarea, 0, sizeof commarea);
    connssl->iocport = QsoCreateIOCompletionPort();
    if(connssl->iocport != -1) {
      cc = gskit_status(data, gsk_secure_soc_startInit(connssl->handle,
                        connssl->iocport, &commarea),
                        "gsk_secure_soc_startInit()", CURLE_SSL_CONNECT_ERROR);
      if(cc == CURLE_OK) {
        connssl->connecting_state = ssl_connect_2;
        return CURLE_OK;
      }
      else
        close_async_handshake(connssl);
    }
    else if(errno != ENOBUFS)
      cc = gskit_status(data, GSK_ERROR_IO, "QsoCreateIOCompletionPort()", 0);
    else {
      /* No more completion port available. Use synchronous IO. */
      cc = gskit_status(data, gsk_secure_soc_init(connssl->handle),
                       "gsk_secure_soc_init()", CURLE_SSL_CONNECT_ERROR);
      if(cc == CURLE_OK) {
        connssl->connecting_state = ssl_connect_3;
        return CURLE_OK;
      }
    }
  }

  /* Error: rollback. */
  close_one(connssl, data);
  return cc;
}


static CURLcode gskit_connect_step2(struct connectdata * conn, int sockindex,
                                    bool nonblocking)
{
  struct SessionHandle * data = conn->data;
  struct ssl_connect_data * connssl = &conn->ssl[sockindex];
  Qso_OverlappedIO_t cstat;
  long timeout_ms;
  struct timeval stmv;
  CURLcode cc;

  /* Poll or wait for end of SSL asynchronous handshake. */

  for(;;) {
    timeout_ms = nonblocking? 0: Curl_timeleft(data, NULL, TRUE);
    if(timeout_ms < 0)
      timeout_ms = 0;
    stmv.tv_sec = timeout_ms / 1000;
    stmv.tv_usec = (timeout_ms - stmv.tv_sec * 1000) * 1000;
    switch (QsoWaitForIOCompletion(connssl->iocport, &cstat, &stmv)) {
    case 1:             /* Operation complete. */
      break;
    case -1:            /* An error occurred: handshake still in progress. */
      if(errno == EINTR) {
        if(nonblocking)
          return CURLE_OK;
        continue;       /* Retry. */
      }
      if(errno != ETIME) {
        failf(data, "QsoWaitForIOCompletion() I/O error: %s", strerror(errno));
        cancel_async_handshake(conn, sockindex);
        close_async_handshake(connssl);
        return CURLE_SSL_CONNECT_ERROR;
      }
      /* FALL INTO... */
    case 0:             /* Handshake in progress, timeout occurred. */
      if(nonblocking)
        return CURLE_OK;
      cancel_async_handshake(conn, sockindex);
      close_async_handshake(connssl);
      return CURLE_OPERATION_TIMEDOUT;
    }
    break;
  }
  cc = gskit_status(data, cstat.returnValue, "SSL handshake",
                    CURLE_SSL_CONNECT_ERROR);
  if(cc == CURLE_OK)
    connssl->connecting_state = ssl_connect_3;
  close_async_handshake(connssl);
  return cc;
}


static CURLcode gskit_connect_step3(struct connectdata * conn, int sockindex)
{
  struct SessionHandle * data = conn->data;
  struct ssl_connect_data * connssl = &conn->ssl[sockindex];
  const gsk_cert_data_elem * cdev;
  int cdec;
  const gsk_cert_data_elem * p;
  const char * cert = (const char *) NULL;
  const char * certend;
  int i;
  CURLcode cc;

  /* SSL handshake done: gather certificate info and verify host. */

  if(gskit_status(data, gsk_attribute_get_cert_info(connssl->handle,
                                                    GSK_PARTNER_CERT_INFO,
                                                    &cdev, &cdec),
                  "gsk_attribute_get_cert_info()", CURLE_SSL_CONNECT_ERROR) ==
     CURLE_OK) {
    infof(data, "Server certificate:\n");
    p = cdev;
    for(i = 0; i++ < cdec; p++)
      switch (p->cert_data_id) {
      case CERT_BODY_DER:
        cert = p->cert_data_p;
        certend = cert + cdev->cert_data_l;
        break;
      case CERT_DN_PRINTABLE:
        infof(data, "\t subject: %.*s\n", p->cert_data_l, p->cert_data_p);
        break;
      case CERT_ISSUER_DN_PRINTABLE:
        infof(data, "\t issuer: %.*s\n", p->cert_data_l, p->cert_data_p);
        break;
      case CERT_VALID_FROM:
        infof(data, "\t start date: %.*s\n", p->cert_data_l, p->cert_data_p);
        break;
      case CERT_VALID_TO:
        infof(data, "\t expire date: %.*s\n", p->cert_data_l, p->cert_data_p);
        break;
    }
  }

  /* Verify host. */
  cc = Curl_verifyhost(conn, cert, certend);
  if(cc != CURLE_OK)
    return cc;

  /* The only place GSKit can get the whole CA chain is a validation
     callback where no user data pointer is available. Therefore it's not
     possible to copy this chain into our structures for CAINFO.
     However the server certificate may be available, thus we can return
     info about it. */
  if(data->set.ssl.certinfo) {
    if(Curl_ssl_init_certinfo(data, 1))
      return CURLE_OUT_OF_MEMORY;
    if(cert) {
      cc = Curl_extract_certinfo(conn, 0, cert, certend);
      if(cc != CURLE_OK)
        return cc;
    }
  }

  connssl->connecting_state = ssl_connect_done;
  return CURLE_OK;
}


static CURLcode gskit_connect_common(struct connectdata * conn, int sockindex,
                                     bool nonblocking, bool * done)
{
  struct SessionHandle * data = conn->data;
  struct ssl_connect_data * connssl = &conn->ssl[sockindex];
  long timeout_ms;
  Qso_OverlappedIO_t cstat;
  CURLcode cc = CURLE_OK;

  *done = connssl->state == ssl_connection_complete;
  if(*done)
    return CURLE_OK;

  /* Step 1: create session, start handshake. */
  if(connssl->connecting_state == ssl_connect_1) {
    /* check allowed time left */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      cc = CURLE_OPERATION_TIMEDOUT;
    }
    else
      cc = gskit_connect_step1(conn, sockindex);
  }

  /* Step 2: check if handshake is over. */
  if(cc == CURLE_OK && connssl->connecting_state == ssl_connect_2) {
    /* check allowed time left */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      cc = CURLE_OPERATION_TIMEDOUT;
    }
    else
      cc = gskit_connect_step2(conn, sockindex, nonblocking);
  }

  /* Step 3: gather certificate info, verify host. */
  if(cc == CURLE_OK && connssl->connecting_state == ssl_connect_3)
    cc = gskit_connect_step3(conn, sockindex);

  if(cc != CURLE_OK)
    close_one(connssl, data);
  else if(connssl->connecting_state == ssl_connect_done) {
    connssl->state = ssl_connection_complete;
    connssl->connecting_state = ssl_connect_1;
    conn->recv[sockindex] = gskit_recv;
    conn->send[sockindex] = gskit_send;
    *done = TRUE;
  }

  return cc;
}


CURLcode Curl_gskit_connect_nonblocking(struct connectdata * conn,
                                        int sockindex,
                                        bool * done)
{
  CURLcode cc;

  cc = gskit_connect_common(conn, sockindex, TRUE, done);
  if(*done || cc != CURLE_OK)
    conn->ssl[sockindex].connecting_state = ssl_connect_1;
  return cc;
}


CURLcode Curl_gskit_connect(struct connectdata * conn, int sockindex)
{
  CURLcode retcode;
  bool done;

  conn->ssl[sockindex].connecting_state = ssl_connect_1;
  retcode = gskit_connect_common(conn, sockindex, FALSE, &done);
  if(retcode)
    return retcode;

  DEBUGASSERT(done);

  return CURLE_OK;
}


void Curl_gskit_close(struct connectdata * conn, int sockindex)
{
  struct SessionHandle * data = conn->data;
  struct ssl_connect_data * connssl = &conn->ssl[sockindex];

  if(connssl->use)
    close_one(connssl, data);
}


int Curl_gskit_close_all(struct SessionHandle * data)
{
  /* Unimplemented. */
  (void) data;
  return 0;
}


int Curl_gskit_shutdown(struct connectdata * conn, int sockindex)
{
  struct ssl_connect_data * connssl = &conn->ssl[sockindex];
  struct SessionHandle * data = conn->data;
  ssize_t nread;
  int what;
  int rc;
  char buf[120];

  if(!connssl->handle)
    return 0;

  if(data->set.ftp_ccc != CURLFTPSSL_CCC_ACTIVE)
    return 0;

  close_one(connssl, data);
  rc = 0;
  what = Curl_socket_ready(conn->sock[sockindex],
                           CURL_SOCKET_BAD, SSL_SHUTDOWN_TIMEOUT);

  for(;;) {
    if(what < 0) {
      /* anything that gets here is fatally bad */
      failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
      rc = -1;
      break;
    }

    if(!what) {                                /* timeout */
      failf(data, "SSL shutdown timeout");
      break;
    }

    /* Something to read, let's do it and hope that it is the close
       notify alert from the server. No way to gsk_secure_soc_read() now, so
       use read(). */

    nread = read(conn->sock[sockindex], buf, sizeof(buf));

    if(nread < 0) {
      failf(data, "read: %s", strerror(errno));
      rc = -1;
    }

    if(nread <= 0)
      break;

    what = Curl_socket_ready(conn->sock[sockindex], CURL_SOCKET_BAD, 0);
  }

  return rc;
}


size_t Curl_gskit_version(char * buffer, size_t size)
{
  strncpy(buffer, "GSKit", size);
  return strlen(buffer);
}


int Curl_gskit_check_cxn(struct connectdata * cxn)
{
  int err;
  int errlen;

  /* The only thing that can be tested here is at the socket level. */

  if(!cxn->ssl[FIRSTSOCKET].handle)
    return 0; /* connection has been closed */

  err = 0;
  errlen = sizeof err;

  if(getsockopt(cxn->sock[FIRSTSOCKET], SOL_SOCKET, SO_ERROR,
                 (unsigned char *) &err, &errlen) ||
     errlen != sizeof err || err)
    return 0; /* connection has been closed */

  return -1;  /* connection status unknown */
}

#endif /* USE_GSKIT */
