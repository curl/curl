/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012 - 2014, Nick Zitzmann, <nickzman@gmail.com>.
 * Copyright (C) 2012 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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
 * Source file for all iOS and Mac OS X SecureTransport-specific code for the
 * TLS/SSL layer. No code but vtls.c should ever call or use these functions.
 */

#include "curl_setup.h"

#include "urldata.h" /* for the Curl_easy definition */
#include "curl_base64.h"
#include "strtok.h"

#ifdef USE_DARWINSSL

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>

/* The Security framework has changed greatly between iOS and different OS X
   versions, and we will try to support as many of them as we can (back to
   Leopard and iOS 5) by using macros and weak-linking.

   IMPORTANT: If TLS 1.1 and 1.2 support are important for you on OS X, then
   you must build this project against the 10.8 SDK or later. */
#if (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE))

#if MAC_OS_X_VERSION_MAX_ALLOWED < 1050
#error "The darwinssl back-end requires Leopard or later."
#endif /* MAC_OS_X_VERSION_MAX_ALLOWED < 1050 */

#define CURL_BUILD_IOS 0
#define CURL_BUILD_IOS_7 0
#define CURL_BUILD_MAC 1
/* This is the maximum API level we are allowed to use when building: */
#define CURL_BUILD_MAC_10_5 MAC_OS_X_VERSION_MAX_ALLOWED >= 1050
#define CURL_BUILD_MAC_10_6 MAC_OS_X_VERSION_MAX_ALLOWED >= 1060
#define CURL_BUILD_MAC_10_7 MAC_OS_X_VERSION_MAX_ALLOWED >= 1070
#define CURL_BUILD_MAC_10_8 MAC_OS_X_VERSION_MAX_ALLOWED >= 1080
#define CURL_BUILD_MAC_10_9 MAC_OS_X_VERSION_MAX_ALLOWED >= 1090
/* These macros mean "the following code is present to allow runtime backward
   compatibility with at least this cat or earlier":
   (You set this at build-time by setting the MACOSX_DEPLOYMENT_TARGET
   environmental variable.) */
#define CURL_SUPPORT_MAC_10_5 MAC_OS_X_VERSION_MIN_REQUIRED <= 1050
#define CURL_SUPPORT_MAC_10_6 MAC_OS_X_VERSION_MIN_REQUIRED <= 1060
#define CURL_SUPPORT_MAC_10_7 MAC_OS_X_VERSION_MIN_REQUIRED <= 1070
#define CURL_SUPPORT_MAC_10_8 MAC_OS_X_VERSION_MIN_REQUIRED <= 1080
#define CURL_SUPPORT_MAC_10_9 MAC_OS_X_VERSION_MIN_REQUIRED <= 1090

#elif TARGET_OS_EMBEDDED || TARGET_OS_IPHONE
#define CURL_BUILD_IOS 1
#define CURL_BUILD_IOS_7 __IPHONE_OS_VERSION_MAX_ALLOWED >= 70000
#define CURL_BUILD_MAC 0
#define CURL_BUILD_MAC_10_5 0
#define CURL_BUILD_MAC_10_6 0
#define CURL_BUILD_MAC_10_7 0
#define CURL_BUILD_MAC_10_8 0
#define CURL_SUPPORT_MAC_10_5 0
#define CURL_SUPPORT_MAC_10_6 0
#define CURL_SUPPORT_MAC_10_7 0
#define CURL_SUPPORT_MAC_10_8 0
#define CURL_SUPPORT_MAC_10_9 0

#else
#error "The darwinssl back-end requires iOS or OS X."
#endif /* (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE)) */

#if CURL_BUILD_MAC
#include <sys/sysctl.h>
#endif /* CURL_BUILD_MAC */

#include "urldata.h"
#include "sendf.h"
#include "inet_pton.h"
#include "connect.h"
#include "select.h"
#include "vtls.h"
#include "darwinssl.h"
#include "curl_printf.h"

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/* From MacTypes.h (which we can't include because it isn't present in iOS: */
#define ioErr -36
#define paramErr -50

#ifdef DARWIN_SSL_PINNEDPUBKEY
/* both new and old APIs return rsa keys missing the spki header (not DER) */
static const unsigned char rsa4096SpkiHeader[] = {
                                       0x30, 0x82, 0x02, 0x22, 0x30, 0x0d,
                                       0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                       0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
                                       0x00, 0x03, 0x82, 0x02, 0x0f, 0x00};

static const unsigned char rsa2048SpkiHeader[] = {
                                       0x30, 0x82, 0x01, 0x22, 0x30, 0x0d,
                                       0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                       0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
                                       0x00, 0x03, 0x82, 0x01, 0x0f, 0x00};
#ifdef DARWIN_SSL_PINNEDPUBKEY_V1
/* the *new* version doesn't return DER encoded ecdsa certs like the old... */
static const unsigned char ecDsaSecp256r1SpkiHeader[] = {
                                       0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
                                       0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
                                       0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
                                       0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
                                       0x42, 0x00};

static const unsigned char ecDsaSecp384r1SpkiHeader[] = {
                                       0x30, 0x76, 0x30, 0x10, 0x06, 0x07,
                                       0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
                                       0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,
                                       0x00, 0x22, 0x03, 0x62, 0x00};
#endif /* DARWIN_SSL_PINNEDPUBKEY_V1 */
#endif /* DARWIN_SSL_PINNEDPUBKEY */

/* The following two functions were ripped from Apple sample code,
 * with some modifications: */
static OSStatus SocketRead(SSLConnectionRef connection,
                           void *data,          /* owned by
                                                 * caller, data
                                                 * RETURNED */
                           size_t *dataLength)  /* IN/OUT */
{
  size_t bytesToGo = *dataLength;
  size_t initLen = bytesToGo;
  UInt8 *currData = (UInt8 *)data;
  /*int sock = *(int *)connection;*/
  struct ssl_connect_data *connssl = (struct ssl_connect_data *)connection;
  int sock = connssl->ssl_sockfd;
  OSStatus rtn = noErr;
  size_t bytesRead;
  ssize_t rrtn;
  int theErr;

  *dataLength = 0;

  for(;;) {
    bytesRead = 0;
    rrtn = read(sock, currData, bytesToGo);
    if(rrtn <= 0) {
      /* this is guesswork... */
      theErr = errno;
      if(rrtn == 0) { /* EOF = server hung up */
        /* the framework will turn this into errSSLClosedNoNotify */
        rtn = errSSLClosedGraceful;
      }
      else /* do the switch */
        switch(theErr) {
          case ENOENT:
            /* connection closed */
            rtn = errSSLClosedGraceful;
            break;
          case ECONNRESET:
            rtn = errSSLClosedAbort;
            break;
          case EAGAIN:
            rtn = errSSLWouldBlock;
            connssl->ssl_direction = false;
            break;
          default:
            rtn = ioErr;
            break;
        }
      break;
    }
    else {
      bytesRead = rrtn;
    }
    bytesToGo -= bytesRead;
    currData  += bytesRead;

    if(bytesToGo == 0) {
      /* filled buffer with incoming data, done */
      break;
    }
  }
  *dataLength = initLen - bytesToGo;

  return rtn;
}

static OSStatus SocketWrite(SSLConnectionRef connection,
                            const void *data,
                            size_t *dataLength)  /* IN/OUT */
{
  size_t bytesSent = 0;
  /*int sock = *(int *)connection;*/
  struct ssl_connect_data *connssl = (struct ssl_connect_data *)connection;
  int sock = connssl->ssl_sockfd;
  ssize_t length;
  size_t dataLen = *dataLength;
  const UInt8 *dataPtr = (UInt8 *)data;
  OSStatus ortn;
  int theErr;

  *dataLength = 0;

  do {
    length = write(sock,
                   (char *)dataPtr + bytesSent,
                   dataLen - bytesSent);
  } while((length > 0) &&
           ( (bytesSent += length) < dataLen) );

  if(length <= 0) {
    theErr = errno;
    if(theErr == EAGAIN) {
      ortn = errSSLWouldBlock;
      connssl->ssl_direction = true;
    }
    else {
      ortn = ioErr;
    }
  }
  else {
    ortn = noErr;
  }
  *dataLength = bytesSent;
  return ortn;
}

#ifndef CURL_DISABLE_VERBOSE_STRINGS
CF_INLINE const char *SSLCipherNameForNumber(SSLCipherSuite cipher)
{
  switch(cipher) {
    /* SSL version 3.0 */
    case SSL_RSA_WITH_NULL_MD5:
      return "SSL_RSA_WITH_NULL_MD5";
      break;
    case SSL_RSA_WITH_NULL_SHA:
      return "SSL_RSA_WITH_NULL_SHA";
      break;
    case SSL_RSA_EXPORT_WITH_RC4_40_MD5:
      return "SSL_RSA_EXPORT_WITH_RC4_40_MD5";
      break;
    case SSL_RSA_WITH_RC4_128_MD5:
      return "SSL_RSA_WITH_RC4_128_MD5";
      break;
    case SSL_RSA_WITH_RC4_128_SHA:
      return "SSL_RSA_WITH_RC4_128_SHA";
      break;
    case SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
      return "SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5";
      break;
    case SSL_RSA_WITH_IDEA_CBC_SHA:
      return "SSL_RSA_WITH_IDEA_CBC_SHA";
      break;
    case SSL_RSA_EXPORT_WITH_DES40_CBC_SHA:
      return "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA";
      break;
    case SSL_RSA_WITH_DES_CBC_SHA:
      return "SSL_RSA_WITH_DES_CBC_SHA";
      break;
    case SSL_RSA_WITH_3DES_EDE_CBC_SHA:
      return "SSL_RSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:
      return "SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA";
      break;
    case SSL_DH_DSS_WITH_DES_CBC_SHA:
      return "SSL_DH_DSS_WITH_DES_CBC_SHA";
      break;
    case SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA:
      return "SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA";
      break;
    case SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:
      return "SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA";
      break;
    case SSL_DH_RSA_WITH_DES_CBC_SHA:
      return "SSL_DH_RSA_WITH_DES_CBC_SHA";
      break;
    case SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA:
      return "SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:
      return "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA";
      break;
    case SSL_DHE_DSS_WITH_DES_CBC_SHA:
      return "SSL_DHE_DSS_WITH_DES_CBC_SHA";
      break;
    case SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
      return "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA";
      break;
    case SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:
      return "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA";
      break;
    case SSL_DHE_RSA_WITH_DES_CBC_SHA:
      return "SSL_DHE_RSA_WITH_DES_CBC_SHA";
      break;
    case SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
      return "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case SSL_DH_anon_EXPORT_WITH_RC4_40_MD5:
      return "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5";
      break;
    case SSL_DH_anon_WITH_RC4_128_MD5:
      return "SSL_DH_anon_WITH_RC4_128_MD5";
      break;
    case SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA:
      return "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA";
      break;
    case SSL_DH_anon_WITH_DES_CBC_SHA:
      return "SSL_DH_anon_WITH_DES_CBC_SHA";
      break;
    case SSL_DH_anon_WITH_3DES_EDE_CBC_SHA:
      return "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA";
      break;
    case SSL_FORTEZZA_DMS_WITH_NULL_SHA:
      return "SSL_FORTEZZA_DMS_WITH_NULL_SHA";
      break;
    case SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA:
      return "SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA";
      break;
    /* TLS 1.0 with AES (RFC 3268)
       (Apparently these are used in SSLv3 implementations as well.) */
    case TLS_RSA_WITH_AES_128_CBC_SHA:
      return "TLS_RSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA:
      return "TLS_DH_DSS_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA:
      return "TLS_DH_RSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
      return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
      return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DH_anon_WITH_AES_128_CBC_SHA:
      return "TLS_DH_anon_WITH_AES_128_CBC_SHA";
      break;
    case TLS_RSA_WITH_AES_256_CBC_SHA:
      return "TLS_RSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA:
      return "TLS_DH_DSS_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA:
      return "TLS_DH_RSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
      return "TLS_DHE_DSS_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
      return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DH_anon_WITH_AES_256_CBC_SHA:
      return "TLS_DH_anon_WITH_AES_256_CBC_SHA";
      break;
    /* SSL version 2.0 */
    case SSL_RSA_WITH_RC2_CBC_MD5:
      return "SSL_RSA_WITH_RC2_CBC_MD5";
      break;
    case SSL_RSA_WITH_IDEA_CBC_MD5:
      return "SSL_RSA_WITH_IDEA_CBC_MD5";
      break;
    case SSL_RSA_WITH_DES_CBC_MD5:
      return "SSL_RSA_WITH_DES_CBC_MD5";
      break;
    case SSL_RSA_WITH_3DES_EDE_CBC_MD5:
      return "SSL_RSA_WITH_3DES_EDE_CBC_MD5";
      break;
  }
  return "SSL_NULL_WITH_NULL_NULL";
}

CF_INLINE const char *TLSCipherNameForNumber(SSLCipherSuite cipher)
{
  switch(cipher) {
    /* TLS 1.0 with AES (RFC 3268) */
    case TLS_RSA_WITH_AES_128_CBC_SHA:
      return "TLS_RSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA:
      return "TLS_DH_DSS_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA:
      return "TLS_DH_RSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
      return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
      return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DH_anon_WITH_AES_128_CBC_SHA:
      return "TLS_DH_anon_WITH_AES_128_CBC_SHA";
      break;
    case TLS_RSA_WITH_AES_256_CBC_SHA:
      return "TLS_RSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA:
      return "TLS_DH_DSS_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA:
      return "TLS_DH_RSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
      return "TLS_DHE_DSS_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
      return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DH_anon_WITH_AES_256_CBC_SHA:
      return "TLS_DH_anon_WITH_AES_256_CBC_SHA";
      break;
#if CURL_BUILD_MAC_10_6 || CURL_BUILD_IOS
    /* TLS 1.0 with ECDSA (RFC 4492) */
    case TLS_ECDH_ECDSA_WITH_NULL_SHA:
      return "TLS_ECDH_ECDSA_WITH_NULL_SHA";
      break;
    case TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
      return "TLS_ECDH_ECDSA_WITH_RC4_128_SHA";
      break;
    case TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
      return "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
      return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
      return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_ECDHE_ECDSA_WITH_NULL_SHA:
      return "TLS_ECDHE_ECDSA_WITH_NULL_SHA";
      break;
    case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
      return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA";
      break;
    case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
      return "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
      return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
      return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_ECDH_RSA_WITH_NULL_SHA:
      return "TLS_ECDH_RSA_WITH_NULL_SHA";
      break;
    case TLS_ECDH_RSA_WITH_RC4_128_SHA:
      return "TLS_ECDH_RSA_WITH_RC4_128_SHA";
      break;
    case TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
      return "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
      return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
      return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_ECDHE_RSA_WITH_NULL_SHA:
      return "TLS_ECDHE_RSA_WITH_NULL_SHA";
      break;
    case TLS_ECDHE_RSA_WITH_RC4_128_SHA:
      return "TLS_ECDHE_RSA_WITH_RC4_128_SHA";
      break;
    case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
      return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
      return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
      return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_ECDH_anon_WITH_NULL_SHA:
      return "TLS_ECDH_anon_WITH_NULL_SHA";
      break;
    case TLS_ECDH_anon_WITH_RC4_128_SHA:
      return "TLS_ECDH_anon_WITH_RC4_128_SHA";
      break;
    case TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA:
      return "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
      return "TLS_ECDH_anon_WITH_AES_128_CBC_SHA";
      break;
    case TLS_ECDH_anon_WITH_AES_256_CBC_SHA:
      return "TLS_ECDH_anon_WITH_AES_256_CBC_SHA";
      break;
#endif /* CURL_BUILD_MAC_10_6 || CURL_BUILD_IOS */
#if CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS
    /* TLS 1.2 (RFC 5246) */
    case TLS_RSA_WITH_NULL_MD5:
      return "TLS_RSA_WITH_NULL_MD5";
      break;
    case TLS_RSA_WITH_NULL_SHA:
      return "TLS_RSA_WITH_NULL_SHA";
      break;
    case TLS_RSA_WITH_RC4_128_MD5:
      return "TLS_RSA_WITH_RC4_128_MD5";
      break;
    case TLS_RSA_WITH_RC4_128_SHA:
      return "TLS_RSA_WITH_RC4_128_SHA";
      break;
    case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
      return "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_RSA_WITH_NULL_SHA256:
      return "TLS_RSA_WITH_NULL_SHA256";
      break;
    case TLS_RSA_WITH_AES_128_CBC_SHA256:
      return "TLS_RSA_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_RSA_WITH_AES_256_CBC_SHA256:
      return "TLS_RSA_WITH_AES_256_CBC_SHA256";
      break;
    case TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
      return "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
      return "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
      return "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
      return "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
      return "TLS_DH_DSS_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
      return "TLS_DH_RSA_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
      return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
      return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
      return "TLS_DH_DSS_WITH_AES_256_CBC_SHA256";
      break;
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
      return "TLS_DH_RSA_WITH_AES_256_CBC_SHA256";
      break;
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
      return "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256";
      break;
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
      return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256";
      break;
    case TLS_DH_anon_WITH_RC4_128_MD5:
      return "TLS_DH_anon_WITH_RC4_128_MD5";
      break;
    case TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
      return "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_DH_anon_WITH_AES_128_CBC_SHA256:
      return "TLS_DH_anon_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_DH_anon_WITH_AES_256_CBC_SHA256:
      return "TLS_DH_anon_WITH_AES_256_CBC_SHA256";
      break;
    /* TLS 1.2 with AES GCM (RFC 5288) */
    case TLS_RSA_WITH_AES_128_GCM_SHA256:
      return "TLS_RSA_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_RSA_WITH_AES_256_GCM_SHA384:
      return "TLS_RSA_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
      return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
      return "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
      return "TLS_DH_RSA_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
      return "TLS_DH_RSA_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
      return "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
      return "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
      return "TLS_DH_DSS_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
      return "TLS_DH_DSS_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_DH_anon_WITH_AES_128_GCM_SHA256:
      return "TLS_DH_anon_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_DH_anon_WITH_AES_256_GCM_SHA384:
      return "TLS_DH_anon_WITH_AES_256_GCM_SHA384";
      break;
    /* TLS 1.2 with elliptic curve ciphers (RFC 5289) */
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
      return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
      return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
      break;
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
      return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
      return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384";
      break;
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
      return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
      return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
      break;
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
      return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
      return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384";
      break;
    case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
      return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
      return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
      return "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
      return "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
      return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
      return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
      return "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
      return "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_EMPTY_RENEGOTIATION_INFO_SCSV:
      return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
      break;
#else
    case SSL_RSA_WITH_NULL_MD5:
      return "TLS_RSA_WITH_NULL_MD5";
      break;
    case SSL_RSA_WITH_NULL_SHA:
      return "TLS_RSA_WITH_NULL_SHA";
      break;
    case SSL_RSA_WITH_RC4_128_MD5:
      return "TLS_RSA_WITH_RC4_128_MD5";
      break;
    case SSL_RSA_WITH_RC4_128_SHA:
      return "TLS_RSA_WITH_RC4_128_SHA";
      break;
    case SSL_RSA_WITH_3DES_EDE_CBC_SHA:
      return "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case SSL_DH_anon_WITH_RC4_128_MD5:
      return "TLS_DH_anon_WITH_RC4_128_MD5";
      break;
    case SSL_DH_anon_WITH_3DES_EDE_CBC_SHA:
      return "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA";
      break;
#endif /* CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS */
#if CURL_BUILD_MAC_10_9 || CURL_BUILD_IOS_7
    /* TLS PSK (RFC 4279): */
    case TLS_PSK_WITH_RC4_128_SHA:
      return "TLS_PSK_WITH_RC4_128_SHA";
      break;
    case TLS_PSK_WITH_3DES_EDE_CBC_SHA:
      return "TLS_PSK_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_PSK_WITH_AES_128_CBC_SHA:
      return "TLS_PSK_WITH_AES_128_CBC_SHA";
      break;
    case TLS_PSK_WITH_AES_256_CBC_SHA:
      return "TLS_PSK_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DHE_PSK_WITH_RC4_128_SHA:
      return "TLS_DHE_PSK_WITH_RC4_128_SHA";
      break;
    case TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
      return "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
      return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
      return "TLS_DHE_PSK_WITH_AES_256_CBC_SHA";
      break;
    case TLS_RSA_PSK_WITH_RC4_128_SHA:
      return "TLS_RSA_PSK_WITH_RC4_128_SHA";
      break;
    case TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
      return "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
      return "TLS_RSA_PSK_WITH_AES_128_CBC_SHA";
      break;
    case TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
      return "TLS_RSA_PSK_WITH_AES_256_CBC_SHA";
      break;
    /* More TLS PSK (RFC 4785): */
    case TLS_PSK_WITH_NULL_SHA:
      return "TLS_PSK_WITH_NULL_SHA";
      break;
    case TLS_DHE_PSK_WITH_NULL_SHA:
      return "TLS_DHE_PSK_WITH_NULL_SHA";
      break;
    case TLS_RSA_PSK_WITH_NULL_SHA:
      return "TLS_RSA_PSK_WITH_NULL_SHA";
      break;
    /* Even more TLS PSK (RFC 5487): */
    case TLS_PSK_WITH_AES_128_GCM_SHA256:
      return "TLS_PSK_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_PSK_WITH_AES_256_GCM_SHA384:
      return "TLS_PSK_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
      return "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
      return "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
      return "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
      return "TLS_PSK_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_PSK_WITH_AES_128_CBC_SHA256:
      return "TLS_PSK_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_PSK_WITH_AES_256_CBC_SHA384:
      return "TLS_PSK_WITH_AES_256_CBC_SHA384";
      break;
    case TLS_PSK_WITH_NULL_SHA256:
      return "TLS_PSK_WITH_NULL_SHA256";
      break;
    case TLS_PSK_WITH_NULL_SHA384:
      return "TLS_PSK_WITH_NULL_SHA384";
      break;
    case TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
      return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
      return "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384";
      break;
    case TLS_DHE_PSK_WITH_NULL_SHA256:
      return "TLS_DHE_PSK_WITH_NULL_SHA256";
      break;
    case TLS_DHE_PSK_WITH_NULL_SHA384:
      return "TLS_RSA_PSK_WITH_NULL_SHA384";
      break;
    case TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:
      return "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
      return "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384";
      break;
    case TLS_RSA_PSK_WITH_NULL_SHA256:
      return "TLS_RSA_PSK_WITH_NULL_SHA256";
      break;
    case TLS_RSA_PSK_WITH_NULL_SHA384:
      return "TLS_RSA_PSK_WITH_NULL_SHA384";
      break;
#endif /* CURL_BUILD_MAC_10_9 || CURL_BUILD_IOS_7 */
  }
  return "TLS_NULL_WITH_NULL_NULL";
}
#endif /* !CURL_DISABLE_VERBOSE_STRINGS */

#if CURL_BUILD_MAC
CF_INLINE void GetDarwinVersionNumber(int *major, int *minor)
{
  int mib[2];
  char *os_version;
  size_t os_version_len;
  char *os_version_major, *os_version_minor;
  char *tok_buf;

  /* Get the Darwin kernel version from the kernel using sysctl(): */
  mib[0] = CTL_KERN;
  mib[1] = KERN_OSRELEASE;
  if(sysctl(mib, 2, NULL, &os_version_len, NULL, 0) == -1)
    return;
  os_version = malloc(os_version_len*sizeof(char));
  if(!os_version)
    return;
  if(sysctl(mib, 2, os_version, &os_version_len, NULL, 0) == -1) {
    free(os_version);
    return;
  }

  /* Parse the version: */
  os_version_major = strtok_r(os_version, ".", &tok_buf);
  os_version_minor = strtok_r(NULL, ".", &tok_buf);
  *major = atoi(os_version_major);
  *minor = atoi(os_version_minor);
  free(os_version);
}
#endif /* CURL_BUILD_MAC */

/* Apple provides a myriad of ways of getting information about a certificate
   into a string. Some aren't available under iOS or newer cats. So here's
   a unified function for getting a string describing the certificate that
   ought to work in all cats starting with Leopard. */
CF_INLINE CFStringRef CopyCertSubject(SecCertificateRef cert)
{
  CFStringRef server_cert_summary = CFSTR("(null)");

#if CURL_BUILD_IOS
  /* iOS: There's only one way to do this. */
  server_cert_summary = SecCertificateCopySubjectSummary(cert);
#else
#if CURL_BUILD_MAC_10_7
  /* Lion & later: Get the long description if we can. */
  if(SecCertificateCopyLongDescription != NULL)
    server_cert_summary =
      SecCertificateCopyLongDescription(NULL, cert, NULL);
  else
#endif /* CURL_BUILD_MAC_10_7 */
#if CURL_BUILD_MAC_10_6
  /* Snow Leopard: Get the certificate summary. */
  if(SecCertificateCopySubjectSummary != NULL)
    server_cert_summary = SecCertificateCopySubjectSummary(cert);
  else
#endif /* CURL_BUILD_MAC_10_6 */
  /* Leopard is as far back as we go... */
  (void)SecCertificateCopyCommonName(cert, &server_cert_summary);
#endif /* CURL_BUILD_IOS */
  return server_cert_summary;
}

#if CURL_SUPPORT_MAC_10_6
/* The SecKeychainSearch API was deprecated in Lion, and using it will raise
   deprecation warnings, so let's not compile this unless it's necessary: */
static OSStatus CopyIdentityWithLabelOldSchool(char *label,
                                               SecIdentityRef *out_c_a_k)
{
  OSStatus status = errSecItemNotFound;
  SecKeychainAttributeList attr_list;
  SecKeychainAttribute attr;
  SecKeychainSearchRef search = NULL;
  SecCertificateRef cert = NULL;

  /* Set up the attribute list: */
  attr_list.count = 1L;
  attr_list.attr = &attr;

  /* Set up our lone search criterion: */
  attr.tag = kSecLabelItemAttr;
  attr.data = label;
  attr.length = (UInt32)strlen(label);

  /* Start searching: */
  status = SecKeychainSearchCreateFromAttributes(NULL,
                                                 kSecCertificateItemClass,
                                                 &attr_list,
                                                 &search);
  if(status == noErr) {
    status = SecKeychainSearchCopyNext(search,
                                       (SecKeychainItemRef *)&cert);
    if(status == noErr && cert) {
      /* If we found a certificate, does it have a private key? */
      status = SecIdentityCreateWithCertificate(NULL, cert, out_c_a_k);
      CFRelease(cert);
    }
  }

  if(search)
    CFRelease(search);
  return status;
}
#endif /* CURL_SUPPORT_MAC_10_6 */

static OSStatus CopyIdentityWithLabel(char *label,
                                      SecIdentityRef *out_cert_and_key)
{
  OSStatus status = errSecItemNotFound;

#if CURL_BUILD_MAC_10_7 || CURL_BUILD_IOS
  CFArrayRef keys_list;
  CFIndex keys_list_count;
  CFIndex i;
  CFStringRef common_name;

  /* SecItemCopyMatching() was introduced in iOS and Snow Leopard.
     kSecClassIdentity was introduced in Lion. If both exist, let's use them
     to find the certificate. */
  if(SecItemCopyMatching != NULL && kSecClassIdentity != NULL) {
    CFTypeRef keys[5];
    CFTypeRef values[5];
    CFDictionaryRef query_dict;
    CFStringRef label_cf = CFStringCreateWithCString(NULL, label,
      kCFStringEncodingUTF8);

    /* Set up our search criteria and expected results: */
    values[0] = kSecClassIdentity; /* we want a certificate and a key */
    keys[0] = kSecClass;
    values[1] = kCFBooleanTrue;    /* we want a reference */
    keys[1] = kSecReturnRef;
    values[2] = kSecMatchLimitAll; /* kSecMatchLimitOne would be better if the
                                    * label matching below worked correctly */
    keys[2] = kSecMatchLimit;
    /* identity searches need a SecPolicyRef in order to work */
    values[3] = SecPolicyCreateSSL(false, NULL);
    keys[3] = kSecMatchPolicy;
    /* match the name of the certificate (doesn't work in macOS 10.12.1) */
    values[4] = label_cf;
    keys[4] = kSecAttrLabel;
    query_dict = CFDictionaryCreate(NULL, (const void **)keys,
                                    (const void **)values, 5L,
                                    &kCFCopyStringDictionaryKeyCallBacks,
                                    &kCFTypeDictionaryValueCallBacks);
    CFRelease(values[3]);

    /* Do we have a match? */
    status = SecItemCopyMatching(query_dict, (CFTypeRef *) &keys_list);

    /* Because kSecAttrLabel matching doesn't work with kSecClassIdentity,
     * we need to find the correct identity ourselves */
    if(status == noErr) {
      keys_list_count = CFArrayGetCount(keys_list);
      *out_cert_and_key = NULL;
      status = 1;
      for(i=0; i<keys_list_count; i++) {
        OSStatus err = noErr;
        SecCertificateRef cert = NULL;
        SecIdentityRef identity =
          (SecIdentityRef) CFArrayGetValueAtIndex(keys_list, i);
        err = SecIdentityCopyCertificate(identity, &cert);
        if(err == noErr) {
#if CURL_BUILD_IOS
          common_name = SecCertificateCopySubjectSummary(cert);
#elif CURL_BUILD_MAC_10_7
          SecCertificateCopyCommonName(cert, &common_name);
#endif
          if(CFStringCompare(common_name, label_cf, 0) == kCFCompareEqualTo) {
            CFRelease(cert);
            CFRelease(common_name);
            CFRetain(identity);
            *out_cert_and_key = identity;
            status = noErr;
            break;
          }
          CFRelease(common_name);
        }
        CFRelease(cert);
      }
    }

    if(keys_list)
      CFRelease(keys_list);
    CFRelease(query_dict);
    CFRelease(label_cf);
  }
  else {
#if CURL_SUPPORT_MAC_10_6
    /* On Leopard and Snow Leopard, fall back to SecKeychainSearch. */
    status = CopyIdentityWithLabelOldSchool(label, out_cert_and_key);
#endif /* CURL_SUPPORT_MAC_10_6 */
  }
#elif CURL_SUPPORT_MAC_10_6
  /* For developers building on older cats, we have no choice but to fall back
     to SecKeychainSearch. */
  status = CopyIdentityWithLabelOldSchool(label, out_cert_and_key);
#endif /* CURL_BUILD_MAC_10_7 || CURL_BUILD_IOS */
  return status;
}

static OSStatus CopyIdentityFromPKCS12File(const char *cPath,
                                           const char *cPassword,
                                           SecIdentityRef *out_cert_and_key)
{
  OSStatus status = errSecItemNotFound;
  CFURLRef pkcs_url = CFURLCreateFromFileSystemRepresentation(NULL,
    (const UInt8 *)cPath, strlen(cPath), false);
  CFStringRef password = cPassword ? CFStringCreateWithCString(NULL,
    cPassword, kCFStringEncodingUTF8) : NULL;
  CFDataRef pkcs_data = NULL;

  /* We can import P12 files on iOS or OS X 10.7 or later: */
  /* These constants are documented as having first appeared in 10.6 but they
     raise linker errors when used on that cat for some reason. */
#if CURL_BUILD_MAC_10_7 || CURL_BUILD_IOS
  if(CFURLCreateDataAndPropertiesFromResource(NULL, pkcs_url, &pkcs_data,
    NULL, NULL, &status)) {
    const void *cKeys[] = {kSecImportExportPassphrase};
    const void *cValues[] = {password};
    CFDictionaryRef options = CFDictionaryCreate(NULL, cKeys, cValues,
      password ? 1L : 0L, NULL, NULL);
    CFArrayRef items = NULL;

    /* Here we go: */
    status = SecPKCS12Import(pkcs_data, options, &items);
    if(status == errSecSuccess && items && CFArrayGetCount(items)) {
      CFDictionaryRef identity_and_trust = CFArrayGetValueAtIndex(items, 0L);
      const void *temp_identity = CFDictionaryGetValue(identity_and_trust,
        kSecImportItemIdentity);

      /* Retain the identity; we don't care about any other data... */
      CFRetain(temp_identity);
      *out_cert_and_key = (SecIdentityRef)temp_identity;
    }

    if(items)
      CFRelease(items);
    CFRelease(options);
    CFRelease(pkcs_data);
  }
#endif /* CURL_BUILD_MAC_10_7 || CURL_BUILD_IOS */
  if(password)
    CFRelease(password);
  CFRelease(pkcs_url);
  return status;
}

/* This code was borrowed from nss.c, with some modifications:
 * Determine whether the nickname passed in is a filename that needs to
 * be loaded as a PEM or a regular NSS nickname.
 *
 * returns 1 for a file
 * returns 0 for not a file
 */
CF_INLINE bool is_file(const char *filename)
{
  struct_stat st;

  if(filename == NULL)
    return false;

  if(stat(filename, &st) == 0)
    return S_ISREG(st.st_mode);
  return false;
}

#if CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS
static CURLcode darwinssl_version_from_curl(long *darwinver, long ssl_version)
{
  switch(ssl_version) {
    case CURL_SSLVERSION_TLSv1_0:
      *darwinver = kTLSProtocol1;
      return CURLE_OK;
    case CURL_SSLVERSION_TLSv1_1:
      *darwinver = kTLSProtocol11;
      return CURLE_OK;
    case CURL_SSLVERSION_TLSv1_2:
      *darwinver = kTLSProtocol12;
      return CURLE_OK;
    case CURL_SSLVERSION_TLSv1_3:
      break;
  }
  return CURLE_SSL_CONNECT_ERROR;
}
#endif

static CURLcode
set_ssl_version_min_max(struct connectdata *conn, int sockindex)
{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  long ssl_version = SSL_CONN_CONFIG(version);
  long ssl_version_max = SSL_CONN_CONFIG(version_max);

  switch(ssl_version) {
    case CURL_SSLVERSION_DEFAULT:
    case CURL_SSLVERSION_TLSv1:
      ssl_version = CURL_SSLVERSION_TLSv1_0;
      ssl_version_max = CURL_SSLVERSION_MAX_TLSv1_2;
      break;
  }

  switch(ssl_version_max) {
    case CURL_SSLVERSION_MAX_NONE:
      ssl_version_max = ssl_version << 16;
      break;
    case CURL_SSLVERSION_MAX_DEFAULT:
      ssl_version_max = CURL_SSLVERSION_MAX_TLSv1_2;
      break;
  }

#if CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS
  if(SSLSetProtocolVersionMax != NULL) {
    SSLProtocol darwin_ver_min = kTLSProtocol1;
    SSLProtocol darwin_ver_max = kTLSProtocol1;
    CURLcode result = darwinssl_version_from_curl(&darwin_ver_min,
                                                  ssl_version);
    if(result) {
      failf(data, "unsupported min version passed via CURLOPT_SSLVERSION");
      return result;
    }
    result = darwinssl_version_from_curl(&darwin_ver_max,
                                         ssl_version_max >> 16);
    if(result) {
      failf(data, "unsupported max version passed via CURLOPT_SSLVERSION");
      return result;
    }

    (void)SSLSetProtocolVersionMin(connssl->ssl_ctx, darwin_ver_min);
    (void)SSLSetProtocolVersionMax(connssl->ssl_ctx, darwin_ver_max);
    return result;
  }
  else {
#if CURL_SUPPORT_MAC_10_8
    long i = ssl_version;
    (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                       kSSLProtocolAll,
                                       false);
    for(; i <= (ssl_version_max >> 16); i++) {
      switch(i) {
        case CURL_SSLVERSION_TLSv1_0:
          (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                            kTLSProtocol1,
                                            true);
          break;
        case CURL_SSLVERSION_TLSv1_1:
          (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                            kTLSProtocol11,
                                            true);
          break;
        case CURL_SSLVERSION_TLSv1_2:
          (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                            kTLSProtocol12,
                                            true);
          break;
        case CURL_SSLVERSION_TLSv1_3:
          failf(data, "DarwinSSL: TLS 1.3 is not yet supported");
          return CURLE_SSL_CONNECT_ERROR;
      }
    }
    return CURLE_OK;
#endif  /* CURL_SUPPORT_MAC_10_8 */
  }
#endif  /* CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS */
  failf(data, "DarwinSSL: cannot set SSL protocol");
  return CURLE_SSL_CONNECT_ERROR;
}


static CURLcode darwinssl_connect_step1(struct connectdata *conn,
                                        int sockindex)
{
  struct Curl_easy *data = conn->data;
  curl_socket_t sockfd = conn->sock[sockindex];
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  const char * const ssl_cafile = SSL_CONN_CONFIG(CAfile);
  const bool verifypeer = SSL_CONN_CONFIG(verifypeer);
  char * const ssl_cert = SSL_SET_OPTION(cert);
  const char * const hostname = SSL_IS_PROXY() ? conn->http_proxy.host.name :
    conn->host.name;
  const long int port = SSL_IS_PROXY() ? conn->port : conn->remote_port;
#ifdef ENABLE_IPV6
  struct in6_addr addr;
#else
  struct in_addr addr;
#endif /* ENABLE_IPV6 */
  size_t all_ciphers_count = 0UL, allowed_ciphers_count = 0UL, i;
  SSLCipherSuite *all_ciphers = NULL, *allowed_ciphers = NULL;
  OSStatus err = noErr;
#if CURL_BUILD_MAC
  int darwinver_maj = 0, darwinver_min = 0;

  GetDarwinVersionNumber(&darwinver_maj, &darwinver_min);
#endif /* CURL_BUILD_MAC */

#if CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS
  if(SSLCreateContext != NULL) {  /* use the newer API if avaialble */
    if(connssl->ssl_ctx)
      CFRelease(connssl->ssl_ctx);
    connssl->ssl_ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    if(!connssl->ssl_ctx) {
      failf(data, "SSL: couldn't create a context!");
      return CURLE_OUT_OF_MEMORY;
    }
  }
  else {
  /* The old ST API does not exist under iOS, so don't compile it: */
#if CURL_SUPPORT_MAC_10_8
    if(connssl->ssl_ctx)
      (void)SSLDisposeContext(connssl->ssl_ctx);
    err = SSLNewContext(false, &(connssl->ssl_ctx));
    if(err != noErr) {
      failf(data, "SSL: couldn't create a context: OSStatus %d", err);
      return CURLE_OUT_OF_MEMORY;
    }
#endif /* CURL_SUPPORT_MAC_10_8 */
  }
#else
  if(connssl->ssl_ctx)
    (void)SSLDisposeContext(connssl->ssl_ctx);
  err = SSLNewContext(false, &(connssl->ssl_ctx));
  if(err != noErr) {
    failf(data, "SSL: couldn't create a context: OSStatus %d", err);
    return CURLE_OUT_OF_MEMORY;
  }
#endif /* CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS */
  connssl->ssl_write_buffered_length = 0UL; /* reset buffered write length */

  /* check to see if we've been told to use an explicit SSL/TLS version */
#if CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS
  if(SSLSetProtocolVersionMax != NULL) {
    switch(conn->ssl_config.version) {
    case CURL_SSLVERSION_DEFAULT:
    case CURL_SSLVERSION_TLSv1:
      (void)SSLSetProtocolVersionMin(connssl->ssl_ctx, kTLSProtocol1);
      (void)SSLSetProtocolVersionMax(connssl->ssl_ctx, kTLSProtocol12);
      break;
    case CURL_SSLVERSION_TLSv1_0:
    case CURL_SSLVERSION_TLSv1_1:
    case CURL_SSLVERSION_TLSv1_2:
    case CURL_SSLVERSION_TLSv1_3:
      {
        CURLcode result = set_ssl_version_min_max(conn, sockindex);
        if(result != CURLE_OK)
          return result;
        break;
      }
    case CURL_SSLVERSION_SSLv3:
      err = SSLSetProtocolVersionMin(connssl->ssl_ctx, kSSLProtocol3);
      if(err != noErr) {
        failf(data, "Your version of the OS does not support SSLv3");
        return CURLE_SSL_CONNECT_ERROR;
      }
      (void)SSLSetProtocolVersionMax(connssl->ssl_ctx, kSSLProtocol3);
      break;
    case CURL_SSLVERSION_SSLv2:
      err = SSLSetProtocolVersionMin(connssl->ssl_ctx, kSSLProtocol2);
      if(err != noErr) {
        failf(data, "Your version of the OS does not support SSLv2");
        return CURLE_SSL_CONNECT_ERROR;
      }
      (void)SSLSetProtocolVersionMax(connssl->ssl_ctx, kSSLProtocol2);
      break;
    default:
      failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
  else {
#if CURL_SUPPORT_MAC_10_8
    (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                       kSSLProtocolAll,
                                       false);
    switch(conn->ssl_config.version) {
    case CURL_SSLVERSION_DEFAULT:
    case CURL_SSLVERSION_TLSv1:
      (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                         kTLSProtocol1,
                                         true);
      (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                         kTLSProtocol11,
                                         true);
      (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                         kTLSProtocol12,
                                         true);
      break;
    case CURL_SSLVERSION_TLSv1_0:
    case CURL_SSLVERSION_TLSv1_1:
    case CURL_SSLVERSION_TLSv1_2:
    case CURL_SSLVERSION_TLSv1_3:
      {
        CURLcode result = set_ssl_version_min_max(conn, sockindex);
        if(result != CURLE_OK)
          return result;
        break;
      }
    case CURL_SSLVERSION_SSLv3:
      err = SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                         kSSLProtocol3,
                                         true);
      if(err != noErr) {
        failf(data, "Your version of the OS does not support SSLv3");
        return CURLE_SSL_CONNECT_ERROR;
      }
      break;
    case CURL_SSLVERSION_SSLv2:
      err = SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                         kSSLProtocol2,
                                         true);
      if(err != noErr) {
        failf(data, "Your version of the OS does not support SSLv2");
        return CURLE_SSL_CONNECT_ERROR;
      }
      break;
    default:
      failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
      return CURLE_SSL_CONNECT_ERROR;
    }
#endif  /* CURL_SUPPORT_MAC_10_8 */
  }
#else
  if(conn->ssl_config.version_max != CURL_SSLVERSION_MAX_NONE) {
    failf(data, "Your version of the OS does not support to set maximum"
                " SSL/TLS version");
    return CURLE_SSL_CONNECT_ERROR;
  }
  (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx, kSSLProtocolAll, false);
  switch(conn->ssl_config.version) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
  case CURL_SSLVERSION_TLSv1_0:
    (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                       kTLSProtocol1,
                                       true);
    break;
  case CURL_SSLVERSION_TLSv1_1:
    failf(data, "Your version of the OS does not support TLSv1.1");
    return CURLE_SSL_CONNECT_ERROR;
  case CURL_SSLVERSION_TLSv1_2:
    failf(data, "Your version of the OS does not support TLSv1.2");
    return CURLE_SSL_CONNECT_ERROR;
  case CURL_SSLVERSION_TLSv1_3:
    failf(data, "Your version of the OS does not support TLSv1.3");
    return CURLE_SSL_CONNECT_ERROR;
  case CURL_SSLVERSION_SSLv2:
    err = SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                       kSSLProtocol2,
                                       true);
    if(err != noErr) {
      failf(data, "Your version of the OS does not support SSLv2");
      return CURLE_SSL_CONNECT_ERROR;
    }
    break;
  case CURL_SSLVERSION_SSLv3:
    err = SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                       kSSLProtocol3,
                                       true);
    if(err != noErr) {
      failf(data, "Your version of the OS does not support SSLv3");
      return CURLE_SSL_CONNECT_ERROR;
    }
    break;
  default:
    failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
    return CURLE_SSL_CONNECT_ERROR;
  }
#endif /* CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS */

  if(SSL_SET_OPTION(key)) {
    infof(data, "WARNING: SSL: CURLOPT_SSLKEY is ignored by Secure "
          "Transport. The private key must be in the Keychain.\n");
  }

  if(ssl_cert) {
    SecIdentityRef cert_and_key = NULL;
    bool is_cert_file = is_file(ssl_cert);

    /* User wants to authenticate with a client cert. Look for it:
       If we detect that this is a file on disk, then let's load it.
       Otherwise, assume that the user wants to use an identity loaded
       from the Keychain. */
    if(is_cert_file) {
      if(!SSL_SET_OPTION(cert_type))
        infof(data, "WARNING: SSL: Certificate type not set, assuming "
                    "PKCS#12 format.\n");
      else if(strncmp(SSL_SET_OPTION(cert_type), "P12",
        strlen(SSL_SET_OPTION(cert_type))) != 0)
        infof(data, "WARNING: SSL: The Security framework only supports "
                    "loading identities that are in PKCS#12 format.\n");

      err = CopyIdentityFromPKCS12File(ssl_cert,
        SSL_SET_OPTION(key_passwd), &cert_and_key);
    }
    else
      err = CopyIdentityWithLabel(ssl_cert, &cert_and_key);

    if(err == noErr && cert_and_key) {
      SecCertificateRef cert = NULL;
      CFTypeRef certs_c[1];
      CFArrayRef certs;

      /* If we found one, print it out: */
      err = SecIdentityCopyCertificate(cert_and_key, &cert);
      if(err == noErr) {
        CFStringRef cert_summary = CopyCertSubject(cert);
        char cert_summary_c[128];

        if(cert_summary) {
          memset(cert_summary_c, 0, 128);
          if(CFStringGetCString(cert_summary,
                                cert_summary_c,
                                128,
                                kCFStringEncodingUTF8)) {
            infof(data, "Client certificate: %s\n", cert_summary_c);
          }
          CFRelease(cert_summary);
          CFRelease(cert);
        }
      }
      certs_c[0] = cert_and_key;
      certs = CFArrayCreate(NULL, (const void **)certs_c, 1L,
                            &kCFTypeArrayCallBacks);
      err = SSLSetCertificate(connssl->ssl_ctx, certs);
      if(certs)
        CFRelease(certs);
      if(err != noErr) {
        failf(data, "SSL: SSLSetCertificate() failed: OSStatus %d", err);
        return CURLE_SSL_CERTPROBLEM;
      }
      CFRelease(cert_and_key);
    }
    else {
      switch(err) {
      case errSecAuthFailed: case -25264: /* errSecPkcs12VerifyFailure */
        failf(data, "SSL: Incorrect password for the certificate \"%s\" "
                    "and its private key.", ssl_cert);
        break;
      case -26275: /* errSecDecode */ case -25257: /* errSecUnknownFormat */
        failf(data, "SSL: Couldn't make sense of the data in the "
                    "certificate \"%s\" and its private key.",
                    ssl_cert);
        break;
      case -25260: /* errSecPassphraseRequired */
        failf(data, "SSL The certificate \"%s\" requires a password.",
                    ssl_cert);
        break;
      case errSecItemNotFound:
        failf(data, "SSL: Can't find the certificate \"%s\" and its private "
                    "key in the Keychain.", ssl_cert);
        break;
      default:
        failf(data, "SSL: Can't load the certificate \"%s\" and its private "
                    "key: OSStatus %d", ssl_cert, err);
        break;
      }
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* SSL always tries to verify the peer, this only says whether it should
   * fail to connect if the verification fails, or if it should continue
   * anyway. In the latter case the result of the verification is checked with
   * SSL_get_verify_result() below. */
#if CURL_BUILD_MAC_10_6 || CURL_BUILD_IOS
  /* Snow Leopard introduced the SSLSetSessionOption() function, but due to
     a library bug with the way the kSSLSessionOptionBreakOnServerAuth flag
     works, it doesn't work as expected under Snow Leopard, Lion or
     Mountain Lion.
     So we need to call SSLSetEnableCertVerify() on those older cats in order
     to disable certificate validation if the user turned that off.
     (SecureTransport will always validate the certificate chain by
     default.)
  Note:
  Darwin 11.x.x is Lion (10.7)
  Darwin 12.x.x is Mountain Lion (10.8)
  Darwin 13.x.x is Mavericks (10.9)
  Darwin 14.x.x is Yosemite (10.10)
  Darwin 15.x.x is El Capitan (10.11)
  */
#if CURL_BUILD_MAC
  if(SSLSetSessionOption != NULL && darwinver_maj >= 13) {
#else
  if(SSLSetSessionOption != NULL) {
#endif /* CURL_BUILD_MAC */
    bool break_on_auth = !conn->ssl_config.verifypeer || ssl_cafile;
    err = SSLSetSessionOption(connssl->ssl_ctx,
                              kSSLSessionOptionBreakOnServerAuth,
                              break_on_auth);
    if(err != noErr) {
      failf(data, "SSL: SSLSetSessionOption() failed: OSStatus %d", err);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
  else {
#if CURL_SUPPORT_MAC_10_8
    err = SSLSetEnableCertVerify(connssl->ssl_ctx,
                                 conn->ssl_config.verifypeer?true:false);
    if(err != noErr) {
      failf(data, "SSL: SSLSetEnableCertVerify() failed: OSStatus %d", err);
      return CURLE_SSL_CONNECT_ERROR;
    }
#endif /* CURL_SUPPORT_MAC_10_8 */
  }
#else
  err = SSLSetEnableCertVerify(connssl->ssl_ctx,
                               conn->ssl_config.verifypeer?true:false);
  if(err != noErr) {
    failf(data, "SSL: SSLSetEnableCertVerify() failed: OSStatus %d", err);
    return CURLE_SSL_CONNECT_ERROR;
  }
#endif /* CURL_BUILD_MAC_10_6 || CURL_BUILD_IOS */

  if(ssl_cafile && verifypeer) {
    bool is_cert_file = is_file(ssl_cafile);

    if(!is_cert_file) {
      failf(data, "SSL: can't load CA certificate file %s", ssl_cafile);
      return CURLE_SSL_CACERT_BADFILE;
    }
  }

  /* Configure hostname check. SNI is used if available.
   * Both hostname check and SNI require SSLSetPeerDomainName().
   * Also: the verifyhost setting influences SNI usage */
  if(conn->ssl_config.verifyhost) {
    err = SSLSetPeerDomainName(connssl->ssl_ctx, hostname,
    strlen(hostname));

    if(err != noErr) {
      infof(data, "WARNING: SSL: SSLSetPeerDomainName() failed: OSStatus %d\n",
            err);
    }

    if((Curl_inet_pton(AF_INET, hostname, &addr))
  #ifdef ENABLE_IPV6
    || (Curl_inet_pton(AF_INET6, hostname, &addr))
  #endif
       ) {
      infof(data, "WARNING: using IP address, SNI is being disabled by "
            "the OS.\n");
    }
  }
  else {
    infof(data, "WARNING: disabling hostname validation also disables SNI.\n");
  }

  /* Disable cipher suites that ST supports but are not safe. These ciphers
     are unlikely to be used in any case since ST gives other ciphers a much
     higher priority, but it's probably better that we not connect at all than
     to give the user a false sense of security if the server only supports
     insecure ciphers. (Note: We don't care about SSLv2-only ciphers.) */
  (void)SSLGetNumberSupportedCiphers(connssl->ssl_ctx, &all_ciphers_count);
  all_ciphers = malloc(all_ciphers_count*sizeof(SSLCipherSuite));
  allowed_ciphers = malloc(all_ciphers_count*sizeof(SSLCipherSuite));
  if(all_ciphers && allowed_ciphers &&
     SSLGetSupportedCiphers(connssl->ssl_ctx, all_ciphers,
       &all_ciphers_count) == noErr) {
    for(i = 0UL ; i < all_ciphers_count ; i++) {
#if CURL_BUILD_MAC
     /* There's a known bug in early versions of Mountain Lion where ST's ECC
        ciphers (cipher suite 0xC001 through 0xC032) simply do not work.
        Work around the problem here by disabling those ciphers if we are
        running in an affected version of OS X. */
      if(darwinver_maj == 12 && darwinver_min <= 3 &&
         all_ciphers[i] >= 0xC001 && all_ciphers[i] <= 0xC032) {
        continue;
      }
#endif /* CURL_BUILD_MAC */
      switch(all_ciphers[i]) {
        /* Disable NULL ciphersuites: */
        case SSL_NULL_WITH_NULL_NULL:
        case SSL_RSA_WITH_NULL_MD5:
        case SSL_RSA_WITH_NULL_SHA:
        case 0x003B: /* TLS_RSA_WITH_NULL_SHA256 */
        case SSL_FORTEZZA_DMS_WITH_NULL_SHA:
        case 0xC001: /* TLS_ECDH_ECDSA_WITH_NULL_SHA */
        case 0xC006: /* TLS_ECDHE_ECDSA_WITH_NULL_SHA */
        case 0xC00B: /* TLS_ECDH_RSA_WITH_NULL_SHA */
        case 0xC010: /* TLS_ECDHE_RSA_WITH_NULL_SHA */
        case 0x002C: /* TLS_PSK_WITH_NULL_SHA */
        case 0x002D: /* TLS_DHE_PSK_WITH_NULL_SHA */
        case 0x002E: /* TLS_RSA_PSK_WITH_NULL_SHA */
        case 0x00B0: /* TLS_PSK_WITH_NULL_SHA256 */
        case 0x00B1: /* TLS_PSK_WITH_NULL_SHA384 */
        case 0x00B4: /* TLS_DHE_PSK_WITH_NULL_SHA256 */
        case 0x00B5: /* TLS_DHE_PSK_WITH_NULL_SHA384 */
        case 0x00B8: /* TLS_RSA_PSK_WITH_NULL_SHA256 */
        case 0x00B9: /* TLS_RSA_PSK_WITH_NULL_SHA384 */
        /* Disable anonymous ciphersuites: */
        case SSL_DH_anon_EXPORT_WITH_RC4_40_MD5:
        case SSL_DH_anon_WITH_RC4_128_MD5:
        case SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA:
        case SSL_DH_anon_WITH_DES_CBC_SHA:
        case SSL_DH_anon_WITH_3DES_EDE_CBC_SHA:
        case TLS_DH_anon_WITH_AES_128_CBC_SHA:
        case TLS_DH_anon_WITH_AES_256_CBC_SHA:
        case 0xC015: /* TLS_ECDH_anon_WITH_NULL_SHA */
        case 0xC016: /* TLS_ECDH_anon_WITH_RC4_128_SHA */
        case 0xC017: /* TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA */
        case 0xC018: /* TLS_ECDH_anon_WITH_AES_128_CBC_SHA */
        case 0xC019: /* TLS_ECDH_anon_WITH_AES_256_CBC_SHA */
        case 0x006C: /* TLS_DH_anon_WITH_AES_128_CBC_SHA256 */
        case 0x006D: /* TLS_DH_anon_WITH_AES_256_CBC_SHA256 */
        case 0x00A6: /* TLS_DH_anon_WITH_AES_128_GCM_SHA256 */
        case 0x00A7: /* TLS_DH_anon_WITH_AES_256_GCM_SHA384 */
        /* Disable weak key ciphersuites: */
        case SSL_RSA_EXPORT_WITH_RC4_40_MD5:
        case SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
        case SSL_RSA_EXPORT_WITH_DES40_CBC_SHA:
        case SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:
        case SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:
        case SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:
        case SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:
        case SSL_RSA_WITH_DES_CBC_SHA:
        case SSL_DH_DSS_WITH_DES_CBC_SHA:
        case SSL_DH_RSA_WITH_DES_CBC_SHA:
        case SSL_DHE_DSS_WITH_DES_CBC_SHA:
        case SSL_DHE_RSA_WITH_DES_CBC_SHA:
        /* Disable IDEA: */
        case SSL_RSA_WITH_IDEA_CBC_SHA:
        case SSL_RSA_WITH_IDEA_CBC_MD5:
        /* Disable RC4: */
        case SSL_RSA_WITH_RC4_128_MD5:
        case SSL_RSA_WITH_RC4_128_SHA:
        case 0xC002: /* TLS_ECDH_ECDSA_WITH_RC4_128_SHA */
        case 0xC007: /* TLS_ECDHE_ECDSA_WITH_RC4_128_SHA*/
        case 0xC00C: /* TLS_ECDH_RSA_WITH_RC4_128_SHA */
        case 0xC011: /* TLS_ECDHE_RSA_WITH_RC4_128_SHA */
        case 0x008A: /* TLS_PSK_WITH_RC4_128_SHA */
        case 0x008E: /* TLS_DHE_PSK_WITH_RC4_128_SHA */
        case 0x0092: /* TLS_RSA_PSK_WITH_RC4_128_SHA */
          break;
        default: /* enable everything else */
          allowed_ciphers[allowed_ciphers_count++] = all_ciphers[i];
          break;
      }
    }
    err = SSLSetEnabledCiphers(connssl->ssl_ctx, allowed_ciphers,
                               allowed_ciphers_count);
    if(err != noErr) {
      failf(data, "SSL: SSLSetEnabledCiphers() failed: OSStatus %d", err);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
  else {
    Curl_safefree(all_ciphers);
    Curl_safefree(allowed_ciphers);
    failf(data, "SSL: Failed to allocate memory for allowed ciphers");
    return CURLE_OUT_OF_MEMORY;
  }
  Curl_safefree(all_ciphers);
  Curl_safefree(allowed_ciphers);

#if CURL_BUILD_MAC_10_9 || CURL_BUILD_IOS_7
  /* We want to enable 1/n-1 when using a CBC cipher unless the user
     specifically doesn't want us doing that: */
  if(SSLSetSessionOption != NULL) {
    /* TODO s/data->set.ssl.enable_beast/SSL_SET_OPTION(enable_beast)/g */
    SSLSetSessionOption(connssl->ssl_ctx, kSSLSessionOptionSendOneByteRecord,
                      !data->set.ssl.enable_beast);
    SSLSetSessionOption(connssl->ssl_ctx, kSSLSessionOptionFalseStart,
                      data->set.ssl.falsestart); /* false start support */
  }
#endif /* CURL_BUILD_MAC_10_9 || CURL_BUILD_IOS_7 */

  /* Check if there's a cached ID we can/should use here! */
  if(SSL_SET_OPTION(primary.sessionid)) {
    char *ssl_sessionid;
    size_t ssl_sessionid_len;

    Curl_ssl_sessionid_lock(conn);
    if(!Curl_ssl_getsessionid(conn, (void **)&ssl_sessionid,
                              &ssl_sessionid_len, sockindex)) {
      /* we got a session id, use it! */
      err = SSLSetPeerID(connssl->ssl_ctx, ssl_sessionid, ssl_sessionid_len);
      Curl_ssl_sessionid_unlock(conn);
      if(err != noErr) {
        failf(data, "SSL: SSLSetPeerID() failed: OSStatus %d", err);
        return CURLE_SSL_CONNECT_ERROR;
      }
      /* Informational message */
      infof(data, "SSL re-using session ID\n");
    }
    /* If there isn't one, then let's make one up! This has to be done prior
       to starting the handshake. */
    else {
      CURLcode result;
      ssl_sessionid =
        aprintf("%s:%d:%d:%s:%hu", ssl_cafile,
                verifypeer, SSL_CONN_CONFIG(verifyhost), hostname, port);
      ssl_sessionid_len = strlen(ssl_sessionid);

      err = SSLSetPeerID(connssl->ssl_ctx, ssl_sessionid, ssl_sessionid_len);
      if(err != noErr) {
        Curl_ssl_sessionid_unlock(conn);
        failf(data, "SSL: SSLSetPeerID() failed: OSStatus %d", err);
        return CURLE_SSL_CONNECT_ERROR;
      }

      result = Curl_ssl_addsessionid(conn, ssl_sessionid, ssl_sessionid_len,
                                     sockindex);
      Curl_ssl_sessionid_unlock(conn);
      if(result) {
        failf(data, "failed to store ssl session");
        return result;
      }
    }
  }

  err = SSLSetIOFuncs(connssl->ssl_ctx, SocketRead, SocketWrite);
  if(err != noErr) {
    failf(data, "SSL: SSLSetIOFuncs() failed: OSStatus %d", err);
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* pass the raw socket into the SSL layers */
  /* We need to store the FD in a constant memory address, because
   * SSLSetConnection() will not copy that address. I've found that
   * conn->sock[sockindex] may change on its own. */
  connssl->ssl_sockfd = sockfd;
  err = SSLSetConnection(connssl->ssl_ctx, connssl);
  if(err != noErr) {
    failf(data, "SSL: SSLSetConnection() failed: %d", err);
    return CURLE_SSL_CONNECT_ERROR;
  }

  connssl->connecting_state = ssl_connect_2;
  return CURLE_OK;
}

static long pem_to_der(const char *in, unsigned char **out, size_t *outlen)
{
  char *sep_start, *sep_end, *cert_start, *cert_end;
  size_t i, j, err;
  size_t len;
  unsigned char *b64;

  /* Jump through the separators at the beginning of the certificate. */
  sep_start = strstr(in, "-----");
  if(sep_start == NULL)
    return 0;
  cert_start = strstr(sep_start + 1, "-----");
  if(cert_start == NULL)
    return -1;

  cert_start += 5;

  /* Find separator after the end of the certificate. */
  cert_end = strstr(cert_start, "-----");
  if(cert_end == NULL)
    return -1;

  sep_end = strstr(cert_end + 1, "-----");
  if(sep_end == NULL)
    return -1;
  sep_end += 5;

  len = cert_end - cert_start;
  b64 = malloc(len + 1);
  if(!b64)
    return -1;

  /* Create base64 string without linefeeds. */
  for(i = 0, j = 0; i < len; i++) {
    if(cert_start[i] != '\r' && cert_start[i] != '\n')
      b64[j++] = cert_start[i];
  }
  b64[j] = '\0';

  err = Curl_base64_decode((const char *)b64, out, outlen);
  free(b64);
  if(err) {
    free(*out);
    return -1;
  }

  return sep_end - in;
}

static int read_cert(const char *file, unsigned char **out, size_t *outlen)
{
  int fd;
  ssize_t n, len = 0, cap = 512;
  unsigned char buf[cap], *data;

  fd = open(file, 0);
  if(fd < 0)
    return -1;

  data = malloc(cap);
  if(!data) {
    close(fd);
    return -1;
  }

  for(;;) {
    n = read(fd, buf, sizeof(buf));
    if(n < 0) {
      close(fd);
      free(data);
      return -1;
    }
    else if(n == 0) {
      close(fd);
      break;
    }

    if(len + n >= cap) {
      cap *= 2;
      data = realloc(data, cap);
      if(!data) {
        close(fd);
        return -1;
      }
    }

    memcpy(data + len, buf, n);
    len += n;
  }
  data[len] = '\0';

  *out = data;
  *outlen = len;

  return 0;
}

static int sslerr_to_curlerr(struct Curl_easy *data, int err)
{
  switch(err) {
    case errSSLXCertChainInvalid:
      failf(data, "SSL certificate problem: Invalid certificate chain");
      return CURLE_SSL_CACERT;
    case errSSLUnknownRootCert:
      failf(data, "SSL certificate problem: Untrusted root certificate");
      return CURLE_SSL_CACERT;
    case errSSLNoRootCert:
      failf(data, "SSL certificate problem: No root certificate");
      return CURLE_SSL_CACERT;
    case errSSLCertExpired:
      failf(data, "SSL certificate problem: Certificate chain had an "
            "expired certificate");
      return CURLE_SSL_CACERT;
    case errSSLBadCert:
      failf(data, "SSL certificate problem: Couldn't understand the server "
            "certificate format");
      return CURLE_SSL_CONNECT_ERROR;
    case errSSLHostNameMismatch:
      failf(data, "SSL certificate peer hostname mismatch");
      return CURLE_PEER_FAILED_VERIFICATION;
    default:
      failf(data, "SSL unexpected certificate error %d", err);
      return CURLE_SSL_CACERT;
  }
}

static int append_cert_to_array(struct Curl_easy *data,
                                unsigned char *buf, size_t buflen,
                                CFMutableArrayRef array)
{
    CFDataRef certdata = CFDataCreate(kCFAllocatorDefault, buf, buflen);
    if(!certdata) {
      failf(data, "SSL: failed to allocate array for CA certificate");
      return CURLE_OUT_OF_MEMORY;
    }

    SecCertificateRef cacert =
      SecCertificateCreateWithData(kCFAllocatorDefault, certdata);
    CFRelease(certdata);
    if(!cacert) {
      failf(data, "SSL: failed to create SecCertificate from CA certificate");
      return CURLE_SSL_CACERT;
    }

    /* Check if cacert is valid. */
    CFStringRef subject = CopyCertSubject(cacert);
    if(subject) {
      char subject_cbuf[128];
      memset(subject_cbuf, 0, 128);
      if(!CFStringGetCString(subject,
                            subject_cbuf,
                            128,
                            kCFStringEncodingUTF8)) {
        CFRelease(cacert);
        failf(data, "SSL: invalid CA certificate subject");
        return CURLE_SSL_CACERT;
      }
      CFRelease(subject);
    }
    else {
      CFRelease(cacert);
      failf(data, "SSL: invalid CA certificate");
      return CURLE_SSL_CACERT;
    }

    CFArrayAppendValue(array, cacert);
    CFRelease(cacert);

    return CURLE_OK;
}

static int verify_cert(const char *cafile, struct Curl_easy *data,
                       SSLContextRef ctx)
{
  int n = 0, rc;
  long res;
  unsigned char *certbuf, *der;
  size_t buflen, derlen, offset = 0;

  if(read_cert(cafile, &certbuf, &buflen) < 0) {
    failf(data, "SSL: failed to read or invalid CA certificate");
    return CURLE_SSL_CACERT;
  }

  /*
   * Certbuf now contains the contents of the certificate file, which can be
   * - a single DER certificate,
   * - a single PEM certificate or
   * - a bunch of PEM certificates (certificate bundle).
   *
   * Go through certbuf, and convert any PEM certificate in it into DER
   * format.
   */
  CFMutableArrayRef array = CFArrayCreateMutable(kCFAllocatorDefault, 0,
                                                 &kCFTypeArrayCallBacks);
  if(array == NULL) {
    free(certbuf);
    failf(data, "SSL: out of memory creating CA certificate array");
    return CURLE_OUT_OF_MEMORY;
  }

  while(offset < buflen) {
    n++;

    /*
     * Check if the certificate is in PEM format, and convert it to DER. If
     * this fails, we assume the certificate is in DER format.
     */
    res = pem_to_der((const char *)certbuf + offset, &der, &derlen);
    if(res < 0) {
      free(certbuf);
      CFRelease(array);
      failf(data, "SSL: invalid CA certificate #%d (offset %d) in bundle",
            n, offset);
      return CURLE_SSL_CACERT;
    }
    offset += res;

    if(res == 0 && offset == 0) {
      /* This is not a PEM file, probably a certificate in DER format. */
      rc = append_cert_to_array(data, certbuf, buflen, array);
      free(certbuf);
      if(rc != CURLE_OK) {
        CFRelease(array);
        return rc;
      }
      break;
    }
    else if(res == 0) {
      /* No more certificates in the bundle. */
      free(certbuf);
      break;
    }

    rc = append_cert_to_array(data, der, derlen, array);
    free(der);
    if(rc != CURLE_OK) {
      free(certbuf);
      CFRelease(array);
      return rc;
    }
  }

  SecTrustRef trust;
  OSStatus ret = SSLCopyPeerTrust(ctx, &trust);
  if(trust == NULL) {
    failf(data, "SSL: error getting certificate chain");
    CFRelease(array);
    return CURLE_OUT_OF_MEMORY;
  }
  else if(ret != noErr) {
    CFRelease(array);
    return sslerr_to_curlerr(data, ret);
  }

  ret = SecTrustSetAnchorCertificates(trust, array);
  if(ret != noErr) {
    CFRelease(trust);
    return sslerr_to_curlerr(data, ret);
  }
  ret = SecTrustSetAnchorCertificatesOnly(trust, true);
  if(ret != noErr) {
    CFRelease(trust);
    return sslerr_to_curlerr(data, ret);
  }

  SecTrustResultType trust_eval = 0;
  ret = SecTrustEvaluate(trust, &trust_eval);
  CFRelease(array);
  CFRelease(trust);
  if(ret != noErr) {
    return sslerr_to_curlerr(data, ret);
  }

  switch(trust_eval) {
    case kSecTrustResultUnspecified:
    case kSecTrustResultProceed:
      return CURLE_OK;

    case kSecTrustResultRecoverableTrustFailure:
    case kSecTrustResultDeny:
    default:
      failf(data, "SSL: certificate verification failed (result: %d)",
            trust_eval);
      return CURLE_PEER_FAILED_VERIFICATION;
  }
}

#ifdef DARWIN_SSL_PINNEDPUBKEY
static CURLcode pkp_pin_peer_pubkey(struct SessionHandle *data,
                                    SSLContextRef ctx,
                                    const char *pinnedpubkey)
{  /* Scratch */
  size_t pubkeylen, realpubkeylen, spkiHeaderLength = 24;
  unsigned char *pubkey = NULL, *realpubkey = NULL, *spkiHeader = NULL;
  CFDataRef publicKeyBits = NULL;

  /* Result is returned to caller */
  CURLcode result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;

  /* if a path wasn't specified, don't pin */
  if(!pinnedpubkey)
    return CURLE_OK;


  if(!ctx)
    return result;

  do {
    SecTrustRef trust;
    OSStatus ret = SSLCopyPeerTrust(ctx, &trust);
    if(ret != noErr || trust == NULL)
      break;

    SecKeyRef keyRef = SecTrustCopyPublicKey(trust);
    CFRelease(trust);
    if(keyRef == NULL)
      break;

#ifdef DARWIN_SSL_PINNEDPUBKEY_V1

    publicKeyBits = SecKeyCopyExternalRepresentation(keyRef, NULL);
    CFRelease(keyRef);
    if(publicKeyBits == NULL)
      break;

#elif DARWIN_SSL_PINNEDPUBKEY_V2

    OSStatus success = SecItemExport(keyRef, kSecFormatOpenSSL, 0, NULL,
                                     &publicKeyBits);
    CFRelease(keyRef);
    if(success != errSecSuccess || publicKeyBits == NULL)
      break;

#endif /* DARWIN_SSL_PINNEDPUBKEY_V2 */

    pubkeylen = CFDataGetLength(publicKeyBits);
    pubkey = CFDataGetBytePtr(publicKeyBits);

    switch(pubkeylen) {
      case 526:
        /* 4096 bit RSA pubkeylen == 526 */
        spkiHeader = rsa4096SpkiHeader;
        break;
      case 270:
        /* 2048 bit RSA pubkeylen == 270 */
        spkiHeader = rsa2048SpkiHeader;
        break;
#ifdef DARWIN_SSL_PINNEDPUBKEY_V1
      case 65:
        /* ecDSA secp256r1 pubkeylen == 65 */
        spkiHeader = ecDsaSecp256r1SpkiHeader;
        spkiHeaderLength = 26;
        break;
      case 97:
        /* ecDSA secp384r1 pubkeylen == 97 */
        spkiHeader = ecDsaSecp384r1SpkiHeader;
        spkiHeaderLength = 23;
        break;
      default:
        infof(data, "SSL: unhandled public key length: %d\n", pubkeylen);
#elif DARWIN_SSL_PINNEDPUBKEY_V2
      default:
        /* ecDSA secp256r1 pubkeylen == 91 header already included?
         * ecDSA secp384r1 header already included too
         * we assume rest of algorithms do same, so do nothing
         */
        result = Curl_pin_peer_pubkey(data, pinnedpubkey, pubkey,
                                    pubkeylen);
#endif /* DARWIN_SSL_PINNEDPUBKEY_V2 */
        continue; /* break from loop */
    }

    realpubkeylen = pubkeylen + spkiHeaderLength;
    realpubkey = malloc(realpubkeylen);
    if(!realpubkey)
      break;

    memcpy(realpubkey, spkiHeader, spkiHeaderLength);
    memcpy(realpubkey + spkiHeaderLength, pubkey, pubkeylen);

    result = Curl_pin_peer_pubkey(data, pinnedpubkey, realpubkey,
                                  realpubkeylen);

  } while(0);

  Curl_safefree(realpubkey);
  if(publicKeyBits != NULL)
    CFRelease(publicKeyBits);

  return result;
}
#endif /* DARWIN_SSL_PINNEDPUBKEY */

static CURLcode
darwinssl_connect_step2(struct connectdata *conn, int sockindex)
{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  OSStatus err;
  SSLCipherSuite cipher;
  SSLProtocol protocol = 0;
  const char * const hostname = SSL_IS_PROXY() ? conn->http_proxy.host.name :
    conn->host.name;

  DEBUGASSERT(ssl_connect_2 == connssl->connecting_state
              || ssl_connect_2_reading == connssl->connecting_state
              || ssl_connect_2_writing == connssl->connecting_state);

  /* Here goes nothing: */
  err = SSLHandshake(connssl->ssl_ctx);

  if(err != noErr) {
    switch(err) {
      case errSSLWouldBlock:  /* they're not done with us yet */
        connssl->connecting_state = connssl->ssl_direction ?
            ssl_connect_2_writing : ssl_connect_2_reading;
        return CURLE_OK;

      /* The below is errSSLServerAuthCompleted; it's not defined in
        Leopard's headers */
      case -9841:
        if(SSL_CONN_CONFIG(CAfile) && SSL_CONN_CONFIG(verifypeer)) {
          int res = verify_cert(SSL_CONN_CONFIG(CAfile), data,
                                connssl->ssl_ctx);
          if(res != CURLE_OK)
            return res;
        }
        /* the documentation says we need to call SSLHandshake() again */
        return darwinssl_connect_step2(conn, sockindex);

      /* These are all certificate problems with the server: */
      case errSSLXCertChainInvalid:
        failf(data, "SSL certificate problem: Invalid certificate chain");
        return CURLE_SSL_CACERT;
      case errSSLUnknownRootCert:
        failf(data, "SSL certificate problem: Untrusted root certificate");
        return CURLE_SSL_CACERT;
      case errSSLNoRootCert:
        failf(data, "SSL certificate problem: No root certificate");
        return CURLE_SSL_CACERT;
      case errSSLCertExpired:
        failf(data, "SSL certificate problem: Certificate chain had an "
              "expired certificate");
        return CURLE_SSL_CACERT;
      case errSSLBadCert:
        failf(data, "SSL certificate problem: Couldn't understand the server "
              "certificate format");
        return CURLE_SSL_CONNECT_ERROR;

      /* These are all certificate problems with the client: */
      case errSecAuthFailed:
        failf(data, "SSL authentication failed");
        return CURLE_SSL_CONNECT_ERROR;
      case errSSLPeerHandshakeFail:
        failf(data, "SSL peer handshake failed, the server most likely "
              "requires a client certificate to connect");
        return CURLE_SSL_CONNECT_ERROR;
      case errSSLPeerUnknownCA:
        failf(data, "SSL server rejected the client certificate due to "
              "the certificate being signed by an unknown certificate "
              "authority");
        return CURLE_SSL_CONNECT_ERROR;

      /* This error is raised if the server's cert didn't match the server's
         host name: */
      case errSSLHostNameMismatch:
        failf(data, "SSL certificate peer verification failed, the "
              "certificate did not match \"%s\"\n", conn->host.dispname);
        return CURLE_PEER_FAILED_VERIFICATION;

      /* Generic handshake errors: */
      case errSSLConnectionRefused:
        failf(data, "Server dropped the connection during the SSL handshake");
        return CURLE_SSL_CONNECT_ERROR;
      case errSSLClosedAbort:
        failf(data, "Server aborted the SSL handshake");
        return CURLE_SSL_CONNECT_ERROR;
      case errSSLNegotiation:
        failf(data, "Could not negotiate an SSL cipher suite with the server");
        return CURLE_SSL_CONNECT_ERROR;
      /* Sometimes paramErr happens with buggy ciphers: */
      case paramErr: case errSSLInternal:
        failf(data, "Internal SSL engine error encountered during the "
              "SSL handshake");
        return CURLE_SSL_CONNECT_ERROR;
      case errSSLFatalAlert:
        failf(data, "Fatal SSL engine error encountered during the SSL "
              "handshake");
        return CURLE_SSL_CONNECT_ERROR;
      default:
        failf(data, "Unknown SSL protocol error in connection to %s:%d",
              hostname, err);
        return CURLE_SSL_CONNECT_ERROR;
    }
  }
  else {
    /* we have been connected fine, we're not waiting for anything else. */
    connssl->connecting_state = ssl_connect_3;

#ifdef DARWIN_SSL_PINNEDPUBKEY
    if(data->set.str[STRING_SSL_PINNEDPUBLICKEY_ORIG]) {
      CURLcode result = pkp_pin_peer_pubkey(data, connssl->ssl_ctx,
                            data->set.str[STRING_SSL_PINNEDPUBLICKEY_ORIG]);
      if(result) {
        failf(data, "SSL: public key does not match pinned public key!");
        return result;
      }
    }
#endif /* DARWIN_SSL_PINNEDPUBKEY */

    /* Informational message */
    (void)SSLGetNegotiatedCipher(connssl->ssl_ctx, &cipher);
    (void)SSLGetNegotiatedProtocolVersion(connssl->ssl_ctx, &protocol);
    switch(protocol) {
      case kSSLProtocol2:
        infof(data, "SSL 2.0 connection using %s\n",
              SSLCipherNameForNumber(cipher));
        break;
      case kSSLProtocol3:
        infof(data, "SSL 3.0 connection using %s\n",
              SSLCipherNameForNumber(cipher));
        break;
      case kTLSProtocol1:
        infof(data, "TLS 1.0 connection using %s\n",
              TLSCipherNameForNumber(cipher));
        break;
#if CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS
      case kTLSProtocol11:
        infof(data, "TLS 1.1 connection using %s\n",
              TLSCipherNameForNumber(cipher));
        break;
      case kTLSProtocol12:
        infof(data, "TLS 1.2 connection using %s\n",
              TLSCipherNameForNumber(cipher));
        break;
#endif
      default:
        infof(data, "Unknown protocol connection\n");
        break;
    }

    return CURLE_OK;
  }
}

#ifndef CURL_DISABLE_VERBOSE_STRINGS
/* This should be called during step3 of the connection at the earliest */
static void
show_verbose_server_cert(struct connectdata *conn,
                         int sockindex)
{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  CFStringRef server_cert_summary;
  char server_cert_summary_c[128];
  CFArrayRef server_certs = NULL;
  SecCertificateRef server_cert;
  OSStatus err;
  CFIndex i, count;
  SecTrustRef trust = NULL;

  if(!connssl->ssl_ctx)
    return;

#if CURL_BUILD_MAC_10_7 || CURL_BUILD_IOS
#if CURL_BUILD_IOS
#pragma unused(server_certs)
  err = SSLCopyPeerTrust(connssl->ssl_ctx, &trust);
  /* For some reason, SSLCopyPeerTrust() can return noErr and yet return
     a null trust, so be on guard for that: */
  if(err == noErr && trust) {
    count = SecTrustGetCertificateCount(trust);
    for(i = 0L ; i < count ; i++) {
      server_cert = SecTrustGetCertificateAtIndex(trust, i);
      server_cert_summary = CopyCertSubject(server_cert);
      memset(server_cert_summary_c, 0, 128);
      if(CFStringGetCString(server_cert_summary,
                            server_cert_summary_c,
                            128,
                            kCFStringEncodingUTF8)) {
        infof(data, "Server certificate: %s\n", server_cert_summary_c);
      }
      CFRelease(server_cert_summary);
    }
    CFRelease(trust);
  }
#else
  /* SSLCopyPeerCertificates() is deprecated as of Mountain Lion.
     The function SecTrustGetCertificateAtIndex() is officially present
     in Lion, but it is unfortunately also present in Snow Leopard as
     private API and doesn't work as expected. So we have to look for
     a different symbol to make sure this code is only executed under
     Lion or later. */
  if(SecTrustEvaluateAsync != NULL) {
#pragma unused(server_certs)
    err = SSLCopyPeerTrust(connssl->ssl_ctx, &trust);
    /* For some reason, SSLCopyPeerTrust() can return noErr and yet return
       a null trust, so be on guard for that: */
    if(err == noErr && trust) {
      count = SecTrustGetCertificateCount(trust);
      for(i = 0L ; i < count ; i++) {
        server_cert = SecTrustGetCertificateAtIndex(trust, i);
        server_cert_summary = CopyCertSubject(server_cert);
        memset(server_cert_summary_c, 0, 128);
        if(CFStringGetCString(server_cert_summary,
                              server_cert_summary_c,
                              128,
                              kCFStringEncodingUTF8)) {
          infof(data, "Server certificate: %s\n", server_cert_summary_c);
        }
        CFRelease(server_cert_summary);
      }
      CFRelease(trust);
    }
  }
  else {
#if CURL_SUPPORT_MAC_10_8
    err = SSLCopyPeerCertificates(connssl->ssl_ctx, &server_certs);
    /* Just in case SSLCopyPeerCertificates() returns null too... */
    if(err == noErr && server_certs) {
      count = CFArrayGetCount(server_certs);
      for(i = 0L ; i < count ; i++) {
        server_cert = (SecCertificateRef)CFArrayGetValueAtIndex(server_certs,
                                                                i);

        server_cert_summary = CopyCertSubject(server_cert);
        memset(server_cert_summary_c, 0, 128);
        if(CFStringGetCString(server_cert_summary,
                              server_cert_summary_c,
                              128,
                              kCFStringEncodingUTF8)) {
          infof(data, "Server certificate: %s\n", server_cert_summary_c);
        }
        CFRelease(server_cert_summary);
      }
      CFRelease(server_certs);
    }
#endif /* CURL_SUPPORT_MAC_10_8 */
  }
#endif /* CURL_BUILD_IOS */
#else
#pragma unused(trust)
  err = SSLCopyPeerCertificates(connssl->ssl_ctx, &server_certs);
  if(err == noErr) {
    count = CFArrayGetCount(server_certs);
    for(i = 0L ; i < count ; i++) {
      server_cert = (SecCertificateRef)CFArrayGetValueAtIndex(server_certs, i);
      server_cert_summary = CopyCertSubject(server_cert);
      memset(server_cert_summary_c, 0, 128);
      if(CFStringGetCString(server_cert_summary,
                            server_cert_summary_c,
                            128,
                            kCFStringEncodingUTF8)) {
        infof(data, "Server certificate: %s\n", server_cert_summary_c);
      }
      CFRelease(server_cert_summary);
    }
    CFRelease(server_certs);
  }
#endif /* CURL_BUILD_MAC_10_7 || CURL_BUILD_IOS */
}
#endif /* !CURL_DISABLE_VERBOSE_STRINGS */

static CURLcode
darwinssl_connect_step3(struct connectdata *conn,
                        int sockindex)
{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  /* There is no step 3!
   * Well, okay, if verbose mode is on, let's print the details of the
   * server certificates. */
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  if(data->set.verbose)
    show_verbose_server_cert(conn, sockindex);
#endif

  connssl->connecting_state = ssl_connect_done;
  return CURLE_OK;
}

static Curl_recv darwinssl_recv;
static Curl_send darwinssl_send;

static CURLcode
darwinssl_connect_common(struct connectdata *conn,
                         int sockindex,
                         bool nonblocking,
                         bool *done)
{
  CURLcode result;
  struct Curl_easy *data = conn->data;
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

    result = darwinssl_connect_step1(conn, sockindex);
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

      curl_socket_t writefd = ssl_connect_2_writing ==
      connssl->connecting_state?sockfd:CURL_SOCKET_BAD;
      curl_socket_t readfd = ssl_connect_2_reading ==
      connssl->connecting_state?sockfd:CURL_SOCKET_BAD;

      what = Curl_socket_check(readfd, CURL_SOCKET_BAD, writefd,
                               nonblocking?0:timeout_ms);
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
    result = darwinssl_connect_step2(conn, sockindex);
    if(result || (nonblocking &&
                  (ssl_connect_2 == connssl->connecting_state ||
                   ssl_connect_2_reading == connssl->connecting_state ||
                   ssl_connect_2_writing == connssl->connecting_state)))
      return result;

  } /* repeat step2 until all transactions are done. */


  if(ssl_connect_3 == connssl->connecting_state) {
    result = darwinssl_connect_step3(conn, sockindex);
    if(result)
      return result;
  }

  if(ssl_connect_done == connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    conn->recv[sockindex] = darwinssl_recv;
    conn->send[sockindex] = darwinssl_send;
    *done = TRUE;
  }
  else
    *done = FALSE;

  /* Reset our connect state machine */
  connssl->connecting_state = ssl_connect_1;

  return CURLE_OK;
}

CURLcode
Curl_darwinssl_connect_nonblocking(struct connectdata *conn,
                                   int sockindex,
                                   bool *done)
{
  return darwinssl_connect_common(conn, sockindex, TRUE, done);
}

CURLcode
Curl_darwinssl_connect(struct connectdata *conn,
                       int sockindex)
{
  CURLcode result;
  bool done = FALSE;

  result = darwinssl_connect_common(conn, sockindex, FALSE, &done);

  if(result)
    return result;

  DEBUGASSERT(done);

  return CURLE_OK;
}

void Curl_darwinssl_close(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  if(connssl->ssl_ctx) {
    (void)SSLClose(connssl->ssl_ctx);
#if CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS
    if(SSLCreateContext != NULL)
      CFRelease(connssl->ssl_ctx);
#if CURL_SUPPORT_MAC_10_8
    else
      (void)SSLDisposeContext(connssl->ssl_ctx);
#endif  /* CURL_SUPPORT_MAC_10_8 */
#else
    (void)SSLDisposeContext(connssl->ssl_ctx);
#endif /* CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS */
    connssl->ssl_ctx = NULL;
  }
  connssl->ssl_sockfd = 0;
}

int Curl_darwinssl_shutdown(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct Curl_easy *data = conn->data;
  ssize_t nread;
  int what;
  int rc;
  char buf[120];

  if(!connssl->ssl_ctx)
    return 0;

  if(data->set.ftp_ccc != CURLFTPSSL_CCC_ACTIVE)
    return 0;

  Curl_darwinssl_close(conn, sockindex);

  rc = 0;

  what = SOCKET_READABLE(conn->sock[sockindex], SSL_SHUTDOWN_TIMEOUT);

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
     notify alert from the server. No way to SSL_Read now, so use read(). */

    nread = read(conn->sock[sockindex], buf, sizeof(buf));

    if(nread < 0) {
      failf(data, "read: %s", strerror(errno));
      rc = -1;
    }

    if(nread <= 0)
      break;

    what = SOCKET_READABLE(conn->sock[sockindex], 0);
  }

  return rc;
}

void Curl_darwinssl_session_free(void *ptr)
{
  /* ST, as of iOS 5 and Mountain Lion, has no public method of deleting a
     cached session ID inside the Security framework. There is a private
     function that does this, but I don't want to have to explain to you why I
     got your application rejected from the App Store due to the use of a
     private API, so the best we can do is free up our own char array that we
     created way back in darwinssl_connect_step1... */
  Curl_safefree(ptr);
}

size_t Curl_darwinssl_version(char *buffer, size_t size)
{
  return snprintf(buffer, size, "SecureTransport");
}

/*
 * This function uses SSLGetSessionState to determine connection status.
 *
 * Return codes:
 *     1 means the connection is still in place
 *     0 means the connection has been closed
 *    -1 means the connection status is unknown
 */
int Curl_darwinssl_check_cxn(struct connectdata *conn)
{
  struct ssl_connect_data *connssl = &conn->ssl[FIRSTSOCKET];
  OSStatus err;
  SSLSessionState state;

  if(connssl->ssl_ctx) {
    err = SSLGetSessionState(connssl->ssl_ctx, &state);
    if(err == noErr)
      return state == kSSLConnected || state == kSSLHandshake;
    return -1;
  }
  return 0;
}

bool Curl_darwinssl_data_pending(const struct connectdata *conn,
                                 int connindex)
{
  const struct ssl_connect_data *connssl = &conn->ssl[connindex];
  OSStatus err;
  size_t buffer;

  if(connssl->ssl_ctx) {  /* SSL is in use */
    err = SSLGetBufferedReadSize(connssl->ssl_ctx, &buffer);
    if(err == noErr)
      return buffer > 0UL;
    return false;
  }
  else
    return false;
}

CURLcode Curl_darwinssl_random(unsigned char *entropy,
                               size_t length)
{
  /* arc4random_buf() isn't available on cats older than Lion, so let's
     do this manually for the benefit of the older cats. */
  size_t i;
  u_int32_t random_number = 0;

  for(i = 0 ; i < length ; i++) {
    if(i % sizeof(u_int32_t) == 0)
      random_number = arc4random();
    entropy[i] = random_number & 0xFF;
    random_number >>= 8;
  }
  i = random_number = 0;
  return CURLE_OK;
}

void Curl_darwinssl_md5sum(unsigned char *tmp, /* input */
                           size_t tmplen,
                           unsigned char *md5sum, /* output */
                           size_t md5len)
{
  (void)md5len;
  (void)CC_MD5(tmp, (CC_LONG)tmplen, md5sum);
}

void Curl_darwinssl_sha256sum(unsigned char *tmp, /* input */
                           size_t tmplen,
                           unsigned char *sha256sum, /* output */
                           size_t sha256len)
{
  assert(sha256len >= SHA256_DIGEST_LENGTH);
  (void)CC_SHA256(tmp, (CC_LONG)tmplen, sha256sum);
}

bool Curl_darwinssl_false_start(void)
{
#if CURL_BUILD_MAC_10_9 || CURL_BUILD_IOS_7
  if(SSLSetSessionOption != NULL)
    return TRUE;
#endif
  return FALSE;
}

static ssize_t darwinssl_send(struct connectdata *conn,
                              int sockindex,
                              const void *mem,
                              size_t len,
                              CURLcode *curlcode)
{
  /*struct Curl_easy *data = conn->data;*/
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  size_t processed = 0UL;
  OSStatus err;

  /* The SSLWrite() function works a little differently than expected. The
     fourth argument (processed) is currently documented in Apple's
     documentation as: "On return, the length, in bytes, of the data actually
     written."

     Now, one could interpret that as "written to the socket," but actually,
     it returns the amount of data that was written to a buffer internal to
     the SSLContextRef instead. So it's possible for SSLWrite() to return
     errSSLWouldBlock and a number of bytes "written" because those bytes were
     encrypted and written to a buffer, not to the socket.

     So if this happens, then we need to keep calling SSLWrite() over and
     over again with no new data until it quits returning errSSLWouldBlock. */

  /* Do we have buffered data to write from the last time we were called? */
  if(connssl->ssl_write_buffered_length) {
    /* Write the buffered data: */
    err = SSLWrite(connssl->ssl_ctx, NULL, 0UL, &processed);
    switch(err) {
      case noErr:
        /* processed is always going to be 0 because we didn't write to
           the buffer, so return how much was written to the socket */
        processed = connssl->ssl_write_buffered_length;
        connssl->ssl_write_buffered_length = 0UL;
        break;
      case errSSLWouldBlock: /* argh, try again */
        *curlcode = CURLE_AGAIN;
        return -1L;
      default:
        failf(conn->data, "SSLWrite() returned error %d", err);
        *curlcode = CURLE_SEND_ERROR;
        return -1L;
    }
  }
  else {
    /* We've got new data to write: */
    err = SSLWrite(connssl->ssl_ctx, mem, len, &processed);
    if(err != noErr) {
      switch(err) {
        case errSSLWouldBlock:
          /* Data was buffered but not sent, we have to tell the caller
             to try sending again, and remember how much was buffered */
          connssl->ssl_write_buffered_length = len;
          *curlcode = CURLE_AGAIN;
          return -1L;
        default:
          failf(conn->data, "SSLWrite() returned error %d", err);
          *curlcode = CURLE_SEND_ERROR;
          return -1L;
      }
    }
  }
  return (ssize_t)processed;
}

static ssize_t darwinssl_recv(struct connectdata *conn,
                              int num,
                              char *buf,
                              size_t buffersize,
                              CURLcode *curlcode)
{
  /*struct Curl_easy *data = conn->data;*/
  struct ssl_connect_data *connssl = &conn->ssl[num];
  size_t processed = 0UL;
  OSStatus err = SSLRead(connssl->ssl_ctx, buf, buffersize, &processed);

  if(err != noErr) {
    switch(err) {
      case errSSLWouldBlock:  /* return how much we read (if anything) */
        if(processed)
          return (ssize_t)processed;
        *curlcode = CURLE_AGAIN;
        return -1L;
        break;

      /* errSSLClosedGraceful - server gracefully shut down the SSL session
         errSSLClosedNoNotify - server hung up on us instead of sending a
           closure alert notice, read() is returning 0
         Either way, inform the caller that the server disconnected. */
      case errSSLClosedGraceful:
      case errSSLClosedNoNotify:
        *curlcode = CURLE_OK;
        return -1L;
        break;

      default:
        failf(conn->data, "SSLRead() return error %d", err);
        *curlcode = CURLE_RECV_ERROR;
        return -1L;
        break;
    }
  }
  return (ssize_t)processed;
}

#endif /* USE_DARWINSSL */
