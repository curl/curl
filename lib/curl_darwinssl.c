/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012-2013, Nick Zitzmann, <nickzman@gmail.com>.
 * Copyright (C) 2012-2013, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * Source file for all iOS and Mac OS X SecureTransport-specific code for the
 * TLS/SSL layer. No code but sslgen.c should ever call or use these functions.
 */

#include "curl_setup.h"

#ifdef USE_DARWINSSL

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#if (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE))
#include <sys/sysctl.h>
#endif

#include "urldata.h"
#include "sendf.h"
#include "inet_pton.h"
#include "connect.h"
#include "select.h"
#include "sslgen.h"
#include "curl_darwinssl.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/* From MacTypes.h (which we can't include because it isn't present in iOS: */
#define ioErr -36

/* In Mountain Lion and iOS 5, Apple made some changes to the API. They
   added TLS 1.1 and 1.2 support, and deprecated and replaced some
   functions. You need to build against the Mountain Lion or iOS 5 SDK
   or later to get TLS 1.1 or 1.2 support working in cURL. We'll weak-link
   to the newer functions and use them if present in the user's OS.

   Builders: If you want TLS 1.1 and 1.2 but still want to retain support
   for older cats, don't forget to set the MACOSX_DEPLOYMENT_TARGET
   environmental variable prior to building cURL. */

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
      if((rrtn == 0) && (theErr == 0)) {
        /* try fix for iSync */
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
                   (char*)dataPtr + bytesSent,
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

CF_INLINE const char *SSLCipherNameForNumber(SSLCipherSuite cipher) {
  switch (cipher) {
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

CF_INLINE const char *TLSCipherNameForNumber(SSLCipherSuite cipher) {
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
#if defined(__MAC_10_8) || defined(__IPHONE_5_0)
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
#endif /* defined(__MAC_10_8) || defined(__IPHONE_5_0) */
  }
  return "TLS_NULL_WITH_NULL_NULL";
}

CF_INLINE bool IsRunningMountainLionOrLater(void)
{
#if (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE))
  int mib[2];
  char *os_version;
  size_t os_version_len;
  char *os_version_major/*, *os_version_minor, *os_version_point*/;
  int os_version_major_int;

  /* Get the Darwin kernel version from the kernel using sysctl(): */
  mib[0] = CTL_KERN;
  mib[1] = KERN_OSRELEASE;
  if(sysctl(mib, 2, NULL, &os_version_len, NULL, 0) == -1)
    return false;
  os_version = malloc(os_version_len*sizeof(char));
  if(!os_version)
    return false;
  if(sysctl(mib, 2, os_version, &os_version_len, NULL, 0) == -1) {
    free(os_version);
    return false;
  }

  /* Parse the version. If it's version 12.0.0 or later, then this user is
     using Mountain Lion. */
  os_version_major = strtok(os_version, ".");
  /*os_version_minor = strtok(NULL, ".");
  os_version_point = strtok(NULL, ".");*/
  os_version_major_int = atoi(os_version_major);
  free(os_version);
  return os_version_major_int >= 12;
#else
  return true;  /* iOS users: this doesn't concern you */
#endif
}

static CURLcode darwinssl_connect_step1(struct connectdata *conn,
                                        int sockindex)
{
  struct SessionHandle *data = conn->data;
  curl_socket_t sockfd = conn->sock[sockindex];
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
#ifdef ENABLE_IPV6
  struct in6_addr addr;
#else
  struct in_addr addr;
#endif
  /*SSLConnectionRef ssl_connection;*/
  OSStatus err = noErr;

#if defined(__MAC_10_8) || defined(__IPHONE_5_0)
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
#if (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE))
    if(connssl->ssl_ctx)
      (void)SSLDisposeContext(connssl->ssl_ctx);
    err = SSLNewContext(false, &(connssl->ssl_ctx));
    if(err != noErr) {
      failf(data, "SSL: couldn't create a context: OSStatus %d", err);
      return CURLE_OUT_OF_MEMORY;
    }
#endif /* (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE)) */
  }
#else
  if(connssl->ssl_ctx)
    (void)SSLDisposeContext(connssl->ssl_ctx);
  err = SSLNewContext(false, &(connssl->ssl_ctx));
  if(err != noErr) {
    failf(data, "SSL: couldn't create a context: OSStatus %d", err);
    return CURLE_OUT_OF_MEMORY;
  }
#endif /* defined(__MAC_10_8) || defined(__IPHONE_5_0) */

  /* check to see if we've been told to use an explicit SSL/TLS version */
#if defined(__MAC_10_8) || defined(__IPHONE_5_0)
  if(SSLSetProtocolVersionMax != NULL) {
    switch(data->set.ssl.version) {
      case CURL_SSLVERSION_DEFAULT: default:
        (void)SSLSetProtocolVersionMin(connssl->ssl_ctx, kSSLProtocol3);
        (void)SSLSetProtocolVersionMax(connssl->ssl_ctx, kTLSProtocol12);
        break;
      case CURL_SSLVERSION_TLSv1:
        (void)SSLSetProtocolVersionMin(connssl->ssl_ctx, kTLSProtocol1);
        (void)SSLSetProtocolVersionMax(connssl->ssl_ctx, kTLSProtocol12);
        break;
      case CURL_SSLVERSION_SSLv3:
        (void)SSLSetProtocolVersionMin(connssl->ssl_ctx, kSSLProtocol3);
        (void)SSLSetProtocolVersionMax(connssl->ssl_ctx, kSSLProtocol3);
        break;
      case CURL_SSLVERSION_SSLv2:
        (void)SSLSetProtocolVersionMin(connssl->ssl_ctx, kSSLProtocol2);
        (void)SSLSetProtocolVersionMax(connssl->ssl_ctx, kSSLProtocol2);
    }
  }
  else {
#if (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE))
    (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                       kSSLProtocolAll,
                                       false);
    switch (data->set.ssl.version) {
      case CURL_SSLVERSION_DEFAULT: default:
        (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                           kSSLProtocol3,
                                           true);
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
      case CURL_SSLVERSION_SSLv3:
        (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                           kSSLProtocol3,
                                           true);
        break;
      case CURL_SSLVERSION_SSLv2:
        (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                           kSSLProtocol2,
                                           true);
        break;
    }
#endif  /* (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE)) */
  }
#else
  (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx, kSSLProtocolAll, false);
  switch(data->set.ssl.version) {
    default:
    case CURL_SSLVERSION_DEFAULT:
      (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                         kSSLProtocol3,
                                         true);
      (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                         kTLSProtocol1,
                                         true);
      break;
    case CURL_SSLVERSION_TLSv1:
      (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                         kTLSProtocol1,
                                         true);
      break;
    case CURL_SSLVERSION_SSLv2:
      (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                         kSSLProtocol2,
                                         true);
      break;
    case CURL_SSLVERSION_SSLv3:
      (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx,
                                         kSSLProtocol3,
                                         true);
      break;
  }
#endif /* defined(__MAC_10_8) || defined(__IPHONE_5_0) */

  /* No need to load certificates here. SecureTransport uses the Keychain
   * (which is also part of the Security framework) to evaluate trust. */

  /* SSL always tries to verify the peer, this only says whether it should
   * fail to connect if the verification fails, or if it should continue
   * anyway. In the latter case the result of the verification is checked with
   * SSL_get_verify_result() below. */
#if defined(__MAC_10_6) || defined(__IPHONE_5_0)
  /* Snow Leopard introduced the SSLSetSessionOption() function, but due to
     a library bug with the way the kSSLSessionOptionBreakOnServerAuth flag
     works, it doesn't work as expected under Snow Leopard or Lion.
     So we need to call SSLSetEnableCertVerify() on those older cats in order
     to disable certificate validation if the user turned that off.
     (SecureTransport will always validate the certificate chain by
     default.) */
  if(SSLSetSessionOption != NULL && IsRunningMountainLionOrLater()) {
    err = SSLSetSessionOption(connssl->ssl_ctx,
                              kSSLSessionOptionBreakOnServerAuth,
                              data->set.ssl.verifypeer?false:true);
    if(err != noErr) {
      failf(data, "SSL: SSLSetSessionOption() failed: OSStatus %d", err);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
  else {
#if (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE))
    err = SSLSetEnableCertVerify(connssl->ssl_ctx,
                                 data->set.ssl.verifypeer?true:false);
    if(err != noErr) {
      failf(data, "SSL: SSLSetEnableCertVerify() failed: OSStatus %d", err);
      return CURLE_SSL_CONNECT_ERROR;
    }
#endif /* (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE)) */
  }
#else
  err = SSLSetEnableCertVerify(connssl->ssl_ctx,
                               data->set.ssl.verifypeer?true:false);
  if(err != noErr) {
    failf(data, "SSL: SSLSetEnableCertVerify() failed: OSStatus %d", err);
    return CURLE_SSL_CONNECT_ERROR;
  }
#endif /* defined(__MAC_10_6) || defined(__IPHONE_5_0) */

  /* If this is a domain name and not an IP address, then configure SNI.
   * Also: the verifyhost setting influences SNI usage */
  /* If this is a domain name and not an IP address, then configure SNI: */
  if((0 == Curl_inet_pton(AF_INET, conn->host.name, &addr)) &&
#ifdef ENABLE_IPV6
     (0 == Curl_inet_pton(AF_INET6, conn->host.name, &addr)) &&
#endif
     data->set.ssl.verifyhost) {
    err = SSLSetPeerDomainName(connssl->ssl_ctx, conn->host.name,
                               strlen(conn->host.name));
    if(err != noErr) {
      infof(data, "WARNING: SSL: SSLSetPeerDomainName() failed: OSStatus %d",
            err);
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
  /*ssl_connection = &(connssl->ssl_sockfd);
  err = SSLSetConnection(connssl->ssl_ctx, ssl_connection);*/
  err = SSLSetConnection(connssl->ssl_ctx, connssl);
  if(err != noErr) {
    failf(data, "SSL: SSLSetConnection() failed: %d", err);
    return CURLE_SSL_CONNECT_ERROR;
  }

  connssl->connecting_state = ssl_connect_2;
  return CURLE_OK;
}

static CURLcode
darwinssl_connect_step2(struct connectdata *conn, int sockindex)
{
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  OSStatus err;
  SSLCipherSuite cipher;
  SSLProtocol protocol = 0;

  DEBUGASSERT(ssl_connect_2 == connssl->connecting_state
              || ssl_connect_2_reading == connssl->connecting_state
              || ssl_connect_2_writing == connssl->connecting_state);

  /* Here goes nothing: */
  err = SSLHandshake(connssl->ssl_ctx);

  if(err != noErr) {
    switch (err) {
      case errSSLWouldBlock:  /* they're not done with us yet */
        connssl->connecting_state = connssl->ssl_direction ?
            ssl_connect_2_writing : ssl_connect_2_reading;
        return CURLE_OK;

      case errSSLServerAuthCompleted:
        /* the documentation says we need to call SSLHandshake() again */
        return darwinssl_connect_step2(conn, sockindex);

      case errSSLXCertChainInvalid:
      case errSSLUnknownRootCert:
      case errSSLNoRootCert:
      case errSSLCertExpired:
        failf(data, "SSL certificate problem: OSStatus %d", err);
        return CURLE_SSL_CACERT;

      case errSSLHostNameMismatch:
        failf(data, "SSL certificate peer verification failed, the "
              "certificate did not match \"%s\"\n", conn->host.dispname);
        return CURLE_PEER_FAILED_VERIFICATION;

      default:
        failf(data, "Unknown SSL protocol error in connection to %s:%d",
              conn->host.name, err);
        return CURLE_SSL_CONNECT_ERROR;
    }
  }
  else {
    /* we have been connected fine, we're not waiting for anything else. */
    connssl->connecting_state = ssl_connect_3;

    /* Informational message */
    (void)SSLGetNegotiatedCipher(connssl->ssl_ctx, &cipher);
    (void)SSLGetNegotiatedProtocolVersion(connssl->ssl_ctx, &protocol);
    switch (protocol) {
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
#if defined(__MAC_10_8) || defined(__IPHONE_5_0)
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

static CURLcode
darwinssl_connect_step3(struct connectdata *conn,
                        int sockindex)
{
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  CFStringRef server_cert_summary;
  char server_cert_summary_c[128];
  CFArrayRef server_certs;
  SecCertificateRef server_cert;
  OSStatus err;
  CFIndex i, count;
  SecTrustRef trust;

  /* There is no step 3!
   * Well, okay, if verbose mode is on, let's print the details of the
   * server certificates. */
#if defined(__MAC_10_7) || defined(__IPHONE_5_0)
#if (TARGET_OS_EMBEDDED || TARGET_OS_IPHONE)
#pragma unused(server_certs)
  err = SSLCopyPeerTrust(connssl->ssl_ctx, &trust);
  if(err == noErr) {
    count = SecTrustGetCertificateCount(trust);
    for(i = 0L ; i < count ; i++) {
      server_cert = SecTrustGetCertificateAtIndex(trust, i);
      server_cert_summary = SecCertificateCopySubjectSummary(server_cert);
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
    if(err == noErr) {
      count = SecTrustGetCertificateCount(trust);
      for(i = 0L ; i < count ; i++) {
        server_cert = SecTrustGetCertificateAtIndex(trust, i);
        server_cert_summary =
          SecCertificateCopyLongDescription(NULL, server_cert, NULL);
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
    err = SSLCopyPeerCertificates(connssl->ssl_ctx, &server_certs);
    if(err == noErr) {
      count = CFArrayGetCount(server_certs);
      for(i = 0L ; i < count ; i++) {
        server_cert = (SecCertificateRef)CFArrayGetValueAtIndex(server_certs,
                                                                i);

        server_cert_summary = SecCertificateCopySubjectSummary(server_cert);
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
  }
#endif /* (TARGET_OS_EMBEDDED || TARGET_OS_IPHONE) */
#else
#pragma unused(trust)
  err = SSLCopyPeerCertificates(connssl->ssl_ctx, &server_certs);
  if(err == noErr) {
    count = CFArrayGetCount(server_certs);
    for(i = 0L ; i < count ; i++) {
      server_cert = (SecCertificateRef)CFArrayGetValueAtIndex(server_certs, i);

      server_cert_summary = SecCertificateCopySubjectSummary(server_cert);
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
#endif /* defined(__MAC_10_7) || defined(__IPHONE_5_0) */

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
    retcode = darwinssl_connect_step1(conn, sockindex);
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

      curl_socket_t writefd = ssl_connect_2_writing ==
      connssl->connecting_state?sockfd:CURL_SOCKET_BAD;
      curl_socket_t readfd = ssl_connect_2_reading ==
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
    retcode = darwinssl_connect_step2(conn, sockindex);
    if(retcode || (nonblocking &&
                   (ssl_connect_2 == connssl->connecting_state ||
                    ssl_connect_2_reading == connssl->connecting_state ||
                    ssl_connect_2_writing == connssl->connecting_state)))
      return retcode;

  } /* repeat step2 until all transactions are done. */


  if(ssl_connect_3==connssl->connecting_state) {
    retcode = darwinssl_connect_step3(conn, sockindex);
    if(retcode)
      return retcode;
  }

  if(ssl_connect_done==connssl->connecting_state) {
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
  CURLcode retcode;
  bool done = FALSE;

  retcode = darwinssl_connect_common(conn, sockindex, FALSE, &done);

  if(retcode)
    return retcode;

  DEBUGASSERT(done);

  return CURLE_OK;
}

void Curl_darwinssl_close(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  if(connssl->ssl_ctx) {
    (void)SSLClose(connssl->ssl_ctx);
#if defined(__MAC_10_8) || defined(__IPHONE_5_0)
    if(SSLCreateContext != NULL)
      CFRelease(connssl->ssl_ctx);
#if (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE))
    else
      (void)SSLDisposeContext(connssl->ssl_ctx);
#endif  /* (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE)) */
#else
    (void)SSLDisposeContext(connssl->ssl_ctx);
#endif /* defined(__MAC_10_8) || defined(__IPHONE_5_0) */
    connssl->ssl_ctx = NULL;
  }
  connssl->ssl_sockfd = 0;
}

void Curl_darwinssl_close_all(struct SessionHandle *data)
{
  /* SecureTransport doesn't separate sessions from contexts, so... */
  (void)data;
}

int Curl_darwinssl_shutdown(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct SessionHandle *data = conn->data;
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
     notify alert from the server. No way to SSL_Read now, so use read(). */

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

void Curl_darwinssl_random(struct SessionHandle *data,
                           unsigned char *entropy,
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
  (void)data;
}

void Curl_darwinssl_md5sum(unsigned char *tmp, /* input */
                           size_t tmplen,
                           unsigned char *md5sum, /* output */
                           size_t md5len)
{
  (void)md5len;
  (void)CC_MD5(tmp, (CC_LONG)tmplen, md5sum);
}

static ssize_t darwinssl_send(struct connectdata *conn,
                              int sockindex,
                              const void *mem,
                              size_t len,
                              CURLcode *curlcode)
{
  /*struct SessionHandle *data = conn->data;*/
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  size_t processed = 0UL;
  OSStatus err = SSLWrite(connssl->ssl_ctx, mem, len, &processed);

  if(err != noErr) {
    switch (err) {
      case errSSLWouldBlock:  /* return how much we sent (if anything) */
        if(processed)
          return (ssize_t)processed;
        *curlcode = CURLE_AGAIN;
        return -1;
        break;

      default:
        failf(conn->data, "SSLWrite() return error %d", err);
        *curlcode = CURLE_SEND_ERROR;
        return -1;
        break;
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
  /*struct SessionHandle *data = conn->data;*/
  struct ssl_connect_data *connssl = &conn->ssl[num];
  size_t processed = 0UL;
  OSStatus err = SSLRead(connssl->ssl_ctx, buf, buffersize, &processed);

  if(err != noErr) {
    switch (err) {
      case errSSLWouldBlock:  /* return how much we read (if anything) */
        if(processed)
          return (ssize_t)processed;
        *curlcode = CURLE_AGAIN;
        return -1;
        break;

      case errSSLClosedGraceful: /* they're done; fail gracefully */
        *curlcode = CURLE_OK;
        return -1;
        break;

      default:
        failf(conn->data, "SSLRead() return error %d", err);
        *curlcode = CURLE_RECV_ERROR;
        return -1;
        break;
    }
  }
  return (ssize_t)processed;
}

#endif /* USE_DARWINSSL */
