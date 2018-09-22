/*
By default wolfSSL has a very conservative configuration that can result in
connections to servers failing due to certificate or algorithm problems.
To remedy this issue for libcurl I've generated this options file that
build-wolfssl will copy to the wolfSSL include directories and will result in
maximum compatibility.

These are the configure options that were used to build wolfSSL v3.11.0 in
mingw and generate the options in this file:

C_EXTRA_FLAGS="\
  -Wno-attributes \
  -Wno-unused-but-set-variable \
  -DFP_MAX_BITS=16384 \
  -DTFM_TIMING_RESISTANT \
  -DWOLFSSL_STATIC_DH \
  -DWOLFSSL_STATIC_RSA \
  " \
./configure --prefix=/usr/local \
  --disable-jobserver \
  --enable-aesgcm \
  --enable-alpn \
  --enable-certgen \
  --enable-des3 \
  --enable-dh \
  --enable-dsa \
  --enable-ecc \
  --enable-eccshamir \
  --enable-fastmath \
  --enable-opensslextra \
  --enable-ripemd \
  --enable-sessioncerts \
  --enable-sha512 \
  --enable-sni \
  --enable-sslv3 \
  --enable-supportedcurves \
  --enable-testcert \
  > config.out 2>&1

Two generated options HAVE_THREAD_LS and _POSIX_THREADS were removed since they
are inapplicable for our Visual Studio build. Currently thread local storage is
only used by the Fixed Point cache ECC which we're not enabling. However even
if we later may decide to enable the cache it will fallback on mutexes when
thread local storage is not available. wolfSSL is using __declspec(thread) to
create the thread local storage and that could be a problem for LoadLibrary.

Regarding the options that were added via C_EXTRA_FLAGS:

FP_MAX_BITS=16384
https://www.yassl.com/forums/topic423-cacertorgs-ca-cert-verify-failed-but-withdisablefastmath-it-works.html
"Since root.crt uses a 4096-bit RSA key, you'll need to increase the fastmath
buffer size.  You can do this using the define:
FP_MAX_BITS and setting it to 8192."

TFM_TIMING_RESISTANT
https://wolfssl.com/wolfSSL/Docs-wolfssl-manual-2-building-wolfssl.html
From section 2.4.5 Increasing Performance, USE_FAST_MATH:
"Because the stack memory usage can be larger when using fastmath, we recommend
defining TFM_TIMING_RESISTANT as well when using this option."

WOLFSSL_STATIC_DH:    Allow TLS_ECDH_ ciphers
WOLFSSL_STATIC_RSA:   Allow TLS_RSA_ ciphers
https://github.com/wolfSSL/wolfssl/blob/v3.6.6/README.md#note-1
Static key cipher suites are deprecated and disabled by default since v3.6.6.
*/

/* wolfssl options.h
 * generated from configure options
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 */

#ifndef WOLFSSL_OPTIONS_H
#define WOLFSSL_OPTIONS_H


#ifdef __cplusplus
extern "C" {
#endif

#undef  FP_MAX_BITS
#define FP_MAX_BITS 16384

#undef  TFM_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT

#undef  WOLFSSL_STATIC_DH
#define WOLFSSL_STATIC_DH

#undef  WOLFSSL_STATIC_RSA
#define WOLFSSL_STATIC_RSA

#undef  OPENSSL_EXTRA
#define OPENSSL_EXTRA

/*
The commented out defines below are the equivalent of --enable-tls13.
Uncomment them to build wolfSSL with TLS 1.3 support as of v3.11.1-tls13-beta.
This is for experimenting only, afaict TLS 1.3 support doesn't appear to be
functioning correctly yet. https://github.com/wolfSSL/wolfssl/pull/943

#undef  WC_RSA_PSS
#define WC_RSA_PSS

#undef  WOLFSSL_TLS13
#define WOLFSSL_TLS13

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_FFDHE_2048
#define HAVE_FFDHE_2048

#undef  HAVE_HKDF
#define HAVE_HKDF
*/

#undef  TFM_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT

#undef  ECC_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT

#undef  WC_RSA_BLINDING
#define WC_RSA_BLINDING

#undef  HAVE_AESGCM
#define HAVE_AESGCM

#undef  WOLFSSL_RIPEMD
#define WOLFSSL_RIPEMD

#undef  WOLFSSL_SHA512
#define WOLFSSL_SHA512

#undef  WOLFSSL_SHA384
#define WOLFSSL_SHA384

#undef  SESSION_CERTS
#define SESSION_CERTS

#undef  WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_GEN

#undef  HAVE_ECC
#define HAVE_ECC

#undef  TFM_ECC256
#define TFM_ECC256

#undef  ECC_SHAMIR
#define ECC_SHAMIR

#undef  WOLFSSL_ALLOW_SSLV3
#define WOLFSSL_ALLOW_SSLV3

#undef  NO_RC4
#define NO_RC4

#undef  NO_HC128
#define NO_HC128

#undef  NO_RABBIT
#define NO_RABBIT

#undef  HAVE_POLY1305
#define HAVE_POLY1305

#undef  HAVE_ONE_TIME_AUTH
#define HAVE_ONE_TIME_AUTH

#undef  HAVE_CHACHA
#define HAVE_CHACHA

#undef  HAVE_HASHDRBG
#define HAVE_HASHDRBG

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_SNI
#define HAVE_SNI

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_ALPN
#define HAVE_ALPN

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_SUPPORTED_CURVES
#define HAVE_SUPPORTED_CURVES

#undef  HAVE_EXTENDED_MASTER
#define HAVE_EXTENDED_MASTER

#undef  WOLFSSL_TEST_CERT
#define WOLFSSL_TEST_CERT

#undef  NO_PSK
#define NO_PSK

#undef  NO_MD4
#define NO_MD4

#undef  USE_FAST_MATH
#define USE_FAST_MATH

#undef  WC_NO_ASYNC_THREADING
#define WC_NO_ASYNC_THREADING


#ifdef __cplusplus
}
#endif


#endif /* WOLFSSL_OPTIONS_H */
