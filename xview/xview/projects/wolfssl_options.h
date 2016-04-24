/*
By default wolfSSL has a very conservative configuration that can result in
connections to servers failing due to certificate or algorithm problems.
To remedy this issue for libcurl I've generated this options file that
build-wolfssl will copy to the wolfSSL include directories and will result in
maximum compatibility.

These configure flags were used in MinGW to generate the options in this file:

--enable-opensslextra
--enable-aesgcm
--enable-ripemd
--enable-sha512
--enable-dh
--enable-dsa
--enable-ecc
--enable-sni
--enable-fastmath
--enable-sessioncerts
--enable-certgen
--enable-testcert
C_EXTRA_FLAGS="-DFP_MAX_BITS=16384 -DTFM_TIMING_RESISTANT"

Two generated options HAVE_THREAD_LS and _POSIX_THREADS were removed since they
are inapplicable for our Visual Studio build.

Regarding the two options that were added via C_EXTRA_FLAGS:

FP_MAX_BITS=16384
http://www.yassl.com/forums/topic423-cacertorgs-ca-cert-verify-failed-but-withdisablefastmath-it-works.html
"Since root.crt uses a 4096-bit RSA key, you'll need to increase the fastmath
buffer size.  You can do this using the define:
FP_MAX_BITS and setting it to 8192."

TFM_TIMING_RESISTANT
https://wolfssl.com/wolfSSL/Docs-wolfssl-manual-2-building-wolfssl.html
From section 2.4.5 Increasing Performance, USE_FAST_MATH:
"Because the stack memory usage can be larger when using fastmath, we recommend
defining TFM_TIMING_RESISTANT as well when using this option."
*/

/* wolfssl options.h
 * generated from configure options
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#undef  FP_MAX_BITS
#define FP_MAX_BITS 16384

#undef  TFM_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT

#undef  OPENSSL_EXTRA
#define OPENSSL_EXTRA

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

#undef  NO_PSK
#define NO_PSK

#undef  NO_RC4
#define NO_RC4

#undef  NO_MD4
#define NO_MD4

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

#undef  WOLFSSL_TEST_CERT
#define WOLFSSL_TEST_CERT

#undef  USE_FAST_MATH
#define USE_FAST_MATH


#ifdef __cplusplus
}
#endif

