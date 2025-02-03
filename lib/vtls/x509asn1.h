#ifndef HEADER_FETCH_X509ASN1_H
#define HEADER_FETCH_X509ASN1_H

/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"

#if defined(USE_GNUTLS) || defined(USE_WOLFSSL) ||     \
    defined(USE_SCHANNEL) || defined(USE_SECTRANSP) || \
    defined(USE_MBEDTLS)

#include "cfilters.h"
#include "urldata.h"

/*
 * Types.
 */

/* ASN.1 parsed element. */
struct Fetch_asn1Element
{
  const char *header;  /* Pointer to header byte. */
  const char *beg;     /* Pointer to element data. */
  const char *end;     /* Pointer to 1st byte after element. */
  unsigned char class; /* ASN.1 element class. */
  unsigned char tag;   /* ASN.1 element tag. */
  bool constructed;    /* Element is constructed. */
};

/* X509 certificate: RFC 5280. */
struct Fetch_X509certificate
{
  struct Fetch_asn1Element certificate;
  struct Fetch_asn1Element version;
  struct Fetch_asn1Element serialNumber;
  struct Fetch_asn1Element signatureAlgorithm;
  struct Fetch_asn1Element signature;
  struct Fetch_asn1Element issuer;
  struct Fetch_asn1Element notBefore;
  struct Fetch_asn1Element notAfter;
  struct Fetch_asn1Element subject;
  struct Fetch_asn1Element subjectPublicKeyInfo;
  struct Fetch_asn1Element subjectPublicKeyAlgorithm;
  struct Fetch_asn1Element subjectPublicKey;
  struct Fetch_asn1Element issuerUniqueID;
  struct Fetch_asn1Element subjectUniqueID;
  struct Fetch_asn1Element extensions;
};

/*
 * Prototypes.
 */

int Fetch_parseX509(struct Fetch_X509certificate *cert,
                   const char *beg, const char *end);
FETCHcode Fetch_extract_certinfo(struct Fetch_easy *data, int certnum,
                                const char *beg, const char *end);
FETCHcode Fetch_verifyhost(struct Fetch_cfilter *cf, struct Fetch_easy *data,
                          const char *beg, const char *end);

#ifdef UNITTESTS
#if defined(USE_GNUTLS) || defined(USE_SCHANNEL) || defined(USE_SECTRANSP) || \
    defined(USE_MBEDTLS)

/* used by unit1656.c */
FETCHcode Fetch_x509_GTime2str(struct dynbuf *store,
                              const char *beg, const char *end);
#endif
#endif

#endif /* USE_GNUTLS or USE_WOLFSSL or USE_SCHANNEL or USE_SECTRANSP */
#endif /* HEADER_FETCH_X509ASN1_H */
