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
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

/*
 * mock_x509.c - X.509 name string and extension decoding mocks.
 *
 * Implements:
 *   CertGetNameStringA, CertGetNameStringW
 *   CertFindExtension, CryptDecodeObjectEx
 */

#include "mock_internal.h"

DWORD WINAPI CertGetNameStringA(PCCERT_CONTEXT pCertContext, DWORD dwType,
                                DWORD dwFlags, void *pvTypePara,
                                LPSTR pszNameString, DWORD cchNameString)
{
  mock_cert_context_t *mc;
  X509 *x509;
  char buf[256];
  size_t needed;
  (void)pvTypePara;

  if(!pCertContext)
    return 0;

  mc = (mock_cert_context_t *)UNCONST(pCertContext);
  x509 = mc->x509;
  if(!x509)
    return 0;

  buf[0] = '\0';

  if(dwType == CERT_NAME_DNS_TYPE) {
    int found = 0;
    GENERAL_NAMES *sans;

    sans = (GENERAL_NAMES *)X509_get_ext_d2i(x509, NID_subject_alt_name,
                                             NULL, NULL);
    if(sans) {
      int sn = sk_GENERAL_NAME_num(sans);
      int j;

      (void)dwFlags;
      for(j = 0; j < sn && !found; j++) {
        GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, j);
        if(gn && gn->type == GEN_DNS) {
          const char *dns = (const char *)
            ASN1_STRING_get0_data(gn->d.dNSName);
          if(dns) {
            snprintf(buf, sizeof(buf), "%s", dns);
            found = 1;
          }
        }
      }
      GENERAL_NAMES_free(sans);
    }

    if(!found) {
      X509_NAME_get_text_by_NID(X509_get_subject_name(x509),
                                NID_commonName, buf, (int)sizeof(buf));
    }
  }
  else {
    X509_NAME_get_text_by_NID(X509_get_subject_name(x509),
                              NID_commonName, buf, (int)sizeof(buf));
  }

  needed = strlen(buf) + 1;
  if(!pszNameString || !cchNameString)
    return (DWORD)needed;

  if(cchNameString < (DWORD)needed) {
    memcpy(pszNameString, buf, (size_t)cchNameString - 1);
    pszNameString[cchNameString - 1] = '\0';
    return cchNameString;
  }

  memcpy(pszNameString, buf, needed);
  return (DWORD)needed;
}

DWORD WINAPI CertGetNameStringW(PCCERT_CONTEXT pCertContext, DWORD dwType,
                                DWORD dwFlags, void *pvTypePara,
                                LPWSTR pszNameString, DWORD cchNameString)
{
  char buf[256];
  DWORD alen;
  DWORD i;

  alen = CertGetNameStringA(pCertContext, dwType, dwFlags, pvTypePara,
                            buf, (DWORD)sizeof(buf));
  if(!alen)
    return 0;

  if(!pszNameString || !cchNameString)
    return alen;

  if(cchNameString < alen)
    alen = cchNameString;

  for(i = 0; i < alen; i++)
    pszNameString[i] = (WCHAR)(unsigned char)buf[i];

  return alen;
}

PCERT_EXTENSION WINAPI CertFindExtension(LPCSTR pszObjId, DWORD cExtensions,
                                         CERT_EXTENSION *rgExtensions)
{
  DWORD i;
  if(!pszObjId || !rgExtensions)
    return NULL;

  for(i = 0; i < cExtensions; i++) {
    if(rgExtensions[i].pszObjId &&
       !strcmp(rgExtensions[i].pszObjId, pszObjId))
      return &rgExtensions[i];
  }
  return NULL;
}

BOOL WINAPI CryptDecodeObjectEx(DWORD dwCertEncodingType,
                                LPCSTR lpszStructType,
                                const BYTE *pbEncoded, DWORD cbEncoded,
                                DWORD dwFlags, PCRYPT_DECODE_PARA pDecodePara,
                                void *pvStructInfo, DWORD *pcbStructInfo)
{
  GENERAL_NAMES *gnames;
  const unsigned char *p;
  int sn;
  int i;
  size_t info_sz;
  size_t str_bytes;
  CERT_ALT_NAME_INFO *info;
  CERT_ALT_NAME_ENTRY *entries;
  BYTE *extra;
  size_t extra_offset;
  (void)dwCertEncodingType;
  (void)pDecodePara;

  if(!pbEncoded || !cbEncoded || !pcbStructInfo) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }

  if(!lpszStructType ||
     strcmp(lpszStructType, szOID_SUBJECT_ALT_NAME2)) {
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
  }

  p = pbEncoded;
  gnames = d2i_GENERAL_NAMES(NULL, &p, (long)cbEncoded);
  if(!gnames) {
    const unsigned char *raw = pbEncoded;
    ASN1_OCTET_STRING *os = d2i_ASN1_OCTET_STRING(NULL, &raw,
                                                  (long)cbEncoded);
    if(os) {
      const unsigned char *inner = ASN1_STRING_get0_data(os);
      int inner_len = ASN1_STRING_length(os);
      gnames = d2i_GENERAL_NAMES(NULL, &inner, (long)inner_len);
      ASN1_OCTET_STRING_free(os);
    }
    if(!gnames) {
      SetLastError(ERROR_INVALID_DATA);
      return FALSE;
    }
  }

  sn = sk_GENERAL_NAME_num(gnames);
  str_bytes = 0;

  for(i = 0; i < sn; i++) {
    GENERAL_NAME *gn = sk_GENERAL_NAME_value(gnames, i);
    if(!gn)
      continue;
    if(gn->type == GEN_DNS) {
      int dlen = ASN1_STRING_length(gn->d.dNSName);
      str_bytes += (size_t)(dlen + 1) * sizeof(WCHAR);
    }
    else if(gn->type == GEN_IPADD) {
      int ilen = ASN1_STRING_length(gn->d.ip);
      str_bytes += (size_t)ilen;
    }
  }

  info_sz = sizeof(CERT_ALT_NAME_INFO) +
    (size_t)sn * sizeof(CERT_ALT_NAME_ENTRY) +
    str_bytes;

  if(!(dwFlags & CRYPT_DECODE_ALLOC_FLAG)) {
    if(!pvStructInfo) {
      *pcbStructInfo = (DWORD)info_sz;
      GENERAL_NAMES_free(gnames);
      return TRUE;
    }
    if(*pcbStructInfo < (DWORD)info_sz) {
      *pcbStructInfo = (DWORD)info_sz;
      GENERAL_NAMES_free(gnames);
      SetLastError(ERROR_INSUFFICIENT_BUFFER);
      return FALSE;
    }
    info = (CERT_ALT_NAME_INFO *)pvStructInfo;
  }
  else {
    info = (CERT_ALT_NAME_INFO *)LocalAlloc(LMEM_ZEROINIT, info_sz);
    if(!info) {
      GENERAL_NAMES_free(gnames);
      SetLastError(ERROR_NOT_ENOUGH_MEMORY);
      return FALSE;
    }
    *(void **)pvStructInfo = info;
  }

  memset(info, 0, info_sz);
  entries = (CERT_ALT_NAME_ENTRY *)((BYTE *)info +
                                    sizeof(CERT_ALT_NAME_INFO));
  extra = (BYTE *)entries + (size_t)sn * sizeof(CERT_ALT_NAME_ENTRY);
  extra_offset = 0;

  info->cAltEntry = (DWORD)sn;
  info->rgAltEntry = entries;

  for(i = 0; i < sn; i++) {
    GENERAL_NAME *gn = sk_GENERAL_NAME_value(gnames, i);
    entries[i].dwAltNameChoice = 0;

    if(!gn)
      continue;

    if(gn->type == GEN_DNS) {
      const unsigned char *dns_data = ASN1_STRING_get0_data(gn->d.dNSName);
      int dns_len = ASN1_STRING_length(gn->d.dNSName);
      WCHAR *wdns = (WCHAR *)(extra + extra_offset);
      int j;
      for(j = 0; j < dns_len; j++)
        wdns[j] = (WCHAR)(unsigned char)dns_data[j];
      wdns[dns_len] = (WCHAR)0;
      entries[i].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
      entries[i].pwszDNSName = wdns;
      extra_offset += (size_t)(dns_len + 1) * sizeof(WCHAR);
    }
    else if(gn->type == GEN_IPADD) {
      const unsigned char *ip_data = ASN1_STRING_get0_data(gn->d.ip);
      int ip_len = ASN1_STRING_length(gn->d.ip);
      BYTE *ip_buf = extra + extra_offset;
      memcpy(ip_buf, ip_data, (size_t)ip_len);
      entries[i].dwAltNameChoice = CERT_ALT_NAME_IP_ADDRESS;
      entries[i].IPAddress.pbData = ip_buf;
      entries[i].IPAddress.cbData = (DWORD)ip_len;
      extra_offset += (size_t)ip_len;
    }
  }

  *pcbStructInfo = (DWORD)info_sz;
  GENERAL_NAMES_free(gnames);
  return TRUE;
}
