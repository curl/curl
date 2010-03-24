/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2009, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "setup.h"

/* NTLM details:

   http://davenport.sourceforge.net/ntlm.html
   http://www.innovation.ch/java/ntlm.html

   Another implementation:
   http://lxr.mozilla.org/mozilla/source/security/manager/ssl/src/nsNTLMAuthModule.cpp

*/

#ifndef CURL_DISABLE_HTTP
#ifdef USE_NTLM

#define DEBUG_ME 0

/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#if (defined(NETWARE) && !defined(__NOVELL_LIBC__))
#include <netdb.h>
#endif

#include "urldata.h"
#include "easyif.h"  /* for Curl_convert_... prototypes */
#include "sendf.h"
#include "rawstr.h"
#include "curl_base64.h"
#include "http_ntlm.h"
#include "url.h"
#include "curl_memory.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* "NTLMSSP" signature is always in ASCII regardless of the platform */
#define NTLMSSP_SIGNATURE "\x4e\x54\x4c\x4d\x53\x53\x50"

#ifdef USE_SSLEAY
#include "ssluse.h"
#    ifdef USE_OPENSSL
#      include <openssl/des.h>
#      ifndef OPENSSL_NO_MD4
#        include <openssl/md4.h>
#      endif
#      include <openssl/md5.h>
#      include <openssl/ssl.h>
#      include <openssl/rand.h>
#    else
#      include <des.h>
#      ifndef OPENSSL_NO_MD4
#        include <md4.h>
#      endif
#      include <md5.h>
#      include <ssl.h>
#      include <rand.h>
#    endif

#if OPENSSL_VERSION_NUMBER < 0x00907001L
#define DES_key_schedule des_key_schedule
#define DES_cblock des_cblock
#define DES_set_odd_parity des_set_odd_parity
#define DES_set_key des_set_key
#define DES_ecb_encrypt des_ecb_encrypt

/* This is how things were done in the old days */
#define DESKEY(x) x
#define DESKEYARG(x) x
#else
/* Modern version */
#define DESKEYARG(x) *x
#define DESKEY(x) &x
#endif

#ifdef OPENSSL_NO_MD4
/* This requires MD4, but OpenSSL was compiled without it */
#define USE_NTRESPONSES 0
#define USE_NTLM2SESSION 0
#endif

#elif defined(USE_GNUTLS)

#include "gtls.h"
#include <gcrypt.h>

#define MD5_DIGEST_LENGTH 16
#define MD4_DIGEST_LENGTH 16

#elif defined(USE_WINDOWS_SSPI)

#include "curl_sspi.h"

#else
#    error "Can't compile NTLM support without a crypto library."
#endif

/* The last #include file should be: */
#include "memdebug.h"

#ifndef USE_NTRESPONSES 
/* Define this to make the type-3 message include the NT response message */
#define USE_NTRESPONSES 1

/* Define this to make the type-3 message include the NTLM2Session response
   message, requires USE_NTRESPONSES. */
#define USE_NTLM2SESSION 1
#endif

#ifndef USE_WINDOWS_SSPI
/* this function converts from the little endian format used in the incoming
   package to whatever endian format we're using natively */
static unsigned int readint_le(unsigned char *buf) /* must point to a
                                                      4 bytes buffer*/
{
  return ((unsigned int)buf[0]) | ((unsigned int)buf[1] << 8) |
    ((unsigned int)buf[2] << 16) | ((unsigned int)buf[3] << 24);
}
#endif

#if DEBUG_ME
# define DEBUG_OUT(x) x
static void print_flags(FILE *handle, unsigned long flags)
{
  if(flags & NTLMFLAG_NEGOTIATE_UNICODE)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_UNICODE ");
  if(flags & NTLMFLAG_NEGOTIATE_OEM)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_OEM ");
  if(flags & NTLMFLAG_REQUEST_TARGET)
    fprintf(handle, "NTLMFLAG_REQUEST_TARGET ");
  if(flags & (1<<3))
    fprintf(handle, "NTLMFLAG_UNKNOWN_3 ");
  if(flags & NTLMFLAG_NEGOTIATE_SIGN)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_SIGN ");
  if(flags & NTLMFLAG_NEGOTIATE_SEAL)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_SEAL ");
  if(flags & NTLMFLAG_NEGOTIATE_DATAGRAM_STYLE)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_DATAGRAM_STYLE ");
  if(flags & NTLMFLAG_NEGOTIATE_LM_KEY)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_LM_KEY ");
  if(flags & NTLMFLAG_NEGOTIATE_NETWARE)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_NETWARE ");
  if(flags & NTLMFLAG_NEGOTIATE_NTLM_KEY)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_NTLM_KEY ");
  if(flags & (1<<10))
    fprintf(handle, "NTLMFLAG_UNKNOWN_10 ");
  if(flags & NTLMFLAG_NEGOTIATE_ANONYMOUS)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_ANONYMOUS ");
  if(flags & NTLMFLAG_NEGOTIATE_DOMAIN_SUPPLIED)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_DOMAIN_SUPPLIED ");
  if(flags & NTLMFLAG_NEGOTIATE_WORKSTATION_SUPPLIED)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_WORKSTATION_SUPPLIED ");
  if(flags & NTLMFLAG_NEGOTIATE_LOCAL_CALL)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_LOCAL_CALL ");
  if(flags & NTLMFLAG_NEGOTIATE_ALWAYS_SIGN)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_ALWAYS_SIGN ");
  if(flags & NTLMFLAG_TARGET_TYPE_DOMAIN)
    fprintf(handle, "NTLMFLAG_TARGET_TYPE_DOMAIN ");
  if(flags & NTLMFLAG_TARGET_TYPE_SERVER)
    fprintf(handle, "NTLMFLAG_TARGET_TYPE_SERVER ");
  if(flags & NTLMFLAG_TARGET_TYPE_SHARE)
    fprintf(handle, "NTLMFLAG_TARGET_TYPE_SHARE ");
  if(flags & NTLMFLAG_NEGOTIATE_NTLM2_KEY)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_NTLM2_KEY ");
  if(flags & NTLMFLAG_REQUEST_INIT_RESPONSE)
    fprintf(handle, "NTLMFLAG_REQUEST_INIT_RESPONSE ");
  if(flags & NTLMFLAG_REQUEST_ACCEPT_RESPONSE)
    fprintf(handle, "NTLMFLAG_REQUEST_ACCEPT_RESPONSE ");
  if(flags & NTLMFLAG_REQUEST_NONNT_SESSION_KEY)
    fprintf(handle, "NTLMFLAG_REQUEST_NONNT_SESSION_KEY ");
  if(flags & NTLMFLAG_NEGOTIATE_TARGET_INFO)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_TARGET_INFO ");
  if(flags & (1<<24))
    fprintf(handle, "NTLMFLAG_UNKNOWN_24 ");
  if(flags & (1<<25))
    fprintf(handle, "NTLMFLAG_UNKNOWN_25 ");
  if(flags & (1<<26))
    fprintf(handle, "NTLMFLAG_UNKNOWN_26 ");
  if(flags & (1<<27))
    fprintf(handle, "NTLMFLAG_UNKNOWN_27 ");
  if(flags & (1<<28))
    fprintf(handle, "NTLMFLAG_UNKNOWN_28 ");
  if(flags & NTLMFLAG_NEGOTIATE_128)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_128 ");
  if(flags & NTLMFLAG_NEGOTIATE_KEY_EXCHANGE)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_KEY_EXCHANGE ");
  if(flags & NTLMFLAG_NEGOTIATE_56)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_56 ");
}

static void print_hex(FILE *handle, const char *buf, size_t len)
{
  const char *p = buf;
  fprintf(stderr, "0x");
  while(len-- > 0)
    fprintf(stderr, "%02.2x", (unsigned int)*p++);
}
#else
# define DEBUG_OUT(x)
#endif

/*
  (*) = A "security buffer" is a triplet consisting of two shorts and one
  long:

  1. a 'short' containing the length of the buffer in bytes
  2. a 'short' containing the allocated space for the buffer in bytes
  3. a 'long' containing the offset to the start of the buffer from the
     beginning of the NTLM message, in bytes.
*/


CURLntlm Curl_input_ntlm(struct connectdata *conn,
                         bool proxy,   /* if proxy or not */
                         const char *header) /* rest of the www-authenticate:
                                                header */
{
  /* point to the correct struct with this */
  struct ntlmdata *ntlm;
#ifndef USE_WINDOWS_SSPI
  static const char type2_marker[] = { 0x02, 0x00, 0x00, 0x00 };
#endif

  ntlm = proxy?&conn->proxyntlm:&conn->ntlm;

  /* skip initial whitespaces */
  while(*header && ISSPACE(*header))
    header++;

  if(checkprefix("NTLM", header)) {
    header += strlen("NTLM");

    while(*header && ISSPACE(*header))
      header++;

    if(*header) {
      /* We got a type-2 message here:

         Index   Description         Content
         0       NTLMSSP Signature   Null-terminated ASCII "NTLMSSP"
                                     (0x4e544c4d53535000)
         8       NTLM Message Type   long (0x02000000)
         12      Target Name         security buffer(*)
         20      Flags               long
         24      Challenge           8 bytes
         (32)    Context (optional)  8 bytes (two consecutive longs)
         (40)    Target Information  (optional) security buffer(*)
         32 (48) start of data block
      */
      size_t size;
      unsigned char *buffer;
      size = Curl_base64_decode(header, &buffer);
      if(!buffer)
        return CURLNTLM_BAD;

      ntlm->state = NTLMSTATE_TYPE2; /* we got a type-2 */

#ifdef USE_WINDOWS_SSPI
      ntlm->type_2 = malloc(size+1);
      if(ntlm->type_2 == NULL) {
        free(buffer);
        return CURLE_OUT_OF_MEMORY;
      }
      ntlm->n_type_2 = size;
      memcpy(ntlm->type_2, buffer, size);
#else
      ntlm->flags = 0;

      if((size < 32) ||
         (memcmp(buffer, NTLMSSP_SIGNATURE, 8) != 0) ||
         (memcmp(buffer+8, type2_marker, sizeof(type2_marker)) != 0)) {
        /* This was not a good enough type-2 message */
        free(buffer);
        return CURLNTLM_BAD;
      }

      ntlm->flags = readint_le(&buffer[20]);
      memcpy(ntlm->nonce, &buffer[24], 8);

      DEBUG_OUT({
        fprintf(stderr, "**** TYPE2 header flags=0x%08.8lx ", ntlm->flags);
        print_flags(stderr, ntlm->flags);
        fprintf(stderr, "\n                  nonce=");
        print_hex(stderr, (char *)ntlm->nonce, 8);
        fprintf(stderr, "\n****\n");
        fprintf(stderr, "**** Header %s\n ", header);
      });
#endif
      free(buffer);
    }
    else {
      if(ntlm->state >= NTLMSTATE_TYPE1)
        return CURLNTLM_BAD;

      ntlm->state = NTLMSTATE_TYPE1; /* we should sent away a type-1 */
    }
  }
  return CURLNTLM_FINE;
}

#ifndef USE_WINDOWS_SSPI

#ifdef USE_SSLEAY
/*
 * Turns a 56 bit key into the 64 bit, odd parity key and sets the key.  The
 * key schedule ks is also set.
 */
static void setup_des_key(const unsigned char *key_56,
                          DES_key_schedule DESKEYARG(ks))
{
  DES_cblock key;

  key[0] = key_56[0];
  key[1] = (unsigned char)(((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1));
  key[2] = (unsigned char)(((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2));
  key[3] = (unsigned char)(((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3));
  key[4] = (unsigned char)(((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4));
  key[5] = (unsigned char)(((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5));
  key[6] = (unsigned char)(((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6));
  key[7] = (unsigned char) ((key_56[6] << 1) & 0xFF);

  DES_set_odd_parity(&key);
  DES_set_key(&key, ks);
}
#elif defined(USE_GNUTLS)

/*
 * Turns a 56 bit key into the 64 bit, odd parity key and sets the key.
 */
static void setup_des_key(const unsigned char *key_56,
                          gcry_cipher_hd_t *des)
{
  char key[8];

  key[0] = key_56[0];
  key[1] = (unsigned char)(((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1));
  key[2] = (unsigned char)(((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2));
  key[3] = (unsigned char)(((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3));
  key[4] = (unsigned char)(((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4));
  key[5] = (unsigned char)(((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5));
  key[6] = (unsigned char)(((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6));
  key[7] = (unsigned char) ((key_56[6] << 1) & 0xFF);

  gcry_cipher_setkey(*des, key, 8);
}
#endif

 /*
  * takes a 21 byte array and treats it as 3 56-bit DES keys. The
  * 8 byte plaintext is encrypted with each key and the resulting 24
  * bytes are stored in the results array.
  */
static void lm_resp(const unsigned char *keys,
                    const unsigned char *plaintext,
                    unsigned char *results)
{
#ifdef USE_SSLEAY
  DES_key_schedule ks;

  setup_des_key(keys, DESKEY(ks));
  DES_ecb_encrypt((DES_cblock*) plaintext, (DES_cblock*) results,
                  DESKEY(ks), DES_ENCRYPT);

  setup_des_key(keys+7, DESKEY(ks));
  DES_ecb_encrypt((DES_cblock*) plaintext, (DES_cblock*) (results+8),
                  DESKEY(ks), DES_ENCRYPT);

  setup_des_key(keys+14, DESKEY(ks));
  DES_ecb_encrypt((DES_cblock*) plaintext, (DES_cblock*) (results+16),
                  DESKEY(ks), DES_ENCRYPT);
#elif defined(USE_GNUTLS)
  gcry_cipher_hd_t des;

  gcry_cipher_open(&des, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, 0);
  setup_des_key(keys, &des);
  gcry_cipher_encrypt(des, results, 8, plaintext, 8);
  gcry_cipher_close(des);

  gcry_cipher_open(&des, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, 0);
  setup_des_key(keys+7, &des);
  gcry_cipher_encrypt(des, results+8, 8, plaintext, 8);
  gcry_cipher_close(des);

  gcry_cipher_open(&des, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, 0);
  setup_des_key(keys+14, &des);
  gcry_cipher_encrypt(des, results+16, 8, plaintext, 8);
  gcry_cipher_close(des);
#endif
}


/*
 * Set up lanmanager hashed password
 */
static void mk_lm_hash(struct SessionHandle *data,
                       const char *password,
                       unsigned char *lmbuffer /* 21 bytes */)
{
  unsigned char pw[14];
  static const unsigned char magic[] = {
    0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 /* i.e. KGS!@#$% */
  };
  size_t len = CURLMIN(strlen(password), 14);

  Curl_strntoupper((char *)pw, password, len);
  memset(&pw[len], 0, 14-len);

#ifdef CURL_DOES_CONVERSIONS
  /*
   * The LanManager hashed password needs to be created using the
   * password in the network encoding not the host encoding.
   */
  if(data)
    Curl_convert_to_network(data, (char *)pw, 14);
#else
  (void)data;
#endif

  {
    /* Create LanManager hashed password. */

#ifdef USE_SSLEAY
    DES_key_schedule ks;

    setup_des_key(pw, DESKEY(ks));
    DES_ecb_encrypt((DES_cblock *)magic, (DES_cblock *)lmbuffer,
                    DESKEY(ks), DES_ENCRYPT);

    setup_des_key(pw+7, DESKEY(ks));
    DES_ecb_encrypt((DES_cblock *)magic, (DES_cblock *)(lmbuffer+8),
                    DESKEY(ks), DES_ENCRYPT);
#elif defined(USE_GNUTLS)
    gcry_cipher_hd_t des;

    gcry_cipher_open(&des, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, 0);
    setup_des_key(pw, &des);
    gcry_cipher_encrypt(des, lmbuffer, 8, magic, 8);
    gcry_cipher_close(des);

    gcry_cipher_open(&des, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, 0);
    setup_des_key(pw+7, &des);
    gcry_cipher_encrypt(des, lmbuffer+8, 8, magic, 8);
    gcry_cipher_close(des);
#endif

    memset(lmbuffer + 16, 0, 21 - 16);
  }
  }

#if USE_NTRESPONSES
static void ascii_to_unicode_le(unsigned char *dest, const char *src,
                               size_t srclen)
{
  size_t i;
  for (i=0; i<srclen; i++) {
    dest[2*i]   = (unsigned char)src[i];
    dest[2*i+1] =   '\0';
  }
}

/*
 * Set up nt hashed passwords
 */
static CURLcode mk_nt_hash(struct SessionHandle *data,
                           const char *password,
                           unsigned char *ntbuffer /* 21 bytes */)
{
  size_t len = strlen(password);
  unsigned char *pw = malloc(len*2);
  if(!pw)
    return CURLE_OUT_OF_MEMORY;

  ascii_to_unicode_le(pw, password, len);

#ifdef CURL_DOES_CONVERSIONS
  /*
   * The NT hashed password needs to be created using the
   * password in the network encoding not the host encoding.
   */
  if(data)
    Curl_convert_to_network(data, (char *)pw, len*2);
#else
  (void)data;
#endif

  {
    /* Create NT hashed password. */
#ifdef USE_SSLEAY
    MD4_CTX MD4pw;
    MD4_Init(&MD4pw);
    MD4_Update(&MD4pw, pw, 2*len);
    MD4_Final(ntbuffer, &MD4pw);
#elif defined(USE_GNUTLS)
    gcry_md_hd_t MD4pw;
    gcry_md_open(&MD4pw, GCRY_MD_MD4, 0);
    gcry_md_write(MD4pw, pw, 2*len);
    memcpy (ntbuffer, gcry_md_read (MD4pw, 0), MD4_DIGEST_LENGTH);
    gcry_md_close(MD4pw);
#endif

    memset(ntbuffer + 16, 0, 21 - 16);
  }

  free(pw);
  return CURLE_OK;
}
#endif


#endif

#ifdef USE_WINDOWS_SSPI

static void
ntlm_sspi_cleanup(struct ntlmdata *ntlm)
{
  if(ntlm->type_2) {
    free(ntlm->type_2);
    ntlm->type_2 = NULL;
  }
  if(ntlm->has_handles) {
    s_pSecFn->DeleteSecurityContext(&ntlm->c_handle);
    s_pSecFn->FreeCredentialsHandle(&ntlm->handle);
    ntlm->has_handles = 0;
  }
  if(ntlm->p_identity) {
    if(ntlm->identity.User) free(ntlm->identity.User);
    if(ntlm->identity.Password) free(ntlm->identity.Password);
    if(ntlm->identity.Domain) free(ntlm->identity.Domain);
    ntlm->p_identity = NULL;
  }
}

#endif

#define SHORTPAIR(x) ((x) & 0xff), (((x) >> 8) & 0xff)
#define LONGQUARTET(x) ((x) & 0xff), (((x) >> 8)&0xff), \
  (((x) >>16)&0xff), (((x)>>24) & 0xff)

#define HOSTNAME_MAX 1024

/* this is for creating ntlm header output */
CURLcode Curl_output_ntlm(struct connectdata *conn,
                          bool proxy)
{
  const char *domain=""; /* empty */
  char host [HOSTNAME_MAX+ 1] = ""; /* empty */
#ifndef USE_WINDOWS_SSPI
  size_t domlen = strlen(domain);
  size_t hostlen = strlen(host);
  size_t hostoff; /* host name offset */
  size_t domoff;  /* domain name offset */
#endif
  size_t size;
  char *base64=NULL;
  unsigned char ntlmbuf[1024]; /* enough, unless the user+host+domain is very
                                  long */

  /* point to the address of the pointer that holds the string to sent to the
     server, which is for a plain host or for a HTTP proxy */
  char **allocuserpwd;

  /* point to the name and password for this */
  const char *userp;
  const char *passwdp;
  /* point to the correct struct with this */
  struct ntlmdata *ntlm;
  struct auth *authp;

  DEBUGASSERT(conn);
  DEBUGASSERT(conn->data);

  if(proxy) {
    allocuserpwd = &conn->allocptr.proxyuserpwd;
    userp = conn->proxyuser;
    passwdp = conn->proxypasswd;
    ntlm = &conn->proxyntlm;
    authp = &conn->data->state.authproxy;
  }
  else {
    allocuserpwd = &conn->allocptr.userpwd;
    userp = conn->user;
    passwdp = conn->passwd;
    ntlm = &conn->ntlm;
    authp = &conn->data->state.authhost;
  }
  authp->done = FALSE;

  /* not set means empty */
  if(!userp)
    userp="";

  if(!passwdp)
    passwdp="";

#ifdef USE_WINDOWS_SSPI
  if (s_hSecDll == NULL) {
    /* not thread safe and leaks - use curl_global_init() to avoid */
    CURLcode err = Curl_sspi_global_init();
    if (s_hSecDll == NULL)
      return err;
  }
#endif

  switch(ntlm->state) {
  case NTLMSTATE_TYPE1:
  default: /* for the weird cases we (re)start here */
#ifdef USE_WINDOWS_SSPI
  {
    SecBuffer buf;
    SecBufferDesc desc;
    SECURITY_STATUS status;
    ULONG attrs;
    const char *user;
    int domlen;
    TimeStamp tsDummy; /* For Windows 9x compatibility of SPPI calls */

    ntlm_sspi_cleanup(ntlm);

    user = strchr(userp, '\\');
    if(!user)
      user = strchr(userp, '/');

    if(user) {
      domain = userp;
      domlen = user - userp;
      user++;
    }
    else {
      user = userp;
      domain = "";
      domlen = 0;
    }

    if(user && *user) {
      /* note: initialize all of this before doing the mallocs so that
       * it can be cleaned up later without leaking memory.
       */
      ntlm->p_identity = &ntlm->identity;
      memset(ntlm->p_identity, 0, sizeof(*ntlm->p_identity));
      if((ntlm->identity.User = (unsigned char *)strdup(user)) == NULL)
        return CURLE_OUT_OF_MEMORY;
      ntlm->identity.UserLength = strlen(user);
      if((ntlm->identity.Password = (unsigned char *)strdup(passwdp)) == NULL)
        return CURLE_OUT_OF_MEMORY;
      ntlm->identity.PasswordLength = strlen(passwdp);
      if((ntlm->identity.Domain = malloc(domlen+1)) == NULL)
        return CURLE_OUT_OF_MEMORY;
      strncpy((char *)ntlm->identity.Domain, domain, domlen);
      ntlm->identity.Domain[domlen] = '\0';
      ntlm->identity.DomainLength = domlen;
      ntlm->identity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
    }
    else {
      ntlm->p_identity = NULL;
    }

    if(s_pSecFn->AcquireCredentialsHandleA(
          NULL, (char *)"NTLM", SECPKG_CRED_OUTBOUND, NULL, ntlm->p_identity,
          NULL, NULL, &ntlm->handle, &tsDummy
          ) != SEC_E_OK) {
      return CURLE_OUT_OF_MEMORY;
    }

    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers  = 1;
    desc.pBuffers  = &buf;
    buf.cbBuffer   = sizeof(ntlmbuf);
    buf.BufferType = SECBUFFER_TOKEN;
    buf.pvBuffer   = ntlmbuf;

    status = s_pSecFn->InitializeSecurityContextA(&ntlm->handle, NULL,
                                                 (char *) host,
                                                 ISC_REQ_CONFIDENTIALITY |
                                                 ISC_REQ_REPLAY_DETECT |
                                                 ISC_REQ_CONNECTION,
                                                 0, SECURITY_NETWORK_DREP,
                                                 NULL, 0,
                                                 &ntlm->c_handle, &desc,
                                                 &attrs, &tsDummy);

    if(status == SEC_I_COMPLETE_AND_CONTINUE ||
        status == SEC_I_CONTINUE_NEEDED) {
      s_pSecFn->CompleteAuthToken(&ntlm->c_handle, &desc);
    }
    else if(status != SEC_E_OK) {
      s_pSecFn->FreeCredentialsHandle(&ntlm->handle);
      return CURLE_RECV_ERROR;
    }

    ntlm->has_handles = 1;
    size = buf.cbBuffer;
  }
#else
    hostoff = 0;
    domoff = hostoff + hostlen; /* This is 0: remember that host and domain
                                   are empty */

    /* Create and send a type-1 message:

    Index Description          Content
    0     NTLMSSP Signature    Null-terminated ASCII "NTLMSSP"
                               (0x4e544c4d53535000)
    8     NTLM Message Type    long (0x01000000)
    12    Flags                long
    16    Supplied Domain      security buffer(*)
    24    Supplied Workstation security buffer(*)
    32    start of data block

    */
#if USE_NTLM2SESSION
#define NTLM2FLAG NTLMFLAG_NEGOTIATE_NTLM2_KEY
#else
#define NTLM2FLAG 0
#endif
    snprintf((char *)ntlmbuf, sizeof(ntlmbuf), NTLMSSP_SIGNATURE "%c"
             "\x01%c%c%c" /* 32-bit type = 1 */
             "%c%c%c%c"   /* 32-bit NTLM flag field */
             "%c%c"  /* domain length */
             "%c%c"  /* domain allocated space */
             "%c%c"  /* domain name offset */
             "%c%c"  /* 2 zeroes */
             "%c%c"  /* host length */
             "%c%c"  /* host allocated space */
             "%c%c"  /* host name offset */
             "%c%c"  /* 2 zeroes */
             "%s"   /* host name */
             "%s",  /* domain string */
             0,     /* trailing zero */
             0,0,0, /* part of type-1 long */

             LONGQUARTET(
               NTLMFLAG_NEGOTIATE_OEM|
               NTLMFLAG_REQUEST_TARGET|
               NTLMFLAG_NEGOTIATE_NTLM_KEY|
               NTLM2FLAG|
               NTLMFLAG_NEGOTIATE_ALWAYS_SIGN
               ),
             SHORTPAIR(domlen),
             SHORTPAIR(domlen),
             SHORTPAIR(domoff),
             0,0,
             SHORTPAIR(hostlen),
             SHORTPAIR(hostlen),
             SHORTPAIR(hostoff),
             0,0,
             host /* this is empty */, domain /* this is empty */);

    /* initial packet length */
    size = 32 + hostlen + domlen;
#endif

    DEBUG_OUT({
      fprintf(stderr, "**** TYPE1 header flags=0x%02.2x%02.2x%02.2x%02.2x 0x%08.8x ",
              LONGQUARTET(NTLMFLAG_NEGOTIATE_OEM|
                          NTLMFLAG_REQUEST_TARGET|
                          NTLMFLAG_NEGOTIATE_NTLM_KEY|
                          NTLM2FLAG|
                          NTLMFLAG_NEGOTIATE_ALWAYS_SIGN),
              NTLMFLAG_NEGOTIATE_OEM|
              NTLMFLAG_REQUEST_TARGET|
              NTLMFLAG_NEGOTIATE_NTLM_KEY|
              NTLM2FLAG|
              NTLMFLAG_NEGOTIATE_ALWAYS_SIGN);
      print_flags(stderr,
                  NTLMFLAG_NEGOTIATE_OEM|
                  NTLMFLAG_REQUEST_TARGET|
                  NTLMFLAG_NEGOTIATE_NTLM_KEY|
                  NTLM2FLAG|
                  NTLMFLAG_NEGOTIATE_ALWAYS_SIGN);
      fprintf(stderr, "\n****\n");
    });

    /* now size is the size of the base64 encoded package size */
    size = Curl_base64_encode(NULL, (char *)ntlmbuf, size, &base64);

    if(size >0 ) {
      Curl_safefree(*allocuserpwd);
      *allocuserpwd = aprintf("%sAuthorization: NTLM %s\r\n",
                              proxy?"Proxy-":"",
                              base64);
      DEBUG_OUT(fprintf(stderr, "**** Header %s\n ", *allocuserpwd));
      free(base64);
    }
    else
      return CURLE_OUT_OF_MEMORY; /* FIX TODO */

    break;

  case NTLMSTATE_TYPE2:
    /* We received the type-2 message already, create a type-3 message:

    Index   Description            Content
    0       NTLMSSP Signature      Null-terminated ASCII "NTLMSSP"
                                   (0x4e544c4d53535000)
    8       NTLM Message Type      long (0x03000000)
    12      LM/LMv2 Response       security buffer(*)
    20      NTLM/NTLMv2 Response   security buffer(*)
    28      Domain Name            security buffer(*)
    36      User Name              security buffer(*)
    44      Workstation Name       security buffer(*)
    (52)    Session Key (optional) security buffer(*)
    (60)    Flags (optional)       long
    52 (64) start of data block

    */

  {
#ifdef USE_WINDOWS_SSPI
    SecBuffer type_2, type_3;
    SecBufferDesc type_2_desc, type_3_desc;
    SECURITY_STATUS status;
    ULONG attrs;
    TimeStamp tsDummy; /* For Windows 9x compatibility of SPPI calls */

    type_2_desc.ulVersion  = type_3_desc.ulVersion  = SECBUFFER_VERSION;
    type_2_desc.cBuffers   = type_3_desc.cBuffers   = 1;
    type_2_desc.pBuffers   = &type_2;
    type_3_desc.pBuffers   = &type_3;

    type_2.BufferType = SECBUFFER_TOKEN;
    type_2.pvBuffer   = ntlm->type_2;
    type_2.cbBuffer   = ntlm->n_type_2;
    type_3.BufferType = SECBUFFER_TOKEN;
    type_3.pvBuffer   = ntlmbuf;
    type_3.cbBuffer   = sizeof(ntlmbuf);

    status = s_pSecFn->InitializeSecurityContextA(&ntlm->handle, &ntlm->c_handle,
                                       (char *) host,
                                       ISC_REQ_CONFIDENTIALITY |
                                       ISC_REQ_REPLAY_DETECT |
                                       ISC_REQ_CONNECTION,
                                       0, SECURITY_NETWORK_DREP, &type_2_desc,
                                       0, &ntlm->c_handle, &type_3_desc,
                                       &attrs, &tsDummy);

    if(status != SEC_E_OK)
      return CURLE_RECV_ERROR;

    size = type_3.cbBuffer;

    ntlm_sspi_cleanup(ntlm);

#else
    int lmrespoff;
    unsigned char lmresp[24]; /* fixed-size */
#if USE_NTRESPONSES
    int ntrespoff;
    unsigned char ntresp[24]; /* fixed-size */
#endif
    size_t useroff;
    const char *user;
    size_t userlen;

    user = strchr(userp, '\\');
    if(!user)
      user = strchr(userp, '/');

    if(user) {
      domain = userp;
      domlen = (user - domain);
      user++;
    }
    else
      user = userp;
    userlen = strlen(user);

    if(gethostname(host, HOSTNAME_MAX)) {
      infof(conn->data, "gethostname() failed, continuing without!");
      hostlen = 0;
    }
    else {
      /* If the workstation if configured with a full DNS name (i.e.
       * workstation.somewhere.net) gethostname() returns the fully qualified
       * name, which NTLM doesn't like.
       */
      char *dot = strchr(host, '.');
      if(dot)
        *dot = '\0';
      hostlen = strlen(host);
    }

#if USE_NTLM2SESSION
    /* We don't support NTLM2 if we don't have USE_NTRESPONSES */
    if(ntlm->flags & NTLMFLAG_NEGOTIATE_NTLM2_KEY) {
      unsigned char ntbuffer[0x18];
      unsigned char tmp[0x18];
      unsigned char md5sum[MD5_DIGEST_LENGTH];
      unsigned char entropy[8];

      /* Need to create 8 bytes random data */
#ifdef USE_SSLEAY
      MD5_CTX MD5pw;
      Curl_ossl_seed(conn->data); /* Initiate the seed if not already done */
      RAND_bytes(entropy,8);
#elif defined(USE_GNUTLS)
      gcry_md_hd_t MD5pw;
      Curl_gtls_seed(conn->data); /* Initiate the seed if not already done */
      gcry_randomize(entropy, 8, GCRY_STRONG_RANDOM);
#endif

      /* 8 bytes random data as challenge in lmresp */
      memcpy(lmresp,entropy,8);
      /* Pad with zeros */
      memset(lmresp+8,0,0x10);

      /* Fill tmp with challenge(nonce?) + entropy */
      memcpy(tmp,&ntlm->nonce[0],8);
      memcpy(tmp+8,entropy,8);

#ifdef USE_SSLEAY
      MD5_Init(&MD5pw);
      MD5_Update(&MD5pw, tmp, 16);
      MD5_Final(md5sum, &MD5pw);
#elif defined(USE_GNUTLS)
      gcry_md_open(&MD5pw, GCRY_MD_MD5, 0);
      gcry_md_write(MD5pw, tmp, MD5_DIGEST_LENGTH);
      memcpy(md5sum, gcry_md_read (MD5pw, 0), MD5_DIGEST_LENGTH);
      gcry_md_close(MD5pw);
#endif

      /* We shall only use the first 8 bytes of md5sum,
         but the des code in lm_resp only encrypt the first 8 bytes */
      if(mk_nt_hash(conn->data, passwdp, ntbuffer) == CURLE_OUT_OF_MEMORY)
        return CURLE_OUT_OF_MEMORY;
      lm_resp(ntbuffer, md5sum, ntresp);

      /* End of NTLM2 Session code */
    }
    else
#endif
	{

#if USE_NTRESPONSES
      unsigned char ntbuffer[0x18];
#endif
      unsigned char lmbuffer[0x18];

#if USE_NTRESPONSES
      if(mk_nt_hash(conn->data, passwdp, ntbuffer) == CURLE_OUT_OF_MEMORY)
        return CURLE_OUT_OF_MEMORY;
      lm_resp(ntbuffer, &ntlm->nonce[0], ntresp);
#endif

      mk_lm_hash(conn->data, passwdp, lmbuffer);
      lm_resp(lmbuffer, &ntlm->nonce[0], lmresp);
      /* A safer but less compatible alternative is:
       *   lm_resp(ntbuffer, &ntlm->nonce[0], lmresp);
       * See http://davenport.sourceforge.net/ntlm.html#ntlmVersion2 */
    }

    lmrespoff = 64; /* size of the message header */
#if USE_NTRESPONSES
    ntrespoff = lmrespoff + 0x18;
    domoff = ntrespoff + 0x18;
#else
    domoff = lmrespoff + 0x18;
#endif
    useroff = domoff + domlen;
    hostoff = useroff + userlen;

    /*
     * In the case the server sets the flag NTLMFLAG_NEGOTIATE_UNICODE, we
     * need to filter it off because libcurl doesn't UNICODE encode the
     * strings it packs into the NTLM authenticate packet.
     */
    ntlm->flags &= ~NTLMFLAG_NEGOTIATE_UNICODE;

    /* Create the big type-3 message binary blob */
    size = snprintf((char *)ntlmbuf, sizeof(ntlmbuf),
                    NTLMSSP_SIGNATURE "%c"
                    "\x03%c%c%c" /* type-3, 32 bits */

                    "%c%c" /* LanManager length */
                    "%c%c" /* LanManager allocated space */
                    "%c%c" /* LanManager offset */
                    "%c%c" /* 2 zeroes */

                    "%c%c" /* NT-response length */
                    "%c%c" /* NT-response allocated space */
                    "%c%c" /* NT-response offset */
                    "%c%c" /* 2 zeroes */

                    "%c%c"  /* domain length */
                    "%c%c"  /* domain allocated space */
                    "%c%c"  /* domain name offset */
                    "%c%c"  /* 2 zeroes */

                    "%c%c"  /* user length */
                    "%c%c"  /* user allocated space */
                    "%c%c"  /* user offset */
                    "%c%c"  /* 2 zeroes */

                    "%c%c"  /* host length */
                    "%c%c"  /* host allocated space */
                    "%c%c"  /* host offset */
                    "%c%c"  /* 2 zeroes */

                    "%c%c"  /* session key length (unknown purpose) */
                    "%c%c"  /* session key allocated space (unknown purpose) */
                    "%c%c"  /* session key offset (unknown purpose) */
                    "%c%c"  /* 2 zeroes */

                    "%c%c%c%c" /* flags */

                    /* domain string */
                    /* user string */
                    /* host string */
                    /* LanManager response */
                    /* NT response */
                    ,
                    0, /* zero termination */
                    0,0,0, /* type-3 long, the 24 upper bits */

                    SHORTPAIR(0x18),  /* LanManager response length, twice */
                    SHORTPAIR(0x18),
                    SHORTPAIR(lmrespoff),
                    0x0, 0x0,

#if USE_NTRESPONSES
                    SHORTPAIR(0x18),  /* NT-response length, twice */
                    SHORTPAIR(0x18),
                    SHORTPAIR(ntrespoff),
                    0x0, 0x0,
#else
                    0x0, 0x0,
                    0x0, 0x0,
                    0x0, 0x0,
                    0x0, 0x0,
#endif
                    SHORTPAIR(domlen),
                    SHORTPAIR(domlen),
                    SHORTPAIR(domoff),
                    0x0, 0x0,

                    SHORTPAIR(userlen),
                    SHORTPAIR(userlen),
                    SHORTPAIR(useroff),
                    0x0, 0x0,

                    SHORTPAIR(hostlen),
                    SHORTPAIR(hostlen),
                    SHORTPAIR(hostoff),
                    0x0, 0x0,

                    0x0, 0x0,
                    0x0, 0x0,
                    0x0, 0x0,
                    0x0, 0x0,

                    LONGQUARTET(ntlm->flags));
    DEBUGASSERT(size==64);

    DEBUGASSERT(size == (size_t)lmrespoff);
    /* We append the binary hashes */
    if(size < (sizeof(ntlmbuf) - 0x18)) {
      memcpy(&ntlmbuf[size], lmresp, 0x18);
      size += 0x18;
    }

    DEBUG_OUT({
        fprintf(stderr, "**** TYPE3 header lmresp=");
        print_hex(stderr, (char *)&ntlmbuf[lmrespoff], 0x18);
    });

#if USE_NTRESPONSES
    if(size < (sizeof(ntlmbuf) - 0x18)) {
      DEBUGASSERT(size == (size_t)ntrespoff);
      memcpy(&ntlmbuf[size], ntresp, 0x18);
      size += 0x18;
    }

    DEBUG_OUT({
        fprintf(stderr, "\n                  ntresp=");
        print_hex(stderr, (char *)&ntlmbuf[ntrespoff], 0x18);
    });

#endif

    DEBUG_OUT({
        fprintf(stderr, "\n                  flags=0x%02.2x%02.2x%02.2x%02.2x 0x%08.8x ",
                LONGQUARTET(ntlm->flags), ntlm->flags);
        print_flags(stderr, ntlm->flags);
        fprintf(stderr, "\n****\n");
    });


    /* Make sure that the domain, user and host strings fit in the target
       buffer before we copy them there. */
    if(size + userlen + domlen + hostlen >= sizeof(ntlmbuf)) {
      failf(conn->data, "user + domain + host name too big");
      return CURLE_OUT_OF_MEMORY;
    }

    DEBUGASSERT(size == domoff);
    memcpy(&ntlmbuf[size], domain, domlen);
    size += domlen;

    DEBUGASSERT(size == useroff);
    memcpy(&ntlmbuf[size], user, userlen);
    size += userlen;

    DEBUGASSERT(size == hostoff);
    memcpy(&ntlmbuf[size], host, hostlen);
    size += hostlen;

#ifdef CURL_DOES_CONVERSIONS
    /* convert domain, user, and host to ASCII but leave the rest as-is */
    if(CURLE_OK != Curl_convert_to_network(conn->data,
                                           (char *)&ntlmbuf[domoff],
                                           size-domoff)) {
      return CURLE_CONV_FAILED;
    }
#endif /* CURL_DOES_CONVERSIONS */

#endif

    /* convert the binary blob into base64 */
    size = Curl_base64_encode(NULL, (char *)ntlmbuf, size, &base64);

    if(size >0 ) {
      Curl_safefree(*allocuserpwd);
      *allocuserpwd = aprintf("%sAuthorization: NTLM %s\r\n",
                              proxy?"Proxy-":"",
                              base64);
      DEBUG_OUT(fprintf(stderr, "**** %s\n ", *allocuserpwd));
      free(base64);
    }
    else
      return CURLE_OUT_OF_MEMORY; /* FIX TODO */

    ntlm->state = NTLMSTATE_TYPE3; /* we sent a type-3 */
    authp->done = TRUE;
  }
  break;

  case NTLMSTATE_TYPE3:
    /* connection is already authenticated,
     * don't send a header in future requests */
    if(*allocuserpwd) {
      free(*allocuserpwd);
      *allocuserpwd=NULL;
    }
    authp->done = TRUE;
    break;
  }

  return CURLE_OK;
}


void
Curl_ntlm_cleanup(struct connectdata *conn)
{
#ifdef USE_WINDOWS_SSPI
  ntlm_sspi_cleanup(&conn->ntlm);
  ntlm_sspi_cleanup(&conn->proxyntlm);
#else
  (void)conn;
#endif
}


#endif /* USE_NTLM */
#endif /* !CURL_DISABLE_HTTP */
