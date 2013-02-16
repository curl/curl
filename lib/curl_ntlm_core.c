/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#if defined(USE_NTLM) && !defined(USE_WINDOWS_SSPI)

/*
 * NTLM details:
 *
 * http://davenport.sourceforge.net/ntlm.html
 * http://www.innovation.ch/java/ntlm.html
 */

#ifdef USE_SSLEAY

#  ifdef USE_OPENSSL
#    include <openssl/des.h>
#    ifndef OPENSSL_NO_MD4
#      include <openssl/md4.h>
#    endif
#    include <openssl/md5.h>
#    include <openssl/ssl.h>
#    include <openssl/rand.h>
#  else
#    include <des.h>
#    ifndef OPENSSL_NO_MD4
#      include <md4.h>
#    endif
#    include <md5.h>
#    include <ssl.h>
#    include <rand.h>
#  endif
#  if (OPENSSL_VERSION_NUMBER < 0x00907001L)
#    define DES_key_schedule des_key_schedule
#    define DES_cblock des_cblock
#    define DES_set_odd_parity des_set_odd_parity
#    define DES_set_key des_set_key
#    define DES_ecb_encrypt des_ecb_encrypt
#    define DESKEY(x) x
#    define DESKEYARG(x) x
#  else
#    define DESKEYARG(x) *x
#    define DESKEY(x) &x
#  endif

#elif defined(USE_GNUTLS_NETTLE)

#  include <nettle/des.h>
#  include <nettle/md4.h>

#elif defined(USE_GNUTLS)

#  include <gcrypt.h>
#  define MD5_DIGEST_LENGTH 16
#  define MD4_DIGEST_LENGTH 16

#elif defined(USE_NSS)

#  include <nss.h>
#  include <pk11pub.h>
#  include <hasht.h>
#  include "curl_md4.h"
#  define MD5_DIGEST_LENGTH MD5_LENGTH

#elif defined(USE_DARWINSSL)

#  include <CommonCrypto/CommonCryptor.h>
#  include <CommonCrypto/CommonDigest.h>

#else
#  error "Can't compile NTLM support without a crypto library."
#endif

#include "urldata.h"
#include "non-ascii.h"
#include "rawstr.h"
#include "curl_memory.h"
#include "curl_ntlm_core.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

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

#else /* defined(USE_SSLEAY) */

/*
 * Turns a 56 bit key into the 64 bit, odd parity key.  Used by GnuTLS and NSS.
 */
static void extend_key_56_to_64(const unsigned char *key_56, char *key)
{
  key[0] = key_56[0];
  key[1] = (unsigned char)(((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1));
  key[2] = (unsigned char)(((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2));
  key[3] = (unsigned char)(((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3));
  key[4] = (unsigned char)(((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4));
  key[5] = (unsigned char)(((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5));
  key[6] = (unsigned char)(((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6));
  key[7] = (unsigned char) ((key_56[6] << 1) & 0xFF);
}

#if defined(USE_GNUTLS_NETTLE)

static void setup_des_key(const unsigned char *key_56,
                          struct des_ctx *des)
{
  char key[8];
  extend_key_56_to_64(key_56, key);
  des_set_key(des, (const uint8_t*)key);
}

#elif defined(USE_GNUTLS)

/*
 * Turns a 56 bit key into the 64 bit, odd parity key and sets the key.
 */
static void setup_des_key(const unsigned char *key_56,
                          gcry_cipher_hd_t *des)
{
  char key[8];
  extend_key_56_to_64(key_56, key);
  gcry_cipher_setkey(*des, key, 8);
}

#elif defined(USE_NSS)

/*
 * Expands a 56 bit key KEY_56 to 64 bit and encrypts 64 bit of data, using
 * the expanded key.  The caller is responsible for giving 64 bit of valid
 * data is IN and (at least) 64 bit large buffer as OUT.
 */
static bool encrypt_des(const unsigned char *in, unsigned char *out,
                        const unsigned char *key_56)
{
  const CK_MECHANISM_TYPE mech = CKM_DES_ECB; /* DES cipher in ECB mode */
  PK11SlotInfo *slot = NULL;
  char key[8];                                /* expanded 64 bit key */
  SECItem key_item;
  PK11SymKey *symkey = NULL;
  SECItem *param = NULL;
  PK11Context *ctx = NULL;
  int out_len;                                /* not used, required by NSS */
  bool rv = FALSE;

  /* use internal slot for DES encryption (requires NSS to be initialized) */
  slot = PK11_GetInternalKeySlot();
  if(!slot)
    return FALSE;

  /* expand the 56 bit key to 64 bit and wrap by NSS */
  extend_key_56_to_64(key_56, key);
  key_item.data = (unsigned char *)key;
  key_item.len = /* hard-wired */ 8;
  symkey = PK11_ImportSymKey(slot, mech, PK11_OriginUnwrap, CKA_ENCRYPT,
                             &key_item, NULL);
  if(!symkey)
    goto fail;

  /* create DES encryption context */
  param = PK11_ParamFromIV(mech, /* no IV in ECB mode */ NULL);
  if(!param)
    goto fail;
  ctx = PK11_CreateContextBySymKey(mech, CKA_ENCRYPT, symkey, param);
  if(!ctx)
    goto fail;

  /* perform the encryption */
  if(SECSuccess == PK11_CipherOp(ctx, out, &out_len, /* outbuflen */ 8,
                                 (unsigned char *)in, /* inbuflen */ 8)
      && SECSuccess == PK11_Finalize(ctx))
    rv = /* all OK */ TRUE;

fail:
  /* cleanup */
  if(ctx)
    PK11_DestroyContext(ctx, PR_TRUE);
  if(symkey)
    PK11_FreeSymKey(symkey);
  if(param)
    SECITEM_FreeItem(param, PR_TRUE);
  PK11_FreeSlot(slot);
  return rv;
}

#elif defined(USE_DARWINSSL)

static bool encrypt_des(const unsigned char *in, unsigned char *out,
                        const unsigned char *key_56)
{
  char key[8];
  size_t out_len;
  CCCryptorStatus err;

  extend_key_56_to_64(key_56, key);
  err = CCCrypt(kCCEncrypt, kCCAlgorithmDES, kCCOptionECBMode, key,
                kCCKeySizeDES, NULL, in, 8 /* inbuflen */, out,
                8 /* outbuflen */, &out_len);
  return err == kCCSuccess;
}

#endif /* defined(USE_DARWINSSL) */

#endif /* defined(USE_SSLEAY) */

 /*
  * takes a 21 byte array and treats it as 3 56-bit DES keys. The
  * 8 byte plaintext is encrypted with each key and the resulting 24
  * bytes are stored in the results array.
  */
void Curl_ntlm_core_lm_resp(const unsigned char *keys,
                            const unsigned char *plaintext,
                            unsigned char *results)
{
#ifdef USE_SSLEAY
  DES_key_schedule ks;

  setup_des_key(keys, DESKEY(ks));
  DES_ecb_encrypt((DES_cblock*) plaintext, (DES_cblock*) results,
                  DESKEY(ks), DES_ENCRYPT);

  setup_des_key(keys + 7, DESKEY(ks));
  DES_ecb_encrypt((DES_cblock*) plaintext, (DES_cblock*) (results + 8),
                  DESKEY(ks), DES_ENCRYPT);

  setup_des_key(keys + 14, DESKEY(ks));
  DES_ecb_encrypt((DES_cblock*) plaintext, (DES_cblock*) (results + 16),
                  DESKEY(ks), DES_ENCRYPT);
#elif defined(USE_GNUTLS_NETTLE)
  struct des_ctx des;
  setup_des_key(keys, &des);
  des_encrypt(&des, 8, results, plaintext);
  setup_des_key(keys + 7, &des);
  des_encrypt(&des, 8, results + 8, plaintext);
  setup_des_key(keys + 14, &des);
  des_encrypt(&des, 8, results + 16, plaintext);
#elif defined(USE_GNUTLS)
  gcry_cipher_hd_t des;

  gcry_cipher_open(&des, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, 0);
  setup_des_key(keys, &des);
  gcry_cipher_encrypt(des, results, 8, plaintext, 8);
  gcry_cipher_close(des);

  gcry_cipher_open(&des, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, 0);
  setup_des_key(keys + 7, &des);
  gcry_cipher_encrypt(des, results + 8, 8, plaintext, 8);
  gcry_cipher_close(des);

  gcry_cipher_open(&des, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, 0);
  setup_des_key(keys + 14, &des);
  gcry_cipher_encrypt(des, results + 16, 8, plaintext, 8);
  gcry_cipher_close(des);
#elif defined(USE_NSS) || defined(USE_DARWINSSL)
  encrypt_des(plaintext, results, keys);
  encrypt_des(plaintext, results + 8, keys + 7);
  encrypt_des(plaintext, results + 16, keys + 14);
#endif
}

/*
 * Set up lanmanager hashed password
 */
void Curl_ntlm_core_mk_lm_hash(struct SessionHandle *data,
                               const char *password,
                               unsigned char *lmbuffer /* 21 bytes */)
{
  CURLcode res;
  unsigned char pw[14];
  static const unsigned char magic[] = {
    0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 /* i.e. KGS!@#$% */
  };
  size_t len = CURLMIN(strlen(password), 14);

  Curl_strntoupper((char *)pw, password, len);
  memset(&pw[len], 0, 14 - len);

  /*
   * The LanManager hashed password needs to be created using the
   * password in the network encoding not the host encoding.
   */
  res = Curl_convert_to_network(data, (char *)pw, 14);
  if(res)
    return;

  {
    /* Create LanManager hashed password. */

#ifdef USE_SSLEAY
    DES_key_schedule ks;

    setup_des_key(pw, DESKEY(ks));
    DES_ecb_encrypt((DES_cblock *)magic, (DES_cblock *)lmbuffer,
                    DESKEY(ks), DES_ENCRYPT);

    setup_des_key(pw + 7, DESKEY(ks));
    DES_ecb_encrypt((DES_cblock *)magic, (DES_cblock *)(lmbuffer + 8),
                    DESKEY(ks), DES_ENCRYPT);
#elif defined(USE_GNUTLS_NETTLE)
    struct des_ctx des;
    setup_des_key(pw, &des);
    des_encrypt(&des, 8, lmbuffer, magic);
    setup_des_key(pw + 7, &des);
    des_encrypt(&des, 8, lmbuffer + 8, magic);
#elif defined(USE_GNUTLS)
    gcry_cipher_hd_t des;

    gcry_cipher_open(&des, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, 0);
    setup_des_key(pw, &des);
    gcry_cipher_encrypt(des, lmbuffer, 8, magic, 8);
    gcry_cipher_close(des);

    gcry_cipher_open(&des, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, 0);
    setup_des_key(pw + 7, &des);
    gcry_cipher_encrypt(des, lmbuffer + 8, 8, magic, 8);
    gcry_cipher_close(des);
#elif defined(USE_NSS) || defined(USE_DARWINSSL)
    encrypt_des(magic, lmbuffer, pw);
    encrypt_des(magic, lmbuffer + 8, pw + 7);
#endif

    memset(lmbuffer + 16, 0, 21 - 16);
  }
}

#if USE_NTRESPONSES
static void ascii_to_unicode_le(unsigned char *dest, const char *src,
                                size_t srclen)
{
  size_t i;
  for(i = 0; i < srclen; i++) {
    dest[2 * i] = (unsigned char)src[i];
    dest[2 * i + 1] = '\0';
  }
}

/*
 * Set up nt hashed passwords
 */
CURLcode Curl_ntlm_core_mk_nt_hash(struct SessionHandle *data,
                                   const char *password,
                                   unsigned char *ntbuffer /* 21 bytes */)
{
  size_t len = strlen(password);
  unsigned char *pw = malloc(len * 2);
  CURLcode result;
  if(!pw)
    return CURLE_OUT_OF_MEMORY;

  ascii_to_unicode_le(pw, password, len);

  /*
   * The NT hashed password needs to be created using the password in the
   * network encoding not the host encoding.
   */
  result = Curl_convert_to_network(data, (char *)pw, len * 2);
  if(result)
    return result;

  {
    /* Create NT hashed password. */
#ifdef USE_SSLEAY
    MD4_CTX MD4pw;
    MD4_Init(&MD4pw);
    MD4_Update(&MD4pw, pw, 2 * len);
    MD4_Final(ntbuffer, &MD4pw);
#elif defined(USE_GNUTLS_NETTLE)
    struct md4_ctx MD4pw;
    md4_init(&MD4pw);
    md4_update(&MD4pw, (unsigned int)(2 * len), pw);
    md4_digest(&MD4pw, MD4_DIGEST_SIZE, ntbuffer);
#elif defined(USE_GNUTLS)
    gcry_md_hd_t MD4pw;
    gcry_md_open(&MD4pw, GCRY_MD_MD4, 0);
    gcry_md_write(MD4pw, pw, 2 * len);
    memcpy (ntbuffer, gcry_md_read (MD4pw, 0), MD4_DIGEST_LENGTH);
    gcry_md_close(MD4pw);
#elif defined(USE_NSS)
    Curl_md4it(ntbuffer, pw, 2 * len);
#elif defined(USE_DARWINSSL)
    (void)CC_MD4(pw, (CC_LONG)(2 * len), ntbuffer);
#endif

    memset(ntbuffer + 16, 0, 21 - 16);
  }

  free(pw);

  return CURLE_OK;
}
#endif /* USE_NTRESPONSES */

#endif /* USE_NTLM && !USE_WINDOWS_SSPI */
