/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2003, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/
#include "setup.h"

/* All NTLM details here: http://www.innovation.ch/java/ntlm.html */

#ifndef CURL_DISABLE_HTTP
#ifdef USE_SSLEAY
/* We need OpenSSL for the crypto lib to provide us with MD4 and DES */

/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>

#include "urldata.h"
#include "sendf.h"
#include "strequal.h"
#include "base64.h"
#include "http_ntlm.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include <openssl/des.h>
#include <openssl/md4.h>

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

/*
  The one and only master resource for NTLM "hacking":

  ====> http://www.innovation.ch/java/ntlm.html <====

  Brought to the world by Ronald Tschalär.
*/

/* Test example header:

WWW-Authenticate: NTLM

*/

CURLntlm Curl_input_ntlm(struct connectdata *conn,
                         char *header) /* rest of the www-authenticate:
                                          header */
{
  struct SessionHandle *data=conn->data;

  /* skip initial whitespaces */
  while(*header && isspace((int)*header))
    header++;

  if(checkprefix("NTLM", header)) {
    char buffer[256];
    header += strlen("NTLM");

    while(*header && isspace((int)*header))
      header++;

    if(*header) {
      /* we got a type-2 message here */

      /* My test-IE session reveived this type-2:

      TlRMTVNTUAACAAAAAgACADAAAAAGgoEAc51AYVDgyNcAAAAAAAAAAG4AbgA\
      yAAAAQ0MCAAQAQwBDAAEAEgBFAEwASQBTAEEAQgBFAFQASAAEABgAYwBjAC4\
      AaQBjAGUAZABlAHYALgBuAHUAAwAsAGUAbABpAHMAYQBiAGUAdABoAC4AYwB\
      jAC4AaQBjAGUAZABlAHYALgBuAHUAAAAAAA==

      which translates to this:

      4e 54 4c 4d 53 53 50 00 02 00 00 00 02 00 02 00 30 00 00 00 06 82 81 00
      73 9d 40 61 50 e0 c8 d7 00 00 00 00 00 00 00 00 6e 00 6e 00 32 00 00 00
      43 43 02 00 04 00 43 00 43 00 01 00 12 00 45 00 4c 00 49 00 53 00 41 00
      42 00 45 00 54 00 48 00 04 00 18 00 63 00 63 00 2e 00 69 00 63 00 65 00
      64 00 65 00 76 00 2e 00 6e 00 75 00 03 00 2c 00 65 00 6c 00 69 00 73 00
      61 00 62 00 65 00 74 00 68 00 2e 00 63 00 63 00 2e 00 69 00 63 00 65 00
      64 00 65 00 76 00 2e 00 6e 00 75 00 00 00 00 00

      */

      int size = Curl_base64_decode(header, buffer);

      data->state.ntlm.state = NTLMSTATE_TYPE2; /* we got a type-2 */

      if(size == 48)
        /* the nonce of interest is index [24 .. 31], 8 bytes */
        memcpy(data->state.ntlm.nonce, &buffer[24], 8);
    }
    else {
      data->state.ntlm.state = NTLMSTATE_TYPE1; /* we should sent away a
                                                  type-1 */
    }
  }
  return CURLNTLM_FINE;
}

/*
 * Turns a 56 bit key into the 64 bit, odd parity key and sets the key.  The
 * key schedule ks is also set.
 */
static void setup_des_key(unsigned char *key_56,
                          DES_key_schedule *ks)
{
  DES_cblock key;

  key[0] = key_56[0];
  key[1] = ((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1);
  key[2] = ((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2);
  key[3] = ((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3);
  key[4] = ((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4);
  key[5] = ((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5);
  key[6] = ((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6);
  key[7] =  (key_56[6] << 1) & 0xFF;

  DES_set_odd_parity(&key);
  DES_set_key(&key, ks);
}

 /*
  * takes a 21 byte array and treats it as 3 56-bit DES keys. The
  * 8 byte plaintext is encrypted with each key and the resulting 24
  * bytes are stored in the results array.
  */
static void calc_resp(unsigned char *keys,
                      unsigned char *plaintext,
                      unsigned char *results)
{
  des_key_schedule ks;

  setup_des_key(keys, &ks);
  DES_ecb_encrypt((DES_cblock*) plaintext, (DES_cblock*) results, &ks,
                  DES_ENCRYPT);

  setup_des_key(keys+7, &ks);
  DES_ecb_encrypt((DES_cblock*) plaintext, (DES_cblock*) (results+8), &ks,
                  DES_ENCRYPT);

  setup_des_key(keys+14, &ks);
  DES_ecb_encrypt((DES_cblock*) plaintext, (DES_cblock*) (results+16), &ks,
                  DES_ENCRYPT);
}

static void mkhash(char *password,
                   unsigned char *nonce,  /* 8 bytes */
                   unsigned char *lmresp, /* must fit 0x18 bytes */
                   unsigned char *ntresp) /* must fit 0x18 bytes */
{
  /* setup LanManager password */
  unsigned char lmbuffer[0x18];
  unsigned char ntbuffer[0x18];
  
  unsigned char lm_pw[14];
  int len = strlen(password);
  unsigned char magic[] = { 0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 };
  int i;

  if (len > 14)
    len = 14;
  
  for (i=0; i<len; i++)
    lm_pw[i] = toupper(password[i]);

  for (; i<14; i++)
    lm_pw[i] = 0;

  /* create LanManager hashed password */
  {
    DES_key_schedule ks;

    setup_des_key(lm_pw, &ks);
    DES_ecb_encrypt((DES_cblock *)magic, (DES_cblock *)lmbuffer, &ks,
                    DES_ENCRYPT);
  
    setup_des_key(lm_pw+7, &ks);
    DES_ecb_encrypt((DES_cblock *)magic, (DES_cblock *)lmbuffer+8, &ks,
                    DES_ENCRYPT);

    memset(lmbuffer+16, 0, 5);

  }

  {
    /* create NT hashed password */
    int len = strlen(password);
    unsigned char nt_pw[256];
    MD4_CTX MD4;

    for (i=0; i<len; i++) {
      nt_pw[2*i]   = password[i];
      nt_pw[2*i+1] = 0;
    }

    MD4_Init(&MD4);
    MD4_Update(&MD4, nt_pw, 2*len);
    MD4_Final(nt_pw, &MD4);

    memset(ntbuffer+16, 0, 5);

  }
  /* create responses */

  calc_resp(lmbuffer, nonce, lmresp);
  calc_resp(ntbuffer, nonce, ntresp);
}

/* convert an ascii string to upper case unicode, the destination buffer
   must fit twice the source size */
static void ascii_to_unicode(unsigned char *destunicode,
                             unsigned char *sourceascii,
                             bool conv)
{
  while (*sourceascii) {
    destunicode[0] = conv?toupper(*sourceascii):*sourceascii;
    destunicode[1] = '\0';
    destunicode += 2;
    sourceascii++;
  }
}

#define SHORTPAIR(x) ((x) & 0xff), ((x) >> 8)

/* this is for creating ntlm header output */
CURLcode Curl_output_ntlm(struct connectdata *conn)
{
  struct SessionHandle *data=conn->data;
  const char *domain="HEMMA";
  const char *host="LILLASYSTER";
  int domlen=strlen(domain);
  int hostlen = strlen(host);
  int hostoff; /* host name offset */
  int domoff;  /* domain name offset */
  int size;
  char *base64=NULL;

  unsigned char ntlm[256]; /* enough, unless the host/domain is very long */
  if(NTLMSTATE_TYPE1 == data->state.ntlm.state) {
    hostoff = 32;
    domoff = hostoff + hostlen;
    
    /* IE used this in the initial dump:

    Authorization: NTLM \
    TlRMTVNTUAABAAAABoIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAA\r\n

    This translates into:

    4e 54 4c 4d 53 53 50 00 01 00 00 00 06 82 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 30 00 00 00 00 00 00 00 30 00 00 00

    Which isn't following the web spec. This uses 0x8206 instead of 0xb203
    and sends a longer chunk of data than we do! Interestingly, there's no
    host or domain either.

    */

    snprintf((char *)ntlm, sizeof(ntlm), "NTLMSSP%c"
             "\x01" /* type 1 */
             "%c%c%c"
             "\x03\xb2"
             "%c%c"
             "%c%c"  /* domain length */
             "%c%c"  /* domain length */
             "%c%c"  /* domain name offset */
             "%c%c"  /* host length */
             "%c%c"  /* host length */
             "%c%c"  /* host name offset */
             "%c%c"
             "%s" /* host name */
             "%s", /* domain string */
             0,0,0,0,0,0,
             SHORTPAIR(domlen),
             SHORTPAIR(domlen),
             SHORTPAIR(domoff),
             SHORTPAIR(hostlen),
             SHORTPAIR(hostlen),
             SHORTPAIR(hostoff),
             0,0,
             host, domain);

    /* initial packet length */
    size = 8 + 1 + 3 + 18 + hostlen + domlen;
#if 0
    #define CHUNK "\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x06\x82\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30\x00\x00\x00\x00\x00\x00\x00\x30\x00\x00\x00"
    memcpy(ntlm, CHUNK, sizeof(CHUNK)-1);
    size = sizeof(CHUNK)-1;
#endif    
    /* now keeper of the base64 encoded package size */
    size = Curl_base64_encode(ntlm, size, &base64);

    if(size >0 ) {
      conn->allocptr.userpwd = aprintf("Authorization: NTLM %s\r\n",
                                       base64);
      free(base64);
    }
    else
      return CURLE_OUT_OF_MEMORY; /* FIX TODO */
  }
  else {
    /* We are not in the first state, create a type-3 message */

    /*
      My test-IE session sent this type-3:

      TlRMTVNTUAADAAAAGAAYAEoAAAAAAAAAYgAAAAUABQA0AAAABgAGADk\
      AAAALAAsAPwAAAEhFTU1BZGFuaWVsTElMTEFTWVNURVJPVPJELoebUg\
      4SvW0ed2QmKu0SjX4qNrI=

      Which translates to:

      4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00 4a 00 00 00 00 00 00 00
      62 00 00 00 05 00 05 00 34 00 00 00 06 00 06 00 39 00 00 00 0b 00 0b 00
      3f 00 00 00 48 45 4d 4d 41 64 61 6e 69 65 6c 4c 49 4c 4c 41 53 59 53 54
      45 52 4f 54 f2 44 2e 87 9b 52 0e 12 bd 6d 1e 77 64 26 2a ed 12 8d 7e 2a
      36 b2

      Note how the domain + username + hostname ARE NOT unicoded in any way.
      Domain and hostname are uppercase, while username are case sensitive.

      We sent (badly):

      4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00 56 00 00 00 00 00 00 00
      6e 00 00 00 05 00 05 00 40 00 00 00 06 00 06 00 45 00 00 00 0b 00 0b 00
      4b 00 00 00 00 00 00 00 6c 00 00 00 01 82 48 45 4d 4d 41 64 61 6e 69 65
      6c 4c 49 4c 4c 41 53 59 53 54 45 52 86 99 4a 4f 1a 54 93 85 f9 a4 85 d7
      ed 14 17 31 8c a6 4d e9 c1 b1 23 a7
    */

    int lmrespoff;
    int ntrespoff;
    int useroff;
    unsigned char lmresp[0x18+1];
    unsigned char ntresp[0x18+1];

    int userlen = strlen(data->state.user);
    
    mkhash(data->state.passwd, &data->state.ntlm.nonce[0], lmresp, ntresp);

    /* these are going unicode */
    domlen *= 2;
    userlen *= 2;
    hostlen *= 2;

    domoff = 64; /* always */
    useroff = domoff + domlen;
    hostoff = useroff + userlen;
    lmrespoff = hostoff + hostlen;
    ntrespoff = lmrespoff + 0x18;

    /* Create the big type-3 message binary blob */
    size = snprintf((char *)ntlm, sizeof(ntlm),
                    "NTLMSSP%c"
                    "\x03" /* type 3 */
                    "%c%c%c" /* 3 zeroes */

                    "%c%c%c%c" /* LanManager length twice */
                    "%c%c" /* LanManager offset */
                    "%c%c" /* 2 zeroes */

                    "%c%c%c%c" /* NT-response length twice */
                    "%c%c" /* NT-response offset */
                    "%c%c" /* 2 zeroes */
                    
                    "%c%c"  /* domain length */
                    "%c%c"  /* domain length */
                    "%c%c"  /* domain name offset */
                    "%c%c"  /* 2 zeroes */
                    
                    "%c%c"  /* user length */
                    "%c%c"  /* user length */
                    "%c%c"  /* user offset */
                    "%c%c"  /* 2 zeroes */
                    
                    "%c%c"  /* host length */
                    "%c%c"  /* host length */
                    "%c%c"  /* host offset */
                    "%c%c%c%c%c%c"  /* 6 zeroes */
                    
                    "\xff\xff"  /* message length */
                    "%c%c"  /* 2 zeroes */
                    
                    "\x01\x82" /* flags */
                    "%c%c"  /* 2 zeroes */

                    /* domain string */
                    /* user string */
                    /* host string */
                    /* LanManager response */
                    /* NT response */
                    ,
                    0,
                    0,0,0,

                    SHORTPAIR(0x18),  /* LanManager response length, twice */
                    SHORTPAIR(0x18),
                    SHORTPAIR(lmrespoff),
                    0x0, 0x0,
                    
                    SHORTPAIR(0x18),  /* NT-response length, twice */
                    SHORTPAIR(0x18),
                    SHORTPAIR(ntrespoff),
                    0x0, 0x0,

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
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
             
                    0x0, 0x0,

                    0x0, 0x0);

    /* size is now 64 */
#if 1
    ascii_to_unicode(&ntlm[size], (unsigned char *)domain, TRUE);
    size += domlen;
    
    ascii_to_unicode(&ntlm[size], (unsigned char *)data->state.user, FALSE);
    size += userlen;

    ascii_to_unicode(&ntlm[size], (unsigned char *)host, TRUE);
    size += hostlen;
#else
    strcpy(&ntlm[size], (unsigned char *)domain);
    size += domlen;

    strcpy(&ntlm[size], (unsigned char *)data->state.user);
    size += userlen;

    strcpy(&ntlm[size], (unsigned char *)host);
    size += hostlen;
#endif

    /* we append the binary hashes to the end of the blob */
    if(size < ((int)sizeof(ntlm) - 0x18)) {
      memcpy(&ntlm[size], lmresp, 0x18);
      size += 0x18;
    }
#ifdef USE_NT
    if(size < ((int)sizeof(ntlm) - 0x18)) {      
      memcpy(&ntlm[size+0x18], ntresp, 0x18);
      size += 0x18*2;
    }
#endif

    ntlm[56] = size & 0xff;
    ntlm[57] = size >> 8;
    
    /* convert the binary blob into base64 */
    size = Curl_base64_encode(ntlm, size, &base64);

    if(size >0 ) {
      conn->allocptr.userpwd = aprintf("Authorization: NTLM %s\r\n",
                                       base64);
      free(base64);
    }
    else
      return CURLE_OUT_OF_MEMORY; /* FIX TODO */

  }

  return CURLE_OK;
}
#endif /* USE_SSLEAY */
#endif /* !CURL_DISABLE_HTTP */
