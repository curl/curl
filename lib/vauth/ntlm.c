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

#include "curl_setup.h"

#if defined(USE_NTLM) && !defined(USE_WINDOWS_SSPI)

/*
 * NTLM details:
 *
 * https://davenport.sourceforge.net/ntlm.html
 * https://www.innovation.ch/java/ntlm.html
 */

#define DEBUG_ME 0

#include "urldata.h"
#include "sendf.h"
#include "curl_ntlm_core.h"
#include "curl_gethostname.h"
#include "curl_multibyte.h"
#include "curl_md5.h"
#include "warnless.h"
#include "rand.h"
#include "vtls/vtls.h"
#include "strdup.h"

#include "vauth/vauth.h"
#include "curl_endian.h"
#include "curl_printf.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"


/* NTLM buffer fixed size, large enough for long user + host + domain */
#define NTLM_BUFSIZE 1024

/* Flag bits definitions based on
   https://davenport.sourceforge.net/ntlm.html */

#define NTLMFLAG_NEGOTIATE_UNICODE               (1<<0)
/* Indicates that Unicode strings are supported for use in security buffer
   data. */

#define NTLMFLAG_NEGOTIATE_OEM                   (1<<1)
/* Indicates that OEM strings are supported for use in security buffer data. */

#define NTLMFLAG_REQUEST_TARGET                  (1<<2)
/* Requests that the server's authentication realm be included in the Type 2
   message. */

/* unknown (1<<3) */
#define NTLMFLAG_NEGOTIATE_SIGN                  (1<<4)
/* Specifies that authenticated communication between the client and server
   should carry a digital signature (message integrity). */

#define NTLMFLAG_NEGOTIATE_SEAL                  (1<<5)
/* Specifies that authenticated communication between the client and server
   should be encrypted (message confidentiality). */

#define NTLMFLAG_NEGOTIATE_DATAGRAM_STYLE        (1<<6)
/* Indicates that datagram authentication is being used. */

#define NTLMFLAG_NEGOTIATE_LM_KEY                (1<<7)
/* Indicates that the LAN Manager session key should be used for signing and
   sealing authenticated communications. */

#define NTLMFLAG_NEGOTIATE_NTLM_KEY              (1<<9)
/* Indicates that NTLM authentication is being used. */

/* unknown (1<<10) */

#define NTLMFLAG_NEGOTIATE_ANONYMOUS             (1<<11)
/* Sent by the client in the Type 3 message to indicate that an anonymous
   context has been established. This also affects the response fields. */

#define NTLMFLAG_NEGOTIATE_DOMAIN_SUPPLIED       (1<<12)
/* Sent by the client in the Type 1 message to indicate that a desired
   authentication realm is included in the message. */

#define NTLMFLAG_NEGOTIATE_WORKSTATION_SUPPLIED  (1<<13)
/* Sent by the client in the Type 1 message to indicate that the client
   workstation's name is included in the message. */

#define NTLMFLAG_NEGOTIATE_LOCAL_CALL            (1<<14)
/* Sent by the server to indicate that the server and client are on the same
   machine. Implies that the client may use a pre-established local security
   context rather than responding to the challenge. */

#define NTLMFLAG_NEGOTIATE_ALWAYS_SIGN           (1<<15)
/* Indicates that authenticated communication between the client and server
   should be signed with a "dummy" signature. */

#define NTLMFLAG_TARGET_TYPE_DOMAIN              (1<<16)
/* Sent by the server in the Type 2 message to indicate that the target
   authentication realm is a domain. */

#define NTLMFLAG_TARGET_TYPE_SERVER              (1<<17)
/* Sent by the server in the Type 2 message to indicate that the target
   authentication realm is a server. */

#define NTLMFLAG_TARGET_TYPE_SHARE               (1<<18)
/* Sent by the server in the Type 2 message to indicate that the target
   authentication realm is a share. Presumably, this is for share-level
   authentication. Usage is unclear. */

#define NTLMFLAG_NEGOTIATE_NTLM2_KEY             (1<<19)
/* Indicates that the NTLM2 signing and sealing scheme should be used for
   protecting authenticated communications. */

#define NTLMFLAG_REQUEST_INIT_RESPONSE           (1<<20)
/* unknown purpose */

#define NTLMFLAG_REQUEST_ACCEPT_RESPONSE         (1<<21)
/* unknown purpose */

#define NTLMFLAG_REQUEST_NONNT_SESSION_KEY       (1<<22)
/* unknown purpose */

#define NTLMFLAG_NEGOTIATE_TARGET_INFO           (1<<23)
/* Sent by the server in the Type 2 message to indicate that it is including a
   Target Information block in the message. */

/* unknown (1<24) */
/* unknown (1<25) */
/* unknown (1<26) */
/* unknown (1<27) */
/* unknown (1<28) */

#define NTLMFLAG_NEGOTIATE_128                   (1<<29)
/* Indicates that 128-bit encryption is supported. */

#define NTLMFLAG_NEGOTIATE_KEY_EXCHANGE          (1<<30)
/* Indicates that the client will provide an encrypted master key in
   the "Session Key" field of the Type 3 message. */

#define NTLMFLAG_NEGOTIATE_56                    (1<<31)
/* Indicates that 56-bit encryption is supported. */

/* "NTLMSSP" signature is always in ASCII regardless of the platform */
#define NTLMSSP_SIGNATURE "\x4e\x54\x4c\x4d\x53\x53\x50"

#if DEBUG_ME
# define DEBUG_OUT(x) x
static void ntlm_print_flags(FILE *handle, unsigned long flags)
{
  if(flags & NTLMFLAG_NEGOTIATE_UNICODE)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_UNICODE ");
  if(flags & NTLMFLAG_NEGOTIATE_OEM)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_OEM ");
  if(flags & NTLMFLAG_REQUEST_TARGET)
    fprintf(handle, "NTLMFLAG_REQUEST_TARGET ");
  if(flags & (1 << 3))
    fprintf(handle, "NTLMFLAG_UNKNOWN_3 ");
  if(flags & NTLMFLAG_NEGOTIATE_SIGN)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_SIGN ");
  if(flags & NTLMFLAG_NEGOTIATE_SEAL)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_SEAL ");
  if(flags & NTLMFLAG_NEGOTIATE_DATAGRAM_STYLE)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_DATAGRAM_STYLE ");
  if(flags & NTLMFLAG_NEGOTIATE_LM_KEY)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_LM_KEY ");
  if(flags & NTLMFLAG_NEGOTIATE_NTLM_KEY)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_NTLM_KEY ");
  if(flags & (1 << 10))
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
  if(flags & (1 << 24))
    fprintf(handle, "NTLMFLAG_UNKNOWN_24 ");
  if(flags & (1 << 25))
    fprintf(handle, "NTLMFLAG_UNKNOWN_25 ");
  if(flags & (1 << 26))
    fprintf(handle, "NTLMFLAG_UNKNOWN_26 ");
  if(flags & (1 << 27))
    fprintf(handle, "NTLMFLAG_UNKNOWN_27 ");
  if(flags & (1 << 28))
    fprintf(handle, "NTLMFLAG_UNKNOWN_28 ");
  if(flags & NTLMFLAG_NEGOTIATE_128)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_128 ");
  if(flags & NTLMFLAG_NEGOTIATE_KEY_EXCHANGE)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_KEY_EXCHANGE ");
  if(flags & NTLMFLAG_NEGOTIATE_56)
    fprintf(handle, "NTLMFLAG_NEGOTIATE_56 ");
}

static void ntlm_print_hex(FILE *handle, const char *buf, size_t len)
{
  const char *p = buf;

  (void) handle;

  fprintf(stderr, "0x");
  while(len-- > 0)
    fprintf(stderr, "%02.2x", (unsigned int)*p++);
}
#else
# define DEBUG_OUT(x) Curl_nop_stmt
#endif

/*
 * ntlm_decode_type2_target()
 *
 * This is used to decode the "target info" in the NTLM type-2 message
 * received.
 *
 * Parameters:
 *
 * data      [in]     - The session handle.
 * type2ref  [in]     - The type-2 message.
 * ntlm      [in/out] - The NTLM data struct being used and modified.
 *
 * Returns CURLE_OK on success.
 */
static CURLcode ntlm_decode_type2_target(struct Curl_easy *data,
                                         const struct bufref *type2ref,
                                         struct ntlmdata *ntlm)
{
  unsigned short target_info_len = 0;
  unsigned int target_info_offset = 0;
  const unsigned char *type2 = Curl_bufref_ptr(type2ref);
  size_t type2len = Curl_bufref_len(type2ref);

#if defined(CURL_DISABLE_VERBOSE_STRINGS)
  (void) data;
#endif

  if(type2len >= 48) {
    target_info_len = Curl_read16_le(&type2[40]);
    target_info_offset = Curl_read32_le(&type2[44]);
    if(target_info_len > 0) {
      if((target_info_offset > type2len) ||
         (target_info_offset + target_info_len) > type2len ||
         target_info_offset < 48) {
        infof(data, "NTLM handshake failure (bad type-2 message). "
              "Target Info Offset Len is set incorrect by the peer");
        return CURLE_BAD_CONTENT_ENCODING;
      }

      FREE(ntlm->target_info); /* replace any previous data */
      ntlm->target_info = Curl_memdup(&type2[target_info_offset],
                                      target_info_len);
      if(!ntlm->target_info)
        return CURLE_OUT_OF_MEMORY;
    }
  }

  ntlm->target_info_len = target_info_len;

  return CURLE_OK;
}

/*
  NTLM message structure notes:

  A 'short' is a 'network short', a little-endian 16-bit unsigned value.

  A 'long' is a 'network long', a little-endian, 32-bit unsigned value.

  A 'security buffer' represents a triplet used to point to a buffer,
  consisting of two shorts and one long:

    1. A 'short' containing the length of the buffer content in bytes.
    2. A 'short' containing the allocated space for the buffer in bytes.
    3. A 'long' containing the offset to the start of the buffer in bytes,
       from the beginning of the NTLM message.
*/

/*
 * Curl_auth_is_ntlm_supported()
 *
 * This is used to evaluate if NTLM is supported.
 *
 * Parameters: None
 *
 * Returns TRUE as NTLM as handled by libcurl.
 */
bool Curl_auth_is_ntlm_supported(void)
{
  return TRUE;
}

/*
 * Curl_auth_decode_ntlm_type2_message()
 *
 * This is used to decode an NTLM type-2 message. The raw NTLM message is
 * checked * for validity before the appropriate data for creating a type-3
 * message is * written to the given NTLM data structure.
 *
 * Parameters:
 *
 * data     [in]     - The session handle.
 * type2ref [in]     - The type-2 message.
 * ntlm     [in/out] - The NTLM data struct being used and modified.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_auth_decode_ntlm_type2_message(struct Curl_easy *data,
                                             const struct bufref *type2ref,
                                             struct ntlmdata *ntlm)
{
  static const char type2_marker[] = { 0x02, 0x00, 0x00, 0x00 };

  /* NTLM type-2 message structure:

          Index  Description            Content
            0    NTLMSSP Signature      Null-terminated ASCII "NTLMSSP"
                                        (0x4e544c4d53535000)
            8    NTLM Message Type      long (0x02000000)
           12    Target Name            security buffer
           20    Flags                  long
           24    Challenge              8 bytes
          (32)   Context                8 bytes (two consecutive longs) (*)
          (40)   Target Information     security buffer (*)
          (48)   OS Version Structure   8 bytes (*)
  32 (48) (56)   Start of data block    (*)
                                        (*) -> Optional
  */

  CURLcode result = CURLE_OK;
  const unsigned char *type2 = Curl_bufref_ptr(type2ref);
  size_t type2len = Curl_bufref_len(type2ref);

#if defined(CURL_DISABLE_VERBOSE_STRINGS)
  (void)data;
#endif

  ntlm->flags = 0;

  if((type2len < 32) ||
     (memcmp(type2, NTLMSSP_SIGNATURE, 8) != 0) ||
     (memcmp(type2 + 8, type2_marker, sizeof(type2_marker)) != 0)) {
    /* This was not a good enough type-2 message */
    infof(data, "NTLM handshake failure (bad type-2 message)");
    return CURLE_BAD_CONTENT_ENCODING;
  }

  ntlm->flags = Curl_read32_le(&type2[20]);
  memcpy(ntlm->nonce, &type2[24], 8);

  if(ntlm->flags & NTLMFLAG_NEGOTIATE_TARGET_INFO) {
    result = ntlm_decode_type2_target(data, type2ref, ntlm);
    if(result) {
      infof(data, "NTLM handshake failure (bad type-2 message)");
      return result;
    }
  }

  DEBUG_OUT({
    fprintf(stderr, "**** TYPE2 header flags=0x%08.8lx ", ntlm->flags);
    ntlm_print_flags(stderr, ntlm->flags);
    fprintf(stderr, "\n                  nonce=");
    ntlm_print_hex(stderr, (char *)ntlm->nonce, 8);
    fprintf(stderr, "\n****\n");
    fprintf(stderr, "**** Header %s\n ", header);
  });

  return result;
}

/* copy the source to the destination and fill in zeroes in every
   other destination byte! */
static void unicodecpy(unsigned char *dest, const char *src, size_t length)
{
  size_t i;
  for(i = 0; i < length; i++) {
    dest[2 * i] = (unsigned char)src[i];
    dest[2 * i + 1] = '\0';
  }
}

/*
 * Curl_auth_create_ntlm_type1_message()
 *
 * This is used to generate an NTLM type-1 message ready for sending to the
 * recipient using the appropriate compile time crypto API.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * userp   [in]     - The username in the format User or Domain\User.
 * passwdp [in]     - The user's password.
 * service [in]     - The service type such as http, smtp, pop or imap.
 * host    [in]     - The hostname.
 * ntlm    [in/out] - The NTLM data struct being used and modified.
 * out     [out]    - The result storage.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_auth_create_ntlm_type1_message(struct Curl_easy *data,
                                             const char *userp,
                                             const char *passwdp,
                                             const char *service,
                                             const char *hostname,
                                             struct ntlmdata *ntlm,
                                             struct bufref *out)
{
  /* NTLM type-1 message structure:

       Index  Description            Content
         0    NTLMSSP Signature      Null-terminated ASCII "NTLMSSP"
                                     (0x4e544c4d53535000)
         8    NTLM Message Type      long (0x01000000)
        12    Flags                  long
       (16)   Supplied Domain        security buffer (*)
       (24)   Supplied Workstation   security buffer (*)
       (32)   OS Version Structure   8 bytes (*)
  (32) (40)   Start of data block    (*)
                                     (*) -> Optional
  */

  size_t size;

  char *ntlmbuf;
  const char *host = "";              /* empty */
  const char *domain = "";            /* empty */
  size_t hostlen = 0;
  size_t domlen = 0;
  size_t hostoff = 0;
  size_t domoff = hostoff + hostlen;  /* This is 0: remember that host and
                                         domain are empty */
  (void)data;
  (void)userp;
  (void)passwdp;
  (void)service;
  (void)hostname;

  /* Clean up any former leftovers and initialise to defaults */
  Curl_auth_cleanup_ntlm(ntlm);

  ntlmbuf = aprintf(NTLMSSP_SIGNATURE "%c"
                    "\x01%c%c%c" /* 32-bit type = 1 */
                    "%c%c%c%c"   /* 32-bit NTLM flag field */
                    "%c%c"       /* domain length */
                    "%c%c"       /* domain allocated space */
                    "%c%c"       /* domain name offset */
                    "%c%c"       /* 2 zeroes */
                    "%c%c"       /* host length */
                    "%c%c"       /* host allocated space */
                    "%c%c"       /* hostname offset */
                    "%c%c"       /* 2 zeroes */
                    "%s"         /* hostname */
                    "%s",        /* domain string */
                    0,           /* trailing zero */
                    0, 0, 0,     /* part of type-1 long */

                    LONGQUARTET(NTLMFLAG_NEGOTIATE_OEM |
                                NTLMFLAG_REQUEST_TARGET |
                                NTLMFLAG_NEGOTIATE_NTLM_KEY |
                                NTLMFLAG_NEGOTIATE_NTLM2_KEY |
                                NTLMFLAG_NEGOTIATE_ALWAYS_SIGN),
                    SHORTPAIR(domlen),
                    SHORTPAIR(domlen),
                    SHORTPAIR(domoff),
                    0, 0,
                    SHORTPAIR(hostlen),
                    SHORTPAIR(hostlen),
                    SHORTPAIR(hostoff),
                    0, 0,
                    host,  /* this is empty */
                    domain /* this is empty */);

  if(!ntlmbuf)
    return CURLE_OUT_OF_MEMORY;

  /* Initial packet length */
  size = 32 + hostlen + domlen;

  DEBUG_OUT({
    fprintf(stderr, "* TYPE1 header flags=0x%02.2x%02.2x%02.2x%02.2x "
            "0x%08.8x ",
            LONGQUARTET(NTLMFLAG_NEGOTIATE_OEM |
                        NTLMFLAG_REQUEST_TARGET |
                        NTLMFLAG_NEGOTIATE_NTLM_KEY |
                        NTLMFLAG_NEGOTIATE_NTLM2_KEY |
                        NTLMFLAG_NEGOTIATE_ALWAYS_SIGN),
            NTLMFLAG_NEGOTIATE_OEM |
            NTLMFLAG_REQUEST_TARGET |
            NTLMFLAG_NEGOTIATE_NTLM_KEY |
            NTLMFLAG_NEGOTIATE_NTLM2_KEY |
            NTLMFLAG_NEGOTIATE_ALWAYS_SIGN);
    ntlm_print_flags(stderr,
                     NTLMFLAG_NEGOTIATE_OEM |
                     NTLMFLAG_REQUEST_TARGET |
                     NTLMFLAG_NEGOTIATE_NTLM_KEY |
                     NTLMFLAG_NEGOTIATE_NTLM2_KEY |
                     NTLMFLAG_NEGOTIATE_ALWAYS_SIGN);
    fprintf(stderr, "\n****\n");
  });

  Curl_bufref_set(out, ntlmbuf, size, curl_free);
  return CURLE_OK;
}

/*
 * Curl_auth_create_ntlm_type3_message()
 *
 * This is used to generate an already encoded NTLM type-3 message ready for
 * sending to the recipient using the appropriate compile time crypto API.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * userp   [in]     - The username in the format User or Domain\User.
 * passwdp [in]     - The user's password.
 * ntlm    [in/out] - The NTLM data struct being used and modified.
 * out     [out]    - The result storage.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_auth_create_ntlm_type3_message(struct Curl_easy *data,
                                             const char *userp,
                                             const char *passwdp,
                                             struct ntlmdata *ntlm,
                                             struct bufref *out)
{
  /* NTLM type-3 message structure:

          Index  Description            Content
            0    NTLMSSP Signature      Null-terminated ASCII "NTLMSSP"
                                        (0x4e544c4d53535000)
            8    NTLM Message Type      long (0x03000000)
           12    LM/LMv2 Response       security buffer
           20    NTLM/NTLMv2 Response   security buffer
           28    Target Name            security buffer
           36    username              security buffer
           44    Workstation Name       security buffer
          (52)   Session Key            security buffer (*)
          (60)   Flags                  long (*)
          (64)   OS Version Structure   8 bytes (*)
  52 (64) (72)   Start of data block
                                          (*) -> Optional
  */

  CURLcode result = CURLE_OK;
  size_t size;
  unsigned char ntlmbuf[NTLM_BUFSIZE];
  unsigned int lmrespoff;
  unsigned char lmresp[24]; /* fixed-size */
  unsigned int ntrespoff;
  unsigned int ntresplen = 24;
  unsigned char ntresp[24]; /* fixed-size */
  unsigned char *ptr_ntresp = &ntresp[0];
  unsigned char *ntlmv2resp = NULL;
  bool unicode = (ntlm->flags & NTLMFLAG_NEGOTIATE_UNICODE);
  /* The fixed hostname we provide, in order to not leak our real local host
     name. Copy the name used by Firefox. */
  static const char host[] = "WORKSTATION";
  const char *user;
  const char *domain = "";
  size_t hostoff = 0;
  size_t useroff = 0;
  size_t domoff = 0;
  size_t hostlen = 0;
  size_t userlen = 0;
  size_t domlen = 0;

  memset(lmresp, 0, sizeof(lmresp));
  memset(ntresp, 0, sizeof(ntresp));
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
  hostlen = sizeof(host) - 1;

  if(ntlm->flags & NTLMFLAG_NEGOTIATE_NTLM2_KEY) {
    unsigned char ntbuffer[0x18];
    unsigned char entropy[8];
    unsigned char ntlmv2hash[0x18];

    /* Full NTLM version 2
       Although this cannot be negotiated, it is used here if available, as
       servers featuring extended security are likely supporting also
       NTLMv2. */
    result = Curl_rand(data, entropy, 8);
    if(result)
      return result;

    result = Curl_ntlm_core_mk_nt_hash(passwdp, ntbuffer);
    if(result)
      return result;

    result = Curl_ntlm_core_mk_ntlmv2_hash(user, userlen, domain, domlen,
                                           ntbuffer, ntlmv2hash);
    if(result)
      return result;

    /* LMv2 response */
    result = Curl_ntlm_core_mk_lmv2_resp(ntlmv2hash, entropy,
                                         &ntlm->nonce[0], lmresp);
    if(result)
      return result;

    /* NTLMv2 response */
    result = Curl_ntlm_core_mk_ntlmv2_resp(ntlmv2hash, entropy,
                                           ntlm, &ntlmv2resp, &ntresplen);
    if(result)
      return result;

    ptr_ntresp = ntlmv2resp;
  }
  else {

    unsigned char ntbuffer[0x18];
    unsigned char lmbuffer[0x18];

    /* NTLM version 1 */

    result = Curl_ntlm_core_mk_nt_hash(passwdp, ntbuffer);
    if(result)
      return result;

    Curl_ntlm_core_lm_resp(ntbuffer, &ntlm->nonce[0], ntresp);

    result = Curl_ntlm_core_mk_lm_hash(passwdp, lmbuffer);
    if(result)
      return result;

    Curl_ntlm_core_lm_resp(lmbuffer, &ntlm->nonce[0], lmresp);
    ntlm->flags &= ~(unsigned int)NTLMFLAG_NEGOTIATE_NTLM2_KEY;

    /* A safer but less compatible alternative is:
     *   Curl_ntlm_core_lm_resp(ntbuffer, &ntlm->nonce[0], lmresp);
     * See https://davenport.sourceforge.net/ntlm.html#ntlmVersion2 */
  }

  if(unicode) {
    domlen = domlen * 2;
    userlen = userlen * 2;
    hostlen = hostlen * 2;
  }

  lmrespoff = 64; /* size of the message header */
  ntrespoff = lmrespoff + 0x18;
  domoff = ntrespoff + ntresplen;
  useroff = domoff + domlen;
  hostoff = useroff + userlen;

  /* Create the big type-3 message binary blob */
  size = msnprintf((char *)ntlmbuf, NTLM_BUFSIZE,
                   NTLMSSP_SIGNATURE "%c"
                   "\x03%c%c%c"  /* 32-bit type = 3 */

                   "%c%c"  /* LanManager length */
                   "%c%c"  /* LanManager allocated space */
                   "%c%c"  /* LanManager offset */
                   "%c%c"  /* 2 zeroes */

                   "%c%c"  /* NT-response length */
                   "%c%c"  /* NT-response allocated space */
                   "%c%c"  /* NT-response offset */
                   "%c%c"  /* 2 zeroes */

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

                   "%c%c%c%c",  /* flags */

                   /* domain string */
                   /* user string */
                   /* host string */
                   /* LanManager response */
                   /* NT response */

                   0,                /* null-termination */
                   0, 0, 0,          /* type-3 long, the 24 upper bits */

                   SHORTPAIR(0x18),  /* LanManager response length, twice */
                   SHORTPAIR(0x18),
                   SHORTPAIR(lmrespoff),
                   0x0, 0x0,

                   SHORTPAIR(ntresplen),  /* NT-response length, twice */
                   SHORTPAIR(ntresplen),
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
                   0x0, 0x0,

                   0x0, 0x0,
                   0x0, 0x0,
                   0x0, 0x0,
                   0x0, 0x0,

                   LONGQUARTET(ntlm->flags));

  DEBUGASSERT(size == 64);
  DEBUGASSERT(size == (size_t)lmrespoff);

  /* We append the binary hashes */
  if(size < (NTLM_BUFSIZE - 0x18)) {
    memcpy(&ntlmbuf[size], lmresp, 0x18);
    size += 0x18;
  }

  DEBUG_OUT({
    fprintf(stderr, "**** TYPE3 header lmresp=");
    ntlm_print_hex(stderr, (char *)&ntlmbuf[lmrespoff], 0x18);
  });

  /* ntresplen + size should not be risking an integer overflow here */
  if(ntresplen + size > sizeof(ntlmbuf)) {
    failf(data, "incoming NTLM message too big");
    return CURLE_OUT_OF_MEMORY;
  }
  DEBUGASSERT(size == (size_t)ntrespoff);
  memcpy(&ntlmbuf[size], ptr_ntresp, ntresplen);
  size += ntresplen;

  DEBUG_OUT({
    fprintf(stderr, "\n   ntresp=");
    ntlm_print_hex(stderr, (char *)&ntlmbuf[ntrespoff], ntresplen);
  });

  FREE(ntlmv2resp);/* Free the dynamic buffer allocated for NTLMv2 */

  DEBUG_OUT({
    fprintf(stderr, "\n   flags=0x%02.2x%02.2x%02.2x%02.2x 0x%08.8x ",
            LONGQUARTET(ntlm->flags), ntlm->flags);
    ntlm_print_flags(stderr, ntlm->flags);
    fprintf(stderr, "\n****\n");
  });

  /* Make sure that the domain, user and host strings fit in the
     buffer before we copy them there. */
  if(size + userlen + domlen + hostlen >= NTLM_BUFSIZE) {
    failf(data, "user + domain + hostname too big");
    return CURLE_OUT_OF_MEMORY;
  }

  DEBUGASSERT(size == domoff);
  if(unicode)
    unicodecpy(&ntlmbuf[size], domain, domlen / 2);
  else
    memcpy(&ntlmbuf[size], domain, domlen);

  size += domlen;

  DEBUGASSERT(size == useroff);
  if(unicode)
    unicodecpy(&ntlmbuf[size], user, userlen / 2);
  else
    memcpy(&ntlmbuf[size], user, userlen);

  size += userlen;

  DEBUGASSERT(size == hostoff);
  if(unicode)
    unicodecpy(&ntlmbuf[size], host, hostlen / 2);
  else
    memcpy(&ntlmbuf[size], host, hostlen);

  size += hostlen;

  /* Return the binary blob. */
  result = Curl_bufref_memdup(out, ntlmbuf, size);

  Curl_auth_cleanup_ntlm(ntlm);

  return result;
}

/*
 * Curl_auth_cleanup_ntlm()
 *
 * This is used to clean up the NTLM specific data.
 *
 * Parameters:
 *
 * ntlm    [in/out] - The NTLM data struct being cleaned up.
 *
 */
void Curl_auth_cleanup_ntlm(struct ntlmdata *ntlm)
{
  /* Free the target info */
  Curl_safefree(ntlm->target_info);

  /* Reset any variables */
  ntlm->target_info_len = 0;
}

#endif /* USE_NTLM && !USE_WINDOWS_SSPI */
