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

#include "setup.h"

#ifdef USE_NTLM

/*
 * NTLM details:
 *
 * http://davenport.sourceforge.net/ntlm.html
 * http://www.innovation.ch/java/ntlm.html
 */

#define DEBUG_ME 0

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
#  include "ssluse.h"

#elif defined(USE_GNUTLS_NETTLE)

#  include <nettle/md5.h>
#  include <gnutls/gnutls.h>
#  include <gnutls/crypto.h>
#  define MD5_DIGEST_LENGTH 16

#elif defined(USE_GNUTLS)

#  include <gcrypt.h>
#  include "gtls.h"
#  define MD5_DIGEST_LENGTH 16
#  define MD4_DIGEST_LENGTH 16

#elif defined(USE_NSS)

#  include <nss.h>
#  include <pk11pub.h>
#  include <hasht.h>
#  include "nssg.h"
#  include "curl_md4.h"
#  define MD5_DIGEST_LENGTH MD5_LENGTH

#elif defined(USE_WINDOWS_SSPI)
#  include "curl_sspi.h"
#else
#  error "Can't compile NTLM support without a crypto library."
#endif

#include "urldata.h"
#include "non-ascii.h"
#include "sendf.h"
#include "curl_base64.h"
#include "curl_ntlm_core.h"
#include "curl_gethostname.h"
#include "curl_memory.h"

#define BUILDING_CURL_NTLM_MSGS_C
#include "curl_ntlm_msgs.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

/* "NTLMSSP" signature is always in ASCII regardless of the platform */
#define NTLMSSP_SIGNATURE "\x4e\x54\x4c\x4d\x53\x53\x50"

#define SHORTPAIR(x) ((x) & 0xff), (((x) >> 8) & 0xff)
#define LONGQUARTET(x) ((x) & 0xff), (((x) >> 8) & 0xff), \
  (((x) >> 16) & 0xff), (((x) >> 24) & 0xff)

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

static void ntlm_print_hex(FILE *handle, const char *buf, size_t len)
{
  const char *p = buf;
  (void)handle;
  fprintf(stderr, "0x");
  while(len-- > 0)
    fprintf(stderr, "%02.2x", (unsigned int)*p++);
}
#else
# define DEBUG_OUT(x) Curl_nop_stmt
#endif

#ifndef USE_WINDOWS_SSPI
/*
 * This function converts from the little endian format used in the
 * incoming package to whatever endian format we're using natively.
 * Argument is a pointer to a 4 byte buffer.
 */
static unsigned int readint_le(unsigned char *buf)
{
  return ((unsigned int)buf[0]) | ((unsigned int)buf[1] << 8) |
    ((unsigned int)buf[2] << 16) | ((unsigned int)buf[3] << 24);
}
#endif

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
 * Curl_ntlm_decode_type2_message()
 *
 * This is used to decode a ntlm type-2 message received from a: HTTP, SMTP
 * or POP3 server. The message is first decoded from a base64 string into a
 * raw ntlm message and checked for validity before the appropriate data for
 * creating a type-3 message is written to the given ntlm data structure.
 *
 * Parameters:
 *
 * data    [in]     - Pointer to session handle.
 * header  [in]     - Pointer to the input buffer.
 * ntlm    [in]     - Pointer to ntlm data struct being used and modified.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_ntlm_decode_type2_message(struct SessionHandle *data,
                                        const char* header,
                                        struct ntlmdata* ntlm)
{
#ifndef USE_WINDOWS_SSPI
  static const char type2_marker[] = { 0x02, 0x00, 0x00, 0x00 };
#endif

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

  size_t size = 0;
  unsigned char *buffer = NULL;
  CURLcode error;

#if defined(CURL_DISABLE_VERBOSE_STRINGS) || defined(USE_WINDOWS_SSPI)
  (void)data;
#endif

  error = Curl_base64_decode(header, &buffer, &size);
  if(error)
    return error;

  if(!buffer) {
    infof(data, "NTLM handshake failure (unhandled condition)\n");
    return CURLE_REMOTE_ACCESS_DENIED;
  }

#ifdef USE_WINDOWS_SSPI
  ntlm->type_2 = malloc(size + 1);
  if(ntlm->type_2 == NULL) {
    free(buffer);
    return CURLE_OUT_OF_MEMORY;
  }
  ntlm->n_type_2 = (unsigned long)size;
  memcpy(ntlm->type_2, buffer, size);
#else
  ntlm->flags = 0;

  if((size < 32) ||
     (memcmp(buffer, NTLMSSP_SIGNATURE, 8) != 0) ||
     (memcmp(buffer + 8, type2_marker, sizeof(type2_marker)) != 0)) {
    /* This was not a good enough type-2 message */
    free(buffer);
    infof(data, "NTLM handshake failure (bad type-2 message)\n");
    return CURLE_REMOTE_ACCESS_DENIED;
  }

  ntlm->flags = readint_le(&buffer[20]);
  memcpy(ntlm->nonce, &buffer[24], 8);

  DEBUG_OUT({
    fprintf(stderr, "**** TYPE2 header flags=0x%08.8lx ", ntlm->flags);
    ntlm_print_flags(stderr, ntlm->flags);
    fprintf(stderr, "\n                  nonce=");
    ntlm_print_hex(stderr, (char *)ntlm->nonce, 8);
    fprintf(stderr, "\n****\n");
    fprintf(stderr, "**** Header %s\n ", header);
  });
#endif
  free(buffer);

  return CURLE_OK;
}

#ifdef USE_WINDOWS_SSPI
void Curl_ntlm_sspi_cleanup(struct ntlmdata *ntlm)
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

#ifndef USE_WINDOWS_SSPI
/* copy the source to the destination and fill in zeroes in every
   other destination byte! */
static void unicodecpy(unsigned char *dest,
                       const char *src, size_t length)
{
  size_t i;
  for(i = 0; i < length; i++) {
    dest[2 * i] = (unsigned char)src[i];
    dest[2 * i + 1] = '\0';
  }
}
#endif

/*
 * Curl_ntlm_create_type1_message()
 *
 * This is used to generate an already encoded NTLM type-1 message ready
 * for sending to the recipient, be it a: HTTP, SMTP or POP3 server,
 * using the appropriate compile time crypo API.
 *
 * Parameters:
 *
 * userp   [in]     - The user name in the format User or Domain\User.
 * passdwp [in]     - The user's password.
 * ntlm    [in/out] - The ntlm data struct being used and modified.
 * outptr  [in/out] - The adress where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_ntlm_create_type1_message(const char *userp,
                                        const char *passwdp,
                                        struct ntlmdata *ntlm,
                                        char **outptr,
                                        size_t *outlen)
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

  unsigned char ntlmbuf[NTLM_BUFSIZE];
  size_t size;

#ifdef USE_WINDOWS_SSPI

  SecBuffer buf;
  SecBufferDesc desc;
  SECURITY_STATUS status;
  ULONG attrs;
  const char *dest = "";
  const char *user;
  const char *domain = "";
  size_t userlen = 0;
  size_t domlen = 0;
  size_t passwdlen = 0;
  TimeStamp tsDummy; /* For Windows 9x compatibility of SSPI calls */

  Curl_ntlm_sspi_cleanup(ntlm);

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

  if(user)
    userlen = strlen(user);

  if(passwdp)
    passwdlen = strlen(passwdp);

  if(userlen > 0) {
    /* note: initialize all of this before doing the mallocs so that
     * it can be cleaned up later without leaking memory.
     */
    ntlm->p_identity = &ntlm->identity;
    memset(ntlm->p_identity, 0, sizeof(*ntlm->p_identity));
    if((ntlm->identity.User = (unsigned char *)strdup(user)) == NULL)
      return CURLE_OUT_OF_MEMORY;

    ntlm->identity.UserLength = (unsigned long)userlen;
    if((ntlm->identity.Password = (unsigned char *)strdup(passwdp)) == NULL)
      return CURLE_OUT_OF_MEMORY;

    ntlm->identity.PasswordLength = (unsigned long)strlen(passwdp);
    if((ntlm->identity.Domain = malloc(domlen + 1)) == NULL)
      return CURLE_OUT_OF_MEMORY;

    strncpy((char *)ntlm->identity.Domain, domain, domlen);
    ntlm->identity.Domain[domlen] = '\0';
    ntlm->identity.DomainLength = (unsigned long)domlen;
    ntlm->identity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
  }
  else
    ntlm->p_identity = NULL;

  status = s_pSecFn->AcquireCredentialsHandleA(NULL, (void *)"NTLM",
                                               SECPKG_CRED_OUTBOUND, NULL,
                                               ntlm->p_identity, NULL, NULL,
                                               &ntlm->handle, &tsDummy);
  if(status != SEC_E_OK)
    return CURLE_OUT_OF_MEMORY;

  desc.ulVersion = SECBUFFER_VERSION;
  desc.cBuffers  = 1;
  desc.pBuffers  = &buf;
  buf.cbBuffer   = NTLM_BUFSIZE;
  buf.BufferType = SECBUFFER_TOKEN;
  buf.pvBuffer   = ntlmbuf;

  status = s_pSecFn->InitializeSecurityContextA(&ntlm->handle, NULL,
                                                (void *)dest,
                                                ISC_REQ_CONFIDENTIALITY |
                                                ISC_REQ_REPLAY_DETECT |
                                                ISC_REQ_CONNECTION,
                                                0, SECURITY_NETWORK_DREP,
                                                NULL, 0,
                                                &ntlm->c_handle, &desc,
                                                &attrs, &tsDummy);

  if(status == SEC_I_COMPLETE_AND_CONTINUE ||
     status == SEC_I_CONTINUE_NEEDED)
    s_pSecFn->CompleteAuthToken(&ntlm->c_handle, &desc);
  else if(status != SEC_E_OK) {
    s_pSecFn->FreeCredentialsHandle(&ntlm->handle);
    return CURLE_RECV_ERROR;
  }

  ntlm->has_handles = 1;
  size = buf.cbBuffer;

#else

  const char *host = "";              /* empty */
  const char *domain = "";            /* empty */
  size_t hostlen = 0;
  size_t domlen = 0;
  size_t hostoff = 0;
  size_t domoff = hostoff + hostlen;  /* This is 0: remember that host and
                                         domain are empty */
  (void)userp;
  (void)passwdp;
  (void)ntlm;

#if USE_NTLM2SESSION
#define NTLM2FLAG NTLMFLAG_NEGOTIATE_NTLM2_KEY
#else
#define NTLM2FLAG 0
#endif
  snprintf((char *)ntlmbuf, NTLM_BUFSIZE,
           NTLMSSP_SIGNATURE "%c"
           "\x01%c%c%c" /* 32-bit type = 1 */
           "%c%c%c%c"   /* 32-bit NTLM flag field */
           "%c%c"       /* domain length */
           "%c%c"       /* domain allocated space */
           "%c%c"       /* domain name offset */
           "%c%c"       /* 2 zeroes */
           "%c%c"       /* host length */
           "%c%c"       /* host allocated space */
           "%c%c"       /* host name offset */
           "%c%c"       /* 2 zeroes */
           "%s"         /* host name */
           "%s",        /* domain string */
           0,           /* trailing zero */
           0, 0, 0,     /* part of type-1 long */

           LONGQUARTET(NTLMFLAG_NEGOTIATE_OEM |
                       NTLMFLAG_REQUEST_TARGET |
                       NTLMFLAG_NEGOTIATE_NTLM_KEY |
                       NTLM2FLAG |
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

  /* Initial packet length */
  size = 32 + hostlen + domlen;

#endif

  DEBUG_OUT({
    fprintf(stderr, "* TYPE1 header flags=0x%02.2x%02.2x%02.2x%02.2x "
            "0x%08.8x ",
            LONGQUARTET(NTLMFLAG_NEGOTIATE_OEM |
                        NTLMFLAG_REQUEST_TARGET |
                        NTLMFLAG_NEGOTIATE_NTLM_KEY |
                        NTLM2FLAG |
                        NTLMFLAG_NEGOTIATE_ALWAYS_SIGN),
            NTLMFLAG_NEGOTIATE_OEM |
            NTLMFLAG_REQUEST_TARGET |
            NTLMFLAG_NEGOTIATE_NTLM_KEY |
            NTLM2FLAG |
            NTLMFLAG_NEGOTIATE_ALWAYS_SIGN);
    ntlm_print_flags(stderr,
                     NTLMFLAG_NEGOTIATE_OEM |
                     NTLMFLAG_REQUEST_TARGET |
                     NTLMFLAG_NEGOTIATE_NTLM_KEY |
                     NTLM2FLAG |
                     NTLMFLAG_NEGOTIATE_ALWAYS_SIGN);
    fprintf(stderr, "\n****\n");
  });

  /* Return with binary blob encoded into base64 */
  return Curl_base64_encode(NULL, (char *)ntlmbuf, size, outptr, outlen);
}

/*
 * Curl_ntlm_create_type3_message()
 *
 * This is used to generate an already encoded NTLM type-3 message ready
 * for sending to the recipient, be it a: HTTP, SMTP or POP3 server,
 * using the appropriate compile time crypo API.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * userp   [in]     - The user name in the format User or Domain\User.
 * passdwp [in]     - The user's password.
 * ntlm    [in/out] - The ntlm data struct being used and modified.
 * outptr  [in/out] - The adress where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_ntlm_create_type3_message(struct SessionHandle *data,
                                        const char *userp,
                                        const char *passwdp,
                                        struct ntlmdata *ntlm,
                                        char **outptr,
                                        size_t *outlen)
{
  /* NTLM type-3 message structure:

          Index  Description            Content
            0    NTLMSSP Signature      Null-terminated ASCII "NTLMSSP"
                                        (0x4e544c4d53535000)
            8    NTLM Message Type      long (0x03000000)
           12    LM/LMv2 Response       security buffer
           20    NTLM/NTLMv2 Response   security buffer
           28    Target Name            security buffer
           36    User Name              security buffer
           44    Workstation Name       security buffer
          (52)   Session Key            security buffer (*)
          (60)   Flags                  long (*)
          (64)   OS Version Structure   8 bytes (*)
  52 (64) (72)   Start of data block
                                          (*) -> Optional
  */

  unsigned char ntlmbuf[NTLM_BUFSIZE];
  size_t size;

#ifdef USE_WINDOWS_SSPI
  const char *dest = "";
  SecBuffer type_2;
  SecBuffer type_3;
  SecBufferDesc type_2_desc;
  SecBufferDesc type_3_desc;
  SECURITY_STATUS status;
  ULONG attrs;
  TimeStamp tsDummy; /* For Windows 9x compatibility of SSPI calls */

  (void)passwdp;
  (void)userp;
  (void)data;

  type_2_desc.ulVersion = type_3_desc.ulVersion  = SECBUFFER_VERSION;
  type_2_desc.cBuffers  = type_3_desc.cBuffers   = 1;
  type_2_desc.pBuffers  = &type_2;
  type_3_desc.pBuffers  = &type_3;

  type_2.BufferType = SECBUFFER_TOKEN;
  type_2.pvBuffer   = ntlm->type_2;
  type_2.cbBuffer   = ntlm->n_type_2;
  type_3.BufferType = SECBUFFER_TOKEN;
  type_3.pvBuffer   = ntlmbuf;
  type_3.cbBuffer   = NTLM_BUFSIZE;

  status = s_pSecFn->InitializeSecurityContextA(&ntlm->handle,
                                                &ntlm->c_handle,
                                                (void *)dest,
                                                ISC_REQ_CONFIDENTIALITY |
                                                ISC_REQ_REPLAY_DETECT |
                                                ISC_REQ_CONNECTION,
                                                0, SECURITY_NETWORK_DREP,
                                                &type_2_desc,
                                                0, &ntlm->c_handle,
                                                &type_3_desc,
                                                &attrs, &tsDummy);
  if(status != SEC_E_OK)
    return CURLE_RECV_ERROR;

  size = type_3.cbBuffer;

  Curl_ntlm_sspi_cleanup(ntlm);

#else
  int lmrespoff;
  unsigned char lmresp[24]; /* fixed-size */
#if USE_NTRESPONSES
  int ntrespoff;
  unsigned char ntresp[24]; /* fixed-size */
#endif
  bool unicode = (ntlm->flags & NTLMFLAG_NEGOTIATE_UNICODE) ? TRUE : FALSE;
  char host[HOSTNAME_MAX + 1] = "";
  const char *user;
  const char *domain = "";
  size_t hostoff = 0;
  size_t useroff = 0;
  size_t domoff = 0;
  size_t hostlen = 0;
  size_t userlen = 0;
  size_t domlen = 0;
  CURLcode res;

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

  if(user)
    userlen = strlen(user);

  /* Get the machine's un-qualified host name as NTLM doesn't like the fully
     qualified domain name */
  if(Curl_gethostname(host, sizeof(host))) {
    infof(data, "gethostname() failed, continuing without!\n");
    hostlen = 0;
  }
  else {
    hostlen = strlen(host);
  }

  if(unicode) {
    domlen = domlen * 2;
    userlen = userlen * 2;
    hostlen = hostlen * 2;
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
    Curl_ossl_seed(data); /* Initiate the seed if not already done */
    RAND_bytes(entropy, 8);
#elif defined(USE_GNUTLS_NETTLE)
    struct md5_ctx MD5pw;
    gnutls_rnd(GNUTLS_RND_RANDOM, entropy, 8);
#elif defined(USE_GNUTLS)
    gcry_md_hd_t MD5pw;
    Curl_gtls_seed(data); /* Initiate the seed if not already done */
    gcry_randomize(entropy, 8, GCRY_STRONG_RANDOM);
#elif defined(USE_NSS)
    PK11Context *MD5pw;
    unsigned int MD5len;
    Curl_nss_seed(data);  /* Initiate the seed if not already done */
    PK11_GenerateRandom(entropy, 8);
#endif

    /* 8 bytes random data as challenge in lmresp */
    memcpy(lmresp, entropy, 8);

    /* Pad with zeros */
    memset(lmresp + 8, 0, 0x10);

    /* Fill tmp with challenge(nonce?) + entropy */
    memcpy(tmp, &ntlm->nonce[0], 8);
    memcpy(tmp + 8, entropy, 8);

#ifdef USE_SSLEAY
    MD5_Init(&MD5pw);
    MD5_Update(&MD5pw, tmp, 16);
    MD5_Final(md5sum, &MD5pw);
#elif defined(USE_GNUTLS_NETTLE)
    md5_init(&MD5pw);
    md5_update(&MD5pw, 16, tmp);
    md5_digest(&MD5pw, 16, md5sum);
#elif defined(USE_GNUTLS)
    gcry_md_open(&MD5pw, GCRY_MD_MD5, 0);
    gcry_md_write(MD5pw, tmp, MD5_DIGEST_LENGTH);
    memcpy(md5sum, gcry_md_read (MD5pw, 0), MD5_DIGEST_LENGTH);
    gcry_md_close(MD5pw);
#elif defined(USE_NSS)
    MD5pw = PK11_CreateDigestContext(SEC_OID_MD5);
    PK11_DigestOp(MD5pw, tmp, 16);
    PK11_DigestFinal(MD5pw, md5sum, &MD5len, MD5_DIGEST_LENGTH);
    PK11_DestroyContext(MD5pw, PR_TRUE);
#endif

    /* We shall only use the first 8 bytes of md5sum, but the des
       code in Curl_ntlm_core_lm_resp only encrypt the first 8 bytes */
    if(CURLE_OUT_OF_MEMORY ==
       Curl_ntlm_core_mk_nt_hash(data, passwdp, ntbuffer))
      return CURLE_OUT_OF_MEMORY;
    Curl_ntlm_core_lm_resp(ntbuffer, md5sum, ntresp);

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
    if(CURLE_OUT_OF_MEMORY ==
       Curl_ntlm_core_mk_nt_hash(data, passwdp, ntbuffer))
      return CURLE_OUT_OF_MEMORY;
    Curl_ntlm_core_lm_resp(ntbuffer, &ntlm->nonce[0], ntresp);
#endif

    Curl_ntlm_core_mk_lm_hash(data, passwdp, lmbuffer);
    Curl_ntlm_core_lm_resp(lmbuffer, &ntlm->nonce[0], lmresp);
    /* A safer but less compatible alternative is:
     *   Curl_ntlm_core_lm_resp(ntbuffer, &ntlm->nonce[0], lmresp);
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

  /* Create the big type-3 message binary blob */
  size = snprintf((char *)ntlmbuf, NTLM_BUFSIZE,
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

                  0,                /* zero termination */
                  0, 0, 0,          /* type-3 long, the 24 upper bits */

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

#if USE_NTRESPONSES
  if(size < (NTLM_BUFSIZE - 0x18)) {
    DEBUGASSERT(size == (size_t)ntrespoff);
    memcpy(&ntlmbuf[size], ntresp, 0x18);
    size += 0x18;
  }

  DEBUG_OUT({
    fprintf(stderr, "\n   ntresp=");
    ntlm_print_hex(stderr, (char *)&ntlmbuf[ntrespoff], 0x18);
  });

#endif

  DEBUG_OUT({
    fprintf(stderr, "\n   flags=0x%02.2x%02.2x%02.2x%02.2x 0x%08.8x ",
            LONGQUARTET(ntlm->flags), ntlm->flags);
    ntlm_print_flags(stderr, ntlm->flags);
    fprintf(stderr, "\n****\n");
  });

  /* Make sure that the domain, user and host strings fit in the
     buffer before we copy them there. */
  if(size + userlen + domlen + hostlen >= NTLM_BUFSIZE) {
    failf(data, "user + domain + host name too big");
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

  /* Convert domain, user, and host to ASCII but leave the rest as-is */
  res = Curl_convert_to_network(data, (char *)&ntlmbuf[domoff],
                                size - domoff);
  if(res)
    return CURLE_CONV_FAILED;

#endif

  /* Return with binary blob encoded into base64 */
  return Curl_base64_encode(NULL, (char *)ntlmbuf, size, outptr, outlen);
}

#endif /* USE_NTLM */
