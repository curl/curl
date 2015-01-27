#ifndef HEADER_CURL_SASL_H
#define HEADER_CURL_SASL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include <curl/curl.h>

struct SessionHandle;
struct connectdata;

#if !defined(CURL_DISABLE_CRYPTO_AUTH)
struct digestdata;
#endif

#if defined(USE_NTLM)
struct ntlmdata;
#endif

#if defined(USE_KERBEROS5)
struct kerberos5data;
#endif

/* Authentication mechanism flags */
#define SASL_MECH_LOGIN             (1 << 0)
#define SASL_MECH_PLAIN             (1 << 1)
#define SASL_MECH_CRAM_MD5          (1 << 2)
#define SASL_MECH_DIGEST_MD5        (1 << 3)
#define SASL_MECH_GSSAPI            (1 << 4)
#define SASL_MECH_EXTERNAL          (1 << 5)
#define SASL_MECH_NTLM              (1 << 6)
#define SASL_MECH_XOAUTH2           (1 << 7)

/* Authentication mechanism values */
#define SASL_AUTH_NONE          0
#define SASL_AUTH_ANY           ~0U
#define SASL_AUTH_DEFAULT       (SASL_AUTH_ANY & \
                                 ~(SASL_MECH_EXTERNAL | SASL_MECH_XOAUTH2))

/* Authentication mechanism strings */
#define SASL_MECH_STRING_LOGIN      "LOGIN"
#define SASL_MECH_STRING_PLAIN      "PLAIN"
#define SASL_MECH_STRING_CRAM_MD5   "CRAM-MD5"
#define SASL_MECH_STRING_DIGEST_MD5 "DIGEST-MD5"
#define SASL_MECH_STRING_GSSAPI     "GSSAPI"
#define SASL_MECH_STRING_EXTERNAL   "EXTERNAL"
#define SASL_MECH_STRING_NTLM       "NTLM"
#define SASL_MECH_STRING_XOAUTH2    "XOAUTH2"

enum {
  CURLDIGESTALGO_MD5,
  CURLDIGESTALGO_MD5SESS
};

/* SASL machine states */
typedef enum {
  SASL_STOP,
  SASL_PLAIN,
  SASL_LOGIN,
  SASL_LOGIN_PASSWD,
  SASL_EXTERNAL,
  SASL_CRAMMD5,
  SASL_DIGESTMD5,
  SASL_DIGESTMD5_RESP,
  SASL_NTLM,
  SASL_NTLM_TYPE2MSG,
  SASL_GSSAPI,
  SASL_GSSAPI_TOKEN,
  SASL_GSSAPI_NO_DATA,
  SASL_XOAUTH2,
  SASL_CANCEL,
  SASL_FINAL
} saslstate;

/* Progress indicator */
typedef enum {
  SASL_IDLE,
  SASL_INPROGRESS,
  SASL_DONE
} saslprogress;

/* Protocol dependent SASL parameters */
struct SASLproto {
  const char *service;     /* The service name */
  int contcode;            /* Code to receive when continuation is expected */
  int finalcode;           /* Code to receive upon authentication success */
  size_t maxirlen;         /* Maximum initial response length */
  CURLcode (*sendauth)(struct connectdata *conn,
                       const char *mech, const char *ir);
                           /* Send authentication command */
  CURLcode (*sendcont)(struct connectdata *conn, const char *contauth);
                           /* Send authentication continuation */
  void (*getmessage)(char *buffer, char **outptr);
                           /* Get SASL response message */
};

/* Per-connection parameters */
struct SASL {
  const struct SASLproto *params; /* Protocol dependent parameters */
  saslstate state;         /* Current machine state */
  unsigned int authmechs;  /* Accepted authentication mechanisms */
  unsigned int prefmech;   /* Preferred authentication mechanism */
  unsigned int authused;   /* Auth mechanism used for the connection */
  bool resetprefs;         /* For URL auth option parsing. */
  bool mutual_auth;        /* Mutual authentication enabled (GSSAPI only) */
  bool force_ir;           /* Protocol always supports initial response */
};

/* This is used to test whether the line starts with the given mechanism */
#define sasl_mech_equal(line, wordlen, mech) \
  (wordlen == (sizeof(mech) - 1) / sizeof(char) && \
   !memcmp(line, mech, wordlen))

/* This is used to build a SPN string */
#if !defined(USE_WINDOWS_SSPI)
char *Curl_sasl_build_spn(const char *service, const char *instance);
#else
TCHAR *Curl_sasl_build_spn(const char *service, const char *instance);
#endif

#if defined(HAVE_GSSAPI)
char *Curl_sasl_build_gssapi_spn(const char *service, const char *host);
#endif

#ifndef CURL_DISABLE_CRYPTO_AUTH

/* This is used to generate a base64 encoded DIGEST-MD5 response message */
CURLcode Curl_sasl_create_digest_md5_message(struct SessionHandle *data,
                                             const char *chlg64,
                                             const char *userp,
                                             const char *passwdp,
                                             const char *service,
                                             char **outptr, size_t *outlen);

/* This is used to decode a HTTP DIGEST challenge message */
CURLcode Curl_sasl_decode_digest_http_message(const char *chlg,
                                              struct digestdata *digest);

/* This is used to generate a HTTP DIGEST response message */
CURLcode Curl_sasl_create_digest_http_message(struct SessionHandle *data,
                                              const char *userp,
                                              const char *passwdp,
                                              const unsigned char *request,
                                              const unsigned char *uri,
                                              struct digestdata *digest,
                                              char **outptr, size_t *outlen);

/* This is used to clean up the digest specific data */
void Curl_sasl_digest_cleanup(struct digestdata *digest);
#endif

#ifdef USE_NTLM
/* This is used to generate a base64 encoded NTLM type-1 message */
CURLcode Curl_sasl_create_ntlm_type1_message(const char *userp,
                                             const char *passwdp,
                                             struct ntlmdata *ntlm,
                                             char **outptr,
                                             size_t *outlen);

/* This is used to decode a base64 encoded NTLM type-2 message */
CURLcode Curl_sasl_decode_ntlm_type2_message(struct SessionHandle *data,
                                             const char *type2msg,
                                             struct ntlmdata *ntlm);

/* This is used to generate a base64 encoded NTLM type-3 message */
CURLcode Curl_sasl_create_ntlm_type3_message(struct SessionHandle *data,
                                             const char *userp,
                                             const char *passwdp,
                                             struct ntlmdata *ntlm,
                                             char **outptr, size_t *outlen);

/* This is used to clean up the ntlm specific data */
void Curl_sasl_ntlm_cleanup(struct ntlmdata *ntlm);

#endif /* USE_NTLM */

#if defined(USE_KERBEROS5)
/* This is used to generate a base64 encoded GSSAPI (Kerberos V5) user token
   message */
CURLcode Curl_sasl_create_gssapi_user_message(struct SessionHandle *data,
                                              const char *userp,
                                              const char *passwdp,
                                              const char *service,
                                              const bool mutual,
                                              const char *chlg64,
                                              struct kerberos5data *krb5,
                                              char **outptr, size_t *outlen);

/* This is used to generate a base64 encoded GSSAPI (Kerberos V5) security
   token message */
CURLcode Curl_sasl_create_gssapi_security_message(struct SessionHandle *data,
                                                  const char *input,
                                                  struct kerberos5data *krb5,
                                                  char **outptr,
                                                  size_t *outlen);

/* This is used to clean up the gssapi specific data */
void Curl_sasl_gssapi_cleanup(struct kerberos5data *krb5);
#endif /* USE_KERBEROS5 */

/* This is used to cleanup any libraries or curl modules used by the sasl
   functions */
void Curl_sasl_cleanup(struct connectdata *conn, unsigned int authused);

/* Convert a mechanism name to a token */
unsigned int Curl_sasl_decode_mech(const char *ptr,
                                   size_t maxlen, size_t *len);

/* Parse the URL login options */
CURLcode Curl_sasl_parse_url_auth_option(struct SASL *sasl,
                                         const char *value, size_t len);

/* Initializes an SASL structure */
void Curl_sasl_init(struct SASL *sasl, const struct SASLproto *params);

/* Check if we have enough auth data and capabilities to authenticate */
bool Curl_sasl_can_authenticate(struct SASL *sasl, struct connectdata *conn);

/* Calculate the required login details for SASL authentication  */
CURLcode Curl_sasl_start(struct SASL *sasl, struct connectdata *conn,
                         bool force_ir, saslprogress *progress);

/* Continue an SASL authentication  */
CURLcode Curl_sasl_continue(struct SASL *sasl, struct connectdata *conn,
                            int code, saslprogress *progress);

#endif /* HEADER_CURL_SASL_H */
