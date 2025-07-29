#ifndef HEADER_CURL_VAUTH_H
#define HEADER_CURL_VAUTH_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Steve Holme, <steve_holme@hotmail.com>.
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

#include <curl/curl.h>

#include "../bufref.h"
#include "../curlx/dynbuf.h"

struct Curl_easy;
struct connectdata;

#ifndef CURL_DISABLE_DIGEST_AUTH
struct digestdata;
#endif

#ifdef USE_NTLM
struct ntlmdata;
#endif

#if (defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)) && defined(USE_SPNEGO)
struct negotiatedata;
#endif

#ifdef USE_GSASL
struct gsasldata;
#endif

#ifdef USE_WINDOWS_SSPI
#include "../curl_sspi.h"
#define GSS_ERROR(status) ((status) & 0x80000000)
#endif

/*
 * Curl_auth_allowed_to_host() tells if authentication, cookies or other
 * "sensitive data" can (still) be sent to this host.
 */
bool Curl_auth_allowed_to_host(struct Curl_easy *data);

/* This is used to build an SPN string */
#ifndef USE_WINDOWS_SSPI
char *Curl_auth_build_spn(const char *service, const char *host,
                          const char *realm);
#else
TCHAR *Curl_auth_build_spn(const char *service, const char *host,
                           const char *realm);
#endif

/* This is used to test if the user contains a Windows domain name */
bool Curl_auth_user_contains_domain(const char *user);

/* This is used to generate a PLAIN cleartext message */
CURLcode Curl_auth_create_plain_message(const char *authzid,
                                        const char *authcid,
                                        const char *passwd,
                                        struct bufref *out);

/* This is used to generate a LOGIN cleartext message */
void Curl_auth_create_login_message(const char *value, struct bufref *out);

/* This is used to generate an EXTERNAL cleartext message */
void Curl_auth_create_external_message(const char *user, struct bufref *out);

#ifndef CURL_DISABLE_DIGEST_AUTH
/* This is used to generate a CRAM-MD5 response message */
CURLcode Curl_auth_create_cram_md5_message(const struct bufref *chlg,
                                           const char *userp,
                                           const char *passwdp,
                                           struct bufref *out);

/* This is used to evaluate if DIGEST is supported */
bool Curl_auth_is_digest_supported(void);

/* This is used to generate a base64 encoded DIGEST-MD5 response message */
CURLcode Curl_auth_create_digest_md5_message(struct Curl_easy *data,
                                             const struct bufref *chlg,
                                             const char *userp,
                                             const char *passwdp,
                                             const char *service,
                                             struct bufref *out);

/* This is used to decode an HTTP DIGEST challenge message */
CURLcode Curl_auth_decode_digest_http_message(const char *chlg,
                                              struct digestdata *digest);

/* This is used to generate an HTTP DIGEST response message */
CURLcode Curl_auth_create_digest_http_message(struct Curl_easy *data,
                                              const char *userp,
                                              const char *passwdp,
                                              const unsigned char *request,
                                              const unsigned char *uri,
                                              struct digestdata *digest,
                                              char **outptr, size_t *outlen);

/* This is used to clean up the digest specific data */
void Curl_auth_digest_cleanup(struct digestdata *digest);
#else
#define Curl_auth_is_digest_supported()       FALSE
#endif /* !CURL_DISABLE_DIGEST_AUTH */

#ifdef USE_GSASL

/* meta key for storing GSASL meta at connection */
#define CURL_META_GSASL_CONN   "meta:auth:gsasl:conn"

#include <gsasl.h>
struct gsasldata {
  Gsasl *ctx;
  Gsasl_session *client;
};

struct gsasldata *Curl_auth_gsasl_get(struct connectdata *conn);

/* This is used to evaluate if MECH is supported by gsasl */
bool Curl_auth_gsasl_is_supported(struct Curl_easy *data,
                                  const char *mech,
                                  struct gsasldata *gsasl);
/* This is used to start a gsasl method */
CURLcode Curl_auth_gsasl_start(struct Curl_easy *data,
                               const char *userp,
                               const char *passwdp,
                               struct gsasldata *gsasl);

/* This is used to process and generate a new SASL token */
CURLcode Curl_auth_gsasl_token(struct Curl_easy *data,
                               const struct bufref *chlg,
                               struct gsasldata *gsasl,
                               struct bufref *out);

/* This is used to clean up the gsasl specific data */
void Curl_auth_gsasl_cleanup(struct gsasldata *digest);
#endif

#ifdef USE_NTLM

/* meta key for storing NTML meta at connection */
#define CURL_META_NTLM_CONN   "meta:auth:ntml:conn"
/* meta key for storing NTML-PROXY meta at connection */
#define CURL_META_NTLM_PROXY_CONN   "meta:auth:ntml-proxy:conn"

struct ntlmdata {
#ifdef USE_WINDOWS_SSPI
/* The sslContext is used for the Schannel bindings. The
 * api is available on the Windows 7 SDK and later.
 */
#ifdef SECPKG_ATTR_ENDPOINT_BINDINGS
  CtxtHandle *sslContext;
#endif
  CredHandle *credentials;
  CtxtHandle *context;
  SEC_WINNT_AUTH_IDENTITY identity;
  SEC_WINNT_AUTH_IDENTITY *p_identity;
  size_t token_max;
  BYTE *output_token;
  BYTE *input_token;
  size_t input_token_len;
  TCHAR *spn;
#else
  unsigned int flags;
  unsigned char nonce[8];
  unsigned int target_info_len;
  void *target_info; /* TargetInfo received in the NTLM type-2 message */
#endif
};

/* This is used to evaluate if NTLM is supported */
bool Curl_auth_is_ntlm_supported(void);

struct ntlmdata *Curl_auth_ntlm_get(struct connectdata *conn, bool proxy);
void Curl_auth_ntlm_remove(struct connectdata *conn, bool proxy);

/* This is used to clean up the NTLM specific data */
void Curl_auth_cleanup_ntlm(struct ntlmdata *ntlm);

/* This is used to generate a base64 encoded NTLM type-1 message */
CURLcode Curl_auth_create_ntlm_type1_message(struct Curl_easy *data,
                                             const char *userp,
                                             const char *passwdp,
                                             const char *service,
                                             const char *host,
                                             struct ntlmdata *ntlm,
                                             struct bufref *out);

/* This is used to decode a base64 encoded NTLM type-2 message */
CURLcode Curl_auth_decode_ntlm_type2_message(struct Curl_easy *data,
                                             const struct bufref *type2,
                                             struct ntlmdata *ntlm);

/* This is used to generate a base64 encoded NTLM type-3 message */
CURLcode Curl_auth_create_ntlm_type3_message(struct Curl_easy *data,
                                             const char *userp,
                                             const char *passwdp,
                                             struct ntlmdata *ntlm,
                                             struct bufref *out);

#else
#define Curl_auth_is_ntlm_supported()     FALSE
#endif /* USE_NTLM */

/* This is used to generate a base64 encoded OAuth 2.0 message */
CURLcode Curl_auth_create_oauth_bearer_message(const char *user,
                                               const char *host,
                                               const long port,
                                               const char *bearer,
                                               struct bufref *out);

/* This is used to generate a base64 encoded XOAuth 2.0 message */
CURLcode Curl_auth_create_xoauth_bearer_message(const char *user,
                                                const char *bearer,
                                                struct bufref *out);

#ifdef USE_KERBEROS5

#ifdef HAVE_GSSAPI
# ifdef HAVE_GSSGNU
#  include <gss.h>
# elif defined HAVE_GSSAPI_GSSAPI_H
#  include <gssapi/gssapi.h>
# else
#  include <gssapi.h>
# endif
# ifdef HAVE_GSSAPI_GSSAPI_GENERIC_H
#  include <gssapi/gssapi_generic.h>
# endif
#endif

/* meta key for storing KRB5 meta at connection */
#define CURL_META_KRB5_CONN   "meta:auth:krb5:conn"

struct kerberos5data {
#ifdef USE_WINDOWS_SSPI
  CredHandle *credentials;
  CtxtHandle *context;
  TCHAR *spn;
  SEC_WINNT_AUTH_IDENTITY identity;
  SEC_WINNT_AUTH_IDENTITY *p_identity;
  size_t token_max;
  BYTE *output_token;
#else
  gss_ctx_id_t context;
  gss_name_t spn;
#endif
};

struct kerberos5data *Curl_auth_krb5_get(struct connectdata *conn);

/* This is used to evaluate if GSSAPI (Kerberos V5) is supported */
bool Curl_auth_is_gssapi_supported(void);

/* This is used to generate a base64 encoded GSSAPI (Kerberos V5) user token
   message */
CURLcode Curl_auth_create_gssapi_user_message(struct Curl_easy *data,
                                              const char *userp,
                                              const char *passwdp,
                                              const char *service,
                                              const char *host,
                                              const bool mutual,
                                              const struct bufref *chlg,
                                              struct kerberos5data *krb5,
                                              struct bufref *out);

/* This is used to generate a base64 encoded GSSAPI (Kerberos V5) security
   token message */
CURLcode Curl_auth_create_gssapi_security_message(struct Curl_easy *data,
                                                  const char *authzid,
                                                  const struct bufref *chlg,
                                                  struct kerberos5data *krb5,
                                                  struct bufref *out);

/* This is used to clean up the GSSAPI specific data */
void Curl_auth_cleanup_gssapi(struct kerberos5data *krb5);
#else
#define Curl_auth_is_gssapi_supported()       FALSE
#endif /* USE_KERBEROS5 */

#ifdef USE_SPNEGO

bool Curl_auth_is_spnego_supported(void);

/* meta key for storing NEGO meta at connection */
#define CURL_META_NEGO_CONN         "meta:auth:nego:conn"
/* meta key for storing NEGO PROXY meta at connection */
#define CURL_META_NEGO_PROXY_CONN   "meta:auth:nego-proxy:conn"

/* Struct used for Negotiate (SPNEGO) authentication */
struct negotiatedata {
#ifdef HAVE_GSSAPI
  OM_uint32 status;
  gss_ctx_id_t context;
  gss_name_t spn;
  gss_buffer_desc output_token;
  struct dynbuf channel_binding_data;
#else
#ifdef USE_WINDOWS_SSPI
#ifdef SECPKG_ATTR_ENDPOINT_BINDINGS
  CtxtHandle *sslContext;
#endif
  DWORD status;
  CredHandle *credentials;
  CtxtHandle *context;
  SEC_WINNT_AUTH_IDENTITY identity;
  SEC_WINNT_AUTH_IDENTITY *p_identity;
  TCHAR *spn;
  size_t token_max;
  BYTE *output_token;
  size_t output_token_length;
#endif
#endif
  BIT(noauthpersist);
  BIT(havenoauthpersist);
  BIT(havenegdata);
  BIT(havemultiplerequests);
};

struct negotiatedata *
Curl_auth_nego_get(struct connectdata *conn, bool proxy);

/* This is used to decode a base64 encoded SPNEGO (Negotiate) challenge
   message */
CURLcode Curl_auth_decode_spnego_message(struct Curl_easy *data,
                                         const char *user,
                                         const char *password,
                                         const char *service,
                                         const char *host,
                                         const char *chlg64,
                                         struct negotiatedata *nego);

/* This is used to generate a base64 encoded SPNEGO (Negotiate) response
   message */
CURLcode Curl_auth_create_spnego_message(struct negotiatedata *nego,
                                         char **outptr, size_t *outlen);

/* This is used to clean up the SPNEGO specific data */
void Curl_auth_cleanup_spnego(struct negotiatedata *nego);

#endif /* USE_SPNEGO */

#endif /* HEADER_CURL_VAUTH_H */
