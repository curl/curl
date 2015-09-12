#ifndef HEADER_CURL_VTLS_H
#define HEADER_CURL_VTLS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "openssl.h"        /* OpenSSL versions */
#include "gtls.h"           /* GnuTLS versions */
#include "nssg.h"           /* NSS versions */
#include "gskit.h"          /* Global Secure ToolKit versions */
#include "polarssl.h"       /* PolarSSL versions */
#include "axtls.h"          /* axTLS versions */
#include "cyassl.h"         /* CyaSSL versions */
#include "schannel.h"       /* Schannel SSPI version */
#include "darwinssl.h"      /* SecureTransport (Darwin) version */

#ifndef MAX_PINNED_PUBKEY_SIZE
#define MAX_PINNED_PUBKEY_SIZE 1048576 /* 1MB */
#endif

#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16 /* fixed size */
#endif

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32 /* fixed size */
#endif

/* see http://tools.ietf.org/html/draft-ietf-tls-applayerprotoneg-04 */
#define ALPN_HTTP_1_1_LENGTH 8
#define ALPN_HTTP_1_1 "http/1.1"

bool Curl_ssl_config_matches(struct ssl_config_data* data,
                             struct ssl_config_data* needle);
bool Curl_clone_ssl_config(struct ssl_config_data* source,
                           struct ssl_config_data* dest);
void Curl_free_ssl_config(struct ssl_config_data* sslc);

unsigned int Curl_rand(struct SessionHandle *);

int Curl_ssl_backend(void);

#ifdef USE_SSL
int Curl_ssl_init(void);
void Curl_ssl_cleanup(void);
CURLcode Curl_ssl_connect(struct connectdata *conn, int sockindex);
CURLcode Curl_ssl_connect_nonblocking(struct connectdata *conn,
                                      int sockindex,
                                      bool *done);
/* tell the SSL stuff to close down all open information regarding
   connections (and thus session ID caching etc) */
void Curl_ssl_close_all(struct SessionHandle *data);
void Curl_ssl_close(struct connectdata *conn, int sockindex);
CURLcode Curl_ssl_shutdown(struct connectdata *conn, int sockindex);
CURLcode Curl_ssl_set_engine(struct SessionHandle *data, const char *engine);
/* Sets engine as default for all SSL operations */
CURLcode Curl_ssl_set_engine_default(struct SessionHandle *data);
struct curl_slist *Curl_ssl_engines_list(struct SessionHandle *data);

/* init the SSL session ID cache */
CURLcode Curl_ssl_initsessions(struct SessionHandle *, size_t);
size_t Curl_ssl_version(char *buffer, size_t size);
bool Curl_ssl_data_pending(const struct connectdata *conn,
                           int connindex);
int Curl_ssl_check_cxn(struct connectdata *conn);

/* Certificate information list handling. */

void Curl_ssl_free_certinfo(struct SessionHandle *data);
CURLcode Curl_ssl_init_certinfo(struct SessionHandle * data, int num);
CURLcode Curl_ssl_push_certinfo_len(struct SessionHandle * data, int certnum,
                                    const char * label, const char * value,
                                    size_t valuelen);
CURLcode Curl_ssl_push_certinfo(struct SessionHandle * data, int certnum,
                                const char * label, const char * value);

/* Functions to be used by SSL library adaptation functions */

/* extract a session ID */
bool Curl_ssl_getsessionid(struct connectdata *conn,
                           void **ssl_sessionid,
                           size_t *idsize) /* set 0 if unknown */;
/* add a new session ID */
CURLcode Curl_ssl_addsessionid(struct connectdata *conn,
                               void *ssl_sessionid,
                               size_t idsize);
/* Kill a single session ID entry in the cache */
void Curl_ssl_kill_session(struct curl_ssl_session *session);
/* delete a session from the cache */
void Curl_ssl_delsessionid(struct connectdata *conn, void *ssl_sessionid);

/* get N random bytes into the buffer, return 0 if a find random is filled
   in */
int Curl_ssl_random(struct SessionHandle *data, unsigned char *buffer,
                    size_t length);
CURLcode Curl_ssl_md5sum(unsigned char *tmp, /* input */
                         size_t tmplen,
                         unsigned char *md5sum, /* output */
                         size_t md5len);
/* Check pinned public key. */
CURLcode Curl_pin_peer_pubkey(struct SessionHandle *data,
                              const char *pinnedpubkey,
                              const unsigned char *pubkey, size_t pubkeylen);

bool Curl_ssl_cert_status_request(void);

bool Curl_ssl_false_start(void);

#define SSL_SHUTDOWN_TIMEOUT 10000 /* ms */

#else
/* Set the API backend definition to none */
#define CURL_SSL_BACKEND CURLSSLBACKEND_NONE

/* When SSL support is not present, just define away these function calls */
#define Curl_ssl_init() 1
#define Curl_ssl_cleanup() Curl_nop_stmt
#define Curl_ssl_connect(x,y) CURLE_NOT_BUILT_IN
#define Curl_ssl_close_all(x) Curl_nop_stmt
#define Curl_ssl_close(x,y) Curl_nop_stmt
#define Curl_ssl_shutdown(x,y) CURLE_NOT_BUILT_IN
#define Curl_ssl_set_engine(x,y) CURLE_NOT_BUILT_IN
#define Curl_ssl_set_engine_default(x) CURLE_NOT_BUILT_IN
#define Curl_ssl_engines_list(x) NULL
#define Curl_ssl_send(a,b,c,d,e) -1
#define Curl_ssl_recv(a,b,c,d,e) -1
#define Curl_ssl_initsessions(x,y) CURLE_OK
#define Curl_ssl_version(x,y) 0
#define Curl_ssl_data_pending(x,y) 0
#define Curl_ssl_check_cxn(x) 0
#define Curl_ssl_free_certinfo(x) Curl_nop_stmt
#define Curl_ssl_connect_nonblocking(x,y,z) CURLE_NOT_BUILT_IN
#define Curl_ssl_kill_session(x) Curl_nop_stmt
#define Curl_ssl_random(x,y,z) ((void)x, CURLE_NOT_BUILT_IN)
#define Curl_ssl_cert_status_request() FALSE
#define Curl_ssl_false_start() FALSE
#endif

#endif /* HEADER_CURL_VTLS_H */
