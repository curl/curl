#ifndef HEADER_CURL_SCHANNEL_H
#define HEADER_CURL_SCHANNEL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012, Marc Hoersken, <info@marc-hoersken.de>, et al.
 * Copyright (C) 2012 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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

#ifdef USE_SCHANNEL

#include "urldata.h"

#ifndef UNISP_NAME_A
#define UNISP_NAME_A "Microsoft Unified Security Protocol Provider"
#endif

#ifndef UNISP_NAME_W
#define UNISP_NAME_W L"Microsoft Unified Security Protocol Provider"
#endif

#ifndef UNISP_NAME
#ifdef UNICODE
#define UNISP_NAME  UNISP_NAME_W
#else
#define UNISP_NAME  UNISP_NAME_A
#endif
#endif

#ifndef SP_PROT_SSL2_CLIENT
#define SP_PROT_SSL2_CLIENT             0x00000008
#endif

#ifndef SP_PROT_SSL3_CLIENT
#define SP_PROT_SSL3_CLIENT             0x00000008
#endif

#ifndef SP_PROT_TLS1_CLIENT
#define SP_PROT_TLS1_CLIENT             0x00000080
#endif

#ifndef SP_PROT_TLS1_0_CLIENT
#define SP_PROT_TLS1_0_CLIENT           SP_PROT_TLS1_CLIENT
#endif

#ifndef SP_PROT_TLS1_1_CLIENT
#define SP_PROT_TLS1_1_CLIENT           0x00000200
#endif

#ifndef SP_PROT_TLS1_2_CLIENT
#define SP_PROT_TLS1_2_CLIENT           0x00000800
#endif

#ifndef SECBUFFER_ALERT
#define SECBUFFER_ALERT                 17
#endif

/* Both schannel buffer sizes must be > 0 */
#define CURL_SCHANNEL_BUFFER_INIT_SIZE   4096
#define CURL_SCHANNEL_BUFFER_FREE_SIZE   1024


CURLcode Curl_schannel_connect(struct connectdata *conn, int sockindex);

CURLcode Curl_schannel_connect_nonblocking(struct connectdata *conn,
                                           int sockindex,
                                           bool *done);

bool Curl_schannel_data_pending(const struct connectdata *conn, int sockindex);
void Curl_schannel_close(struct connectdata *conn, int sockindex);
int Curl_schannel_shutdown(struct connectdata *conn, int sockindex);
void Curl_schannel_session_free(void *ptr);

int Curl_schannel_init(void);
void Curl_schannel_cleanup(void);
size_t Curl_schannel_version(char *buffer, size_t size);

int Curl_schannel_random(unsigned char *entropy, size_t length);

/* Set the API backend definition to Schannel */
#define CURL_SSL_BACKEND CURLSSLBACKEND_SCHANNEL

/* this backend supports CURLOPT_CERTINFO */
#define have_curlssl_certinfo 1

/* API setup for Schannel */
#define curlssl_init Curl_schannel_init
#define curlssl_cleanup Curl_schannel_cleanup
#define curlssl_connect Curl_schannel_connect
#define curlssl_connect_nonblocking Curl_schannel_connect_nonblocking
#define curlssl_session_free Curl_schannel_session_free
#define curlssl_close_all(x) ((void)x)
#define curlssl_close Curl_schannel_close
#define curlssl_shutdown Curl_schannel_shutdown
#define curlssl_set_engine(x,y) ((void)x, (void)y, CURLE_NOT_BUILT_IN)
#define curlssl_set_engine_default(x) ((void)x, CURLE_NOT_BUILT_IN)
#define curlssl_engines_list(x) ((void)x, (struct curl_slist *)NULL)
#define curlssl_version Curl_schannel_version
#define curlssl_check_cxn(x) ((void)x, -1)
#define curlssl_data_pending Curl_schannel_data_pending
#define curlssl_random(x,y,z) ((void)x, Curl_schannel_random(y,z))

#endif /* USE_SCHANNEL */
#endif /* HEADER_CURL_SCHANNEL_H */
