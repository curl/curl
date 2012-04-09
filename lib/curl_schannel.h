#ifndef HEADER_SCHANNEL_H
#define HEADER_SCHANNEL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012, Marc Hoersken, <info@marc-hoersken.de>, et al.
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

#ifdef USE_WINDOWS_SSPI
#ifdef USE_SCHANNEL

#include <schnlsp.h>

#ifndef UNISP_NAME_A
#define UNISP_NAME_A "Microsoft Unified Security Protocol Provider"
#endif

typedef struct curl_schannel_cred {
  CredHandle cred_handle;
  TimeStamp time_stamp;
} curl_schannel_cred;

typedef struct curl_schannel_ctxt {
  CtxtHandle ctxt_handle;
  TimeStamp time_stamp;
} curl_schannel_ctxt;

CURLcode Curl_schannel_connect(struct connectdata *conn, int sockindex);

CURLcode Curl_schannel_connect_nonblocking(struct connectdata *conn,
                                           int sockindex,
                                           bool *done);

bool Curl_schannel_data_pending(const struct connectdata *conn, int sockindex);
void Curl_schannel_close(struct connectdata *conn, int sockindex);
int Curl_schannel_shutdown(struct connectdata *conn, int sockindex);
void Curl_schannel_session_free(void *ptr);

int Curl_schannel_init();
void Curl_schannel_cleanup();
size_t Curl_schannel_version(char *buffer, size_t size);

/* API setup for Schannel */
#define curlssl_init Curl_schannel_init
#define curlssl_cleanup Curl_schannel_cleanup
#define curlssl_connect Curl_schannel_connect
#define curlssl_connect_nonblocking Curl_schannel_connect_nonblocking
#define curlssl_session_free Curl_schannel_session_free
#define curlssl_close_all(x) (x=x, CURLE_NOT_BUILT_IN)
#define curlssl_close Curl_schannel_close
#define curlssl_shutdown Curl_schannel_shutdown
#define curlssl_set_engine(x,y) (x=x, y=y, CURLE_NOT_BUILT_IN)
#define curlssl_set_engine_default(x) (x=x, CURLE_NOT_BUILT_IN)
#define curlssl_engines_list(x) (x=x, (struct curl_slist *)NULL)
#define curlssl_version Curl_schannel_version
#define curlssl_check_cxn(x) (x=x, -1)
#define curlssl_data_pending Curl_schannel_data_pending

#endif /* USE_SCHANNEL */
#endif /* USE_WINDOWS_SSPI */
#endif /* HEADER_SCHANNEL_H */
