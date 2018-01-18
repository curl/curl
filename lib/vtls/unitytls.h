#ifndef HEADER_CURL_UNITYTLS_H
#define HEADER_CURL_UNITYTLS_H

#include "curl_setup.h"

#ifdef USE_UNITYTLS

CURL_EXTERN void curl_unitytls_set_interface(unitytls_interface_struct* interface);


CURLcode Curl_unitytls_connect(struct connectdata *conn, int sockindex);
CURLcode Curl_unitytls_connect_nonblocking(struct connectdata *conn, int sockindex, bool *done);

void Curl_unitytls_close(struct connectdata *conn, int sockindex);
size_t Curl_unitytls_version(char *buffer, size_t size);

/* Support HTTPS-proxy */
/* #define HTTPS_PROXY_SUPPORT 1 */

/* this backend supports the CAPATH option */
#define have_curlssl_ca_path 1

/* this backend supports does not CURLOPT_CERTINFO */
/* #define have_curlssl_certinfo 1 */

/* this backends does not supports CURLOPT_PINNEDPUBLICKEY */
/*#define have_curlssl_pinnedpubkey 1 */ /* TODO: We should be able to support this without changing unitytls */

/* API setup for unitytls */
#define curlssl_init() 1
#define curlssl_cleanup() Curl_nop_stmt
#define curlssl_connect Curl_unitytls_connect
#define curlssl_connect_nonblocking Curl_unitytls_connect_nonblocking
#define curlssl_session_free(x) ((void)x)
#define curlssl_close_all(x) ((void)x)
#define curlssl_close Curl_unitytls_close
#define curlssl_shutdown(x,y) 0
#define curlssl_set_engine(x,y) (x=x, y=y, CURLE_NOT_BUILT_IN)
#define curlssl_set_engine_default(x) (x=x, CURLE_NOT_BUILT_IN)
#define curlssl_engines_list(x) (x=x, (struct curl_slist *)NULL)
#define curlssl_version Curl_unitytls_version
#define curlssl_check_cxn(x) (x=x, -1)
#define curlssl_data_pending(x,y) ((void)x, (void)y, 0)
#define CURL_SSL_BACKEND CURLSSLBACKEND_UNITYTLS
/* #define curlssl_sha256sum(a,b,c,d) unitytls_sha256(a,b,c,0)   TODO?  */

/* This might cause libcurl to use a weeker random! */
#define curlssl_random(x,y,z) (x=x, y=y, z=z, CURLE_NOT_BUILT_IN)

#endif /* USE_UNITYTLS */
#endif /* HEADER_CURL_UNITYTLS_H */
