#ifndef HEADER_CURL_UNITYTLS_H
#define HEADER_CURL_UNITYTLS_H

#include "curl/curl.h"
#include "curl_setup.h"

#ifdef USE_UNITYTLS

struct unitytls_interface_struct;

CURL_EXTERN void curl_unitytls_set_interface(struct unitytls_interface_struct* interface);

extern const struct Curl_ssl Curl_ssl_unitytls;

#endif /* USE_UNITYTLS */
#endif /* HEADER_CURL_UNITYTLS_H */
