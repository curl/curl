---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXY_SSL_OPTIONS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY_SSLVERSION (3)
  - CURLOPT_PROXY_SSL_CIPHER_LIST (3)
  - CURLOPT_SSLVERSION (3)
  - CURLOPT_SSL_CIPHER_LIST (3)
Protocol:
  - TLS
TLS-backend:
  - All
Added-in: 7.52.0
---

# NAME

CURLOPT_PROXY_SSL_OPTIONS - HTTPS proxy SSL behavior options

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXY_SSL_OPTIONS,
                          long bitmask);
~~~

# DESCRIPTION

Pass a long with a bitmask to tell libcurl about specific SSL
behaviors. Available bits:

## CURLSSLOPT_ALLOW_BEAST

Tells libcurl to not attempt to use any workarounds for a security flaw in the
SSL3 and TLS1.0 protocols. If this option is not used or this bit is set to 0,
the SSL layer libcurl uses may use a work-around for this flaw although it
might cause interoperability problems with some (older) SSL implementations.
WARNING: avoiding this work-around lessens the security, and by setting this
option to 1 you ask for exactly that. This option is only supported for Secure
Transport and OpenSSL.

## CURLSSLOPT_NO_REVOKE

Tells libcurl to disable certificate revocation checks for those SSL backends
where such behavior is present. This option is only supported for Schannel
(the native Windows SSL library), with an exception in the case of Windows'
Untrusted Publishers block list which it seems cannot be bypassed. (Added in
7.44.0)

## CURLSSLOPT_NO_PARTIALCHAIN

Tells libcurl to not accept "partial" certificate chains, which it otherwise
does by default. This option is only supported for OpenSSL and fails the
certificate verification if the chain ends with an intermediate certificate
and not with a root cert. (Added in 7.68.0)

## CURLSSLOPT_REVOKE_BEST_EFFORT

Tells libcurl to ignore certificate revocation checks in case of missing or
offline distribution points for those SSL backends where such behavior is
present. This option is only supported for Schannel (the native Windows SSL
library). If combined with *CURLSSLOPT_NO_REVOKE*, the latter takes
precedence. (Added in 7.70.0)

## CURLSSLOPT_NATIVE_CA

Tell libcurl to use the operating system's native CA store for certificate
verification. This option is independent of other CA certificate locations set
at run time or build time. Those locations are searched in addition to the
native CA store.

Works with wolfSSL on Windows, Linux (Debian, Ubuntu, Gentoo, Fedora, RHEL),
macOS, Android and iOS (added in 8.3.0); with GnuTLS (added in 8.5.0) and with
OpenSSL and its forks (LibreSSL, BoringSSL, etc) on Windows (Added in 7.71.0).

## CURLSSLOPT_AUTO_CLIENT_CERT

Tell libcurl to automatically locate and use a client certificate for
authentication, when requested by the server. This option is only supported
for Schannel (the native Windows SSL library). Prior to 7.77.0 this was the
default behavior in libcurl with Schannel. Since the server can request any
certificate that supports client authentication in the OS certificate store it
could be a privacy violation and unexpected.
(Added in 7.77.0)

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_PROXY, "https://proxy");
    /* weaken TLS only for use with silly proxies */
    curl_easy_setopt(curl, CURLOPT_PROXY_SSL_OPTIONS, (long)
                     CURLSSLOPT_ALLOW_BEAST | CURLSSLOPT_NO_REVOKE);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
