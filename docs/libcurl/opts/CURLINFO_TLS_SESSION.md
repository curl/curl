---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_TLS_SESSION
Section: 3
Source: libcurl
See-also:
  - CURLINFO_TLS_SSL_PTR (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
Added-in: 7.34.0
---

# NAME

CURLINFO_TLS_SESSION - get TLS session info

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_TLS_SESSION,
                           struct curl_tlssessioninfo **session);
~~~

# DESCRIPTION

**This option has been superseded** by CURLINFO_TLS_SSL_PTR(3) which
was added in 7.48.0. The only reason you would use this option instead is if
you could be using a version of libcurl earlier than 7.48.0.

This option is exactly the same as CURLINFO_TLS_SSL_PTR(3) except in the
case of OpenSSL. If the session *backend* is CURLSSLBACKEND_OPENSSL the
session *internals* pointer varies depending on the option:

CURLINFO_TLS_SESSION(3) OpenSSL session *internals* is **SSL_CTX ***.

CURLINFO_TLS_SSL_PTR(3) OpenSSL session *internals* is **SSL ***.

You can obtain an **SSL_CTX** pointer from an SSL pointer using OpenSSL
function *SSL_get_SSL_CTX(3)*. Therefore unless you need compatibility
with older versions of libcurl use CURLINFO_TLS_SSL_PTR(3). Refer to
that document for more information.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    struct curl_tlssessioninfo *tls;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    res = curl_easy_perform(curl);
    if(res)
      printf("error: %s\n", curl_easy_strerror(res));
    curl_easy_getinfo(curl, CURLINFO_TLS_SESSION, &tls);
    curl_easy_cleanup(curl);
  }
}
~~~

# DEPRECATED

Deprecated since 7.48.0

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
