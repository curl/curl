---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSLENGINE
Section: 3
Source: libcurl
See-also:
  - CURLINFO_SSL_ENGINES (3)
  - CURLOPT_SSLENGINE_DEFAULT (3)
  - CURLOPT_SSLKEY (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
Added-in: 7.9.3
---

# NAME

CURLOPT_SSLENGINE - Set SSL engine or provider

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSLENGINE, char *id);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. It is used as the
identifier for the *engine* or *provider* you want to use for your private
key. OpenSSL 1 had engines, OpenSSL 3 has providers.

The application does not have to keep the string around after setting this
option.

When asking libcurl to use a provider, the application can also optionally
provide a *property*, a set of name value pairs. Such a property can be
specified separated from the name with a colon (`:`).

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_SSLENGINE, "dynamic");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

CURLE_OK - Engine found.

CURLE_SSL_ENGINE_NOTFOUND - Engine not found, or OpenSSL was not built with
engine support.

CURLE_SSL_ENGINE_INITFAILED - Engine found but initialization failed.

CURLE_NOT_BUILT_IN - Option not built in, OpenSSL is not the SSL backend.

CURLE_UNKNOWN_OPTION - Option not recognized.

CURLE_OUT_OF_MEMORY - Insufficient heap space.
