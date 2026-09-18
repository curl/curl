---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SOCKS5_AUTH
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY (3)
  - CURLOPT_PROXYTYPE (3)
Protocol:
  - All
Added-in: 7.55.0
---

# NAME

CURLOPT_SOCKS5_AUTH - methods for SOCKS5 proxy authentication

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SOCKS5_AUTH, long bitmask);
~~~

# DESCRIPTION

Pass a long as parameter, which is set to a bitmask, to tell libcurl which
authentication method(s) are allowed for SOCKS5 proxy authentication. The only
supported flags are *CURLAUTH_BASIC*, which allows username/password
authentication, and *CURLAUTH_GSSAPI*, which allows GSS-API authentication.
Set the actual username and password with the CURLOPT_PROXYUSERPWD(3) option.

libcurl offers the SOCKS5 "no authentication" method in addition to the ones
in the bitmask, and accepts it if the proxy selects it. *CURLAUTH_NONE* is zero
and therefore cannot be combined with the other flags; setting the bitmask to
*CURLAUTH_NONE* makes libcurl offer only the no authentication method.

Add *CURLAUTH_ONLY* to the bitmask to require authentication. libcurl then does
not offer the no authentication method, and rejects it with *CURLE_PROXY* if
the proxy selects it anyway. A connection that was set up without SOCKS5
authentication is also not reused for such a transfer. Setting *CURLAUTH_ONLY*
without *CURLAUTH_BASIC* or *CURLAUTH_GSSAPI* makes curl_easy_setopt(3) return
*CURLE_BAD_FUNCTION_ARGUMENT*.

The specific socks authentication method is an *access property*, it does not
change the security context. This means that this option changes how the
connection and access to the proxy happens when a connection is setup, but it
does not affect which proxy connections libcurl can reuse. libcurl may reuse a
connection that was set up with a different socks authentication method. Proxy
connection reuse still depends on other properties matching, such as the
protocol, proxy hostname, port number, credentials and other settings that
affect the connection.

# DEFAULT

CURLAUTH_BASIC | CURLAUTH_GSSAPI

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode result;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* request to use a SOCKS5 proxy */
    curl_easy_setopt(curl, CURLOPT_PROXY, "socks5://user:pass@myproxy.com");

    /* enable username/password authentication only */
    curl_easy_setopt(curl, CURLOPT_SOCKS5_AUTH, CURLAUTH_BASIC);

    /* Perform the request */
    result = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# HISTORY

**CURLAUTH_*** macros became `long` types in 7.26.0, prior to this version
a `long` cast was necessary when passed to curl_easy_setopt(3).

*CURLAUTH_ONLY* is supported since 8.23.0.

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
