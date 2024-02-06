---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_FOLLOWLOCATION
Section: 3
Source: libcurl
See-also:
  - CURLINFO_REDIRECT_COUNT (3)
  - CURLINFO_REDIRECT_URL (3)
  - CURLOPT_POSTREDIR (3)
  - CURLOPT_PROTOCOLS (3)
  - CURLOPT_REDIR_PROTOCOLS (3)
---

# NAME

CURLOPT_FOLLOWLOCATION - follow HTTP 3xx redirects

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_FOLLOWLOCATION, long enable);
~~~

# DESCRIPTION

A long parameter set to 1 tells the library to follow any Location: header
redirects that an HTTP server sends in a 30x response. The Location: header
can specify a relative or an absolute URL to follow.

libcurl issues another request for the new URL and follows subsequent new
Location: redirects all the way until no more such headers are returned or the
maximum limit is reached. CURLOPT_MAXREDIRS(3) is used to limit the
number of redirects libcurl follows.

libcurl restricts what protocols it automatically follow redirects to. The
accepted target protocols are set with CURLOPT_REDIR_PROTOCOLS(3). By
default libcurl allows HTTP, HTTPS, FTP and FTPS on redirects.

When following a redirect, the specific 30x response code also dictates which
request method libcurl uses in the subsequent request: For 301, 302 and 303
responses libcurl switches method from POST to GET unless
CURLOPT_POSTREDIR(3) instructs libcurl otherwise. All other redirect
response codes make libcurl use the same method again.

For users who think the existing location following is too naive, too simple
or just lacks features, it is easy to instead implement your own redirect
follow logic with the use of curl_easy_getinfo(3)'s
CURLINFO_REDIRECT_URL(3) option instead of using
CURLOPT_FOLLOWLOCATION(3).

# NOTE

Since libcurl changes method or not based on the specific HTTP response code,
setting CURLOPT_CUSTOMREQUEST(3) while following redirects may change
what libcurl would otherwise do and if not that carefully may even make it
misbehave since CURLOPT_CUSTOMREQUEST(3) overrides the method libcurl
would otherwise select internally.

# DEFAULT

0, disabled

# PROTOCOLS

HTTP(S)

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* example.com is redirected, so we tell libcurl to follow redirection */
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Along with HTTP

# RETURN VALUE

Returns CURLE_OK if HTTP is supported, and CURLE_UNKNOWN_OPTION if not.
