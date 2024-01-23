---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_UNRESTRICTED_AUTH
Section: 3
Source: libcurl
See-also:
  - CURLINFO_REDIRECT_COUNT (3)
  - CURLOPT_FOLLOWLOCATION (3)
  - CURLOPT_MAXREDIRS (3)
  - CURLOPT_REDIR_PROTOCOLS_STR (3)
  - CURLOPT_USERPWD (3)
---

# NAME

CURLOPT_UNRESTRICTED_AUTH - send credentials to other hosts too

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_UNRESTRICTED_AUTH,
                          long goahead);
~~~

# DESCRIPTION

Set the long *gohead* parameter to 1L to make libcurl continue to send
authentication (user+password) credentials when following locations, even when
hostname changed. This option is meaningful only when setting
CURLOPT_FOLLOWLOCATION(3).

Further, when this option is not used or set to **0L**, libcurl does not
send custom nor internally generated Authentication: headers on requests done
to other hosts than the one used for the initial URL.

By default, libcurl only sends credentials and Authentication headers to the
initial hostname as given in the original URL, to avoid leaking username +
password to other sites.

This option should be used with caution: when curl follows redirects it
blindly fetches the next URL as instructed by the server. Setting
CURLOPT_UNRESTRICTED_AUTH(3) to 1L makes curl trust the server and sends
possibly sensitive credentials to any host the server points to, possibly
again and again as the following hosts can keep redirecting to new hosts.

# DEFAULT

0

# PROTOCOLS

HTTP

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_UNRESTRICTED_AUTH, 1L);
    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Along with HTTP

# RETURN VALUE

Returns CURLE_OK if HTTP is supported, and CURLE_UNKNOWN_OPTION if not.
