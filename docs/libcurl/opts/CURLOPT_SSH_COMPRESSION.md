---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSH_COMPRESSION
Section: 3
Source: libcurl
See-also:
  - CURLOPT_ACCEPT_ENCODING (3)
  - CURLOPT_TRANSFER_ENCODING (3)
---

# NAME

CURLOPT_SSH_COMPRESSION - enable SSH compression

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSH_COMPRESSION, long enable);
~~~

# DESCRIPTION

Pass a long as parameter set to 1L to enable or 0L to disable.

Enables built-in SSH compression. This is a request, not an order; the server
may or may not do it.

# DEFAULT

0, disabled

# PROTOCOLS

All SSH based protocols: SCP, SFTP

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "sftp://example.com");

    /* enable built-in compression */
    curl_easy_setopt(curl, CURLOPT_SSH_COMPRESSION, 1L);

    /* Perform the request */
    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.56.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
