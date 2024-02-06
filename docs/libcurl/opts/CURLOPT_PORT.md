---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PORT
Section: 3
Source: libcurl
See-also:
  - CURLINFO_PRIMARY_PORT (3)
  - CURLOPT_STDERR (3)
  - CURLOPT_URL (3)
---

# NAME

CURLOPT_PORT - remote port number to connect to

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PORT, long number);
~~~

# DESCRIPTION

We discourage using this option since its scope is not obvious and hard to
predict. Set the preferred port number in the URL instead.

This option sets *number* to be the remote port number to connect to,
instead of the one specified in the URL or the default port for the used
protocol.

Usually, you just let the URL decide which port to use but this allows the
application to override that.

While this option accepts a 'long', a port number is an unsigned 16 bit number
and therefore using a port number lower than zero or over 65535 causes a
**CURLE_BAD_FUNCTION_ARGUMENT** error.

# DEFAULT

By default this is 0 which makes it not used. This also makes port number zero
impossible to set with this API.

# PROTOCOLS

Used for all protocols that speak to a port number.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/foo.bin");
    curl_easy_setopt(curl, CURLOPT_PORT, 8080L);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Always

# RETURN VALUE

Returns CURLE_OK
