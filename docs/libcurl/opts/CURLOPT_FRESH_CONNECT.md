---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_FRESH_CONNECT
Section: 3
Source: libcurl
Protocol:
  - All
See-also:
  - CURLOPT_FORBID_REUSE (3)
  - CURLOPT_MAXAGE_CONN (3)
  - CURLOPT_MAXLIFETIME_CONN (3)
  - CURLMOPT_NETWORK_CHANGED (3)
Added-in: 7.7
---

# NAME

CURLOPT_FRESH_CONNECT - force a new connection to be used

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_FRESH_CONNECT, long fresh);
~~~

# DESCRIPTION

Pass a long. Set to 1 to make the next transfer use a new (fresh) connection
by force instead of trying to reuse an existing one. This option should be
used with caution and only if you understand what it does as it may impact
performance negatively.

Related functionality is CURLOPT_FORBID_REUSE(3) which makes sure the
connection is closed after use so that it cannot be reused.

Set *fresh* to 0 to have libcurl attempt reusing an existing connection
(default behavior).

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1L);
    /* this transfer must use a new connection, not reuse an existing */
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
